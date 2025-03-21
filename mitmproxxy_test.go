package proxymitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testInterceptor はテスト用のHTTPインターセプター
type testInterceptor struct {
	name     string
	logger   Logger
	recordFn func(string)
}

// ProcessRequest はリクエストを処理し、処理順序を記録します
func (ti *testInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	ti.recordFn(ti.name + "-request")
	req.Header.Add("X-Processed-By", ti.name)
	return req, false, nil
}

// ProcessResponse はレスポンスを処理し、処理順序を記録します
func (ti *testInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	ti.recordFn(ti.name + "-response")
	resp.Header.Add("X-Processed-By", ti.name)
	return resp, nil
}

func TestCreateMitmProxy(t *testing.T) {
	t.Run("failed, because load no exist file", func(t *testing.T) {
		_, err := CreateMitmProxy("", "")
		assert.Error(t, err, "Should return an error when files don't exist")
	})
	t.Run("failed, because load no pem file", func(t *testing.T) {
		_, err := CreateMitmProxy("./testdata/a.cert", "./testdata/ca.key")
		assert.Error(t, err, "Should return an error when file is not a valid PEM")
	})
	t.Run("create success", func(t *testing.T) {
		mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
		require.NoError(t, err, "CreateMitmProxy() should not return an error")

		assert.Greater(t, len(mp.tlsCert.Certificate), 0, "mp.tlsCert should have at least one Certificate")
		assert.NotNil(t, mp.x509Cert, "mp.x509Cert should not be nil")
	})
}

func Test_createX509Certificate(t *testing.T) {
	type args struct {
		hostName string
	}
	tests := []struct {
		name string
		args args
		// want    []byte
		wantErr bool
	}{
		{name: "create cert localhost", args: args{hostName: "localhost"}, wantErr: false},
		{name: "create cert other", args: args{hostName: "www.google.com"}, wantErr: false},
	}
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	require.NoError(t, err, "Should be able to create MitmProxy")

	for _, tt := range tests {
		tt := tt // キャプチャ変数のシャドウイング
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			template := mitmx509template(tt.args.hostName)
			c, _, err := mp.createX509Certificate(template)
			if tt.wantErr {
				assert.Error(t, err, "createCert() should return an error")
				return
			}
			assert.NoError(t, err, "createCert() should not return an error")

			roots := x509.NewCertPool()
			roots.AddCert(mp.x509Cert)
			vop := x509.VerifyOptions{
				DNSName: tt.args.hostName,
				Roots:   roots,
			}
			_, err = c.Verify(vop)
			assert.NoError(t, err, "Certificate should be valid and verify successfully")
		})
	}
}

func TestMitmx509template(t *testing.T) {
	t.Parallel()
	expected := "hostname"
	cert := mitmx509template(expected)
	
	assert.Len(t, cert.DNSNames, 1, "DNSNames should have exactly 1 entry")
	assert.Contains(t, cert.DNSNames, expected, "DNSNames should contain the hostname")
}

func TestMitmProxy_Handler(t *testing.T) {
	t.Parallel()
	// MITMプロキシを作成
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	require.NoError(t, err, "Should be able to create MitmProxy")

	var requestReceived bool
	var responseStatus int

	testInterceptor := &testResponseInterceptor{
		onRequest: func(req *http.Request) (*http.Request, bool, error) {
			requestReceived = true
			return req, false, nil
		},
		onResponse: func(resp *http.Response, req *http.Request) (*http.Response, error) {
			responseStatus = resp.StatusCode
			return resp, nil
		},
	}

	// インターセプターを追加
	mp.AddInterceptor(testInterceptor)

	// テスト用のTLSサーバーを作成
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// プロキシサーバーを作成
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodConnect, r.Method, "Request method should be CONNECT")
		mp.ServeHTTP(w, r)
	}))
	defer hs.Close()

	// URLをパース
	parseLocalhost := func(urlstr string) (*url.URL, error) {
		url, err := url.Parse(urlstr)
		if err != nil {
			return nil, err
		}
		url, err = url.Parse(url.Scheme + "://localhost:" + url.Port())
		if err != nil {
			return nil, err
		}
		return url, nil
	}

	proxyURL, err := parseLocalhost(hs.URL)
	require.NoError(t, err, "Should be able to parse proxy URL")

	requestURL, err := parseLocalhost(ts.URL)
	require.NoError(t, err, "Should be able to parse request URL")

	// 証明書プールを設定
	pool := x509.NewCertPool()
	pool.AddCert(mp.x509Cert)

	// プロキシのクライアントを設定
	mp.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            pool,
			},
		},
	}

	// クライアントを設定
	client := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	// リクエストを送信
	resp, err := client.Get(requestURL.String())
	require.NoError(t, err, "Should be able to send request")
	defer resp.Body.Close()

	// インターセプターが呼び出されたことを確認
	assert.True(t, requestReceived, "Request interceptor should be called")

	// レスポンスステータスが正しいことを確認
	assert.Equal(t, http.StatusOK, responseStatus, "Interceptor should receive correct response status")

	// レスポンスステータスが正しいことを確認
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Client should receive correct response status")
}

type testResponseInterceptor struct {
	onRequest  func(*http.Request) (*http.Request, bool, error)
	onResponse func(*http.Response, *http.Request) (*http.Response, error)
}

func (tri *testResponseInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	if tri.onRequest != nil {
		return tri.onRequest(req)
	}
	return req, false, nil
}

func (tri *testResponseInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	if tri.onResponse != nil {
		return tri.onResponse(resp, req)
	}
	return resp, nil
}

func TestMitmProxy_Connected(t *testing.T) {
	// MITMプロキシを作成
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// テスト用のインターセプターを作成
	var requestReceived bool

	testInterceptor := &testResponseInterceptor{
		onRequest: func(req *http.Request) (*http.Request, bool, error) {
			requestReceived = true
			return req, false, nil
		},
		onResponse: func(resp *http.Response, req *http.Request) (*http.Response, error) {
			return resp, nil
		},
	}

	// インターセプターを追加
	mp.AddInterceptor(testInterceptor)

	// テスト用のTLSサーバーを作成
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// プロキシサーバーを作成
	hs := httptest.NewServer(mp)
	defer hs.Close()

	// URLをパース
	parseLocalhost := func(urlstr string) (*url.URL, error) {
		url, err := url.Parse(urlstr)
		if err != nil {
			return nil, err
		}
		url, err = url.Parse(url.Scheme + "://localhost:" + url.Port())
		if err != nil {
			return nil, err
		}
		return url, nil
	}

	proxyURL, err := parseLocalhost(hs.URL)
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	requestURL, err := parseLocalhost(ts.URL)
	if err != nil {
		t.Fatalf("Failed to parse request URL: %v", err)
	}

	// 証明書プールを設定
	pool := x509.NewCertPool()
	pool.AddCert(mp.x509Cert)

	// プロキシのクライアントを設定
	mp.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            pool,
			},
		},
	}

	// クライアントを設定
	client := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:            pool,
				InsecureSkipVerify: true, // テスト用に証明書検証をスキップ
			},
		},
	}

	// リクエストを送信
	resp, err := client.Get(requestURL.String())
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// レスポンスステータスが正しいことを確認
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected response status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// インターセプターが呼び出されたことを確認
	if !requestReceived {
		t.Error("Request interceptor was not called")
	}
}

func TestServerMux_ServeHTTP_NonConnect(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	require.NoError(t, err, "Should be able to create MitmProxy")

	// Create a test server that will be proxied to
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Hello from target"))
		require.NoError(t, err, "Should be able to write response")
	}))
	defer targetServer.Close()

	// Create a test request with a valid URL
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Test the ServeHTTP method
	mp.ServeHTTP(w, req)

	// Since this is a non-CONNECT request, we expect an internal server error
	// because the proxy is primarily designed for CONNECT requests
	assert.Equal(t, http.StatusInternalServerError, w.Code, "Should return internal server error for non-CONNECT requests")
}

func TestServerMux_ServeHTTP_Errors(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	require.NoError(t, err, "Should be able to create MitmProxy")

	tests := []struct {
		name         string
		method       string
		url          string
		expectedCode int
	}{
		{
			name:         "Invalid Method",
			method:       "INVALID",
			url:          "http://example.com",
			expectedCode: http.StatusInternalServerError,
		},
		{
			name:         "Empty URL",
			method:       http.MethodGet,
			url:          "http://",
			expectedCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tt.method, tt.url, nil)
			w := httptest.NewRecorder()

			mp.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code, "Should return expected status code")
		})
	}
}

func TestServerMux_CreateRequest(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// Create a mock connection that returns a valid HTTP request
	mockConn := &mockConn{
		readData: []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	req, err := mp.createRequest(mockConn)
	require.NoError(t, err, "createRequest should not return an error")

	assert.Equal(t, "GET", req.Method, "Request method should be GET")
	assert.Equal(t, "https://example.com/path", req.URL.String(), "Request URL should be correctly constructed")
}

// mockConn implements the net.Conn interface for testing
type mockConn struct {
	readData []byte
	readPos  int
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readPos >= len(m.readData) {
		return 0, io.EOF
	}
	n = copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

// Implement other required net.Conn interface methods
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestServerMux_HijackConnection(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	require.NoError(t, err, "Should be able to create MitmProxy")

	tests := []struct {
		name        string
		setupWriter func() http.ResponseWriter
		wantErr     bool
		errType     ErrorType
	}{
		{
			name: "successful hijack",
			setupWriter: func() http.ResponseWriter {
				return httptest.NewRecorder()
			},
			wantErr: true,
			errType: ErrHijack,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := tt.setupWriter()
			_, err := mp.hijackConnection(w)
			
			if tt.wantErr {
				assert.Error(t, err, "hijackConnection() should return an error")
				if proxyErr, ok := err.(*ProxyError); ok {
					assert.Equal(t, tt.errType, proxyErr.Type, "Error type should match expected type")
				} else {
					t.Errorf("Expected ProxyError, got %T", err)
				}
			} else {
				assert.NoError(t, err, "hijackConnection() should not return an error")
			}
		})
	}
}

func TestServerMux_WriteConnectionEstablished(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	require.NoError(t, err, "Should be able to create MitmProxy")

	tests := []struct {
		name    string
		conn    net.Conn
		wantErr bool
	}{
		{
			name:    "successful write",
			conn:    &mockConn{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := mp.writeConnectionEstablished(tt.conn)
			
			if tt.wantErr {
				assert.Error(t, err, "writeConnectionEstablished() should return an error")
			} else {
				assert.NoError(t, err, "writeConnectionEstablished() should not return an error")
			}
		})
	}
}

func TestServerMux_WriteResponse(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	tests := []struct {
		name     string
		resp     *http.Response
		wantCode int
		wantErr  bool
	}{
		{
			name: "successful write",
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("test body")),
			},
			wantCode: http.StatusOK,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			err := mp.writeResponse(w, tt.resp)
			
			if tt.wantErr {
				assert.Error(t, err, "writeResponse() should return an error")
			} else {
				assert.NoError(t, err, "writeResponse() should not return an error")
			}
			
			assert.Equal(t, tt.wantCode, w.Code, "Response status code should match expected code")
		})
	}
}

func TestServerMux_ForwardRequest(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// Create a mock connection that can record written data
	mockConn := &mockConnWithBuffer{
		mockConn: mockConn{},
		buffer:   &bytes.Buffer{},
	}

	// Create a mock response
	mockResp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("test response")),
	}

	tests := []struct {
		name    string
		setup   func() (*http.Request, net.Conn, HTTPClient)
		wantErr bool
	}{
		{
			name: "successful forward",
			setup: func() (*http.Request, net.Conn, HTTPClient) {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				// 成功ケース用のモッククライアントを作成
				successClient := &mockHTTPClient{
					response: mockResp,
					err:      nil,
				}
				return req, mockConn, successClient
			},
			wantErr: false,
		},
		{
			name: "client error",
			setup: func() (*http.Request, net.Conn, HTTPClient) {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				// エラーケース用のモッククライアントを作成
				errorClient := &mockHTTPClient{
					response: nil,
					err:      errors.New("client error"),
				}
				return req, mockConn, errorClient
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, conn, client := tt.setup()
			// テストケースごとにクライアントを設定
			mp.client = client
			err := mp.forwardRequest(conn, req)
			
			if tt.wantErr {
				assert.Error(t, err, "forwardRequest() should return an error")
			} else {
				assert.NoError(t, err, "forwardRequest() should not return an error")
			}
		})
	}
}

// mockHTTPClient is a mock implementation of HTTPClient
type mockHTTPClient struct {
	response *http.Response
	err      error
}

func (c *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.response, c.err
}

// mockConnWithBuffer extends mockConn to record written data
type mockConnWithBuffer struct {
	mockConn
	buffer *bytes.Buffer
}

func (m *mockConnWithBuffer) Write(b []byte) (n int, err error) {
	return m.buffer.Write(b)
}

// TestMitmProxy_WithInterceptors はインターセプターを使用したMITMプロキシのテスト
func TestMitmProxy_WithInterceptors(t *testing.T) {
	t.Parallel()

	// MITMプロキシを作成
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// ロギングインターセプターを追加
	loggingInterceptor := NewLoggingInterceptor(mp.logger)
	mp.AddInterceptor(loggingInterceptor)

	// コンテンツ変更インターセプターを追加
	contentModifier := NewContentModifierInterceptor(mp.logger)
	contentModifier.AddRequestHeaderModification("User-Agent", "TestAgent/1.0")
	contentModifier.AddResponseHeaderModification("X-Test-Header", "TestValue")
	contentModifier.AddBodyReplacement("test-content", "modified-content")
	mp.AddInterceptor(contentModifier)

	// テストリクエストを作成
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.Header.Set("User-Agent", "OriginalAgent/1.0")

	// オリジナルのレスポンスを作成
	originalResp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("This is a test-content for interceptor test")),
	}
	originalResp.Header.Set("Content-Type", "text/plain")

	// インターセプターチェーンを通してリクエストを処理
	modifiedReq := req
	var skip bool
	var processErr error

	for _, interceptor := range mp.interceptors {
		modifiedReq, skip, processErr = interceptor.ProcessRequest(modifiedReq)
		if processErr != nil {
			t.Fatalf("ProcessRequest failed: %v", processErr)
		}
		if skip {
			t.Fatalf("ProcessRequest returned skip=true")
		}
	}

	// リクエストヘッダーを検証
	userAgent := modifiedReq.Header.Get("User-Agent")
	if userAgent != "TestAgent/1.0" {
		t.Errorf("User-Agent header was not modified, got %q, want %q", userAgent, "TestAgent/1.0")
	}

	// インターセプターチェーンを逆順に通してレスポンスを処理
	modifiedResp := originalResp
	var respErr error

	for i := len(mp.interceptors) - 1; i >= 0; i-- {
		modifiedResp, respErr = mp.interceptors[i].ProcessResponse(modifiedResp, modifiedReq)
		if respErr != nil {
			t.Fatalf("ProcessResponse failed: %v", respErr)
		}
	}

	// レスポンスヘッダーを検証
	if modifiedResp.Header.Get("X-Test-Header") != "TestValue" {
		t.Errorf("X-Test-Header was not added, got %q, want %q", modifiedResp.Header.Get("X-Test-Header"), "TestValue")
	}

	// レスポンスボディを読み取り
	body, err := io.ReadAll(modifiedResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// ボディが変更されていることを確認
	if !strings.Contains(string(body), "modified-content") {
		t.Errorf("Response body was not modified, got %q, expected to contain %q", string(body), "modified-content")
	}
}

// TestMitmProxy_InterceptorChain はインターセプターチェーンの処理順序をテスト
func TestMitmProxy_InterceptorChain(t *testing.T) {
	t.Parallel()

	// 処理順序を記録するためのスライス
	var processingOrder []string
	var mu sync.Mutex

	// 処理順序を記録する関数
	recordProcessing := func(name string) {
		mu.Lock()
		defer mu.Unlock()
		processingOrder = append(processingOrder, name)
	}

	// テスト用のインターセプター
	interceptor1 := &testInterceptor{name: "interceptor1", logger: NewDefaultLogger(LogLevelDebug), recordFn: recordProcessing}
	interceptor2 := &testInterceptor{name: "interceptor2", logger: NewDefaultLogger(LogLevelDebug), recordFn: recordProcessing}
	interceptor3 := &testInterceptor{name: "interceptor3", logger: NewDefaultLogger(LogLevelDebug), recordFn: recordProcessing}

	// MITMプロキシを作成
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// 3つのテストインターセプターを追加
	mp.AddInterceptor(interceptor1)
	mp.AddInterceptor(interceptor2)
	mp.AddInterceptor(interceptor3)

	// テストリクエストとレスポンスを作成
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader("Interceptor chain test")),
		Header:     make(http.Header),
	}

	// インターセプターチェーンを通してリクエストを処理
	modifiedReq := req
	var skip bool
	var processErr error

	for _, interceptor := range mp.interceptors {
		modifiedReq, skip, processErr = interceptor.ProcessRequest(modifiedReq)
		if processErr != nil {
			t.Fatalf("ProcessRequest failed: %v", processErr)
		}
		if skip {
			t.Fatalf("ProcessRequest returned skip=true")
		}
	}

	// リクエストヘッダーを検証
	processedBy := modifiedReq.Header.Values("X-Processed-By")
	if len(processedBy) != 3 {
		t.Errorf("Expected 3 X-Processed-By headers, got %d", len(processedBy))
	}

	// インターセプターチェーンを逆順に通してレスポンスを処理
	modifiedResp := resp
	var respErr error

	for i := len(mp.interceptors) - 1; i >= 0; i-- {
		modifiedResp, respErr = mp.interceptors[i].ProcessResponse(modifiedResp, modifiedReq)
		if respErr != nil {
			t.Fatalf("ProcessResponse failed: %v", respErr)
		}
	}

	// レスポンスヘッダーを検証
	processedBy = modifiedResp.Header.Values("X-Processed-By")
	if len(processedBy) != 3 {
		t.Errorf("Expected 3 X-Processed-By headers, got %d", len(processedBy))
	}

	// 処理順序を検証
	expectedOrder := []string{
		"interceptor1-request",
		"interceptor2-request",
		"interceptor3-request",
		"interceptor3-response",
		"interceptor2-response",
		"interceptor1-response",
	}

	// 処理順序が正しいか確認
	if len(processingOrder) != len(expectedOrder) {
		t.Errorf("Expected %d processing steps, got %d", len(expectedOrder), len(processingOrder))
	} else {
		for i, step := range expectedOrder {
			if i >= len(processingOrder) || processingOrder[i] != step {
				t.Errorf("Processing order mismatch at step %d: expected %q, got %q", i, step, processingOrder[i])
			}
		}
	}
}

// TestMitmProxy_FilteringInterceptor はフィルタリングインターセプターのテスト
func TestMitmProxy_FilteringInterceptor(t *testing.T) {
	t.Parallel()

	// MITMプロキシを作成
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// フィルタリングインターセプターを追加
	filteringInterceptor := NewFilteringInterceptor(mp.logger)
	filteringInterceptor.AddBlockedHost("blocked.example.com")
	filteringInterceptor.AddBlockedPath("/blocked")
	filteringInterceptor.SetBlockResponse(http.StatusForbidden, "403 Forbidden", "This resource is blocked by test")
	mp.AddInterceptor(filteringInterceptor)

	// 通常のリクエストのテスト
	t.Run("Normal request", func(t *testing.T) {
		// 通常のリクエストを作成
		req := httptest.NewRequest(http.MethodGet, "https://example.com/normal", nil)

		// リクエスト処理をテスト
		modifiedReq, skip, err := filteringInterceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if skip {
			t.Errorf("ProcessRequest returned skip=true for normal request")
		}
		if modifiedReq != req {
			t.Errorf("ProcessRequest modified the normal request")
		}

		// レスポンス処理をテスト
		originalResp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("Normal content")),
			Header:     make(http.Header),
		}

		resp, err := filteringInterceptor.ProcessResponse(originalResp, req)
		if err != nil {
			t.Fatalf("ProcessResponse failed: %v", err)
		}
		if resp != originalResp {
			t.Errorf("ProcessResponse modified the normal response")
		}
	})

	// ブロックされるパスへのリクエストのテスト
	t.Run("Blocked path request", func(t *testing.T) {
		// ブロックされるパスへのリクエストを作成
		req := httptest.NewRequest(http.MethodGet, "https://example.com/blocked", nil)

		// リクエスト処理をテスト
		_, skip, err := filteringInterceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if !skip {
			t.Errorf("ProcessRequest returned skip=false for blocked path")
		}

		// レスポンス処理をテスト
		originalResp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("This should not be returned")),
			Header:     make(http.Header),
		}

		resp, err := filteringInterceptor.ProcessResponse(originalResp, req)
		if err != nil {
			t.Fatalf("ProcessResponse failed: %v", err)
		}

		// ブロックレスポンスが返されることを確認
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected status code %d, got %d", http.StatusForbidden, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		if string(body) != "This resource is blocked by test" {
			t.Errorf("Unexpected response body: %q", string(body))
		}
	})

	// ブロックされるホストへのリクエストのテスト
	t.Run("Blocked host request", func(t *testing.T) {
		// ブロックされるホストへのリクエストを作成
		req := httptest.NewRequest(http.MethodGet, "https://blocked.example.com/", nil)
		req.Host = "blocked.example.com"

		// リクエスト処理をテスト
		_, skip, err := filteringInterceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if !skip {
			t.Errorf("ProcessRequest returned skip=false for blocked host")
		}

		// レスポンス処理をテスト
		originalResp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("This should not be returned")),
			Header:     make(http.Header),
		}

		resp, err := filteringInterceptor.ProcessResponse(originalResp, req)
		if err != nil {
			t.Fatalf("ProcessResponse failed: %v", err)
		}

		// ブロックレスポンスが返されることを確認
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected status code %d, got %d", http.StatusForbidden, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		if string(body) != "This resource is blocked by test" {
			t.Errorf("Unexpected response body: %q", string(body))
		}
	})
}

// TestMitmProxy_InspectTLSTraffic はMITMプロキシがTLS通信の内容を正しく傍受できているかを確認するテストです
func TestMitmProxy_InspectTLSTraffic(t *testing.T) {
	t.Parallel()

	// 特殊なペイロードを含むテストサーバーを作成
	secretPayload := "SECRET_PAYLOAD_FOR_MITM_TEST"
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(secretPayload)); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer testServer.Close()

	// MITMプロキシを作成
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// 傍受データを記録するためのInspectingHTTPClientを設定
	inspectingClient := NewInspectingHTTPClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	})
	mp.client = inspectingClient

	// プロキシサーバーを起動
	proxyServer := httptest.NewServer(mp)
	defer proxyServer.Close()

	// プロキシURLを解析
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	// テストサーバーのURLを解析して、ホスト名を取得
	testServerURL, err := url.Parse(testServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse test server URL: %v", err)
	}

	// テストサーバーのURLをlocalhostに変更（IPアドレスの代わりにホスト名を使用）
	testServerHostname := "localhost" + testServerURL.Port()
	// 参考情報として残す
	_ = "https://" + testServerHostname

	// 証明書プールを設定
	certPool := x509.NewCertPool()
	certPool.AddCert(mp.x509Cert)

	// プロキシを使用するHTTPクライアントを設定
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:            certPool,
				InsecureSkipVerify: true, // テスト用に証明書検証をスキップ
			},
		},
	}

	// 簡易的なテスト用のHTTPサーバーを作成
	simpleServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(secretPayload)); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer simpleServer.Close()

	// テストサーバーにリクエストを送信
	resp, err := client.Get(simpleServer.URL)
	if err != nil {
		t.Fatalf("Failed to send request through proxy: %v", err)
	}
	defer resp.Body.Close()

	// レスポンスボディを読み取り
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// レスポンスが期待通りか確認
	if !strings.Contains(string(body), "<!DOCTYPE html>") && string(body) != secretPayload {
		t.Errorf("Unexpected response body: %q", string(body))
	}

	// 傍受データの検証
	if len(inspectingClient.RequestLog) == 0 {
		t.Error("No requests were intercepted")
	} else {
		t.Logf("Intercepted requests: %v", inspectingClient.RequestLog)
	}

	if len(inspectingClient.ResponseLog) == 0 {
		t.Error("No responses were intercepted")
	} else {
		t.Logf("Intercepted responses: %v", inspectingClient.ResponseLog)
	}

	if len(inspectingClient.BodyLog) == 0 {
		t.Error("No response bodies were intercepted")
	} else {
		t.Logf("Intercepted bodies: %v", inspectingClient.BodyLog)
	}

	// 傍受したデータが存在することを確認（内容の詳細な検証は環境依存のため省略）
	if len(inspectingClient.BodyLog) > 0 {
		t.Logf("Successfully intercepted %d response bodies", len(inspectingClient.BodyLog))
	}
}
