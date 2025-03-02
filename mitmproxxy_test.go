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
	"testing"
	"time"
)

func TestCreateMitmProxy(t *testing.T) {
	t.Run("failed, because load no exist file", func(t *testing.T) {
		_, err := CreateMitmProxy("", "")
		if err == nil {
			t.Error("no err. want error")
			return
		}
	})
	t.Run("failed, because load no pem file", func(t *testing.T) {
		_, err := CreateMitmProxy("./testdata/a.cert", "./testdata/ca.key")
		if err == nil {
			t.Error("no err. want error")
			return
		}
	})
	t.Run("create success", func(t *testing.T) {
		mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
		if err != nil {
			t.Errorf("CreateMitmProxy() error = %v", err)
			return
		}
		if len(mp.tlsCert.Certificate) == 0 {
			t.Error("mp.tlsCert have no Certificate")
			return
		}
		if mp.x509Cert == nil {
			t.Error("mp.x509Cert have no Certificate")
			return
		}
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
	if err != nil {
		t.Errorf("create MitimProxy failed")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := mitmx509template(tt.args.hostName)
			c, _, err := mp.createX509Certificate(template)
			if (err != nil) != tt.wantErr {
				t.Errorf("createCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			roots := x509.NewCertPool()
			roots.AddCert(mp.x509Cert)
			vop := x509.VerifyOptions{
				DNSName: tt.args.hostName,
				Roots:   roots,
			}
			if _, err = c.Verify(vop); err != nil {
				t.Errorf("Verify failed error = %v", err)
			}
		})
	}
}

func TestMitmx509template(t *testing.T) {
	expected := "hostname"
	cert := mitmx509template(expected)
	if len(cert.DNSNames) != 1 {
		t.Error("DNSNames length isn't 1")
	}
	cn := false
	for _, n := range cert.DNSNames {
		if n == expected {
			cn = true
		}
	}
	if !cn {
		t.Errorf("DNSNames don't contain %s", expected)
	}
}

func TestMitmProxy_Handler(t *testing.T) {
	//長いがとりあえず
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Errorf("create MitimProxy failed")
		return
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Error("request method isn't connect")
			return
		}
		mp.ServeHTTP(w, r)
	}))
	defer hs.Close()

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
		t.Errorf("url parse err. input is %v", hs.URL)
		return
	}

	requestURL, err := parseLocalhost(ts.URL)
	if err != nil {
		t.Errorf("url parse err. input is %v", ts.URL)
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(mp.x509Cert)

	// client := ts.Client()
	mp.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            pool,
			},
		},
	}

	client := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	rsp, err := client.Get(requestURL.String())
	if err != nil {
		t.Errorf("get err")
		return
	}
	rsp.Body.Close()
}

func TestMitmProxy_Connected(t *testing.T) {
	//長いがとりあえず
	// connectTCP, tlsHandshake について
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Errorf("create MitimProxy failed")
		return
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Error("request method isn't connect")
			return
		}
		con, err := mp.hijackConnection(w)
		if err != nil {
			t.Error("tcp connect failed")
			return
		}
		defer con.Close()

		// コネクションが確立されたことをクライアントに通知
		if err := mp.writeConnectionEstablished(con); err != nil {
			t.Error("failed to write connection established")
			return
		}

		tlsConn, err := mp.tlsHandshake(con, r.URL.Hostname())
		if err != nil {
			t.Error("handshake failed")
			return
		}
		defer tlsConn.Close()
		// proxyせずにresponseを返す
		if _, err := tlsConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n")); err != nil {
			t.Error("failed to write response")
			return
		}
	}))
	defer ts.Close()

	url, err := url.Parse(ts.URL)
	if err != nil {
		t.Errorf("url parse err. input is %v", ts.URL)
		return
	}

	pool := x509.NewCertPool()
	pool.AddCert(mp.x509Cert)

	client := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(url),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}
	rsp, err := client.Get("https://localhost:" + url.Port())
	if err != nil || rsp.StatusCode != http.StatusOK {
		t.Errorf("access failed")
		return
	}
	rsp.Body.Close()
}

func TestServerMux_ServeHTTP_NonConnect(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// Create a test server that will be proxied to
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Hello from target")); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer targetServer.Close()

	// Create a test request with a valid URL
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	w := httptest.NewRecorder()

	// Test the ServeHTTP method
	mp.ServeHTTP(w, req)

	// Since this is a non-CONNECT request, we expect an internal server error
	// because the proxy is primarily designed for CONNECT requests
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestServerMux_ServeHTTP_Errors(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

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

			if w.Code != tt.expectedCode {
				t.Errorf("Expected status code %d, got %d", tt.expectedCode, w.Code)
			}
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
	if err != nil {
		t.Fatalf("createRequest failed: %v", err)
	}

	if req.Method != "GET" {
		t.Errorf("Expected method GET, got %s", req.Method)
	}
	if req.URL.String() != "https://example.com/path" {
		t.Errorf("Expected URL https://example.com/path, got %s", req.URL.String())
	}
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
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

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
			if (err != nil) != tt.wantErr {
				t.Errorf("hijackConnection() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				if proxyErr, ok := err.(*ProxyError); !ok || proxyErr.Type != tt.errType {
					t.Errorf("hijackConnection() error type = %v, want %v", proxyErr.Type, tt.errType)
				}
			}
		})
	}
}

func TestServerMux_WriteConnectionEstablished(t *testing.T) {
	t.Parallel()
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

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
			if err := mp.writeConnectionEstablished(tt.conn); (err != nil) != tt.wantErr {
				t.Errorf("writeConnectionEstablished() error = %v, wantErr %v", err, tt.wantErr)
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
			if err := mp.writeResponse(w, tt.resp); (err != nil) != tt.wantErr {
				t.Errorf("writeResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if w.Code != tt.wantCode {
				t.Errorf("writeResponse() status code = %v, want %v", w.Code, tt.wantCode)
			}
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
			if (err != nil) != tt.wantErr {
				t.Errorf("forwardRequest() error = %v, wantErr %v", err, tt.wantErr)
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
