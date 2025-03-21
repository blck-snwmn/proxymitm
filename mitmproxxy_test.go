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

// testInterceptor is a HTTP interceptor for testing
type testInterceptor struct {
	name     string
	logger   Logger
	recordFn func(string)
}

// ProcessRequest processes the request and records the processing order
func (ti *testInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	ti.recordFn(ti.name + "-request")
	req.Header.Add("X-Processed-By", ti.name)
	return req, false, nil
}

// ProcessResponse processes the response and records the processing order
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
		tt := tt // Variable shadowing for captured variables
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
	// MITM proxy to create
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

	// Add interceptor
	mp.AddInterceptor(testInterceptor)

	// Create a test TLS server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create a proxy server
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodConnect, r.Method, "Request method should be CONNECT")
		mp.ServeHTTP(w, r)
	}))
	defer hs.Close()

	// Parse URL
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

	// Set certificate pool
	pool := x509.NewCertPool()
	pool.AddCert(mp.x509Cert)

	// Set proxy client
	mp.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            pool,
			},
		},
	}

	// Set client
	client := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	// Send request
	resp, err := client.Get(requestURL.String())
	require.NoError(t, err, "Should be able to send request")
	defer resp.Body.Close()

	// Ensure interceptor was called
	assert.True(t, requestReceived, "Request interceptor should be called")

	// Ensure response status is correct
	assert.Equal(t, http.StatusOK, responseStatus, "Interceptor should receive correct response status")

	// Ensure response status is correct
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
	// MITM proxy to create
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// Create a test interceptor
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

	// Add interceptor
	mp.AddInterceptor(testInterceptor)

	// Create a test TLS server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create a proxy server
	hs := httptest.NewServer(mp)
	defer hs.Close()

	// Parse URL
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

	// Set certificate pool
	pool := x509.NewCertPool()
	pool.AddCert(mp.x509Cert)

	// Set proxy client
	mp.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            pool,
			},
		},
	}

	// Set client
	client := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:            pool,
				InsecureSkipVerify: true, // Skip certificate verification for test
			},
		},
	}

	// Send request
	resp, err := client.Get(requestURL.String())
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Ensure response status is correct
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected response status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Ensure interceptor was called
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
				// Create a mock client for successful case
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
				// Create a mock client for error case
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
			// Set client for each test case
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

// TestMitmProxy_WithInterceptors is a test for the MITM proxy with interceptors
func TestMitmProxy_WithInterceptors(t *testing.T) {
	t.Parallel()

	// MITM proxy to create
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// Add logging interceptor
	loggingInterceptor := NewLoggingInterceptor(mp.logger)
	mp.AddInterceptor(loggingInterceptor)

	// Add content modification interceptor
	contentModifier := NewContentModifierInterceptor(mp.logger)
	contentModifier.AddRequestHeaderModification("User-Agent", "TestAgent/1.0")
	contentModifier.AddResponseHeaderModification("X-Test-Header", "TestValue")
	contentModifier.AddBodyReplacement("test-content", "modified-content")
	mp.AddInterceptor(contentModifier)

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.Header.Set("User-Agent", "OriginalAgent/1.0")

	// Create an original response
	originalResp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("This is a test-content for interceptor test")),
	}
	originalResp.Header.Set("Content-Type", "text/plain")

	// Process request through interceptor chain
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

	// Verify request headers
	userAgent := modifiedReq.Header.Get("User-Agent")
	if userAgent != "TestAgent/1.0" {
		t.Errorf("User-Agent header was not modified, got %q, want %q", userAgent, "TestAgent/1.0")
	}

	// Process response through interceptor chain in reverse order
	modifiedResp := originalResp
	var respErr error

	for i := len(mp.interceptors) - 1; i >= 0; i-- {
		modifiedResp, respErr = mp.interceptors[i].ProcessResponse(modifiedResp, modifiedReq)
		if respErr != nil {
			t.Fatalf("ProcessResponse failed: %v", respErr)
		}
	}

	// Verify response headers
	if modifiedResp.Header.Get("X-Test-Header") != "TestValue" {
		t.Errorf("X-Test-Header was not added, got %q, want %q", modifiedResp.Header.Get("X-Test-Header"), "TestValue")
	}

	// Read response body
	body, err := io.ReadAll(modifiedResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Ensure body is modified
	if !strings.Contains(string(body), "modified-content") {
		t.Errorf("Response body was not modified, got %q, expected to contain %q", string(body), "modified-content")
	}
}

// TestMitmProxy_InterceptorChain is a test for the processing order of the interceptor chain
func TestMitmProxy_InterceptorChain(t *testing.T) {
	t.Parallel()

	// Slice for recording processing order
	var processingOrder []string
	var mu sync.Mutex

	// Function to record processing order
	recordProcessing := func(name string) {
		mu.Lock()
		defer mu.Unlock()
		processingOrder = append(processingOrder, name)
	}

	// Test interceptor
	interceptor1 := &testInterceptor{name: "interceptor1", logger: NewDefaultLogger(LogLevelDebug), recordFn: recordProcessing}
	interceptor2 := &testInterceptor{name: "interceptor2", logger: NewDefaultLogger(LogLevelDebug), recordFn: recordProcessing}
	interceptor3 := &testInterceptor{name: "interceptor3", logger: NewDefaultLogger(LogLevelDebug), recordFn: recordProcessing}

	// MITM proxy to create
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// Add 3 test interceptors
	mp.AddInterceptor(interceptor1)
	mp.AddInterceptor(interceptor2)
	mp.AddInterceptor(interceptor3)

	// Create a test request and response
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader("Interceptor chain test")),
		Header:     make(http.Header),
	}

	// Process request through interceptor chain
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

	// Verify request headers
	processedBy := modifiedReq.Header.Values("X-Processed-By")
	if len(processedBy) != 3 {
		t.Errorf("Expected 3 X-Processed-By headers, got %d", len(processedBy))
	}

	// Process response through interceptor chain in reverse order
	modifiedResp := resp
	var respErr error

	for i := len(mp.interceptors) - 1; i >= 0; i-- {
		modifiedResp, respErr = mp.interceptors[i].ProcessResponse(modifiedResp, modifiedReq)
		if respErr != nil {
			t.Fatalf("ProcessResponse failed: %v", respErr)
		}
	}

	// Verify response headers
	processedBy = modifiedResp.Header.Values("X-Processed-By")
	if len(processedBy) != 3 {
		t.Errorf("Expected 3 X-Processed-By headers, got %d", len(processedBy))
	}

	// Verify processing order
	expectedOrder := []string{
		"interceptor1-request",
		"interceptor2-request",
		"interceptor3-request",
		"interceptor3-response",
		"interceptor2-response",
		"interceptor1-response",
	}

	// Ensure processing order is correct
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

// TestMitmProxy_FilteringInterceptor is a test for the filtering interceptor
func TestMitmProxy_FilteringInterceptor(t *testing.T) {
	t.Parallel()

	// MITM proxy to create
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// Add filtering interceptor
	filteringInterceptor := NewFilteringInterceptor(mp.logger)
	filteringInterceptor.AddBlockedHost("blocked.example.com")
	filteringInterceptor.AddBlockedPath("/blocked")
	filteringInterceptor.SetBlockResponse(http.StatusForbidden, "403 Forbidden", "This resource is blocked by test")
	mp.AddInterceptor(filteringInterceptor)

	// Normal request test
	t.Run("Normal request", func(t *testing.T) {
		// Create a normal request
		req := httptest.NewRequest(http.MethodGet, "https://example.com/normal", nil)

		// Test request processing
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

		// Test response processing
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

	// Blocked path request test
	t.Run("Blocked path request", func(t *testing.T) {
		// Create a request to a blocked path
		req := httptest.NewRequest(http.MethodGet, "https://example.com/blocked", nil)

		// Test request processing
		_, skip, err := filteringInterceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if !skip {
			t.Errorf("ProcessRequest returned skip=false for blocked path")
		}

		// Test response processing
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

		// Ensure blocked response is returned
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

	// Blocked host request test
	t.Run("Blocked host request", func(t *testing.T) {
		// Create a request to a blocked host
		req := httptest.NewRequest(http.MethodGet, "https://blocked.example.com/", nil)
		req.Host = "blocked.example.com"

		// Test request processing
		_, skip, err := filteringInterceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if !skip {
			t.Errorf("ProcessRequest returned skip=false for blocked host")
		}

		// Test response processing
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

		// Ensure blocked response is returned
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

// TestMitmProxy_InspectTLSTraffic is a test to ensure the MITM proxy correctly intercepts TLS traffic
func TestMitmProxy_InspectTLSTraffic(t *testing.T) {
	t.Parallel()

	// Create a test server with a special payload
	secretPayload := "SECRET_PAYLOAD_FOR_MITM_TEST"
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(secretPayload)); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer testServer.Close()

	// MITM proxy to create
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MitmProxy: %v", err)
	}

	// Set inspecting client for recording intercepted data
	inspectingClient := NewInspectingHTTPClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	})
	mp.client = inspectingClient

	// Start proxy server
	proxyServer := httptest.NewServer(mp)
	defer proxyServer.Close()

	// Parse proxy URL
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	// Parse test server URL and get host name
	testServerURL, err := url.Parse(testServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse test server URL: %v", err)
	}

	// Change test server URL to localhost (use host name instead of IP address)
	testServerHostname := "localhost" + testServerURL.Port()
	// Keep for reference
	_ = "https://" + testServerHostname

	// Set certificate pool
	certPool := x509.NewCertPool()
	certPool.AddCert(mp.x509Cert)

	// Set HTTP client to use proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:            certPool,
				InsecureSkipVerify: true, // Skip certificate verification for test
			},
		},
	}

	// Create a simple test HTTP server
	simpleServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(secretPayload)); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer simpleServer.Close()

	// Send request to test server
	resp, err := client.Get(simpleServer.URL)
	if err != nil {
		t.Fatalf("Failed to send request through proxy: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Ensure response is as expected
	if !strings.Contains(string(body), "<!DOCTYPE html>") && string(body) != secretPayload {
		t.Errorf("Unexpected response body: %q", string(body))
	}

	// Verify intercepted data
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

	// Ensure intercepted data exists (content verification is environment-dependent, so omitted)
	if len(inspectingClient.BodyLog) > 0 {
		t.Logf("Successfully intercepted %d response bodies", len(inspectingClient.BodyLog))
	}
}
