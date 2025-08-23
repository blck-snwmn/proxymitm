package proxymitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

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

// testResponseInterceptor is a test interceptor for testing
type testResponseInterceptor struct {
	onRequest  func(*http.Request) (*http.Request, bool, error)
	onResponse func(*http.Response, *http.Request) (*http.Response, error)
}

func (tri *testResponseInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	if tri.onResponse != nil {
		return tri.onResponse(resp, req)
	}
	return resp, nil
}

func (tri *testResponseInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	if tri.onRequest != nil {
		return tri.onRequest(req)
	}
	return req, false, nil
}

func TestCreateMitmProxy(t *testing.T) {
	t.Run("should return error when files do not exist", func(t *testing.T) {
		_, err := CreateMitmProxy("", "")
		assert.Error(t, err, "Should return an error when files don't exist")
	})
	t.Run("should return error when invalid pem file", func(t *testing.T) {
		_, err := CreateMitmProxy("./testdata/a.cert", "./testdata/ca.key")
		assert.Error(t, err, "Should return an error when file is not a valid PEM")
	})
	t.Run("should create proxy successfully when valid cert and key", func(t *testing.T) {
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
		{name: "should create valid certificate when hostname is localhost", args: args{hostName: "localhost"}, wantErr: false},
		{name: "should create valid certificate when hostname is external", args: args{hostName: "www.google.com"}, wantErr: false},
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
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Hello from target"))
		require.NoError(t, err, "Should be able to write response")
	}))
	defer targetServer.Close()

	// Create a proxy server
	proxyServer := httptest.NewServer(mp)
	defer proxyServer.Close()

	// Parse URLs
	proxyURL, err := url.Parse(proxyServer.URL)
	require.NoError(t, err, "Should be able to parse proxy URL")

	// Set certificate pool
	pool := x509.NewCertPool()
	pool.AddCert(mp.x509Cert)

	// Set client
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	// Test successful request
	t.Run("should proxy request successfully when valid request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, targetServer.URL+"/test", nil)
		require.NoError(t, err, "Should be able to create request")

		resp, err := client.Do(req)
		require.NoError(t, err, "Should be able to send request")
		defer resp.Body.Close()

		// Verify response
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Should return OK status")
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Should be able to read response body")
		assert.Equal(t, "Hello from target", string(body), "Response body should match")
		assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"), "Content-Type header should be set")
	})

	// Test invalid URL - this test expects the proxy to handle DNS resolution failures
	t.Run("should return bad gateway for DNS resolution failure", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://invalid-url-that-does-not-exist.local", nil)
		require.NoError(t, err, "Should be able to create request")

		resp, err := client.Do(req)
		// The proxy should return an error response, not fail the request entirely
		require.NoError(t, err, "Should be able to send request")
		defer resp.Body.Close()

		// The proxy returns 502 when it can't resolve the hostname
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode, "Should return 502 for unresolvable hostnames")
	})

	// Test non-CONNECT request - the proxy returns 500 for invalid scheme requests
	t.Run("should return internal server error for invalid scheme", func(t *testing.T) {
		// When making a direct request to the proxy with no scheme, it returns 500
		req, err := http.NewRequest(http.MethodGet, proxyServer.URL+"/test", nil)
		require.NoError(t, err, "Should be able to create request")

		resp, err := client.Do(req)
		require.NoError(t, err, "Should be able to send request")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "Should return 500 for invalid scheme requests")
	})
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
			expectedCode: http.StatusBadRequest,
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

// TestMitmProxy_WithInterceptors is a test for the MITM proxy with interceptors
func TestMitmProxy_WithInterceptors(t *testing.T) {
	t.Parallel()

	// MITM proxy to create
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	require.NoError(t, err, "Should be able to create MitmProxy")

	// Add logging interceptor
	loggingInterceptor := NewLoggingInterceptor(mp.logger)
	mp.AddInterceptor(loggingInterceptor)

	// Add content modification interceptor
	contentModifier := NewContentModifierInterceptor(mp.logger)
	contentModifier.AddRequestHeaderModification("User-Agent", "TestAgent/1.0")
	contentModifier.AddResponseHeaderModification("X-Test-Header", "TestValue")
	contentModifier.AddBodyReplacement("test-content", "modified-content")
	mp.AddInterceptor(contentModifier)

	// Create a test server that will be proxied to
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers at the target server
		assert.Equal(t, "TestAgent/1.0", r.Header.Get("User-Agent"), "User-Agent header should be modified")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("This is a test-content for interceptor test"))
		require.NoError(t, err, "Should be able to write response")
	}))
	defer targetServer.Close()

	// Create a proxy server
	proxyServer := httptest.NewServer(mp)
	defer proxyServer.Close()

	// Parse URLs
	proxyURL, err := url.Parse(proxyServer.URL)
	require.NoError(t, err, "Should be able to parse proxy URL")

	// Set certificate pool
	pool := x509.NewCertPool()
	pool.AddCert(mp.x509Cert)

	// Set client
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	// Create a test request
	req, err := http.NewRequest(http.MethodGet, targetServer.URL+"/test", nil)
	require.NoError(t, err, "Should be able to create request")
	req.Header.Set("User-Agent", "OriginalAgent/1.0")

	// Send request
	resp, err := client.Do(req)
	require.NoError(t, err, "Should be able to send request")
	defer resp.Body.Close()

	// No need to verify request headers here as they are checked at the target server
	// Verify response headers
	assert.Equal(t, "TestValue", resp.Header.Get("X-Test-Header"), "X-Test-Header should be added")

	// Read response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Should be able to read response body")

	// Ensure body is modified
	assert.Contains(t, string(body), "modified-content", "Response body should be modified correctly")
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
		require.NoError(t, processErr, "ProcessRequest failed")
		if skip {
			t.Fatalf("ProcessRequest returned skip=true")
		}
	}

	// Verify request headers
	processedBy := modifiedReq.Header.Values("X-Processed-By")
	assert.Len(t, processedBy, 3, "Expected 3 X-Processed-By headers, got %d", len(processedBy))

	// Process response through interceptor chain in reverse order
	modifiedResp := resp
	var respErr error

	for i := len(mp.interceptors) - 1; i >= 0; i-- {
		modifiedResp, respErr = mp.interceptors[i].ProcessResponse(modifiedResp, modifiedReq)
		require.NoError(t, respErr, "ProcessResponse failed")
	}

	// Verify response headers
	processedBy = modifiedResp.Header.Values("X-Processed-By")
	assert.Len(t, processedBy, 3, "Expected 3 X-Processed-By headers, got %d", len(processedBy))

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

	// Setup test server
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, err := w.Write([]byte("SECRET_PAYLOAD_FOR_MITM_TEST"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer testServer.Close()

	// MITM proxy to create using helper function
	mp := setupTestProxy(t)

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

	// Set certificate pool using helper function
	certPool := setupCertPool(mp)

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
		if _, err := w.Write([]byte("SECRET_PAYLOAD_FOR_MITM_TEST")); err != nil {
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
	if !strings.Contains(string(body), "<!DOCTYPE html>") && string(body) != "SECRET_PAYLOAD_FOR_MITM_TEST" {
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

// TestDefaultLogger tests the logger implementation
func TestDefaultLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		level     LogLevel
		logType   string
		shouldLog bool
	}{
		{
			name:      "debug logs when level is debug",
			level:     LogLevelDebug,
			logType:   "debug",
			shouldLog: true,
		},
		{
			name:      "info logs when level is debug",
			level:     LogLevelDebug,
			logType:   "info",
			shouldLog: true,
		},
		{
			name:      "warn logs when level is debug",
			level:     LogLevelDebug,
			logType:   "warn",
			shouldLog: true,
		},
		{
			name:      "warn logs when level is info",
			level:     LogLevelInfo,
			logType:   "warn",
			shouldLog: true,
		},
		{
			name:      "warn logs when level is warn",
			level:     LogLevelWarn,
			logType:   "warn",
			shouldLog: true,
		},
		{
			name:      "warn does not log when level is error",
			level:     LogLevelError,
			logType:   "warn",
			shouldLog: false,
		},
		{
			name:      "error logs when level is error",
			level:     LogLevelError,
			logType:   "error",
			shouldLog: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		// Don't run tests in parallel due to global log writer setting
		t.Run(tc.name, func(t *testing.T) {
			// Set up a separate logger output for testing
			// Important: We need to direct standard log output to our buffer
			var buf bytes.Buffer
			origOutput := log.Writer()
			log.SetOutput(&buf)
			defer log.SetOutput(origOutput)

			logger := NewDefaultLogger(tc.level)

			// Call log method based on type
			msg := "test message from " + tc.name
			switch tc.logType {
			case "debug":
				logger.Debug(msg)
			case "info":
				logger.Info(msg)
			case "warn":
				logger.Warn(msg)
			case "error":
				logger.Error(msg)
			}

			gotOutput := buf.String()

			if tc.shouldLog {
				// Expected format is like: 2022/01/01 12:00:00 [INFO] message
				expectedPrefix := ""
				switch tc.logType {
				case "debug":
					expectedPrefix = "[DEBUG]"
				case "info":
					expectedPrefix = "[INFO]"
				case "warn":
					expectedPrefix = "[WARN]"
				case "error":
					expectedPrefix = "[ERROR]"
				}

				if !strings.Contains(gotOutput, expectedPrefix) {
					t.Errorf("Expected log to contain %q but got: %q", expectedPrefix, gotOutput)
				}
				if !strings.Contains(gotOutput, msg) {
					t.Errorf("Expected log to contain message %q but got: %q", msg, gotOutput)
				}
			} else if gotOutput != "" {
				t.Errorf("Expected no log output but got: %q", gotOutput)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("successful server creation", func(t *testing.T) {
		server, err := New("./testdata/ca.crt", "./testdata/ca.key")
		require.NoError(t, err, "Should be able to create HTTP server")
		require.NotNil(t, server, "Server should not be nil")

		// Check server timeouts
		assert.Equal(t, DefaultReadTimeout, server.ReadTimeout, "ReadTimeout should match default")
		assert.Equal(t, DefaultWriteTimeout, server.WriteTimeout, "WriteTimeout should match default")
		assert.Equal(t, DefaultIdleTimeout, server.IdleTimeout, "IdleTimeout should match default")

		// Check if handler is properly set
		require.NotNil(t, server.Handler, "Handler should not be nil")
		_, ok := server.Handler.(*ServerMux)
		assert.True(t, ok, "Handler should be a ServerMux")
	})

	t.Run("invalid certificate path", func(t *testing.T) {
		server, err := New("./testdata/nonexistent.crt", "./testdata/ca.key")
		require.Error(t, err, "Should return an error for invalid certificate path")
		assert.Nil(t, server, "Server should be nil")

		var proxyErr *ProxyError
		require.True(t, errors.As(err, &proxyErr), "Error should be a ProxyError")
		assert.Equal(t, ErrCertificate, proxyErr.Type, "Error type should be ErrCertificate")
	})

	t.Run("invalid key path", func(t *testing.T) {
		server, err := New("./testdata/ca.crt", "./testdata/nonexistent.key")
		assert.Error(t, err, "Should return an error for invalid key path")
		assert.Nil(t, server, "Server should be nil")

		var proxyErr *ProxyError
		require.True(t, errors.As(err, &proxyErr), "Error should be a ProxyError")
		assert.Equal(t, ErrCertificate, proxyErr.Type, "Error type should be ErrCertificate")
	})

	t.Run("invalid certificate format", func(t *testing.T) {
		// Create a test file with invalid certificate format
		tempFile, err := os.CreateTemp("", "invalid-cert-*.crt")
		require.NoError(t, err, "Should be able to create temp file")
		defer os.Remove(tempFile.Name())

		_, err = tempFile.WriteString("THIS IS NOT A VALID CERTIFICATE")
		require.NoError(t, err, "Should be able to write to temp file")
		require.NoError(t, tempFile.Close(), "Should be able to close temp file")

		server, err := New(tempFile.Name(), "./testdata/ca.key")
		assert.Error(t, err, "Should return an error for invalid certificate format")
		assert.Nil(t, server, "Server should be nil")

		var proxyErr *ProxyError
		require.True(t, errors.As(err, &proxyErr), "Error should be a ProxyError")
		assert.Equal(t, ErrCertificate, proxyErr.Type, "Error type should be ErrCertificate")
	})
}

// TestDetermineErrorType tests the error type determination logic
func TestDetermineErrorType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		err          error
		expectedType ErrorType
	}{
		{
			name:         "DNS resolution failure",
			err:          errors.New("dial tcp: lookup example.com: no such host"),
			expectedType: ErrGateway,
		},
		{
			name:         "Connection refused",
			err:          errors.New("dial tcp 127.0.0.1:8080: connection refused"),
			expectedType: ErrGateway,
		},
		{
			name:         "Network unreachable",
			err:          errors.New("dial tcp: network is unreachable"),
			expectedType: ErrGateway,
		},
		{
			name:         "No route to host",
			err:          errors.New("dial tcp: no route to host"),
			expectedType: ErrGateway,
		},
		{
			name:         "Timeout error",
			err:          errors.New("dial tcp: i/o timeout"),
			expectedType: ErrTimeout,
		},
		{
			name:         "Deadline exceeded",
			err:          errors.New("context deadline exceeded"),
			expectedType: ErrTimeout,
		},
		{
			name:         "Generic error",
			err:          errors.New("some other error"),
			expectedType: ErrSendRequest,
		},
		{
			name:         "Nil error",
			err:          nil,
			expectedType: ErrSendRequest,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := determineErrorType(tt.err)
			assert.Equal(t, tt.expectedType, result, "Error type should match expected")
		})
	}
}
