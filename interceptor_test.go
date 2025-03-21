package proxymitm

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggingInterceptor(t *testing.T) {
	t.Parallel()

	// Create a test logger
	logger := NewDefaultLogger(LogLevelDebug)
	interceptor := NewLoggingInterceptor(logger)

	// Test request processing
	t.Run("ProcessRequest", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", strings.NewReader("test body"))
		req.Header.Set("Content-Type", "text/plain")

		modifiedReq, skip, err := interceptor.ProcessRequest(req)
		require.NoError(t, err, "ProcessRequest should not return an error")
		assert.False(t, skip, "ProcessRequest should not skip")

		// Verify the request hasn't been modified
		assert.Equal(t, req.Method, modifiedReq.Method, "Request method should not be modified")
		assert.Equal(t, req.URL.String(), modifiedReq.URL.String(), "Request URL should not be modified")

		// Verify the body is still readable
		body, err := io.ReadAll(modifiedReq.Body)
		require.NoError(t, err, "Should be able to read request body")
		assert.Equal(t, "test body", string(body), "Request body should not be modified")
	})

	// Test response processing
	t.Run("ProcessResponse", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("response body")),
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/plain")

		modifiedResp, err := interceptor.ProcessResponse(resp, req)
		require.NoError(t, err, "ProcessResponse should not return an error")

		// Verify the response hasn't been modified
		assert.Equal(t, resp.StatusCode, modifiedResp.StatusCode, "Response status code should not be modified")

		// Verify the body is still readable
		body, err := io.ReadAll(modifiedResp.Body)
		require.NoError(t, err, "Should be able to read response body")
		assert.Equal(t, "response body", string(body), "Response body should not be modified")
	})
}

func TestContentModifierInterceptor(t *testing.T) {
	t.Parallel()

	// Create a test logger
	logger := NewDefaultLogger(LogLevelDebug)
	interceptor := NewContentModifierInterceptor(logger)

	// Add request header modifications
	interceptor.AddRequestHeaderModification("User-Agent", "Modified/1.0")
	interceptor.AddRequestHeaderModification("X-Custom-Header", "CustomValue")

	// Add response header modifications
	interceptor.AddResponseHeaderModification("Server", "Modified/1.0")
	interceptor.AddResponseHeaderModification("X-Custom-Response", "CustomValue")

	// Add response body replacements
	interceptor.AddBodyReplacement("original", "replaced")

	// Test request processing
	t.Run("ProcessRequest", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		req.Header.Set("User-Agent", "Original/1.0")

		modifiedReq, skip, err := interceptor.ProcessRequest(req)
		require.NoError(t, err, "ProcessRequest should not return an error")
		assert.False(t, skip, "ProcessRequest should not skip the request")

		// Verify request headers are modified
		assert.Equal(t, "Modified/1.0", modifiedReq.Header.Get("User-Agent"), "User-Agent header should be modified")
		assert.Equal(t, "CustomValue", modifiedReq.Header.Get("X-Custom-Header"), "X-Custom-Header should be added")
	})

	// Test response processing
	t.Run("ProcessResponse", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("This is an original text")),
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "Original/1.0")

		modifiedResp, err := interceptor.ProcessResponse(resp, req)
		require.NoError(t, err, "ProcessResponse should not return an error")

		// Verify headers are modified
		assert.Equal(t, "Modified/1.0", modifiedResp.Header.Get("Server"), "Server header should be modified")
		assert.Equal(t, "CustomValue", modifiedResp.Header.Get("X-Custom-Response"), "X-Custom-Response should be added")

		// Verify body is modified
		body, err := io.ReadAll(modifiedResp.Body)
		require.NoError(t, err, "Should be able to read response body")
		expectedBody := "This is an replaced text"
		assert.Equal(t, expectedBody, string(body), "Response body should be modified correctly")

		// Verify Content-Length header is updated
		assert.Equal(t, "24", modifiedResp.Header.Get("Content-Length"), "Content-Length header should be updated")
	})
}

func TestFilteringInterceptor(t *testing.T) {
	t.Parallel()

	// Create a test logger
	logger := NewDefaultLogger(LogLevelDebug)
	interceptor := NewFilteringInterceptor(logger)

	// Add blocked host names
	interceptor.AddBlockedHost("blocked.example.com")

	// Add blocked URL paths
	interceptor.AddBlockedPath("/blocked")

	// Add blocked user agents
	interceptor.AddBlockedUserAgent("BlockedAgent")

	// Set custom blocked response
	interceptor.SetBlockResponse(http.StatusForbidden, "403 Forbidden", "This resource is blocked")

	// Test allowed request processing
	t.Run("ProcessRequest_Allowed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/allowed", nil)
		req.Header.Set("User-Agent", "AllowedAgent")

		modifiedReq, skip, err := interceptor.ProcessRequest(req)
		require.NoError(t, err, "ProcessRequest should not return an error")
		assert.False(t, skip, "ProcessRequest should not skip the request")
		assert.Equal(t, req, modifiedReq, "ProcessRequest should not modify the allowed request")
	})

	// Test blocked host name processing
	t.Run("ProcessRequest_BlockedHost", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://blocked.example.com/test", nil)

		_, skip, err := interceptor.ProcessRequest(req)
		require.NoError(t, err, "ProcessRequest should not return an error")
		assert.True(t, skip, "ProcessRequest should skip the blocked host request")

		// Verify response processing returns blocked response
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("Original response")),
			Header:     make(http.Header),
		}

		blockedResp, err := interceptor.ProcessResponse(resp, req)
		require.NoError(t, err, "ProcessResponse should not return an error")

		assert.Equal(t, http.StatusForbidden, blockedResp.StatusCode, "Response status code should be 403 Forbidden")

		// Read body and convert to string
		bodyBytes, err := io.ReadAll(blockedResp.Body)
		require.NoError(t, err, "Should be able to read response body")
		// Read body and close
		_ = blockedResp.Body.Close()
		// Set new body (for subsequent test processing)
		blockedResp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		assert.Equal(t, "This resource is blocked", string(bodyBytes), "Response body should be the block message")
	})

	// Test blocked path processing
	t.Run("ProcessRequest_BlockedPath", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/blocked/resource", nil)

		_, skip, err := interceptor.ProcessRequest(req)
		require.NoError(t, err, "ProcessRequest should not return an error")
		assert.True(t, skip, "ProcessRequest should skip the blocked path request")
	})

	// Test blocked user agent processing
	t.Run("ProcessRequest_BlockedUserAgent", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		req.Header.Set("User-Agent", "BlockedAgent/1.0")

		_, skip, err := interceptor.ProcessRequest(req)
		require.NoError(t, err, "ProcessRequest should not return an error")
		assert.True(t, skip, "ProcessRequest should skip the blocked user agent request")
	})
}

func TestRequestIDInterceptor(t *testing.T) {
	t.Parallel()

	// Create a test logger
	logger := NewDefaultLogger(LogLevelDebug)
	interceptor := NewRequestIDInterceptor(logger)

	// Test request processing
	t.Run("ProcessRequest", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		modifiedReq, skip, err := interceptor.ProcessRequest(req)
		require.NoError(t, err, "ProcessRequest should not return an error")
		assert.False(t, skip, "ProcessRequest should not skip the request")

		// Verify request ID is set
		requestID := modifiedReq.Header.Get("X-Request-ID")
		assert.NotEmpty(t, requestID, "Request ID should be set")

		// Verify request is saved
		savedReq := interceptor.GetRequestByID(requestID)
		assert.NotNil(t, savedReq, "Request should be saved with ID %s", requestID)
	})

	// Test response processing
	t.Run("ProcessResponse", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		// First process request to set ID
		modifiedReq, _, _ := interceptor.ProcessRequest(req)
		requestID := modifiedReq.Header.Get("X-Request-ID")

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("response body")),
			Header:     make(http.Header),
		}

		modifiedResp, err := interceptor.ProcessResponse(resp, modifiedReq)
		require.NoError(t, err, "ProcessResponse should not return an error")

		// Verify response headers contain correct request ID
		assert.Equal(t, requestID, modifiedResp.Header.Get("X-Request-ID"), "Response header should contain the correct request ID")

		// Verify response is saved
		savedResp := interceptor.GetResponseByID(requestID)
		assert.NotNil(t, savedResp, "Response should be saved with ID %s", requestID)
	})

	// Verify IDs are unique across multiple requests
	t.Run("UniqueIDs", func(t *testing.T) {
		t.Parallel()
		req1 := httptest.NewRequest(http.MethodGet, "https://example.com/test1", nil)
		req2 := httptest.NewRequest(http.MethodGet, "https://example.com/test2", nil)

		modifiedReq1, _, _ := interceptor.ProcessRequest(req1)
		modifiedReq2, _, _ := interceptor.ProcessRequest(req2)

		id1 := modifiedReq1.Header.Get("X-Request-ID")
		id2 := modifiedReq2.Header.Get("X-Request-ID")

		assert.NotEqual(t, id1, id2, "Request IDs should be unique")
	})
}

func TestInterceptorChain(t *testing.T) {
	t.Parallel()

	// Create a test MITM proxy
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	// Create a test interceptor
	loggingInterceptor := NewLoggingInterceptor(mp.logger)
	contentModifier := NewContentModifierInterceptor(mp.logger)
	contentModifier.AddRequestHeaderModification("User-Agent", "Modified/1.0")
	contentModifier.AddBodyReplacement("original", "modified")
	requestIDInterceptor := NewRequestIDInterceptor(mp.logger)

	// Add interceptor to chain
	mp.AddInterceptor(requestIDInterceptor)
	mp.AddInterceptor(loggingInterceptor)
	mp.AddInterceptor(contentModifier)

	// Create a test request and response
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.Header.Set("User-Agent", "Original/1.0")

	// Create a mock HTTP client
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader("This is an original text")),
		Header:     make(http.Header),
		Request:    req,
	}
	mockClient := &mockHTTPClient{
		response: mockResp,
		err:      nil,
	}
	mp.client = mockClient

	// Create a test connection
	mockConn := &mockConnWithBuffer{
		mockConn: mockConn{},
		buffer:   &bytes.Buffer{},
	}

	// Call forwardRequest method to test interceptor chain
	err = mp.forwardRequest(mockConn, req)
	if err != nil {
		t.Fatalf("forwardRequest failed: %v", err)
	}

	// Verify request headers are modified
	assert.Equal(t, "Modified/1.0", req.Header.Get("User-Agent"), "User-Agent header should be modified")

	// Verify request ID is set
	assert.NotEmpty(t, req.Header.Get("X-Request-ID"), "Request ID should be set")

	// Verify response body is modified (check mockConn buffer)
	responseStr := mockConn.buffer.String()
	assert.Contains(t, responseStr, "This is an modified text", "Response body should be modified correctly")
}

// TestFilteringInterceptorBlock is the test for filtering interceptor blocking requests
func TestFilteringInterceptorBlock(t *testing.T) {
	t.Parallel()

	// Create a test MITM proxy
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	// Create filtering interceptor
	filteringInterceptor := NewFilteringInterceptor(mp.logger)
	filteringInterceptor.AddBlockedHost("blocked.example.com")
	filteringInterceptor.SetBlockResponse(http.StatusForbidden, "403 Forbidden", "This resource is blocked")

	// Add interceptor to chain
	mp.AddInterceptor(filteringInterceptor)

	// Create blocked request
	req := httptest.NewRequest(http.MethodGet, "https://blocked.example.com/test", nil)

	// Create mock HTTP client (this client should not be called)
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader("This should not be returned")),
		Header:     make(http.Header),
		Request:    req,
	}
	mockClient := &mockHTTPClient{
		response: mockResp,
		err:      nil,
	}
	mp.client = mockClient

	// Create a test connection
	mockConn := &mockConnWithBuffer{
		mockConn: mockConn{},
		buffer:   &bytes.Buffer{},
	}

	// Call forwardRequest method to test interceptor chain
	err = mp.forwardRequest(mockConn, req)
	if err != nil {
		t.Fatalf("forwardRequest failed: %v", err)
	}

	// Verify response is blocked response
	responseStr := mockConn.buffer.String()
	assert.Contains(t, responseStr, "HTTP/1.1 403 Forbidden", "Response status should be 403 Forbidden")
	assert.Contains(t, responseStr, "This resource is blocked", "Response body should be the block message")
}
