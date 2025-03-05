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

	// テスト用のロガーを作成
	logger := NewDefaultLogger(LogLevelDebug)
	interceptor := NewLoggingInterceptor(logger)

	// リクエスト処理のテスト
	t.Run("ProcessRequest", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", strings.NewReader("test body"))
		req.Header.Set("Content-Type", "text/plain")

		modifiedReq, skip, err := interceptor.ProcessRequest(req)
		require.NoError(t, err, "ProcessRequest should not return an error")
		assert.False(t, skip, "ProcessRequest should not skip")

		// リクエストが変更されていないことを確認
		assert.Equal(t, req.Method, modifiedReq.Method, "Request method should not be modified")
		assert.Equal(t, req.URL.String(), modifiedReq.URL.String(), "Request URL should not be modified")

		// ボディが読み取り可能であることを確認
		body, err := io.ReadAll(modifiedReq.Body)
		require.NoError(t, err, "Should be able to read request body")
		assert.Equal(t, "test body", string(body), "Request body should not be modified")
	})

	// レスポンス処理のテスト
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

		// レスポンスが変更されていないことを確認
		assert.Equal(t, resp.StatusCode, modifiedResp.StatusCode, "Response status code should not be modified")

		// ボディが読み取り可能であることを確認
		body, err := io.ReadAll(modifiedResp.Body)
		require.NoError(t, err, "Should be able to read response body")
		assert.Equal(t, "response body", string(body), "Response body should not be modified")
	})
}

func TestContentModifierInterceptor(t *testing.T) {
	t.Parallel()

	// テスト用のロガーを作成
	logger := NewDefaultLogger(LogLevelDebug)
	interceptor := NewContentModifierInterceptor(logger)

	// リクエストヘッダーの変更を追加
	interceptor.AddRequestHeaderModification("User-Agent", "Modified/1.0")
	interceptor.AddRequestHeaderModification("X-Custom-Header", "CustomValue")

	// レスポンスヘッダーの変更を追加
	interceptor.AddResponseHeaderModification("Server", "Modified/1.0")
	interceptor.AddResponseHeaderModification("X-Custom-Response", "CustomValue")

	// レスポンスボディの置換を追加
	interceptor.AddBodyReplacement("original", "replaced")

	// リクエスト処理のテスト
	t.Run("ProcessRequest", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		req.Header.Set("User-Agent", "Original/1.0")

		modifiedReq, skip, err := interceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if skip {
			t.Errorf("ProcessRequest returned skip=true, expected false")
		}

		// ヘッダーが変更されていることを確認
		if modifiedReq.Header.Get("User-Agent") != "Modified/1.0" {
			t.Errorf("User-Agent header was not modified, got %q, want %q", modifiedReq.Header.Get("User-Agent"), "Modified/1.0")
		}
		if modifiedReq.Header.Get("X-Custom-Header") != "CustomValue" {
			t.Errorf("X-Custom-Header was not added, got %q, want %q", modifiedReq.Header.Get("X-Custom-Header"), "CustomValue")
		}
	})

	// レスポンス処理のテスト
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
		if err != nil {
			t.Fatalf("ProcessResponse failed: %v", err)
		}

		// ヘッダーが変更されていることを確認
		if modifiedResp.Header.Get("Server") != "Modified/1.0" {
			t.Errorf("Server header was not modified, got %q, want %q", modifiedResp.Header.Get("Server"), "Modified/1.0")
		}
		if modifiedResp.Header.Get("X-Custom-Response") != "CustomValue" {
			t.Errorf("X-Custom-Response was not added, got %q, want %q", modifiedResp.Header.Get("X-Custom-Response"), "CustomValue")
		}

		// ボディが変更されていることを確認
		body, err := io.ReadAll(modifiedResp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		expectedBody := "This is an replaced text"
		if string(body) != expectedBody {
			t.Errorf("Response body was not modified correctly, got %q, want %q", string(body), expectedBody)
		}

		// Content-Lengthヘッダーが更新されていることを確認
		if modifiedResp.Header.Get("Content-Length") != "24" {
			t.Errorf("Content-Length header was not updated, got %q, want %q", modifiedResp.Header.Get("Content-Length"), "24")
		}
	})
}

func TestFilteringInterceptor(t *testing.T) {
	t.Parallel()

	// テスト用のロガーを作成
	logger := NewDefaultLogger(LogLevelDebug)
	interceptor := NewFilteringInterceptor(logger)

	// ブロックするホスト名を追加
	interceptor.AddBlockedHost("blocked.example.com")

	// ブロックするURLパスを追加
	interceptor.AddBlockedPath("/blocked")

	// ブロックするユーザーエージェントを追加
	interceptor.AddBlockedUserAgent("BlockedAgent")

	// カスタムブロックレスポンスを設定
	interceptor.SetBlockResponse(http.StatusForbidden, "403 Forbidden", "This resource is blocked")

	// 許可されたリクエストのテスト
	t.Run("ProcessRequest_Allowed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/allowed", nil)
		req.Header.Set("User-Agent", "AllowedAgent")

		modifiedReq, skip, err := interceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if skip {
			t.Errorf("ProcessRequest returned skip=true for allowed request")
		}
		if modifiedReq != req {
			t.Errorf("ProcessRequest modified the allowed request")
		}
	})

	// ブロックされたホスト名のテスト
	t.Run("ProcessRequest_BlockedHost", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://blocked.example.com/test", nil)

		_, skip, err := interceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if !skip {
			t.Errorf("ProcessRequest returned skip=false for blocked host")
		}

		// レスポンス処理でブロックレスポンスが返されることを確認
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("Original response")),
			Header:     make(http.Header),
		}

		blockedResp, err := interceptor.ProcessResponse(resp, req)
		if err != nil {
			t.Fatalf("ProcessResponse failed: %v", err)
		}

		if blockedResp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected status code %d, got %d", http.StatusForbidden, blockedResp.StatusCode)
		}

		body, err := io.ReadAll(blockedResp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		if string(body) != "This resource is blocked" {
			t.Errorf("Expected body %q, got %q", "This resource is blocked", string(body))
		}
	})

	// ブロックされたパスのテスト
	t.Run("ProcessRequest_BlockedPath", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/blocked/resource", nil)

		_, skip, err := interceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if !skip {
			t.Errorf("ProcessRequest returned skip=false for blocked path")
		}
	})

	// ブロックされたユーザーエージェントのテスト
	t.Run("ProcessRequest_BlockedUserAgent", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		req.Header.Set("User-Agent", "BlockedAgent/1.0")

		_, skip, err := interceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if !skip {
			t.Errorf("ProcessRequest returned skip=false for blocked user agent")
		}
	})
}

func TestRequestIDInterceptor(t *testing.T) {
	t.Parallel()

	// テスト用のロガーを作成
	logger := NewDefaultLogger(LogLevelDebug)
	interceptor := NewRequestIDInterceptor(logger)

	// リクエスト処理のテスト
	t.Run("ProcessRequest", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		modifiedReq, skip, err := interceptor.ProcessRequest(req)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}
		if skip {
			t.Errorf("ProcessRequest returned skip=true, expected false")
		}

		// リクエストIDが設定されていることを確認
		requestID := modifiedReq.Header.Get("X-Request-ID")
		if requestID == "" {
			t.Errorf("Request ID was not set")
		}

		// リクエストが保存されていることを確認
		savedReq := interceptor.GetRequestByID(requestID)
		if savedReq == nil {
			t.Errorf("Request was not saved with ID %s", requestID)
		}
	})

	// レスポンス処理のテスト
	t.Run("ProcessResponse", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

		// まずリクエスト処理を行ってIDを設定
		modifiedReq, _, _ := interceptor.ProcessRequest(req)
		requestID := modifiedReq.Header.Get("X-Request-ID")

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("response body")),
			Header:     make(http.Header),
		}

		modifiedResp, err := interceptor.ProcessResponse(resp, modifiedReq)
		if err != nil {
			t.Fatalf("ProcessResponse failed: %v", err)
		}

		// レスポンスヘッダーにリクエストIDが設定されていることを確認
		if modifiedResp.Header.Get("X-Request-ID") != requestID {
			t.Errorf("Response header does not contain the correct request ID")
		}

		// レスポンスが保存されていることを確認
		savedResp := interceptor.GetResponseByID(requestID)
		if savedResp == nil {
			t.Errorf("Response was not saved with ID %s", requestID)
		}
	})

	// 複数のリクエストでIDが一意であることを確認
	t.Run("UniqueIDs", func(t *testing.T) {
		t.Parallel()
		req1 := httptest.NewRequest(http.MethodGet, "https://example.com/test1", nil)
		req2 := httptest.NewRequest(http.MethodGet, "https://example.com/test2", nil)

		modifiedReq1, _, _ := interceptor.ProcessRequest(req1)
		modifiedReq2, _, _ := interceptor.ProcessRequest(req2)

		id1 := modifiedReq1.Header.Get("X-Request-ID")
		id2 := modifiedReq2.Header.Get("X-Request-ID")

		if id1 == id2 {
			t.Errorf("Request IDs are not unique: %s", id1)
		}
	})
}

func TestInterceptorChain(t *testing.T) {
	t.Parallel()

	// テスト用のMITMプロキシを作成
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	// テスト用のインターセプターを作成
	loggingInterceptor := NewLoggingInterceptor(mp.logger)
	contentModifier := NewContentModifierInterceptor(mp.logger)
	contentModifier.AddRequestHeaderModification("User-Agent", "Modified/1.0")
	contentModifier.AddBodyReplacement("original", "modified")
	requestIDInterceptor := NewRequestIDInterceptor(mp.logger)

	// インターセプターをチェーンに追加
	mp.AddInterceptor(requestIDInterceptor)
	mp.AddInterceptor(loggingInterceptor)
	mp.AddInterceptor(contentModifier)

	// テスト用のリクエストとレスポンスを作成
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.Header.Set("User-Agent", "Original/1.0")

	// モックHTTPクライアントを作成
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

	// テスト用のコネクションを作成
	mockConn := &mockConnWithBuffer{
		mockConn: mockConn{},
		buffer:   &bytes.Buffer{},
	}

	// forwardRequestメソッドを呼び出してインターセプターチェーンをテスト
	err = mp.forwardRequest(mockConn, req)
	if err != nil {
		t.Fatalf("forwardRequest failed: %v", err)
	}

	// リクエストヘッダーが変更されていることを確認
	if req.Header.Get("User-Agent") != "Modified/1.0" {
		t.Errorf("User-Agent header was not modified, got %q, want %q", req.Header.Get("User-Agent"), "Modified/1.0")
	}

	// リクエストIDが設定されていることを確認
	if req.Header.Get("X-Request-ID") == "" {
		t.Errorf("Request ID was not set")
	}

	// レスポンスボディが変更されていることを確認（mockConnのバッファを確認）
	responseStr := mockConn.buffer.String()
	if !strings.Contains(responseStr, "This is an modified text") {
		t.Errorf("Response body was not modified correctly, got %q, expected to contain %q", responseStr, "This is an modified text")
	}
}

// TestFilteringInterceptorBlock はフィルタリングインターセプターがリクエストをブロックするテスト
func TestFilteringInterceptorBlock(t *testing.T) {
	t.Parallel()

	// テスト用のMITMプロキシを作成
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	// フィルタリングインターセプターを作成
	filteringInterceptor := NewFilteringInterceptor(mp.logger)
	filteringInterceptor.AddBlockedHost("blocked.example.com")
	filteringInterceptor.SetBlockResponse(http.StatusForbidden, "403 Forbidden", "This resource is blocked")

	// インターセプターをチェーンに追加
	mp.AddInterceptor(filteringInterceptor)

	// ブロックされるリクエストを作成
	req := httptest.NewRequest(http.MethodGet, "https://blocked.example.com/test", nil)

	// モックHTTPクライアントを作成（このクライアントは呼び出されないはず）
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

	// テスト用のコネクションを作成
	mockConn := &mockConnWithBuffer{
		mockConn: mockConn{},
		buffer:   &bytes.Buffer{},
	}

	// forwardRequestメソッドを呼び出してインターセプターチェーンをテスト
	err = mp.forwardRequest(mockConn, req)
	if err != nil {
		t.Fatalf("forwardRequest failed: %v", err)
	}

	// レスポンスがブロックレスポンスであることを確認
	responseStr := mockConn.buffer.String()
	if !strings.Contains(responseStr, "HTTP/1.1 403 Forbidden") {
		t.Errorf("Response status was not 403 Forbidden, got %q", responseStr)
	}
	if !strings.Contains(responseStr, "This resource is blocked") {
		t.Errorf("Response body does not contain the block message, got %q", responseStr)
	}
}
