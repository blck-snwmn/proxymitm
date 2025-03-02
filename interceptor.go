package proxymitm

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// HTTPInterceptor はリクエストとレスポンスの両方を処理できる基本インターフェース
type HTTPInterceptor interface {
	// リクエスト処理 - 変更されたリクエストを返す
	// エラーを返すと処理が中断される
	// trueを返すと後続のインターセプターがスキップされる（中断）
	ProcessRequest(*http.Request) (*http.Request, bool, error)

	// レスポンス処理 - 変更されたレスポンスを返す
	// 関連するリクエストにもアクセス可能
	// エラーを返すと処理が中断される
	ProcessResponse(*http.Response, *http.Request) (*http.Response, error)
}

// LoggingInterceptor はリクエストとレスポンスの内容をログに記録するインターセプター
type LoggingInterceptor struct {
	logger Logger
}

// NewLoggingInterceptor は新しいLoggingInterceptorを作成します
func NewLoggingInterceptor(logger Logger) *LoggingInterceptor {
	if logger == nil {
		logger = NewDefaultLogger(LogLevelInfo)
	}
	return &LoggingInterceptor{
		logger: logger,
	}
}

// ProcessRequest はリクエストの内容をログに記録します
func (li *LoggingInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	li.logger.Info("Request: %s %s", req.Method, req.URL)

	// ヘッダーの内容をログに記録
	for name, values := range req.Header {
		li.logger.Debug("Request Header: %s: %s", name, strings.Join(values, ", "))
	}

	// リクエストボディがある場合は内容をログに記録
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			li.logger.Error("Failed to read request body: %v", err)
			return req, false, err
		}

		// ボディを再設定
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// ボディの内容をログに記録（長すぎる場合は省略）
		if len(bodyBytes) > 1024 {
			li.logger.Debug("Request Body (truncated): %s...", bodyBytes[:1024])
		} else if len(bodyBytes) > 0 {
			li.logger.Debug("Request Body: %s", bodyBytes)
		}
	}

	return req, false, nil
}

// ProcessResponse はレスポンスの内容をログに記録します
func (li *LoggingInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	li.logger.Info("Response: %d %s for %s %s", resp.StatusCode, resp.Status, req.Method, req.URL)

	// ヘッダーの内容をログに記録
	for name, values := range resp.Header {
		li.logger.Debug("Response Header: %s: %s", name, strings.Join(values, ", "))
	}

	// レスポンスボディがある場合は内容をログに記録
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			li.logger.Error("Failed to read response body: %v", err)
			return resp, err
		}

		// ボディを再設定
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// ボディの内容をログに記録（長すぎる場合は省略）
		if len(bodyBytes) > 1024 {
			li.logger.Debug("Response Body (truncated): %s...", bodyBytes[:1024])
		} else if len(bodyBytes) > 0 {
			li.logger.Debug("Response Body: %s", bodyBytes)
		}
	}

	return resp, nil
}

// ContentModifierInterceptor はリクエストとレスポンスの内容を変更するインターセプター
type ContentModifierInterceptor struct {
	// リクエストヘッダーの変更マップ (key: ヘッダー名, value: 設定する値)
	requestHeaderModifications map[string]string

	// レスポンスヘッダーの変更マップ (key: ヘッダー名, value: 設定する値)
	responseHeaderModifications map[string]string

	// レスポンスボディの置換マップ (key: 検索文字列, value: 置換文字列)
	bodyReplacements map[string]string

	logger Logger
}

// NewContentModifierInterceptor は新しいContentModifierInterceptorを作成します
func NewContentModifierInterceptor(logger Logger) *ContentModifierInterceptor {
	if logger == nil {
		logger = NewDefaultLogger(LogLevelInfo)
	}
	return &ContentModifierInterceptor{
		requestHeaderModifications:  make(map[string]string),
		responseHeaderModifications: make(map[string]string),
		bodyReplacements:            make(map[string]string),
		logger:                      logger,
	}
}

// AddRequestHeaderModification はリクエストヘッダーの変更を追加します
func (cmi *ContentModifierInterceptor) AddRequestHeaderModification(header, value string) {
	cmi.requestHeaderModifications[header] = value
}

// AddResponseHeaderModification はレスポンスヘッダーの変更を追加します
func (cmi *ContentModifierInterceptor) AddResponseHeaderModification(header, value string) {
	cmi.responseHeaderModifications[header] = value
}

// AddBodyReplacement はレスポンスボディの置換を追加します
func (cmi *ContentModifierInterceptor) AddBodyReplacement(search, replace string) {
	cmi.bodyReplacements[search] = replace
}

// ProcessRequest はリクエストの内容を変更します
func (cmi *ContentModifierInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	// ヘッダーの変更を適用
	for header, value := range cmi.requestHeaderModifications {
		cmi.logger.Debug("Modifying request header: %s: %s", header, value)
		req.Header.Set(header, value)
	}

	return req, false, nil
}

// ProcessResponse はレスポンスの内容を変更します
func (cmi *ContentModifierInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	// ヘッダーの変更を適用
	for header, value := range cmi.responseHeaderModifications {
		cmi.logger.Debug("Modifying response header: %s: %s", header, value)
		resp.Header.Set(header, value)
	}

	// ボディの置換が設定されている場合のみ処理
	if len(cmi.bodyReplacements) > 0 && resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			cmi.logger.Error("Failed to read response body: %v", err)
			return resp, err
		}
		resp.Body.Close()

		// ボディの内容を文字列に変換
		bodyStr := string(bodyBytes)
		modified := false

		// 置換を適用
		for search, replace := range cmi.bodyReplacements {
			if strings.Contains(bodyStr, search) {
				cmi.logger.Debug("Replacing '%s' with '%s' in response body", search, replace)
				bodyStr = strings.ReplaceAll(bodyStr, search, replace)
				modified = true
			}
		}

		// 変更があった場合のみ、新しいボディを設定
		if modified {
			newBodyBytes := []byte(bodyStr)
			resp.Body = io.NopCloser(bytes.NewBuffer(newBodyBytes))

			// Content-Lengthヘッダーを更新
			resp.Header.Set("Content-Length", strconv.Itoa(len(newBodyBytes)))
			cmi.logger.Info("Response body modified")
		} else {
			// 変更がなかった場合は元のボディを再設定
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	return resp, nil
}

// FilteringInterceptor はリクエストをフィルタリングするインターセプター
type FilteringInterceptor struct {
	// ブロックするホスト名のリスト
	blockedHosts []string

	// ブロックするURLパスのリスト
	blockedPaths []string

	// ブロックするユーザーエージェントのリスト
	blockedUserAgents []string

	// ブロック時のカスタムレスポンス
	blockResponseStatus  int
	blockResponseMessage string
	blockResponseBody    string

	logger Logger
}

// NewFilteringInterceptor は新しいFilteringInterceptorを作成します
func NewFilteringInterceptor(logger Logger) *FilteringInterceptor {
	if logger == nil {
		logger = NewDefaultLogger(LogLevelInfo)
	}
	return &FilteringInterceptor{
		blockedHosts:         make([]string, 0),
		blockedPaths:         make([]string, 0),
		blockedUserAgents:    make([]string, 0),
		blockResponseStatus:  http.StatusForbidden,
		blockResponseMessage: "Forbidden",
		blockResponseBody:    "Access to this resource is forbidden",
		logger:               logger,
	}
}

// AddBlockedHost はブロックするホスト名を追加します
func (fi *FilteringInterceptor) AddBlockedHost(host string) {
	fi.blockedHosts = append(fi.blockedHosts, host)
}

// AddBlockedPath はブロックするURLパスを追加します
func (fi *FilteringInterceptor) AddBlockedPath(path string) {
	fi.blockedPaths = append(fi.blockedPaths, path)
}

// AddBlockedUserAgent はブロックするユーザーエージェントを追加します
func (fi *FilteringInterceptor) AddBlockedUserAgent(userAgent string) {
	fi.blockedUserAgents = append(fi.blockedUserAgents, userAgent)
}

// SetBlockResponse はブロック時のカスタムレスポンスを設定します
func (fi *FilteringInterceptor) SetBlockResponse(status int, message, body string) {
	fi.blockResponseStatus = status
	fi.blockResponseMessage = message
	fi.blockResponseBody = body
}

// ProcessRequest はリクエストをフィルタリングします
func (fi *FilteringInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	// ホスト名のフィルタリング
	for _, blockedHost := range fi.blockedHosts {
		if strings.Contains(req.Host, blockedHost) {
			fi.logger.Info("Blocked request to host: %s", req.Host)
			return req, true, nil // 処理を中断
		}
	}

	// URLパスのフィルタリング
	for _, blockedPath := range fi.blockedPaths {
		if strings.Contains(req.URL.Path, blockedPath) {
			fi.logger.Info("Blocked request to path: %s", req.URL.Path)
			return req, true, nil // 処理を中断
		}
	}

	// ユーザーエージェントのフィルタリング
	userAgent := req.Header.Get("User-Agent")
	for _, blockedUserAgent := range fi.blockedUserAgents {
		if strings.Contains(userAgent, blockedUserAgent) {
			fi.logger.Info("Blocked request with User-Agent: %s", userAgent)
			return req, true, nil // 処理を中断
		}
	}

	return req, false, nil
}

// ProcessResponse はレスポンスを処理します
// リクエスト処理でブロックされた場合、カスタムレスポンスを返します
func (fi *FilteringInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	// ホスト名のフィルタリング
	for _, blockedHost := range fi.blockedHosts {
		if strings.Contains(req.Host, blockedHost) {
			return fi.createBlockResponse(req), nil
		}
	}

	// URLパスのフィルタリング
	for _, blockedPath := range fi.blockedPaths {
		if strings.Contains(req.URL.Path, blockedPath) {
			return fi.createBlockResponse(req), nil
		}
	}

	// ユーザーエージェントのフィルタリング
	userAgent := req.Header.Get("User-Agent")
	for _, blockedUserAgent := range fi.blockedUserAgents {
		if strings.Contains(userAgent, blockedUserAgent) {
			return fi.createBlockResponse(req), nil
		}
	}

	return resp, nil
}

// createBlockResponse はブロック時のカスタムレスポンスを作成します
func (fi *FilteringInterceptor) createBlockResponse(req *http.Request) *http.Response {
	resp := &http.Response{
		StatusCode: fi.blockResponseStatus,
		Status:     fi.blockResponseMessage,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(fi.blockResponseBody)),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Content-Length", strconv.Itoa(len(fi.blockResponseBody)))
	return resp
}

// RequestIDInterceptor はリクエストIDを生成して追跡するインターセプター
type RequestIDInterceptor struct {
	// リクエストとレスポンスの関連付けに使用するマップ
	requests  map[string]*http.Request
	responses map[string]*http.Response
	mutex     sync.Mutex

	// リクエストIDのヘッダー名
	requestIDHeader string

	// 次のリクエストID
	nextID int

	logger Logger
}

// NewRequestIDInterceptor は新しいRequestIDInterceptorを作成します
func NewRequestIDInterceptor(logger Logger) *RequestIDInterceptor {
	if logger == nil {
		logger = NewDefaultLogger(LogLevelInfo)
	}
	return &RequestIDInterceptor{
		requests:        make(map[string]*http.Request),
		responses:       make(map[string]*http.Response),
		requestIDHeader: "X-Request-ID",
		nextID:          1,
		logger:          logger,
	}
}

// ProcessRequest はリクエストにIDを付与します
func (ri *RequestIDInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	// リクエストIDを生成
	id := ri.generateRequestID()

	// リクエストIDをヘッダーに設定
	req.Header.Set(ri.requestIDHeader, id)

	// リクエストを保存
	ri.mutex.Lock()
	ri.requests[id] = req.Clone(req.Context())
	ri.mutex.Unlock()

	ri.logger.Debug("Assigned request ID: %s to %s %s", id, req.Method, req.URL)

	return req, false, nil
}

// ProcessResponse はレスポンスを処理し、リクエストIDを関連付けます
func (ri *RequestIDInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	// リクエストIDを取得
	id := req.Header.Get(ri.requestIDHeader)
	if id == "" {
		ri.logger.Warn("No request ID found in request: %s %s", req.Method, req.URL)
		return resp, nil
	}

	// レスポンスヘッダーにリクエストIDを設定
	resp.Header.Set(ri.requestIDHeader, id)

	// レスポンスを保存
	ri.mutex.Lock()
	ri.responses[id] = resp
	ri.mutex.Unlock()

	ri.logger.Debug("Associated response with request ID: %s", id)

	return resp, nil
}

// generateRequestID は一意のリクエストIDを生成します
func (ri *RequestIDInterceptor) generateRequestID() string {
	ri.mutex.Lock()
	defer ri.mutex.Unlock()

	id := "REQ-" + strconv.Itoa(ri.nextID)
	ri.nextID++
	return id
}

// GetRequestByID は指定されたIDのリクエストを取得します
func (ri *RequestIDInterceptor) GetRequestByID(id string) *http.Request {
	ri.mutex.Lock()
	defer ri.mutex.Unlock()

	return ri.requests[id]
}

// GetResponseByID は指定されたIDのレスポンスを取得します
func (ri *RequestIDInterceptor) GetResponseByID(id string) *http.Response {
	ri.mutex.Lock()
	defer ri.mutex.Unlock()

	return ri.responses[id]
}
