package proxymitm

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// HTTPInterceptor is a basic interface that can process both requests and responses
type HTTPInterceptor interface {
	// Request processing - returns the modified request
	// Returning an error will stop the processing
	// Returning true will skip subsequent interceptors (termination)
	ProcessRequest(*http.Request) (*http.Request, bool, error)

	// Response processing - returns the modified response
	// Can also access the related request
	// Returning an error will stop the processing
	ProcessResponse(*http.Response, *http.Request) (*http.Response, error)
}

// LoggingInterceptor is an interceptor that logs the contents of requests and responses
type LoggingInterceptor struct {
	logger Logger
}

// NewLoggingInterceptor creates a new LoggingInterceptor
func NewLoggingInterceptor(logger Logger) *LoggingInterceptor {
	if logger == nil {
		logger = NewDefaultLogger(LogLevelInfo)
	}
	return &LoggingInterceptor{
		logger: logger,
	}
}

// ProcessRequest logs the contents of a request
func (li *LoggingInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	li.logger.Info("Request: %s %s", req.Method, req.URL)

	// Log header contents
	for name, values := range req.Header {
		li.logger.Debug("Request Header: %s: %s", name, strings.Join(values, ", "))
	}

	// Log request body contents if present
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			li.logger.Error("Failed to read request body: %v", err)
			return req, false, err
		}

		// Restore body
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Log body contents (truncated if too long)
		if len(bodyBytes) > 1024 {
			li.logger.Debug("Request Body (truncated): %s...", bodyBytes[:1024])
		} else if len(bodyBytes) > 0 {
			li.logger.Debug("Request Body: %s", bodyBytes)
		}
	}

	return req, false, nil
}

// ProcessResponse logs the contents of a response
func (li *LoggingInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	li.logger.Info("Response: %d %s for %s %s", resp.StatusCode, resp.Status, req.Method, req.URL)

	// Log header contents
	for name, values := range resp.Header {
		li.logger.Debug("Response Header: %s: %s", name, strings.Join(values, ", "))
	}

	// Log response body contents if present
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			li.logger.Error("Failed to read response body: %v", err)
			return resp, err
		}

		// Restore body
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Log body contents (truncated if too long)
		if len(bodyBytes) > 1024 {
			li.logger.Debug("Response Body (truncated): %s...", bodyBytes[:1024])
		} else if len(bodyBytes) > 0 {
			li.logger.Debug("Response Body: %s", bodyBytes)
		}
	}

	return resp, nil
}

// ContentModifierInterceptor is an interceptor that modifies the contents of requests and responses
type ContentModifierInterceptor struct {
	// Request header modification map (key: header name, value: value to set)
	requestHeaderModifications map[string]string

	// Response header modification map (key: header name, value: value to set)
	responseHeaderModifications map[string]string

	// Response body replacement map (key: search string, value: replacement string)
	bodyReplacements map[string]string

	logger Logger
}

// NewContentModifierInterceptor creates a new ContentModifierInterceptor
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

// AddRequestHeaderModification adds a request header modification
func (cmi *ContentModifierInterceptor) AddRequestHeaderModification(header, value string) {
	cmi.requestHeaderModifications[header] = value
}

// AddResponseHeaderModification adds a response header modification
func (cmi *ContentModifierInterceptor) AddResponseHeaderModification(header, value string) {
	cmi.responseHeaderModifications[header] = value
}

// AddBodyReplacement adds a response body replacement
func (cmi *ContentModifierInterceptor) AddBodyReplacement(search, replace string) {
	cmi.bodyReplacements[search] = replace
}

// ProcessRequest modifies the contents of a request
func (cmi *ContentModifierInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	// Apply header modifications
	for header, value := range cmi.requestHeaderModifications {
		cmi.logger.Debug("Modifying request header: %s: %s", header, value)
		req.Header.Set(header, value)
	}

	return req, false, nil
}

// ProcessResponse modifies the contents of a response
func (cmi *ContentModifierInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	// Apply header modifications
	for header, value := range cmi.responseHeaderModifications {
		cmi.logger.Debug("Modifying response header: %s: %s", header, value)
		resp.Header.Set(header, value)
	}

	// Process only if body replacements are set
	if len(cmi.bodyReplacements) > 0 && resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			cmi.logger.Error("Failed to read response body: %v", err)
			return resp, err
		}
		resp.Body.Close()

		// Convert body content to string
		bodyStr := string(bodyBytes)
		modified := false

		// Apply replacements
		for search, replace := range cmi.bodyReplacements {
			if strings.Contains(bodyStr, search) {
				cmi.logger.Debug("Replacing '%s' with '%s' in response body", search, replace)
				bodyStr = strings.ReplaceAll(bodyStr, search, replace)
				modified = true
			}
		}

		// Set new body only if modified
		if modified {
			newBodyBytes := []byte(bodyStr)
			resp.Body = io.NopCloser(bytes.NewBuffer(newBodyBytes))

			// Update Content-Length header
			resp.Header.Set("Content-Length", strconv.Itoa(len(newBodyBytes)))
			cmi.logger.Info("Response body modified")
		} else {
			// Reset original body if not modified
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	return resp, nil
}

// FilteringInterceptor is an interceptor that filters requests
type FilteringInterceptor struct {
	// List of hosts to block
	blockedHosts []string

	// List of URL paths to block
	blockedPaths []string

	// List of User-Agents to block
	blockedUserAgents []string

	// Custom response for blocked requests
	blockResponseStatus  int
	blockResponseMessage string
	blockResponseBody    string

	logger Logger
}

// NewFilteringInterceptor creates a new FilteringInterceptor
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

// AddBlockedHost adds a hostname to block
func (fi *FilteringInterceptor) AddBlockedHost(host string) {
	fi.blockedHosts = append(fi.blockedHosts, host)
}

// AddBlockedPath adds a URL path to block
func (fi *FilteringInterceptor) AddBlockedPath(path string) {
	fi.blockedPaths = append(fi.blockedPaths, path)
}

// AddBlockedUserAgent adds a user agent to block
func (fi *FilteringInterceptor) AddBlockedUserAgent(userAgent string) {
	fi.blockedUserAgents = append(fi.blockedUserAgents, userAgent)
}

// SetBlockResponse is used to set a custom response for blocked requests
func (fi *FilteringInterceptor) SetBlockResponse(status int, message, body string) {
	fi.blockResponseStatus = status
	fi.blockResponseMessage = message
	fi.blockResponseBody = body
}

// ProcessRequest filters requests
func (fi *FilteringInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	// Host filtering
	for _, blockedHost := range fi.blockedHosts {
		if strings.Contains(req.Host, blockedHost) {
			fi.logger.Info("Blocked request to host: %s", req.Host)
			return req, true, nil // Skip subsequent interceptors and let ProcessResponse handle it
		}
	}

	// URL path filtering
	for _, blockedPath := range fi.blockedPaths {
		if strings.Contains(req.URL.Path, blockedPath) {
			fi.logger.Info("Blocked request to path: %s", req.URL.Path)
			return req, true, nil // Skip subsequent interceptors and let ProcessResponse handle it
		}
	}

	// User-Agent filtering
	userAgent := req.Header.Get("User-Agent")
	for _, blockedUserAgent := range fi.blockedUserAgents {
		if strings.Contains(userAgent, blockedUserAgent) {
			fi.logger.Info("Blocked request with User-Agent: %s", userAgent)
			return req, true, nil // Skip subsequent interceptors and let ProcessResponse handle it
		}
	}

	return req, false, nil
}

// ProcessResponse processes responses
// Returns custom response if the request was blocked in request processing
func (fi *FilteringInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	// Check if request was blocked
	isBlocked := false
	blockReason := ""

	// Host filtering
	for _, blockedHost := range fi.blockedHosts {
		if strings.Contains(req.Host, blockedHost) {
			isBlocked = true
			blockReason = "host"
			break
		}
	}

	// URL path filtering
	if !isBlocked {
		for _, blockedPath := range fi.blockedPaths {
			if strings.Contains(req.URL.Path, blockedPath) {
				isBlocked = true
				blockReason = "path"
				break
			}
		}
	}

	// User-Agent filtering
	if !isBlocked {
		userAgent := req.Header.Get("User-Agent")
		for _, blockedUserAgent := range fi.blockedUserAgents {
			if strings.Contains(userAgent, blockedUserAgent) {
				isBlocked = true
				blockReason = "user-agent"
				break
			}
		}
	}

	// If request was blocked, return block response
	if isBlocked {
		fi.logger.Info("Returning block response for %s: %s", blockReason, req.URL)
		return fi.createBlockResponse(req), nil
	}

	return resp, nil
}

// Creates a custom response for blocked requests
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

// RequestIDInterceptor is an interceptor that generates and tracks request IDs
type RequestIDInterceptor struct {
	// Map used for associating requests and responses
	requests  map[string]*http.Request
	responses map[string]*http.Response
	mutex     sync.Mutex

	// Header name for request ID
	requestIDHeader string

	// Next request ID
	nextID int

	logger Logger
}

// NewRequestIDInterceptor creates a new RequestIDInterceptor
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

// ProcessRequest assigns an ID to a request
func (ri *RequestIDInterceptor) ProcessRequest(req *http.Request) (*http.Request, bool, error) {
	// Generate request ID
	id := ri.generateRequestID()

	// Set request ID in header
	req.Header.Set(ri.requestIDHeader, id)

	// Store request
	ri.mutex.Lock()
	ri.requests[id] = req.Clone(req.Context())
	ri.mutex.Unlock()

	ri.logger.Debug("Assigned request ID: %s to %s %s", id, req.Method, req.URL)

	return req, false, nil
}

// ProcessResponse processes responses and associates request IDs
func (ri *RequestIDInterceptor) ProcessResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	// Get request ID
	id := req.Header.Get(ri.requestIDHeader)
	if id == "" {
		ri.logger.Warn("No request ID found in request: %s %s", req.Method, req.URL)
		return resp, nil
	}

	// Set request ID in response header
	resp.Header.Set(ri.requestIDHeader, id)

	// Store response
	ri.mutex.Lock()
	ri.responses[id] = resp
	ri.mutex.Unlock()

	ri.logger.Debug("Associated response with request ID: %s", id)

	return resp, nil
}

// Generates a unique request ID
func (ri *RequestIDInterceptor) generateRequestID() string {
	ri.mutex.Lock()
	defer ri.mutex.Unlock()

	id := "REQ-" + strconv.Itoa(ri.nextID)
	ri.nextID++
	return id
}

// Gets the request with the specified ID
func (ri *RequestIDInterceptor) GetRequestByID(id string) *http.Request {
	ri.mutex.Lock()
	defer ri.mutex.Unlock()

	return ri.requests[id]
}

// Gets the response with the specified ID
func (ri *RequestIDInterceptor) GetResponseByID(id string) *http.Response {
	ri.mutex.Lock()
	defer ri.mutex.Unlock()

	return ri.responses[id]
}
