package proxymitm

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// LogLevel represents the logging level
type LogLevel int

const (
	// LogLevelDebug represents the debug level log
	LogLevelDebug LogLevel = iota
	// LogLevelInfo represents the information level log
	LogLevelInfo
	// LogLevelWarn represents the warning level log
	LogLevelWarn
	// LogLevelError represents the error level log
	LogLevelError
)

// Logger defines the logging interface
type Logger interface {
	Debug(format string, v ...interface{})
	Info(format string, v ...interface{})
	Warn(format string, v ...interface{})
	Error(format string, v ...interface{})
}

// DefaultLogger is the default logger implementation
type DefaultLogger struct {
	level LogLevel
}

// NewDefaultLogger creates a new default logger
func NewDefaultLogger(level LogLevel) *DefaultLogger {
	return &DefaultLogger{
		level: level,
	}
}

// Debug outputs logs at debug level
func (l *DefaultLogger) Debug(format string, v ...interface{}) {
	if l.level <= LogLevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Info outputs logs at information level
func (l *DefaultLogger) Info(format string, v ...interface{}) {
	if l.level <= LogLevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

// Warn outputs logs at warning level
func (l *DefaultLogger) Warn(format string, v ...interface{}) {
	if l.level <= LogLevelWarn {
		log.Printf("[WARN] "+format, v...)
	}
}

// Error outputs logs at error level
func (l *DefaultLogger) Error(format string, v ...interface{}) {
	if l.level <= LogLevelError {
		log.Printf("[ERROR] "+format, v...)
	}
}

var (
	internalServerError = []byte("HTTP/1.0 " + strconv.Itoa(http.StatusInternalServerError) + " \r\n\r\n")
)

var _ http.Handler = (*ServerMux)(nil)

// HTTPClient is an interface for making HTTP requests
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// RequestCreator is an interface for creating requests
type RequestCreator interface {
	CreateRequest(conn net.Conn) (*http.Request, error)
}

// TLSHandshaker is an interface for performing TLS handshakes
type TLSHandshaker interface {
	TLSHandshake(con net.Conn, hostName string) (*tls.Conn, error)
}

// Default timeout values
const (
	DefaultReadTimeout  = 30 * time.Second
	DefaultWriteTimeout = 30 * time.Second
	DefaultIdleTimeout  = 90 * time.Second
)

type ServerMux struct {
	tlsCert      tls.Certificate
	x509Cert     *x509.Certificate
	client       HTTPClient
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
	logger       Logger
	interceptors []HTTPInterceptor
}

// AddInterceptor adds an interceptor to the list
func (mp *ServerMux) AddInterceptor(interceptor HTTPInterceptor) {
	mp.interceptors = append(mp.interceptors, interceptor)
	mp.logger.Info("Added interceptor: %T", interceptor)
}

func (mp *ServerMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mp.logger.Info("Received request: %s %s", r.Method, r.URL.String())

	switch r.Method {
	case http.MethodConnect:
		mp.logger.Debug("Handling CONNECT request for %s", r.URL.String())
		// Establish TCP connection for CONNECT requests
		con, err := mp.hijackConnection(w)
		if err != nil {
			mp.handleError(w, err)
			return
		}
		defer con.Close()

		if err := mp.handleConnect(con, r); err != nil {
			mp.handleConnectError(con, err)
		}
	default:
		mp.logger.Debug("Handling non-CONNECT request for %s", r.URL.String())
		if err := mp.handleNonConnect(w, r); err != nil {
			mp.handleError(w, err)
		}
	}
}

func (mp *ServerMux) hijackConnection(w http.ResponseWriter) (net.Conn, error) {
	hjk, ok := w.(http.Hijacker)
	if !ok {
		return nil, NewProxyError(ErrHijack, "hijack", "http.Hijacker not available", nil)
	}
	con, _, err := hjk.Hijack()
	if err != nil {
		return nil, NewProxyError(ErrHijack, "hijack", "failed to hijack connection", err)
	}
	return con, nil
}

func (mp *ServerMux) handleConnect(con net.Conn, r *http.Request) error {
	// Set connection timeout
	if err := con.SetDeadline(time.Now().Add(mp.readTimeout)); err != nil {
		return NewProxyError(ErrHijack, "set_deadline", "failed to set connection deadline", err)
	}

	mp.logger.Debug("Writing connection established for %s", r.URL.String())
	if err := mp.writeConnectionEstablished(con); err != nil {
		return err
	}

	// TLS handshake with client
	mp.logger.Debug("Starting TLS handshake with %s", r.URL.Hostname())
	tlsConn, err := mp.TLSHandshake(con, r.URL.Hostname())
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// Set TLS connection timeout
	if err := tlsConn.SetDeadline(time.Now().Add(mp.readTimeout)); err != nil {
		return NewProxyError(ErrTLSHandshake, "set_deadline", "failed to set TLS connection deadline", err)
	}

	// Exchange data
	// Send client request to server
	mp.logger.Debug("Creating request from TLS connection")
	req, err := mp.CreateRequest(tlsConn)
	if err != nil {
		return err
	}

	mp.logger.Debug("Forwarding request to %s", req.URL.String())
	return mp.forwardRequest(tlsConn, req.WithContext(r.Context()))
}

func (mp *ServerMux) handleNonConnect(w http.ResponseWriter, r *http.Request) error {
	mp.logger.Debug("Creating new request for %s %s", r.Method, r.URL.String())
	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		return NewProxyError(ErrCreateRequest, "new_request", "failed to create request", err)
	}
	req = req.WithContext(r.Context())

	// Copy headers from original request
	for k, v := range r.Header {
		req.Header[k] = v
	}

	// Make sure to close the request body if it exists
	if r.Body != nil {
		defer r.Body.Close()
	}

	var skipRemaining bool

	// Request interception processing
	for _, interceptor := range mp.interceptors {
		mp.logger.Debug("Applying request interceptor: %T", interceptor)
		if req, skipRemaining, err = interceptor.ProcessRequest(req); err != nil {
			mp.logger.Error("Interceptor error during request processing: %v", err)
			return NewProxyError(ErrSendRequest, "interceptor_request", "interceptor failed to process request", err)
		}
		if skipRemaining {
			mp.logger.Debug("Request processing interrupted by interceptor: %T", interceptor)
			break // Skip subsequent interceptors
		}
	}

	// Update original request headers with modified headers
	for k := range r.Header {
		r.Header.Del(k)
	}
	for k, v := range req.Header {
		r.Header[k] = v
	}

	mp.logger.Debug("Sending request to %s", req.URL.String())
	resp, err := mp.client.Do(req)
	if err != nil {
		errorType := determineErrorType(err)
		return NewProxyError(errorType, "do_request", "failed to send request", err)
	}
	defer resp.Body.Close()

	// Response interception processing
	for _, interceptor := range mp.interceptors {
		mp.logger.Debug("Applying response interceptor: %T", interceptor)
		if resp, err = interceptor.ProcessResponse(resp, req); err != nil {
			mp.logger.Error("Interceptor error during response processing: %v", err)
			return NewProxyError(ErrSendRequest, "interceptor_response", "interceptor failed to process response", err)
		}
	}

	mp.logger.Debug("Writing response with status %d", resp.StatusCode)

	// Copy headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy body
	if _, err := io.Copy(w, resp.Body); err != nil {
		return NewProxyError(ErrSendRequest, "write_body", "failed to write response body", err)
	}

	return nil
}

func (mp *ServerMux) writeConnectionEstablished(con net.Conn) error {
	_, err := con.Write([]byte("HTTP/1.0 200 Connection established \r\n\r\n"))
	if err != nil {
		return NewProxyError(ErrHijack, "write", "failed to write connection established", err)
	}
	return nil
}

func (mp *ServerMux) writeResponse(w http.ResponseWriter, resp *http.Response) error {
	// Copy headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	// Copy body using a buffer to avoid memory issues
	buf := make([]byte, 32*1024) // 32KB buffer
	_, err := io.CopyBuffer(w, resp.Body, buf)
	if err != nil {
		return NewProxyError(ErrSendRequest, "write_response", "failed to write response", err)
	}
	return nil
}

func (mp *ServerMux) forwardRequest(conn net.Conn, req *http.Request) error {
	// Make sure to close the request body if it exists
	if req.Body != nil {
		defer req.Body.Close()
	}

	var err error
	skipRemaining := false

	// Request interception processing
	for _, interceptor := range mp.interceptors {
		mp.logger.Debug("Applying request interceptor: %T", interceptor)
		if req, skipRemaining, err = interceptor.ProcessRequest(req); err != nil {
			mp.logger.Error("Interceptor error during request processing: %v", err)
			return NewProxyError(ErrSendRequest, "interceptor_request", "interceptor failed to process request", err)
		}
		if skipRemaining {
			mp.logger.Debug("Request processing interrupted by interceptor: %T", interceptor)
			break // Skip subsequent interceptors
		}
	}

	mp.logger.Debug("Sending request to %s", req.URL.String())
	resp, err := mp.client.Do(req)
	if err != nil {
		errorType := determineErrorType(err)
		return NewProxyError(errorType, "do_request", "failed to send request", err)
	}
	defer resp.Body.Close()

	// Response interception processing
	for _, interceptor := range mp.interceptors {
		mp.logger.Debug("Applying response interceptor: %T", interceptor)
		if resp, err = interceptor.ProcessResponse(resp, req); err != nil {
			mp.logger.Error("Interceptor error during response processing: %v", err)
			return NewProxyError(ErrSendRequest, "interceptor_response", "interceptor failed to process response", err)
		}
	}

	mp.logger.Debug("Writing response with status %d", resp.StatusCode)
	writer := io.MultiWriter(conn, os.Stdout)
	if err := resp.Write(writer); err != nil {
		return NewProxyError(ErrSendRequest, "write_response", "failed to write response", err)
	}
	return nil
}

func New(certPath, keyPath string) (*http.Server, error) {
	// Load the certificate of the custom certificate authority
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, NewProxyError(ErrCertificate, "load_cert", "failed to load certificate", err)
	}
	// Create a certificate signed by the custom certificate authority
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, NewProxyError(ErrCertificate, "parse_cert", "failed to parse certificate", err)
	}

	mux := &ServerMux{
		tlsCert:      tlsCert,
		x509Cert:     x509Cert,
		client:       &http.Client{},
		readTimeout:  DefaultReadTimeout,
		writeTimeout: DefaultWriteTimeout,
		idleTimeout:  DefaultIdleTimeout,
		logger:       NewDefaultLogger(LogLevelInfo),
		interceptors: make([]HTTPInterceptor, 0),
	}

	server := http.Server{
		Handler:      mux,
		ReadTimeout:  mux.readTimeout,
		WriteTimeout: mux.writeTimeout,
		IdleTimeout:  mux.idleTimeout,
	}

	return &server, nil
}

func mitmx509template(hostName string) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		DNSNames:     []string{hostName},
		NotBefore:    now,
		NotAfter:     now.AddDate(1, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

// CreateMitmProxy load pem, and then it return MitmProxy
func CreateMitmProxy(certPath, keyPath string) (*ServerMux, error) {
	// Load the certificate of the custom certificate authority
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	// Create a certificate signed by the custom certificate authority
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &ServerMux{
		tlsCert:      tlsCert,
		x509Cert:     x509Cert,
		client:       &http.Client{},
		readTimeout:  DefaultReadTimeout,
		writeTimeout: DefaultWriteTimeout,
		idleTimeout:  DefaultIdleTimeout,
		logger:       NewDefaultLogger(LogLevelInfo),
		interceptors: make([]HTTPInterceptor, 0),
	}, nil
}

func (mp *ServerMux) tlsHandshake(con net.Conn, hostName string) (*tls.Conn, error) {
	// Create a certificate for the domain to connect to
	template := mitmx509template(hostName)
	c, pk, err := mp.createX509Certificate(template)
	if err != nil {
		return nil, NewProxyError(ErrTLSHandshake, "create_cert", "failed to create certificate", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{c.Raw},
		PrivateKey:  pk,
	}

	config := tls.Config{}
	config.Certificates = []tls.Certificate{cert}

	tlsConn := tls.Server(con, &config)
	if err = tlsConn.Handshake(); err != nil {
		return nil, NewProxyError(ErrTLSHandshake, "handshake", "failed to perform TLS handshake", err)
	}
	return tlsConn, nil
}

func (mp *ServerMux) createX509Certificate(template *x509.Certificate) (*x509.Certificate, crypto.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, NewProxyError(ErrTLSHandshake, "generate_key", "failed to generate RSA key", err)
	}
	pub := &priv.PublicKey
	cb, err := x509.CreateCertificate(
		rand.Reader,
		template, mp.x509Cert,
		pub, mp.tlsCert.PrivateKey,
	)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(cb)
	if err != nil {
		return nil, nil, err
	}
	return c, priv, nil
}

func (mp *ServerMux) createRequest(tlsConn net.Conn) (*http.Request, error) {
	creq, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		return nil, NewProxyError(ErrCreateRequest, "read_request", "failed to read request", err)
	}

	requestURL := "https://" + creq.Host + creq.RequestURI
	creq, err = http.NewRequest(creq.Method, requestURL, creq.Body)
	if err != nil {
		return nil, NewProxyError(ErrCreateRequest, "new_request", "failed to create request", err)
	}
	return creq, nil
}

// CreateRequest implements the RequestCreator interface
func (mp *ServerMux) CreateRequest(conn net.Conn) (*http.Request, error) {
	return mp.createRequest(conn)
}

// determineErrorType determines the appropriate ErrorType based on the error message
func determineErrorType(err error) ErrorType {
	if err == nil {
		return ErrSendRequest
	}
	
	errMsg := err.Error()
	
	// Check for gateway errors (DNS, connection issues)
	if strings.Contains(errMsg, "no such host") ||
		strings.Contains(errMsg, "connection refused") ||
		strings.Contains(errMsg, "network is unreachable") ||
		strings.Contains(errMsg, "no route to host") {
		return ErrGateway
	}
	
	// Check for timeout errors
	if strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "deadline exceeded") {
		return ErrTimeout
	}
	
	// Default to send request error
	return ErrSendRequest
}

// handleError provides unified error handling
func (mp *ServerMux) handleError(w http.ResponseWriter, err error) {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		mp.logger.Error("Proxy error: %v", proxyErr)

		// Determine the appropriate status code based on error type
		statusCode := http.StatusInternalServerError // Default to 500
		switch proxyErr.Type {
		case ErrGateway:
			statusCode = http.StatusBadGateway // 502
		case ErrTimeout:
			statusCode = http.StatusGatewayTimeout // 504
		// ErrSendRequest and others default to 500
		}

		if hijacker, ok := w.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				defer conn.Close()
				resp := &http.Response{
					StatusCode: statusCode,
					Status:     http.StatusText(statusCode),
					Proto:      "HTTP/1.1",
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(proxyErr.Message)),
				}
				resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
				resp.Header.Set("Content-Length", strconv.Itoa(len(proxyErr.Message)))
				if err := resp.Write(conn); err != nil {
					mp.logger.Error("Failed to write error response: %v", err)
				}
				return
			}
		}
		http.Error(w, proxyErr.Message, statusCode)
	} else {
		mp.logger.Error("Internal error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleConnectError provides error handling for the CONNECT method
func (mp *ServerMux) handleConnectError(con net.Conn, err error) {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		mp.logger.Error("Connect error: %v", proxyErr)

		// Determine the appropriate status code based on error type
		statusCode := http.StatusInternalServerError // Default to 500
		switch proxyErr.Type {
		case ErrGateway:
			statusCode = http.StatusBadGateway // 502
		case ErrTimeout:
			statusCode = http.StatusGatewayTimeout // 504
		// ErrSendRequest and others default to 500
		}

		resp := &http.Response{
			StatusCode: statusCode,
			Status:     http.StatusText(statusCode),
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(proxyErr.Message)),
		}
		resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
		resp.Header.Set("Content-Length", strconv.Itoa(len(proxyErr.Message)))
		if err := resp.Write(con); err != nil {
			mp.logger.Error("Failed to write error response: %v", err)
		}
	} else {
		mp.logger.Error("Connect error: %v", err)
		if _, writeErr := con.Write(internalServerError); writeErr != nil {
			mp.logger.Error("Failed to write error response: %v", writeErr)
		}
	}
}

// TLSHandshake implements the TLSHandshaker interface
func (mp *ServerMux) TLSHandshake(con net.Conn, hostName string) (*tls.Conn, error) {
	return mp.tlsHandshake(con, hostName)
}

// InspectingHTTPClient is an HTTPClient that records HTTP requests and responses
type InspectingHTTPClient struct {
	Client      HTTPClient
	RequestLog  []string
	ResponseLog []string
	BodyLog     []string
}

// NewInspectingHTTPClient creates a new InspectingHTTPClient
func NewInspectingHTTPClient(client HTTPClient) *InspectingHTTPClient {
	return &InspectingHTTPClient{
		Client:      client,
		RequestLog:  make([]string, 0),
		ResponseLog: make([]string, 0),
		BodyLog:     make([]string, 0),
	}
}

// Do executes an HTTP request and records the request and response
func (c *InspectingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Record the request contents
	c.RequestLog = append(c.RequestLog, req.Method+" "+req.URL.String())

	// Execute the request using the original client
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	// Record the response contents
	c.ResponseLog = append(c.ResponseLog, resp.Status)

	// Read and record the response body
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()

		// Record the body
		c.BodyLog = append(c.BodyLog, string(body))

		// Recreate the body and return it
		resp.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	return resp, nil
}
