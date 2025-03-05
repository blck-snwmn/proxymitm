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
	"time"
)

// LogLevel はログレベルを表します
type LogLevel int

const (
	// LogLevelDebug はデバッグレベルのログを表します
	LogLevelDebug LogLevel = iota
	// LogLevelInfo は情報レベルのログを表します
	LogLevelInfo
	// LogLevelWarn は警告レベルのログを表します
	LogLevelWarn
	// LogLevelError はエラーレベルのログを表します
	LogLevelError
)

// Logger はロギングインターフェースを定義します
type Logger interface {
	Debug(format string, v ...interface{})
	Info(format string, v ...interface{})
	Warn(format string, v ...interface{})
	Error(format string, v ...interface{})
}

// DefaultLogger はデフォルトのロガー実装です
type DefaultLogger struct {
	level LogLevel
}

// NewDefaultLogger は新しいデフォルトロガーを作成します
func NewDefaultLogger(level LogLevel) *DefaultLogger {
	return &DefaultLogger{
		level: level,
	}
}

// Debug はデバッグレベルのログを出力します
func (l *DefaultLogger) Debug(format string, v ...interface{}) {
	if l.level <= LogLevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Info は情報レベルのログを出力します
func (l *DefaultLogger) Info(format string, v ...interface{}) {
	if l.level <= LogLevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

// Warn は警告レベルのログを出力します
func (l *DefaultLogger) Warn(format string, v ...interface{}) {
	if l.level <= LogLevelWarn {
		log.Printf("[WARN] "+format, v...)
	}
}

// Error はエラーレベルのログを出力します
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

// RequestCreator はリクエストを作成するためのインターフェースです
type RequestCreator interface {
	CreateRequest(conn net.Conn) (*http.Request, error)
}

// TLSHandshaker はTLSハンドシェイクを行うためのインターフェースです
type TLSHandshaker interface {
	TLSHandshake(con net.Conn, hostName string) (*tls.Conn, error)
}

// デフォルトのタイムアウト値
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

// AddInterceptor はインターセプターを追加するメソッド
func (mp *ServerMux) AddInterceptor(interceptor HTTPInterceptor) {
	mp.interceptors = append(mp.interceptors, interceptor)
	mp.logger.Info("Added interceptor: %T", interceptor)
}

func (mp *ServerMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mp.logger.Info("Received request: %s %s", r.Method, r.URL.String())

	// TCP コネクションの確立
	con, err := mp.hijackConnection(w)
	if err != nil {
		mp.handleError(w, err)
		return
	}
	defer con.Close()

	switch r.Method {
	case http.MethodConnect:
		mp.logger.Debug("Handling CONNECT request for %s", r.URL.String())
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
	// コネクションのタイムアウト設定
	if err := con.SetDeadline(time.Now().Add(mp.readTimeout)); err != nil {
		return NewProxyError(ErrHijack, "set_deadline", "failed to set connection deadline", err)
	}

	mp.logger.Debug("Writing connection established for %s", r.URL.String())
	if err := mp.writeConnectionEstablished(con); err != nil {
		return err
	}

	// Client との TLS ハンドシェイク
	mp.logger.Debug("Starting TLS handshake with %s", r.URL.Hostname())
	tlsConn, err := mp.TLSHandshake(con, r.URL.Hostname())
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// TLSコネクションのタイムアウト設定
	if err := tlsConn.SetDeadline(time.Now().Add(mp.readTimeout)); err != nil {
		return NewProxyError(ErrTLSHandshake, "set_deadline", "failed to set TLS connection deadline", err)
	}

	// データのやりとり
	// Clientのリクエストをサーバーへ送信
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

	// リクエストボディがある場合は、必ず閉じるようにする
	if r.Body != nil {
		defer r.Body.Close()
	}

	mp.logger.Debug("Sending request to %s", req.URL.String())
	resp, err := mp.client.Do(req)
	if err != nil {
		return NewProxyError(ErrSendRequest, "do_request", "failed to send request", err)
	}
	defer resp.Body.Close()

	mp.logger.Debug("Writing response with status %d", resp.StatusCode)
	return mp.writeResponse(w, resp)
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

	// Copy body
	_, err := io.Copy(w, resp.Body)
	if err != nil {
		return NewProxyError(ErrSendRequest, "write_response", "failed to write response", err)
	}
	return nil
}

func (mp *ServerMux) forwardRequest(conn net.Conn, req *http.Request) error {
	// リクエストボディがある場合は、必ず閉じるようにする
	if req.Body != nil {
		defer req.Body.Close()
	}

	var err error
	skipRemaining := false

	// リクエストインターセプト処理
	for _, interceptor := range mp.interceptors {
		mp.logger.Debug("Applying request interceptor: %T", interceptor)
		if req, skipRemaining, err = interceptor.ProcessRequest(req); err != nil {
			mp.logger.Error("Interceptor error during request processing: %v", err)
			return NewProxyError(ErrSendRequest, "interceptor_request", "interceptor failed to process request", err)
		}
		if skipRemaining {
			mp.logger.Debug("Request processing interrupted by interceptor: %T", interceptor)
			break // 後続のインターセプターをスキップ
		}
	}

	mp.logger.Debug("Sending request to %s", req.URL.String())
	resp, err := mp.client.Do(req)
	if err != nil {
		return NewProxyError(ErrSendRequest, "do_request", "failed to send request", err)
	}
	defer resp.Body.Close()

	// レスポンスインターセプト処理
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
	// 自作の認証局の証明書の読み込み
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, NewProxyError(ErrCertificate, "load_cert", "failed to load certificate", err)
	}
	// 自作の認証局の証明書で署名された証明書を作成
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
	// 自作の認証局の証明書の読み込み
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	// 自作の認証局の証明書で署名された証明書を作成
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
	// 接続するドメインの証明書を作成する
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

// CreateRequest はRequestCreatorインターフェースの実装です
func (mp *ServerMux) CreateRequest(conn net.Conn) (*http.Request, error) {
	return mp.createRequest(conn)
}

// handleError は統一されたエラーハンドリングを提供します
func (mp *ServerMux) handleError(w http.ResponseWriter, err error) {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		mp.logger.Error("Proxy error: %v", proxyErr)
		http.Error(w, proxyErr.Message, http.StatusInternalServerError)
	} else {
		mp.logger.Error("Internal error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleConnectError はCONNECTメソッドのエラーハンドリングを提供します
func (mp *ServerMux) handleConnectError(con net.Conn, err error) {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		mp.logger.Error("Connect error: %v", proxyErr)
	} else {
		mp.logger.Error("Connect error: %v", err)
	}
	if _, writeErr := con.Write(internalServerError); writeErr != nil {
		mp.logger.Error("Failed to write error response: %v", writeErr)
	}
}

// TLSHandshake はTLSHandshakerインターフェースの実装です
func (mp *ServerMux) TLSHandshake(con net.Conn, hostName string) (*tls.Conn, error) {
	return mp.tlsHandshake(con, hostName)
}

// InspectingHTTPClient はHTTPリクエストとレスポンスを記録するHTTPClientです
type InspectingHTTPClient struct {
	Client      HTTPClient
	RequestLog  []string
	ResponseLog []string
	BodyLog     []string
}

// NewInspectingHTTPClient は新しいInspectingHTTPClientを作成します
func NewInspectingHTTPClient(client HTTPClient) *InspectingHTTPClient {
	return &InspectingHTTPClient{
		Client:      client,
		RequestLog:  make([]string, 0),
		ResponseLog: make([]string, 0),
		BodyLog:     make([]string, 0),
	}
}

// Do はHTTPリクエストを実行し、リクエストとレスポンスを記録します
func (c *InspectingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// リクエストの内容を記録
	c.RequestLog = append(c.RequestLog, req.Method+" "+req.URL.String())

	// 元のクライアントでリクエストを実行
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	// レスポンスの内容を記録
	c.ResponseLog = append(c.ResponseLog, resp.Status)

	// レスポンスボディを読み取り、記録
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()

		// ボディを記録
		c.BodyLog = append(c.BodyLog, string(body))

		// ボディを再作成して返す
		resp.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	return resp, nil
}
