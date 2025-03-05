package proxymitm

import (
	"errors"
	"fmt"
)

// ErrorType はプロキシエラーの種別を表す型です
type ErrorType string

const (
	// ErrHijack はHTTP接続のハイジャックに失敗した場合のエラーです
	ErrHijack ErrorType = "hijack"
	// ErrTLSHandshake はTLSハンドシェイクに失敗した場合のエラーです
	ErrTLSHandshake ErrorType = "tls_handshake"
	// ErrCreateRequest はリクエストの作成に失敗した場合のエラーです
	ErrCreateRequest ErrorType = "create_request"
	// ErrSendRequest はリクエストの送信に失敗した場合のエラーです
	ErrSendRequest ErrorType = "send_request"
	// ErrCertificate は証明書関連の処理に失敗した場合のエラーです
	ErrCertificate ErrorType = "certificate"
)

// ProxyError はプロキシ処理中のエラーを表す型です
type ProxyError struct {
	Type    ErrorType // エラーの種別
	Op      string    // エラーが発生した操作
	Message string    // エラーメッセージ
	Err     error     // 元のエラー
}

// Error はerrorインターフェースを実装します
func (e *ProxyError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Op, e.Err)
	}
	return fmt.Sprintf("%s: %s: %s", e.Type, e.Op, e.Message)
}

// Unwrap は元のエラーを返します
func (e *ProxyError) Unwrap() error {
	return e.Err
}

// Is はerrors.Isで使用するためのメソッドです
// 同じエラータイプを持つProxyErrorと比較できるようにします
func (e *ProxyError) Is(target error) bool {
	t, ok := target.(*ProxyError)
	if !ok {
		return false
	}
	return e.Type == t.Type
}

// NewProxyError は新しいProxyErrorを作成します
func NewProxyError(typ ErrorType, op string, message string, err error) *ProxyError {
	return &ProxyError{
		Type:    typ,
		Op:      op,
		Message: message,
		Err:     err,
	}
}

// IsErrorType は指定されたエラーが特定のErrorTypeを持つProxyErrorかどうかを判定します
func IsErrorType(err error, typ ErrorType) bool {
	target := &ProxyError{Type: typ}
	return errors.Is(err, target)
}

// GetProxyError はエラーからProxyErrorを取得します
// ProxyErrorでない場合はnilを返します
func GetProxyError(err error) *ProxyError {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		return proxyErr
	}
	return nil
}
