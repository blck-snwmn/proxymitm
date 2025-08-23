package proxymitm

import (
	"errors"
	"fmt"
)

// ErrorType represents the type of proxy error
type ErrorType string

const (
	// ErrHijack is an error that occurs when HTTP connection hijacking fails
	ErrHijack ErrorType = "hijack"
	// ErrTLSHandshake is an error that occurs when TLS handshake fails
	ErrTLSHandshake ErrorType = "tls_handshake"
	// ErrCreateRequest is an error that occurs when request creation fails
	ErrCreateRequest ErrorType = "create_request"
	// ErrSendRequest is an error that occurs when request sending fails
	ErrSendRequest ErrorType = "send_request"
	// ErrCertificate is an error that occurs when certificate-related processing fails
	ErrCertificate ErrorType = "certificate"
	// ErrGateway is an error that occurs when the proxy cannot reach the upstream server (502 Bad Gateway)
	ErrGateway ErrorType = "gateway"
	// ErrTimeout is an error that occurs when the upstream server doesn't respond in time (504 Gateway Timeout)
	ErrTimeout ErrorType = "timeout"
)

// ProxyError represents an error that occurs during proxy processing
type ProxyError struct {
	Type    ErrorType // Type of error
	Op      string    // Operation where the error occurred
	Message string    // Error message
	Err     error     // Original error
}

// Error implements the error interface
func (e *ProxyError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Op, e.Err)
	}
	return fmt.Sprintf("%s: %s: %s", e.Type, e.Op, e.Message)
}

// Unwrap returns the original error
func (e *ProxyError) Unwrap() error {
	return e.Err
}

// Is is a method used for errors.Is
// It allows comparison with ProxyErrors that have the same error type
func (e *ProxyError) Is(target error) bool {
	t, ok := target.(*ProxyError)
	if !ok {
		return false
	}
	return e.Type == t.Type
}

// NewProxyError creates a new ProxyError
func NewProxyError(typ ErrorType, op string, message string, err error) *ProxyError {
	return &ProxyError{
		Type:    typ,
		Op:      op,
		Message: message,
		Err:     err,
	}
}

// IsErrorType determines if the specified error is a ProxyError with a specific ErrorType
func IsErrorType(err error, typ ErrorType) bool {
	target := &ProxyError{Type: typ}
	return errors.Is(err, target)
}

// GetProxyError retrieves a ProxyError from an error
// Returns nil if not a ProxyError
func GetProxyError(err error) *ProxyError {
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		return proxyErr
	}
	return nil
}
