package proxymitm

import (
	"errors"
	"strings"
	"testing"
)

func TestProxyError_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		err     *ProxyError
		want    string
		wantErr error
	}{
		{
			name: "with wrapped error",
			err: &ProxyError{
				Type:    ErrHijack,
				Op:      "test_operation",
				Message: "test message",
				Err:     errors.New("original error"),
			},
			want:    "hijack: test_operation: original error",
			wantErr: errors.New("original error"),
		},
		{
			name: "without wrapped error",
			err: &ProxyError{
				Type:    ErrTLSHandshake,
				Op:      "test_operation",
				Message: "test message",
			},
			want:    "tls_handshake: test_operation: test message",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("ProxyError.Error() = %v, want %v", got, tt.want)
			}
			if got := tt.err.Unwrap(); (got != nil && tt.wantErr == nil) || (got == nil && tt.wantErr != nil) {
				t.Errorf("ProxyError.Unwrap() = %v, want %v", got, tt.wantErr)
			}
		})
	}
}

func TestNewProxyError(t *testing.T) {
	t.Parallel()
	originalErr := errors.New("test error")
	err := NewProxyError(ErrHijack, "test_op", "test message", originalErr)

	if err.Type != ErrHijack {
		t.Errorf("NewProxyError().Type = %v, want %v", err.Type, ErrHijack)
	}
	if err.Op != "test_op" {
		t.Errorf("NewProxyError().Op = %v, want %v", err.Op, "test_op")
	}
	if err.Message != "test message" {
		t.Errorf("NewProxyError().Message = %v, want %v", err.Message, "test message")
	}
	if err.Err != originalErr {
		t.Errorf("NewProxyError().Err = %v, want %v", err.Err, originalErr)
	}

	errStr := err.Error()
	if !strings.Contains(errStr, string(ErrHijack)) || !strings.Contains(errStr, "test_op") || !strings.Contains(errStr, "test error") {
		t.Errorf("NewProxyError().Error() = %v, want to contain type, op and error", errStr)
	}
}
