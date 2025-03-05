package proxymitm

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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
			assert.Equal(t, tt.want, tt.err.Error(), "ProxyError.Error() should match expected value")

			got := tt.err.Unwrap()
			if tt.wantErr == nil {
				assert.Nil(t, got, "ProxyError.Unwrap() should be nil")
			} else {
				assert.NotNil(t, got, "ProxyError.Unwrap() should not be nil")
				assert.Equal(t, tt.wantErr.Error(), got.Error(), "Unwrapped error message should match")
			}
		})
	}
}

func TestNewProxyError(t *testing.T) {
	t.Parallel()
	originalErr := errors.New("test error")
	err := NewProxyError(ErrHijack, "test_op", "test message", originalErr)

	assert.Equal(t, ErrHijack, err.Type, "NewProxyError().Type should match")
	assert.Equal(t, "test_op", err.Op, "NewProxyError().Op should match")
	assert.Equal(t, "test message", err.Message, "NewProxyError().Message should match")
	assert.Equal(t, originalErr, err.Err, "NewProxyError().Err should match")

	errStr := err.Error()
	assert.Contains(t, errStr, string(ErrHijack), "Error string should contain error type")
	assert.Contains(t, errStr, "test_op", "Error string should contain operation")
	assert.Contains(t, errStr, "test error", "Error string should contain original error")
}

func TestProxyError_Is(t *testing.T) {
	t.Parallel()

	err1 := NewProxyError(ErrHijack, "op1", "message1", nil)
	err2 := NewProxyError(ErrHijack, "op2", "message2", nil)
	err3 := NewProxyError(ErrTLSHandshake, "op3", "message3", nil)

	// 同じTypeを持つエラーはIsでtrueを返す
	assert.True(t, errors.Is(err1, err2), "errors with same Type should match")

	// 異なるTypeを持つエラーはIsでfalseを返す
	assert.False(t, errors.Is(err1, err3), "errors with different Type should not match")

	// ラップされたエラーでもIsで検出できる
	wrappedErr := fmt.Errorf("wrapped: %w", err1)
	assert.True(t, errors.Is(wrappedErr, err2), "wrapped errors with same Type should match")
}

func TestIsErrorType(t *testing.T) {
	t.Parallel()

	err := NewProxyError(ErrHijack, "op", "message", nil)
	wrappedErr := fmt.Errorf("wrapped: %w", err)

	assert.True(t, IsErrorType(err, ErrHijack), "IsErrorType should return true for matching type")
	assert.False(t, IsErrorType(err, ErrTLSHandshake), "IsErrorType should return false for non-matching type")
	assert.True(t, IsErrorType(wrappedErr, ErrHijack), "IsErrorType should work with wrapped errors")
}

func TestGetProxyError(t *testing.T) {
	t.Parallel()

	originalErr := errors.New("original error")
	proxyErr := NewProxyError(ErrHijack, "op", "message", originalErr)
	wrappedErr := fmt.Errorf("wrapped: %w", proxyErr)
	plainErr := errors.New("plain error")

	// ProxyErrorからProxyErrorを取得
	got1 := GetProxyError(proxyErr)
	assert.NotNil(t, got1, "GetProxyError should return non-nil for ProxyError")
	assert.Equal(t, ErrHijack, got1.Type, "GetProxyError should return correct Type")

	// ラップされたエラーからProxyErrorを取得
	got2 := GetProxyError(wrappedErr)
	assert.NotNil(t, got2, "GetProxyError should return non-nil for wrapped ProxyError")
	assert.Equal(t, ErrHijack, got2.Type, "GetProxyError should return correct Type")

	// 通常のエラーからはnilを返す
	got3 := GetProxyError(plainErr)
	assert.Nil(t, got3, "GetProxyError should return nil for non-ProxyError")
}
