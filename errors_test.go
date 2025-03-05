package proxymitm

import (
	"errors"
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
