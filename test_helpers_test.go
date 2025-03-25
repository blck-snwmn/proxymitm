package proxymitm

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

// setupTestProxy creates a MitmProxy for testing purposes
func setupTestProxy(t testing.TB) *ServerMux {
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	require.NoError(t, err, "Should be able to create MitmProxy")
	return mp
}

// setupCertPool creates a certificate pool for testing TLS connections
func setupCertPool(mp *ServerMux) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(mp.x509Cert)
	return pool
}
