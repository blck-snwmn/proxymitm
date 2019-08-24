package main

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func Test_createCert(t *testing.T) {
	type args struct {
		hostName string
	}
	tests := []struct {
		name string
		args args
		// want    []byte
		wantErr bool
	}{
		{name: "create cert localhost", args: args{hostName: "localhost"}, wantErr: false},
		{name: "create cert other", args: args{hostName: "www.google.com"}, wantErr: false},
	}
	tCert, err := tls.LoadX509KeyPair("./ca.crt", "./ca.key")
	if err != nil {
		t.Errorf("tls.LoadX509KeyPair failed")
	}
	pCert, err := x509.ParseCertificate(tCert.Certificate[0])
	if err != nil {
		t.Errorf("x509.ParseCertificate failed")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, err := createCert(tt.args.hostName)
			if (err != nil) != tt.wantErr {
				t.Errorf("createCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			roots := x509.NewCertPool()
			roots.AddCert(pCert)
			vop := x509.VerifyOptions{
				DNSName: tt.args.hostName,
				Roots:   roots,
			}
			if _, err = c.Verify(vop); err != nil {
				t.Errorf("Verify failed error = %v", err)
			}
		})
	}
}
