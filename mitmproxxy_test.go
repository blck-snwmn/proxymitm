package main

import (
	"crypto/x509"
	"testing"
)

func TestCreateMitmProxy(t *testing.T) {
	t.Run("failed, because load no exist file", func(t *testing.T) {
		_, err := CreateMitmProxy("", "")
		if err == nil {
			t.Error("no err. want error")
			return
		}
	})
	t.Run("failed, because load no pem file", func(t *testing.T) {
		_, err := CreateMitmProxy("./testdata/a.cert", "./testdata/ca.key")
		if err == nil {
			t.Error("no err. want error")
			return
		}
	})
	t.Run("create success", func(t *testing.T) {
		mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
		if err != nil {
			t.Errorf("CreateMitmProxy() error = %v", err)
			return
		}
		if len(mp.tlsCert.Certificate) == 0 {
			t.Error("mp.tlsCert have no Certificate")
			return
		}
		if mp.x509Cert == nil {
			t.Error("mp.x509Cert have no Certificate")
			return
		}
	})
}

func Test_createX509Certificate(t *testing.T) {
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
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		t.Errorf("create MitimProxy failed")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := mitmx509template(tt.args.hostName)
			c, _, err := mp.createX509Certificate(template)
			if (err != nil) != tt.wantErr {
				t.Errorf("createCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			roots := x509.NewCertPool()
			roots.AddCert(mp.x509Cert)
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

func TestMitmx509template(t *testing.T) {
	expected := "hostname"
	cert := mitmx509template(expected)
	if len(cert.DNSNames) != 1 {
		t.Error("DNSNames length isn't 1")
	}
	cn := false
	for _, n := range cert.DNSNames {
		if n == expected {
			cn = true
		}
	}
	if !cn {
		t.Errorf("DNSNames don't contain %s", expected)
	}
}
