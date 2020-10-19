package proxymitm

import (
	"bufio"
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

	"golang.org/x/xerrors"
)

var (
	internalServerError = []byte("HTTP/1.0 " + strconv.Itoa(http.StatusInternalServerError) + " \r\n\r\n")
)

// MitmProxy is proxy for mitm
type MitmProxy struct {
	tlsCert  tls.Certificate
	x509Cert *x509.Certificate
	client   *http.Client
}

// CreateMitmProxy load pem, and then it return MitmProxy
func CreateMitmProxy(certPath, keyPath string) (*MitmProxy, error) {
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
	return &MitmProxy{
		tlsCert:  tlsCert,
		x509Cert: x509Cert,
		client:   &http.Client{},
	}, nil
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

// Handler handle request for mitim
func (mp *MitmProxy) Handler(w http.ResponseWriter, r *http.Request) {
	// TCP コネクションの確立
	// Server 側とはコネクションを張らず、Client に 200 を返す
	con, err := mp.connectTCP(w)
	if err != nil {
		con.Write(internalServerError)
		log.Println(xerrors.Errorf("Failed to connect TCP: %w", err))
		return
	}
	defer con.Close()

	// Client との TLS ハンドシェイク
	tlsConn, err := mp.tlsHandshake(con, r.URL.Hostname())
	if err != nil {
		con.Write(internalServerError)
		log.Println(xerrors.Errorf("Failed to tls handshake: %w", err))
		return
	}
	defer tlsConn.Close()

	// データのやりとり
	// Clientのリクエストをサーバーへ送信
	req, err := mp.createRequest(tlsConn)
	if err != nil {
		tlsConn.Write(internalServerError)
		log.Println(xerrors.Errorf("Failed to create request: %w", err))
		return
	}
	// コンテキストも渡す
	req = req.WithContext(r.Context())

	rsp, err := mp.client.Do(req)
	if err != nil {
		tlsConn.Write(internalServerError)
		log.Println(xerrors.Errorf("Failed to send request: %w", err))
		return
	}
	defer rsp.Body.Close()

	// ResponseをClientに返す
	writer := io.MultiWriter(tlsConn, os.Stdout)
	rsp.Write(writer)

	log.Println("end")
}
func (mp *MitmProxy) connectTCP(w http.ResponseWriter) (net.Conn, error) {
	// TCP コネクションの確立
	// Server 側とはコネクションを張らず、Client に 200 を返す
	hjk, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("Not available http.Hijacker")
	}
	con, _, err := hjk.Hijack()
	if err != nil {
		return nil, err
	}

	//コネクションが張れたため、200 を返す
	// ハイジャックをしているため w.WriteHeader 使えない
	con.Write([]byte("HTTP/1.0 200 Connection established \r\n\r\n"))

	return con, nil
}

func (mp *MitmProxy) tlsHandshake(con net.Conn, hostName string) (*tls.Conn, error) {
	// 接続するドメインの証明書を作成する
	template := mitmx509template(hostName)
	c, pk, err := mp.createX509Certificate(template)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{c.Raw},
		PrivateKey:  pk,
	}

	config := tls.Config{}
	config.Certificates = []tls.Certificate{cert}

	tlsConn := tls.Server(con, &config)
	if err = tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (mp *MitmProxy) createX509Certificate(template *x509.Certificate) (*x509.Certificate, crypto.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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

func (mp *MitmProxy) createRequest(tlsConn *tls.Conn) (*http.Request, error) {
	creq, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		return nil, err
	}

	requestURL := "https://" + creq.Host + creq.RequestURI
	creq, err = http.NewRequest(creq.Method, requestURL, creq.Body)
	if err != nil {
		return nil, err
	}
	return creq, nil
}
