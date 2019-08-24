package main

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
	"strconv"
	"time"
)

func proxy(w http.ResponseWriter, r *http.Request) {
	dest, err := net.Dial("tcp", r.RequestURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Fatal(err)
		return
	}
	hjk, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Not available http.Hijacker", http.StatusInternalServerError)
		return
	}
	con, _, err := hjk.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Fatal(err)
		return
	}
	//コネクションが張れたため、200 を返す
	// ハイジャックをしているため w.WriteHeader 使えない
	con.Write([]byte("HTTP/1.0 200 Connection established"))
	con.Write([]byte("\r\n\r\n"))

	go transfer(dest, con)
	go transfer(con, dest)
}

//dest -> drc へデータを渡す
func transfer(dest io.WriteCloser, src io.ReadCloser) {
	defer dest.Close()
	defer src.Close()
	io.Copy(dest, src)
}

func proxyWithMitm(w http.ResponseWriter, r *http.Request) {
	// TCP コネクションの確立
	// Server 側とはコネクションを張らず、Client に 200 を返す
	con, err := connectTCP(w)
	if err != nil {
		con.Write([]byte("HTTP/1.0 " + strconv.Itoa(http.StatusInternalServerError) + " \r\n\r\n"))
		log.Fatal(err)
		return
	}
	defer con.Close()

	// Client との TLS ハンドシェイク
	tlsConn, err := tlsHandshake(con, r.URL.Hostname())
	if err != nil {
		con.Write([]byte("HTTP/1.0 " + strconv.Itoa(http.StatusInternalServerError) + " \r\n\r\n"))
		log.Fatal(err)
		return
	}
	defer tlsConn.Close()

	// データのやりとり
	// Clientのリクエストをサーバーへ送信
	req, err := createRequest(tlsConn)
	if err != nil {
		tlsConn.Write([]byte("HTTP/1.0 " + strconv.Itoa(http.StatusInternalServerError) + " \r\n\r\n"))
		log.Fatal(err)
		return
	}

	client := &http.Client{}
	rsp, err := client.Do(req)
	if err != nil {
		tlsConn.Write([]byte("HTTP/1.0 " + strconv.Itoa(http.StatusInternalServerError) + " \r\n\r\n"))
		log.Fatal(err)
		return
	}
	defer rsp.Body.Close()

	// ResponseをClientに返す
	rsp.Write(tlsConn)

	log.Println("end")
}
func connectTCP(w http.ResponseWriter) (net.Conn, error) {
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
	con.Write([]byte("HTTP/1.0 200 Connection established"))
	con.Write([]byte("\r\n\r\n"))

	return con, nil
}

func tlsHandshake(con net.Conn, hostName string) (*tls.Conn, error) {
	// 接続するドメインの証明書を作成する
	c, pk, err := createCert(hostName)
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

func createCert(hostName string) (*x509.Certificate, crypto.PrivateKey, error) {
	// 自作の認証局の証明書の読み込み
	cert, err := tls.LoadX509KeyPair("./ca.crt", "./ca.key")
	if err != nil {
		return nil, nil, err
	}
	// 自作の認証局の証明書で署名された証明書を作成
	parent, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		DNSNames:     []string{hostName},
		NotBefore:    now,
		NotAfter:     now.AddDate(1, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	cb, err := x509.CreateCertificate(
		rand.Reader,
		template, parent,
		pub, cert.PrivateKey,
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

func createRequest(tlsConn *tls.Conn) (*http.Request, error) {
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

func main() {
	server := &http.Server{
		Addr: ":18080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// curl 等で proxyの設定をして、アクセスすると
			// https の場合、`aa` を出力していることが分かる
			if r.Method == http.MethodConnect {
				log.Println("aa")
				proxyWithMitm(w, r)
				// proxy(w, r)
			} else {
				log.Println("bb")
			}
		}),
	}

	log.Println(server.ListenAndServe())
}
