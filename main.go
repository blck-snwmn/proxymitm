package main

import (
	"io"
	"log"
	"net"
	"net/http"
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

func main() {
	mp, err := CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		log.Fatal(err)
		return
	}
	server := &http.Server{
		Addr: ":18080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// curl 等で proxyの設定をして、アクセスすると
			// https の場合、`aa` を出力していることが分かる
			if r.Method == http.MethodConnect {
				log.Println("aa")
				mp.Handler(w, r)
				// proxy(w, r)
			} else {
				log.Println("bb")
			}
		}),
	}

	log.Println(server.ListenAndServe())
}
