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
	var handler http.HandlerFunc = proxy
	log.Println(http.ListenAndServe(":8090", handler))
}
