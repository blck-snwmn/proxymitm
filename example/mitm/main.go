package main

import (
	"log"
	"net/http"

	"github.com/blck-snwmn/proxymitm"
)

func main() {
	mp, err := proxymitm.CreateMitmProxy("./testdata/ca.crt", "./testdata/ca.key")
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
				mp.ServeHTTP(w, r)
				// proxy(w, r)
			} else {
				log.Println("bb")
			}
		}),
	}

	log.Println(server.ListenAndServe())
}
