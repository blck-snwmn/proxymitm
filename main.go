package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	server := &http.Server{
		Addr: ":18080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// curl 等で proxyの設定をして、アクセスすると
			// https の場合、`aa` を出力していることが分かる
			if r.Method == http.MethodConnect {
				fmt.Println("aa")
			} else {
				fmt.Println("bb")
			}
		}),
	}

	log.Fatal(server.ListenAndServe())
}
