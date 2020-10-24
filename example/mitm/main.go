package main

import (
	"log"

	"github.com/blck-snwmn/proxymitm"
)

func main() {
	server, err := proxymitm.New("./testdata/ca.crt", "./testdata/ca.key")
	if err != nil {
		log.Fatal(err)
		return
	}
	server.Addr = ":18080"
	log.Println(server.ListenAndServe())
}
