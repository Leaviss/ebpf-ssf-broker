package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("recv %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		fmt.Fprintln(w, "hello from service-b")
	})

	log.Printf("service-b listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
