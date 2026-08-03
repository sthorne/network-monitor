// Command echoserver is a tiny HTTP server for manually exercising netmon:
// run it, point curl at it, and watch the flow appear.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from echoserver: %s %s\n", r.Method, r.URL.Path)
	})
	log.Printf("listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
