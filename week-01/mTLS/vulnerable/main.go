package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
)

func hello(w http.ResponseWriter, r *http.Request) {
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	log.Printf("authenticated: %s  %s %s", cn, r.Method, r.URL.Path)
	fmt.Fprintln(w, "Hello World")
}

func main() {
	clientCAs := x509.NewCertPool()
	data, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatal("Cannot read byte data from ca.crt")
	}
	clientCAs.AppendCertsFromPEM(data)

	serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}

	tlsCfg := &tls.Config{
		ClientCAs:    clientCAs,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", hello)


	srv := http.Server{
		Addr: ":8081",
		Handler: mux,
		TLSConfig: tlsCfg,
	}

	log.Fatal(srv.ListenAndServeTLS("",""))
}

