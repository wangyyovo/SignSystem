package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	pool := x509.NewCertPool()
	caCertPath := "./cfssl/ca.pem"
	caCrt, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	pool.AppendCertsFromPEM(caCrt)

	s := &http.Server{
		Addr: ":8889",
		Handler: &handler{},
		TLSConfig: &tls.Config{
			ClientCAs: pool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
	}

	err = s.ListenAndServeTLS("./cfssl/server.pem", "./cfssl/server-key.pem")
	if err != nil {
		fmt.Println(err.Error())
	}
}

type handler struct {}

func (h *handler)ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi, This is an example of http service in golang!\n")
}
