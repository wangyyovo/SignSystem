package main

import (
	"fmt"
	"net/http"
)
import httputil "warden/pkg/playground-apiclient"



func main() {
	api := &httputil.API{
		ClientCertFile: "client.pem",
		ClientKeyFile: "client-key.pem",
		ServerCertFile:"ca.pem",
		URLBase: "https://127.0.0.1:9000",
	}
	req := &struct{}{}
	res := &struct{}{}
	code, err := api.Call(httputil.URLJoin("/sign/playstore-app"), "GET", map[string]string{},req, res)
	if err != nil { /* handle network or I/O error */ }
	switch code {
	case http.StatusOK:
		fmt.Println(code)
	  /* ... */
	case http.StatusNotFound:
		fmt.Println(code)
	  /* ... */
	default:
		fmt.Println(code)
	  /* ... */
	}
}


