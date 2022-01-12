package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	pool := x509.NewCertPool()
	caCertPath := "C:/Users/xxxx/Desktop/SignSystem/client/ca.pem"
	caCrt, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	pool.AppendCertsFromPEM(caCrt)

	cliCrt, err := tls.LoadX509KeyPair("C:/Users/xxxx/Desktop/SignSystem/client/client.pem", "C:/Users/xxxx/Desktop/SignSystem/client/client-key.pem")
	if err != nil {
		fmt.Println(err.Error())
		return
	}


	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
			Certificates: []tls.Certificate{cliCrt},
		},
	}

	client := &http.Client{Transport: tr}

	f,err := os.Open("C:/Users/xxxx/Desktop/android_debug-release.apk")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	req,err := http.NewRequest("POST","https://127.0.0.1:9000/sign/playstore-app",f)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	ioutil.WriteFile("C:/Users/xxxx/Desktop/android_debug-release-sign.apk",body,0644)

	//fmt.Println(string(body))
}
