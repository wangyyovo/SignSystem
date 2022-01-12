# Archived Copy

This is a clone of Azure's PKCS#12 implementation in Go, originally from
`github.com/Azure/go-pkcs12`. That project has since been retired, in favor of a PKCS#12
implementation from the Go project itself. However, the official version is read-only, whereas our
projects need to generate `.p12` files. So we have this (unmaintained, but functional) copy.

Original README content follows.



# Package pkcs12

[![GoDoc](https://godoc.org/github.com/Azure/go-pkcs12?status.svg)](https://godoc.org/github.com/Azure/go-pkcs12)

Package pkcs12 provides some Go implementations of PKCS#12.

This implementation is distilled from https://tools.ietf.org/html/rfc7292 and referenced documents.
It is intented for decoding P12/PFX-stored certificate+key for use with the crypto/tls package.

## Example

```go
p12, err := base64.StdEncoding.DecodeString(`base64-encoded-pfx-file`)
if err != nil {
	panic(err)
}

blocks, err := pkcs12.ConvertToPEM(p12, passwordBytes)
if err != nil {
	panic(err)
}
for i := 0; i < len(passwordBytes); i++ {
	passwordBytes[i] = 0 // clear password data after use
}

pemData := []byte{}
for _, b := range blocks {
	pemData = append(pemData, pem.EncodeToMemory(b)...)
}

// then use PEM data for tls to construct tls certificate:

cert, err := tls.X509KeyPair(pemData, pemData)
if err != nil {
	panic(err)
}

config := tls.Config{
	Certificates: []tls.Certificate{cert},
}

// use tls config for http client
```
