// Copyright © 2018 Playground Global, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ca implements a Certificate Authority, useful for creating CA and client certs.
package ca

import "errors"
import "io/ioutil"
import "time"

import "crypto/rsa"
import "crypto/rand"
import "crypto/sha256"
import "crypto/x509"
import "warden/pkg/go-pkcs12"
import "crypto/x509/pkix"
import "encoding/hex"
import "encoding/pem"
import "math/big"


// Template represents the meta-data of a certificate, such as expiration, serial number, etc.
type Template x509.Certificate

// GenerateSerial tells a Template to populate its serial number as a randomly-generated 128-bit
// integer.
func (t *Template) GenerateSerial() error {
	ceiling := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, ceiling)
	if err != nil {
		return err
	}
	t.SerialNumber = serial
	return nil
}

// Keypair represents a generated certificate, with private key and public key (i.e. certificate.)
type Keypair struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	rawCert []byte
	parent  *Keypair
}

func (kp *Keypair) GetValidityPeriod() (string, string) {
	return kp.cert.NotBefore.UTC().Format(time.RFC3339), kp.cert.NotAfter.UTC().Format(time.RFC3339)
}

// LoadFromPEM populates a Keypair's data and metadata from existing PEM data.
func (kp *Keypair) LoadFromPEM(certFile string, keyFile string, password string) error {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}
	block, certBytes := pem.Decode(certBytes)
	if block == nil {
		return errors.New("authority: cannot decode root PEM data")
	}
	kp.cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	kp.rawCert = block.Bytes

	cur := kp
	for {
		block, certBytes = pem.Decode(certBytes)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			cur.parent = &Keypair{
				cert:    cert,
				rawCert: block.Bytes,
			}
			cur = cur.parent
		}
	}

	block, keyBytes = pem.Decode(keyBytes)
	if block == nil {
		return errors.New("authority: cannot decode root key PEM data")
	}
	if x509.IsEncryptedPEMBlock(block) {
		decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return err
		}
		block.Bytes = decrypted
	}
	kp.key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	for i := range block.Bytes {
		block.Bytes[i] = 0
	}
	if err != nil {
		return err
	}

	return nil
}

// ToPEM returns the keypair's certificate and private key as PEM bytes. The order is private key,
// public key, error. The private key is encrypted password using the provided password.
func (kp *Keypair) ToPEM(password string, includeCertChain bool) ([]byte, []byte, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kp.rawCert})

	if includeCertChain {
		for p := kp.parent; p != nil; p = p.parent {
			x := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.rawCert})
			certPEM = append(certPEM, x...)
		}
	}

	pkey := x509.MarshalPKCS1PrivateKey(kp.key)
	var pkblock *pem.Block
	var err error
	if password != "" {
		pkblock, err = x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", pkey, []byte(password), x509.PEMCipherDES)
		for i := range pkey {
			pkey[i] = 0
		}
		if err != nil {
			return nil, nil, err
		}
	} else {
		pkblock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkey}
	}
	keyPEM := pem.EncodeToMemory(pkblock)

	return certPEM, keyPEM, nil
}

// ToPKCS12 generates a single PKCS12 file containing both private key and certificate.
func (kp *Keypair) ToPKCS12(password string, includeCertChain bool) ([]byte, error) {
	var caList [][]byte = nil

	if includeCertChain {
		caList = make([][]byte, 0)
		for p := kp.parent; p != nil; p = p.parent {
			caList = append(caList, p.rawCert)
		}
	}

	pkey := x509.MarshalPKCS1PrivateKey(kp.key)

	p12, err := pkcs12.Create(kp.rawCert, pkey, []byte(password), caList)
	for i := range pkey {
		pkey[i] = 0
	}
	if err != nil {
		return nil, err
	}

	return p12, nil
}

func (kp *Keypair) CertFingerprint() (string, error) {
	if kp == nil || kp.cert == nil || kp.cert.Raw == nil {
		return "", errors.New("no certificate available")
	}
	b := sha256.Sum256(kp.cert.Raw)
	return hex.EncodeToString(b[:]), nil
}

// Authority represents a CA, meaning that it is a certificate configured as a CA cert that may sign
// other certificates.
type Authority struct {
	Keypair
}

// Authority generates a new random private key and public key, and then signs the public key as a
// certificate using the metadata of the provided Template.
func (a *Authority) GenerateKeypair(t *Template, bits int) (*Keypair, error) {
	if t.SerialNumber == nil {
		err := t.GenerateSerial()
		if err != nil {
			return nil, err
		}
	}

	switch bits {
	case 2048:
	case 4096:
	default:
		return nil, errors.New("invalid RSA bit length, must be 2048 or 4096")
	}

	var err error
	kp := &Keypair{}
	kp.key, err = rsa.GenerateKey(rand.Reader, int(bits))
	if err != nil {
		return nil, err
	}

	kp.rawCert, err = x509.CreateCertificate(rand.Reader, (*x509.Certificate)(t), a.cert, &kp.key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}

	kp.cert, err = x509.ParseCertificate(kp.rawCert)
	if err != nil {
		return nil, err
	}

	kp.parent = &a.Keypair

	return kp, nil
}

// CreateRootAuthority generates a new root CA Authority and self-signed certificate and key, from
// the provided template. The certificate is not saved to disk.
func CreateRootAuthority(days int, subj *pkix.Name, bits int) (*Authority, error) {
	return CreateRestrictedRootAuthority(days, subj, bits, "")
}

// CreateRestrictedRootAuthority generates a new root CA Authority and self-signed certificate and
// key, restricted to the indicated domain, from the provided template. The certificate is not saved
// to disk.
func CreateRestrictedRootAuthority(days int, subj *pkix.Name, bits int, domain string) (*Authority, error) {
	now := time.Now()
	t := &Template{
		Subject:               *subj,
		NotBefore:             now.Add(-(24 * time.Hour)),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		CRLDistributionPoints: []string{""},
		BasicConstraintsValid: true,
		IsCA:       true,
		MaxPathLen: 1,
	}
	err := t.GenerateSerial()
	if err != nil {
		return nil, err
	}

	if domain != "" {
		t.PermittedDNSDomainsCritical = true
		t.PermittedDNSDomains = []string{domain}
	}

	switch bits {
	case 2048:
	case 4096:
	default:
		return nil, errors.New("invalid RSA bit length, must be 2048 or 4096")
	}

	a := &Authority{}
	a.key, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	a.rawCert, err = x509.CreateCertificate(rand.Reader, (*x509.Certificate)(t), (*x509.Certificate)(t), &a.key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}

	a.cert, err = x509.ParseCertificate(a.rawCert)
	if err != nil {
		return nil, err
	}

	a.parent = nil

	return a, nil
}

// ExportCertChain produces a bottom-up sequence of PEM blocks encoding the (signed)
// certificates of a CA tree.
func (a *Authority) ExportCertChain() []byte {
	data := make([]byte, 0)

	for p := &((*a).Keypair); p != nil; p = p.parent {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.rawCert})
		data = append(data, certPEM...)
	}

	return data
}

// CreateIntermediateAuthority generates an intermediate signing certificate. The intent is that the
// top-level root key is loaded as an Authority instance, and then this method is called to produce
// one or more intermediate signing certificates, as an aid for typical good CA management practices.
// Note: this is currently not well tested.
func (a *Authority) CreateIntermediateAuthority(days int, subj *pkix.Name, bits int) (*Authority, error) {
	now := time.Now()
	t := &Template{
		Subject:               *subj,
		NotBefore:             now.Add(-(24 * time.Hour)),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		CRLDistributionPoints: []string{"https://ca.playground.global/ca.crl"},
		BasicConstraintsValid: true,
		IsCA:       true,
		MaxPathLen: 1,
	}
	err := t.GenerateSerial()
	if err != nil {
		return nil, err
	}

	kp, err := a.GenerateKeypair(t, bits)
	if err != nil {
		return nil, err
	}

	ia := &Authority{Keypair: *kp}

	return ia, nil
}

func basicTemplate(subject *pkix.Name, days int, serial *big.Int) (*Template, error) {
	now := time.Now()
	t := &Template{
		Subject:               *subject,
		NotBefore:             now.Add(-(24 * time.Hour)),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		CRLDistributionPoints: []string{"https://ca.playground.global/ca.crl"},
	}
	if serial != nil {
		t.SerialNumber = serial
	} else {
		err := t.GenerateSerial()
		if err != nil {
			return nil, err
		}
	}
	return t, nil
}

// CreateClientKeypair generates a keypair from scratch using the provided constraints. The
// resulting certificate will be configured as a client (non-signing) certificate.
func (a *Authority) CreateClientKeypair(days int, subject *pkix.Name, serial *big.Int, bits int) (*Keypair, error) {
	t, err := basicTemplate(subject, days, serial)
	if err != nil {
		return nil, err
	}

	t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	kp, err := a.GenerateKeypair(t, bits)
	if err != nil {
		return nil, err
	}

	return kp, nil
}

// CreateServerKeypair generates a keypair from scratch, suitable for use as a server identifying
// key. That is, this could be used for an HTTPS or LDAPS server, etc.
func (a *Authority) CreateServerKeypair(days int, subject *pkix.Name, serial *big.Int, bits int) (*Keypair, error) {
	t, err := basicTemplate(subject, days, serial)
	if err != nil {
		return nil, err
	}

	t.DNSNames = []string{subject.CommonName}
	t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	kp, err := a.GenerateKeypair(t, bits)
	if err != nil {
		return nil, err
	}

	return kp, nil
}
