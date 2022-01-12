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

package main

import (
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"warden/pkg/playground-ca"
)

var config = struct {
	country            string
	locality           string
	province           string
	organization       string
	commonName         string
	signingKeyPassword string
	outputKeyPassword  string
	days               int
	bits               int
	apple              bool
	pkcs12             bool
	ssid               string
}{}

func scrubPath(f string) string {
	if f == "" {
		return ""
	}

	return f
}

func doFlags() {
	flag.StringVar(&config.country, "country", "US", "country code for the Subject")
	flag.StringVar(&config.locality, "locality", "Palo Alto", "locality (city) for the Subject")
	flag.StringVar(&config.province, "province", "CA", "state/provice for the Subject")
	flag.StringVar(&config.organization, "org", "Playground Global, LLC", "the organization name for the Subject")
	flag.StringVar(&config.commonName, "cn", "False Authority", "the Common Name (ultimate target) for the Subject")
	flag.StringVar(&config.signingKeyPassword, "rootpass", "whatever", "the password for the CA key (the one used to sign)")
	flag.StringVar(&config.outputKeyPassword, "pass", "whatever", "the password to encrypt the intermediate key (the one to be created)")
	flag.StringVar(&config.ssid, "ssid", "Playground Global", "the SSID to bind the configuration to (only useful with -apple)")
	flag.IntVar(&config.days, "days", 365, "validity period in days")
	flag.IntVar(&config.bits, "bits", 2048, "RSA key length in bits, must be either 2048 or 4096")
	flag.BoolVar(&config.apple, "apple", false, "write client cert in iOS/Mac format (.mobileconfig)")
	flag.BoolVar(&config.pkcs12, "pkcs12", false, "write client cert in PKCS12 format (.p12; Windows, Android)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Please run %s with one of these modes:\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s [options] client <signing_key> <signing_cert>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\tGenerates a client (machine) cert good for access to the indicated network, assigned to the indicated user\n\n")
		fmt.Fprintf(os.Stderr, "%s [options] server <signing_key> <signing_cert>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\tGenerates a server cert good for use by a TLS server (e.g. RADIUS, HTTPS, LDAP)\n")
		fmt.Fprintf(os.Stderr, "\tServer identity is specified via flags (especially -cn)\n\n")
		fmt.Fprintf(os.Stderr, "%s [options] intca <root_key> <root_cert> <intermediate_key> <intermediate_crt>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\tGenerates an intermediate CA cert\n\n")
		fmt.Fprintf(os.Stderr, "%s [options] rootca <root_key> <root_cert> [domain]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\tGenerates a root CA cert\n\n")
		fmt.Fprintf(os.Stderr, "options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()
}

func main() {
	doFlags()

	positionals := flag.Args()
	if len(positionals) < 3 {
		flag.Usage()
		os.Exit(255)
	}

	op := positionals[0]
	if op == "client" {
		doClient(positionals[1:])
	} else if op == "server" {
		doServer(positionals[1:])
	} else if op == "intca" {
		doICA(positionals[1:])
	} else if op == "rootca" {
		doRoot(positionals[1:])
	} else {
		flag.Usage()
		os.Exit(1)
	}
}

func doClient(args []string) {
	if len(args) != 2 {
		flag.Usage()
		os.Exit(1)
	}

	rootKeyPath := args[0]
	rootCertPath := args[1]

	a := &ca.Authority{}
	err := a.LoadFromPEM(rootCertPath, rootKeyPath, config.signingKeyPassword)
	if err != nil {
		log.Fatal("Cannot initialize Authority: ", err)
	}

	subject := &pkix.Name{
		Country:      []string{config.country},
		Locality:     []string{config.locality},
		Province:     []string{config.province},
		Organization: []string{config.organization},
		CommonName:   config.commonName,
	}
	c, err := a.CreateClientKeypair(config.days, subject, nil, config.bits)
	if err != nil {
		log.Fatal("Cannot create client cert: ", err)
	}

	if !config.apple && !config.pkcs12 {
		certBytes, keyBytes, err := c.ToPEM(config.outputKeyPassword, true)
		if err != nil {
			log.Fatal("could not generate cert and key: ", err)
		}

		certName := fmt.Sprintf("%s.crt", config.commonName)
		log.Printf("Writing certificate to '%s'...\n", certName)
		err = ioutil.WriteFile(certName, certBytes, 0600)
		if err != nil {
			log.Fatal("could not write certificate "+certName+": ", err)
		}

		keyName := fmt.Sprintf("%s.key", config.commonName)
		log.Printf("Writing private key to '%s'...\n", keyName)
		err = ioutil.WriteFile(keyName, keyBytes, 0600)
		if err != nil {
			log.Fatal("could not write private key: ", err)
		}
	} else {
		p12Bytes, err := c.ToPKCS12(config.outputKeyPassword, true)
		if err != nil {
			log.Fatal("could not generate pkcs12: ", err)
		}

		if config.pkcs12 {
			keyName := fmt.Sprintf("%s.p12", config.commonName)
			log.Printf("Writing PKCS12 cert and private key to '%s'...\n", keyName)
			err = ioutil.WriteFile(keyName, p12Bytes, 0600)
			if err != nil {
				log.Fatal("could not write private key: ", err)
			}
		} else {
			mcBytes, err := ca.PKCS12ToMobileConfig(p12Bytes, config.commonName, config.outputKeyPassword, "", config.organization)
			if err != nil {
				log.Fatal("error creating mobileconfig bytes: ", err)
			}

			keyName := fmt.Sprintf("%s.mobileconfig", config.commonName)
			log.Printf("Writing cert and private key to '%s'...\n", keyName)
			err = ioutil.WriteFile(keyName, mcBytes, 0600)
			if err != nil {
				log.Fatal("could not write private key: ", err)
			}
		}
	}
}

func doServer(args []string) {
	if len(args) != 2 {
		flag.Usage()
		os.Exit(1)
	}

	rootKeyPath := args[0]
	rootCertPath := args[1]

	a := &ca.Authority{}
	err := a.LoadFromPEM(rootCertPath, rootKeyPath, config.signingKeyPassword)
	if err != nil {
		log.Fatal("Cannot initialize Authority: ", err)
	}

	subject := &pkix.Name{
		Country:      []string{config.country},
		Locality:     []string{config.locality},
		Province:     []string{config.province},
		Organization: []string{config.organization},
		CommonName:   config.commonName,
	}
	c, err := a.CreateServerKeypair(config.days, subject, nil, config.bits)
	if err != nil {
		log.Fatal("Cannot create client cert: ", err)
	}

	certBytes, keyBytes, err := c.ToPEM(config.outputKeyPassword, true)
	if err != nil {
		log.Fatal("could not generate cert and key: ", err)
	}

	certName := fmt.Sprintf("%s.crt", config.commonName)
	log.Printf("Writing certificate to '%s'...\n", certName)
	err = ioutil.WriteFile(certName, certBytes, 0600)
	if err != nil {
		log.Fatal("could not write certificate "+certName+": ", err)
	}

	keyName := fmt.Sprintf("%s.key", config.commonName)
	log.Printf("Writing private key to '%s'...\n", keyName)
	err = ioutil.WriteFile(keyName, keyBytes, 0600)
	if err != nil {
		log.Fatal("could not write private key: ", err)
	}
}

func doICA(args []string) {
	if len(args) != 4 || config.country == "" || config.locality == "" || config.organization == "" || config.commonName == "" {
		flag.Usage()
		os.Exit(255)
	}

	rootKey := scrubPath(args[0])
	rootCert := scrubPath(args[1])
	intKey := scrubPath(args[2])
	intCert := scrubPath(args[3])

	if rootKey == "" || rootCert == "" || intKey == "" || intCert == "" {
		flag.Usage()
		os.Exit(254)
	}

	a := &ca.Authority{}
	err := a.LoadFromPEM(rootCert, rootKey, config.signingKeyPassword)
	if err != nil {
		log.Fatal("Cannot initialize Authority: ", err)
	}

	subj := &pkix.Name{
		Country:      []string{config.country},
		Locality:     []string{config.locality},
		Province:     []string{config.province},
		Organization: []string{config.organization},
		CommonName:   config.commonName,
	}
	ia, err := a.CreateIntermediateAuthority(config.days, subj, config.bits)
	if err != nil {
		log.Fatal("Cannot create intermediate cert: ", err)
	}

	intCertBytes, intKeyBytes, err := ia.ToPEM(config.outputKeyPassword, true)
	if err != nil {
		log.Fatal("could not generate cert and key: ", err)
	}

	log.Printf("Writing certificate to '%s'...\n", intCert)
	err = ioutil.WriteFile(intCert, intCertBytes, 0600)
	if err != nil {
		log.Fatal("could not write certificate: ", err)
	}

	log.Printf("Writing private key to '%s'...\n", intKey)
	err = ioutil.WriteFile(intKey, intKeyBytes, 0600)
	if err != nil {
		log.Fatal("could not write private key: ", err)
	}
}

func doRoot(args []string) {
	if len(args) < 2 || config.country == "" || config.locality == "" || config.organization == "" || config.commonName == "" {
		flag.Usage()
		os.Exit(255)
	}

	domain := ""
	if len(args) == 3 {
		domain = args[2]
	}

	rootKey := scrubPath(args[0])
	rootCert := scrubPath(args[1])

	if rootKey == "" || rootCert == "" {
		flag.Usage()
		os.Exit(254)
	}

	if config.days < 3650 {
		log.Printf("Your root CA validity period is less than 10 years.\n")
		log.Printf("Be sure this is your intention before using it.\n")
	}

	subj := &pkix.Name{
		Country:      []string{config.country},
		Locality:     []string{config.locality},
		Province:     []string{config.province},
		Organization: []string{config.organization},
		CommonName:   config.commonName,
	}
	a, err := ca.CreateRestrictedRootAuthority(config.days, subj, config.bits, domain)
	if err != nil {
		log.Fatal("Cannot create root cert: ", err)
	}

	certBytes, keyBytes, err := a.ToPEM(config.outputKeyPassword, true)
	if err != nil {
		log.Fatal("could not generate cert and key: ", err)
	}

	log.Printf("Writing certificate to '%s'...\n", rootCert)
	err = ioutil.WriteFile(rootCert, certBytes, 0600)
	if err != nil {
		log.Fatal("could not write certificate: ", err)
	}

	log.Printf("Writing private key to '%s'...\n", rootKey)
	err = ioutil.WriteFile(rootKey, keyBytes, 0600)
	if err != nil {
		log.Fatal("could not write private key: ", err)
	}
}
