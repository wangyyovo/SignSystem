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

package warden

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"warden/pkg/playground-config"
	"warden/pkg/playground-httputil"
	"warden/pkg/playground-log"
)

/*
 * Configuration objects to pass to JSON
 */
type signerType struct {
	AuthorizedKeys []string
	Config         json.RawMessage
}

type configType struct {
	Port           int
	Debug          bool
	ServerCertFile string
	ServerKeyFile  string
	ServerLogFile  string
	SignersDir     string
	Handlers       map[string]map[string]*signerType
}

var cfg configType = configType{
	9000,
	false,
	"./server.crt",
	"./server.key",
	"./server.log",
	"./signers",
	make(map[string]map[string]*signerType),
}

/*
 * 2-level map that stores client certificate authorizations to specific signing endpoints, when
 * those endpoints specify an ACL/whitelist
 */
var authMap map[string]map[string]bool = make(map[string]map[string]bool)
var authRE *regexp.Regexp = regexp.MustCompile(`[^a-fA-F0-9]`)

func initConfig() {
	config.Load(&cfg)

	// make one pass over Handlers to populate references to the registry of SignFuncs in signfuncs packge
	for typ, instances := range cfg.Handlers {
		if typ == "custom" {
			continue
		}

		factory, ok := Registry[typ]
		if !ok {
			log.Warn("initConfig", "reference to unknown signfunc '"+typ+"'")
			continue
		}

		for k := range instances {
			handler := factory()
			cfg := handler.Config // force a shallow copy; this assumes Registry contains only struct values, not pointers
			SignFunc(k, cfg, handler.SignFunc)
		}
	}

	// make another pass to load up their configs
	for _, instances := range cfg.Handlers {
		for k, st := range instances {
			cobj, ok := signHandlers[k]
			if ok {
				if err := json.Unmarshal([]byte(st.Config), cobj.config); err != nil {
					log.Error("initConfig", "error unmarshaling SignFunc-specific config for '"+k+"'")
				}
				for _, pubkey := range st.AuthorizedKeys {
					canonKey := strings.ToLower(authRE.ReplaceAllString(pubkey, ""))
					if len(canonKey) != 64 {
						log.Warn("initConfig", "bogus public key fingerprint '"+pubkey+"'")
						continue
					}
					auths, ok := authMap[k]
					if !ok {
						auths = make(map[string]bool)
						authMap[k] = auths
					}
					authMap[k][canonKey] = true
				}
			} else {
				log.Warn("initConfig", "config provided for unregistered SignFunc '"+k+"'")
			}
		}
	}

	if cfg.ServerLogFile != "" {
		log.SetLogFile(cfg.ServerLogFile)
	}
	if config.Debug || cfg.Debug {
		log.SetLogLevel(log.LEVEL_DEBUG)
	}
}

func recoverAndError(writer http.ResponseWriter) {
	if r := recover(); r != nil {
		log.Warn("warden", "panic in handler", r)
		httputil.SendJSON(writer, http.StatusInternalServerError, struct{}{})
	}
}

/*
 * a structure to handle the final, configured list of active signing functions
 */
type signHandler struct {
	name    string
	config  interface{}
	handler func(config interface{}, req *SigningRequest) (int, string, []byte)
}

var signHandlers map[string]*signHandler = make(map[string]*signHandler)

// SignFunc registers a new signing function callback under the indicated URL endpoint path. This
// function emulates the http.HandleFunc model. Upon a client request to the URL path denoted in
// `name`, the handler function is invoked with a SigningRequest instance containing the payload to
// be signed and various metadata.
//
// The handler func returns a triple of HTTP response code, the content-type of the signed bytes to
// use in the HTTPS response, and the signed bytes (or a string containing an error message, for
// non-200-series response codes.)
func  SignFunc(name string, config interface{}, handler func(config interface{}, req *SigningRequest) (int, string, []byte)) {
	signHandlers[name] = &signHandler{name, config, handler}
}

// ListenAndServe starts a Warden server instance, which configures itself from the JSON config
// file. No pre-configuration in code is required, although code may optionally call SignFunc to add
// one or more custom signing functions.
func ListenAndServe() error {
	initConfig()

	if !cfg.Debug {
		defer func() {
			if r := recover(); r != nil {
				log.Error("warden", "panic on startup", r)
			}
		}()
	}

	sm := &SignerManager{cfg.SignersDir}

	http.HandleFunc("/signers", func(writer http.ResponseWriter, req *http.Request) {
		// GET /signers -- fetch a PEM file containing all authorized PEM public keys
		//   I: None
		//   O: application/x-pem-file
		//   200: success; cannot return other since you can't get this far w/o at least 1 working PEM
		// PUT /signers -- add a PEM file containing a cert to be authorized
		//   I: application/x-pem-file
		//   O: None
		//   200: success; 409 (conflict): (Subject, serial) tuple already exists
		// DELETE /signers -- remove a PEM file from the list of authorized signers
		//   I: {Serial: "", Subject: ""}
		//   O: None
		//   200: deleted; 404: specified PEM not found; 400 (bad request): bogus input
		// Non-GET/PUT/DELETE: 405 (bad method)
		defer recoverAndError(writer)

		switch req.Method {
		case "GET":
			buf := bytes.Buffer{}
			for _, s := range sm.GetSigners() {
				buf.Write(s.pem)
			}
			httputil.Send(writer, http.StatusOK, "application/x-pem-file", buf.Bytes())
		case "PUT":
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				httputil.SendJSON(writer, http.StatusBadRequest, struct{}{})
				return
			}
			err = sm.AddSigner(body)
			if err != nil {
				httputil.SendJSON(writer, http.StatusConflict, struct{}{})
				return
			}
			httputil.SendJSON(writer, http.StatusOK, struct{}{})
		case "DELETE":
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				httputil.SendJSON(writer, http.StatusBadRequest, struct{}{})
				return
			}
			err = sm.DeleteSigner(body)
			if err != nil {
				httputil.SendJSON(writer, http.StatusBadRequest, struct{}{})
				return
			}
			httputil.SendJSON(writer, http.StatusOK, struct{}{})
		default:
			httputil.SendJSON(writer, http.StatusMethodNotAllowed, struct{}{})
		}
	})

	http.HandleFunc("/sign/", func(writer http.ResponseWriter, req *http.Request) {
		// POST /sign/<fingerprint> -- request a binary be signed
		//   I: application/octet-stream
		//   O: whatever payload and content-type the signing callback returns
		//   200: signed data; 404: unrecognized config; 400: missing body
		// Non-POST: 405 (bad method)
		defer recoverAndError(writer)

		chunks := strings.Split(req.URL.Path, "/")
		if len(chunks) != 3 {
			log.Warn("main/sign/", "bogus URL '"+req.URL.Path+"'")
			httputil.SendJSON(writer, http.StatusBadRequest, struct{}{})
			return
		}

		name := chunks[2]
		handler, ok := signHandlers[name]
		if !ok {
			log.Warn("main/sign/", "unknown signer '"+name+"'")
			httputil.SendJSON(writer, http.StatusNotFound, struct{}{})
			return
		}

		log.Debug("main/sign/", "located handler for '"+name+"'")

		sreq, err := NewSigningRequestFrom(req)
		if err != nil {
			log.Warn("main/sign", "error constructing signing request", err)
			httputil.SendJSON(writer, http.StatusInternalServerError, struct{}{})
			return
		}

		log.Debug("main/sign", "client cert fingerprint", sreq.CertFingerprint)

		if auths, ok := authMap[name]; ok && len(auths) > 0 {
			if _, ok := auths[sreq.CertFingerprint]; !ok {
				log.Warn("main/sign", "unauthorized signing attempt by '"+sreq.CertFingerprint+"' to '"+req.URL.Path+"'")
				httputil.SendJSON(writer, http.StatusForbidden, struct{}{})
				return
			}
		}

		resCode, contentType, body := handler.handler(handler.config, sreq)

		if resCode < 300 {
			// log all successful signing operations
			log.Status("SIGNATURE",
				fmt.Sprintf("signed payload '%s' via '%s' for '%s' at '%s'",
					sreq.PayloadSHA256, name, sreq.CertSubject, sreq.When.UTC().Format("2006-01-02T15:04:05-0700")))
		}

		httputil.Send(writer, resCode, contentType, body)
	})

	http.HandleFunc("/", func(writer http.ResponseWriter, req *http.Request) {
		log.Warn("main/", "attempted access to unknown URL '"+req.URL.Path+"'")
		httputil.SendJSON(writer, http.StatusNotFound, struct{}{})
	})

	// now make an HTTPS server using the self-signed-ready tls.Config
	server := &http.Server{
		Addr: ":" + strconv.Itoa(cfg.Port),
		TLSConfig: &tls.Config{
			ClientAuth:            tls.RequireAnyClientCert,
			VerifyPeerCertificate: sm.VerifyPeerCallback,
		},
	}

	log.Status("warden", "starting HTTPS on port "+strconv.Itoa(cfg.Port))
	return server.ListenAndServeTLS(cfg.ServerCertFile, cfg.ServerKeyFile)
	//return server.ListenAndServe()
}
