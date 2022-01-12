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

package apiclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"warden/pkg/playground-log"
)

// URLJoin safely constructs a URL from the provided components. "Safely" means that it properly
// handles duplicate / characters, etc. That is, URLJoin("/foo/", "bar") is equivalent to
// URLJoin("/foo/", "/bar"), etc.
func URLJoin(base string, elements ...string) string {
	u, err := url.Parse(base)
	if err != nil {
		log.Error("httputil.URLJoin", fmt.Sprintf("base URL '%s' does not parse", base), err)
		panic(err)
	}
	scrubbed := []string{}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path != "" {
		scrubbed = append(scrubbed, u.Path)
	}
	for _, s := range elements {
		s = strings.Trim(s, "/")
		if s != "" {
			scrubbed = append(scrubbed, s)
		}
	}
	u.Path = strings.Join(scrubbed, "/")
	return u.String()
}

// API represents a client to an API server. It simply encapsulates common initialization and usage
// code to minimize boilerplate in code that must call into an API server.
//
// api := &httputil.API{ /* server URL base values here */ }
// req := &uploadType{}
// res := &responseType{}
// code, err := api.Call(httputil.URLJoin("/api/endpoint", entityID), "GET", req, res)
// if err != nil { /* handle network or I/O error */ }
// switch code {
// case http.StatusOK:
//   /* ... */
// case http.StatusNotFound:
//   /* ... */
// default:
//   /* ... */
// }
//
// The request and response pointers are optional and will be ignored if nil.
type API struct {
	Header         string
	Value          string
	URLBase        string
	ClientCertFile string
	ClientKeyFile  string
	ServerCertFile string
	Headers        map[string][]string

	client *http.Client
}

// Generally we only want to transmit requests to the API server instance we trust, which we want
// to authenticate by its server certificate. So this function creates an HTTPS client instance
// configured such that its root CA list contains only our trusted server cert. It follows, then,
// that that server cert must be self-signed.
func (api *API) initHTTPSClient() {
	tlsConfig := &tls.Config{}

	if api.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(api.ClientCertFile, api.ClientKeyFile)
		if err != nil {
			panic(err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		//tlsConfig.BuildNameToCertificate()
	}

	if api.ServerCertFile != "" {
		serverCert, err := ioutil.ReadFile(api.ServerCertFile)
		if err != nil {
			panic(err)
		}
		serverRoot := x509.NewCertPool()
		serverRoot.AppendCertsFromPEM(serverCert)
		tlsConfig.RootCAs = serverRoot
	}

	api.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

// Call is a convenience wrapper specifically around API calls. It handles setting the
// shared-secret header for authentication to the remote server, automatically constructs a final
// URL using the server/scheme specified in the server's config file, etc. Returns the HTTP status
// code, or the underlying error if not nil.
func (api *API) Call(endpoint string, method string, query map[string]string, sendObj interface{}, recvObj interface{}) (int, error) {
	TAG := "API.Call"

	if api.client == nil {
		api.initHTTPSClient()
	}

	body, err := json.Marshal(sendObj)
	if err != nil {
		log.Error(TAG, "trivial Request failed to marshal", err)
		return -1, err
	}

	req, err := http.NewRequest(method, URLJoin(api.URLBase, endpoint), bytes.NewReader(body))
	if err != nil {
		return -1, err
	}
	if _, ok := api.Headers["Content-Type"]; !ok {
		req.Header.Add("Content-Type", "application/json")
	}
	if api.Header != "" && api.Value != "" {
		req.Header.Add(api.Header, api.Value)
	}
	if api.Headers != nil {
		for k, vs := range api.Headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}

	if query != nil {
		q := req.URL.Query()
		for k, v := range query {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	res, err := api.client.Do(req)
	if err != nil {
		return -1, err
	}

	log.Debug(TAG, fmt.Sprintf("%s %s", method, req.URL.Path), string(body))

	if recvObj != nil {
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			log.Error(TAG, "low-level I/O error reading HTTP response body", err)
			return -1, err
		}
		log.Debug("Call", string(body))
		b, ok := recvObj.(*[]byte)
		if ok {
			*b = make([]byte, len(body))
			copy(*b, body)
		} else {
			err = json.Unmarshal(body, recvObj)
			if err != nil {
				log.Error(TAG, "parse error unmarshaling HTTP response JSON", err)
				return -1, err
			}
		}
	}

	return res.StatusCode, nil
}
