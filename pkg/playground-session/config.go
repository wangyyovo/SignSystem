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

package session

type OAuthConfig struct {
	Issuer           string
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	RedirectPath     string
	Scopes           []string
	AuthURL          string
	TokenExchangeURL string
	JWTPubKeyURL     string
	ValidEmailRegex  string
}

type ConfigType struct {
	SessionCookieKey string
	OAuth            OAuthConfig
}

var Config ConfigType = ConfigType{
	"X-Playground-Session",
	OAuthConfig{
		"accounts.example.com",
		"client_id_aka_audience",
		"client_secret",
		"http://localhost:9000/oauth",
		"/oauth",
		[]string{"openid", "email"},
		"https://oauth.example.com/auth",
		"https://oauth.example.com/token",
		"https://oauth.example.com/keys",
		".*",
	},
}
