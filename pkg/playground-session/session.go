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

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"sync"
	"time"

	"warden/pkg/playground-log"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

// Session represents a user agent. It can record cross-request session state data, and tracks
// authentication status with the upstream provider.
type Session struct {
	Email       string
	ID          string
	OriginalURL string

	extras            map[string]interface{}
	lock              *sync.RWMutex
	loginExpiration   time.Time
	oauthComplete     bool
	pendingLoginState string
	rawJWT            string
}

var sessionData map[string]*Session = make(map[string]*Session)
var mapLock sync.Mutex
var validEmailRegex *regexp.Regexp = regexp.MustCompile(Config.OAuth.ValidEmailRegex)
var jwtKeyMap map[string]string

// returns a randomly generated SHA256 hash
func randomHash() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%16x%16x%v", r.Int63(), r.Int63(), time.Now().UnixNano()))))
}

// struct containing config settings for the OAuth2 provider
var oauthConf *oauth2.Config

// NewSession constructs a new Session instance, with a unique ID. Also takes care of tracking and
// bookkeeping.
func NewSession() *Session {
	ssn := Session{}
	ssn.extras = make(map[string]interface{})
	ssn.lock = &sync.RWMutex{}

	newID := ""
	for newID == "" {
		newID = randomHash()
		if _, ok := sessionData[newID]; ok {
			log.Warn("session.NewSession", "curious cookie namespace collision on "+newID)
			newID = ""
			continue
		}
	}

	ssn.ID = newID

	mapLock.Lock()
	sessionData[ssn.ID] = &ssn
	mapLock.Unlock()

	return &ssn
}

// GetSession attempts to load the Session assigned to the client via HTTP cookie. Returns a
// freshly-created Session if the request doesn't already have one, or if it has a value for the
// cookie but we can't find a corresponding Session.
func GetSession(req *http.Request) *Session {
	c, err := req.Cookie(Config.SessionCookieKey)
	if err != nil {
		// this is simply the "not-found" case, so we don't log here.
		// Why this returns an error instead of returning nil *http.Cookie is a mystery.
		log.Debug("session.GetSession", "unset cookie, returning fresh session")
		return NewSession()
	}

	mapLock.Lock()
	ssn, ok := sessionData[c.Value]
	mapLock.Unlock()
	if !ok {
		log.Debug("session.GetSession", "unknown cookie '"+c.Value+"', returning fresh session")
		ssn = NewSession()
	}
	log.Debug("session.GetSession", "returning known session '"+ssn.ID+"'")
	return ssn
}

// IsLoggedIn returns true if and only if the session is currently associated with an active,
// logged-in OpenID Connect (i.e. OAuth2) account.
func (ssn *Session) IsLoggedIn() bool {
	return ssn.oauthComplete && ssn.loginExpiration.After(time.Now())
}

// GetExtra retrieves an arbitrary data value hung off this Session.
func (ssn *Session) GetExtra(key string) (interface{}, bool) {
	ssn.lock.RLock()
	val, ok := ssn.extras[key]
	ssn.lock.RUnlock()
	return val, ok
}

// PutExtra hangs an arbitrary value off this Session, as a convenient place for storing
// session-state data.
func (ssn *Session) PutExtra(key string, val interface{}) {
	ssn.lock.Lock()
	ssn.extras[key] = val
	ssn.lock.Unlock()
}

// Update links a Session with an HTTP client. Essentially this sets the cookie for the Session.
func (ssn *Session) Update(res http.ResponseWriter) {
	c := http.Cookie{
		Name:    Config.SessionCookieKey,
		Value:   ssn.ID,
		Path:    "/",
		Expires: time.Now().Add(24 * 365 * time.Hour),
	}
	http.SetCookie(res, &c)
}

// StartLogin kicks off the OAuth2/OpenID Connect login process by redirecting the client to the
// OAuth2 Provider URL specified in configuration. The expectation is:
// s := session.GetHandler(request)
// if !s.IsLoggedIn() {
//   s.StartLogin()
//   return
// }
func (ssn *Session) StartLogin(req *http.Request, res http.ResponseWriter) {
	ssn.Update(res)
	ssn.pendingLoginState = randomHash()
	ssn.OriginalURL = req.URL.String()
	loginPage := oauthConf.AuthCodeURL(ssn.pendingLoginState)
	http.Redirect(res, req, loginPage, http.StatusFound)
}

// CompleteLogin is intended to be called from the OAuth2 redirect handler, and handles the final
// steps of the OAuth2 flow by exchanging the auth code for the final token. It also extracts the
// JWT token from the request, validates it, and stores relevant data in the Session. If this
// method returns nil, subsequent calls to IsLoggedIn() will return true, until the JWT token expires.
func (ssn *Session) CompleteLogin(req *http.Request) error {
	// verify the anti-replay nonce is correct
	state := req.FormValue("state")
	if state != "" && state != ssn.pendingLoginState {
		log.Warn("session.CompleteLogin", "redirect lacks valid nonce")
		log.Warn("session.CompleteLogin", "('"+state+"' vs. '"+ssn.pendingLoginState+"')")
		return errors.New("invalid login nonce")
	}

	// make sure we actually got an auth code (i.e. not visiting us directly)
	code := req.FormValue("code")
	if code == "" {
		log.Warn("session.CompleteLogin", "redirect lacks auth code from upstream")
		return errors.New("invalid upstream auth code")
	}

	// exchange the auth code for the actual auth token
	token, err := oauthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Warn("session.CompleteLogin", "error in code/token exchange attempt", err)
		return err
	}

	// extract the JWT from the auth token, since we only care about the JWT as we don't access any
	// actual Google APIs
	ssn.rawJWT = token.Extra("id_token").(string)
	log.Debug("session.CompleteLogin", "raw jwt", ssn.rawJWT)
	tk, err := jwt.Parse(token.Extra("id_token").(string), func(t *jwt.Token) (interface{}, error) {
		log.Debug("session.CompleteLogin", "jwtKeyMap", jwtKeyMap)
		c, ok := jwtKeyMap[t.Header["kid"].(string)]
		log.Debug("session.CompleteLogin", "c is", c)
		log.Debug("session.CompleteLogin", "ok is", ok)
		if !ok {
			log.Error("parse", "unknown kid "+t.Header["kid"].(string))
			return nil, errors.New("signed by unknown kid " + t.Header["kid"].(string))
		}
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			// WARNING: do not remove! JWT is vulnerable to certain forms of replay or spoofing attack if
			// you don't verify that the algorithm used is what you expected
			log.Error("parse", "JWT signed by unexpected algorithm '"+t.Header["alg"].(string)+"'")
			return nil, errors.New("invalid JWT signature algorithm")
		}

		return jwt.ParseRSAPublicKeyFromPEM([]byte(c))
	})
	if err != nil || !tk.Valid {
		log.Warn("session.CompleteLogin", "error parsing JWT", err)
		return err
	}

	claims := tk.Claims.(jwt.MapClaims)

	// Verify claims in the JWT
	if claims["email"] == nil || claims["aud"] == nil ||
		claims["iss"] == nil || claims["exp"] == nil {
		log.Warn("session.CompleteLogin", "invalid JWT returned by server")
		return err
	}
	email := claims["email"].(string)
	aud := claims["aud"].(string)
	iss := claims["iss"].(string)
	exp := int64(claims["exp"].(float64))

	if iss != Config.OAuth.Issuer {
		// wrong issuer means someone could be replaying a login attempt from another provider
		log.Warn("session.CompleteLogin", "JWT contains invalid iss '"+iss+"'")
		log.Warn("session.CompleteLogin", "(expected 'accounts.google.com')")
		return errors.New("invalid iss")
	}
	if aud != Config.OAuth.ClientID {
		// wrong audience could be an attempted login w/ a phished account
		log.Warn("session.CompleteLogin", "JWT contains invalid aud '"+aud+"'")
		log.Warn("session.CompleteLogin", "(expected '"+Config.OAuth.ClientID+"')")
		return errors.New("invalid iss")
	}
	if !validEmailRegex.MatchString(email) {
		// this could just be that someone got on LAN and logged in with their @gmail.com
		log.Warn("session.CompleteLogin", "email '"+email+"' disallowed by regex")
		return errors.New("invalid email")
	}

	ssn.Email = email
	ssn.oauthComplete = true
	ssn.loginExpiration = time.Unix(exp, 0)

	log.Debug("session.CompleteLogin", "email '"+email+"' ('"+ssn.ID+"') successfully (re)authenticated")

	return nil
}

func Ready() {
	// spin up a thread to periodically reload the keys published by the auth provider to verify JWT
	// signatures (as these will generally be rotated at least daily)
	jwtKeyMap = make(map[string]string)
	go func() {
		ticker := time.Tick(1 * time.Hour)
		for {
			log.Debug("session.certs", "updating jwtKeyMap")

			res, err := http.Get(Config.OAuth.JWTPubKeyURL)
			if err == nil {
				dec := json.NewDecoder(res.Body)
				err = dec.Decode(&jwtKeyMap)
				log.Debug("session.certs", jwtKeyMap)

				res.Body.Close()
			} else {
				log.Warn("session.certs", "failure fetching JWT cert keys", err)
			}

			<-ticker
		}
	}()

	oauthConf = &oauth2.Config{
		ClientID:     Config.OAuth.ClientID,
		ClientSecret: Config.OAuth.ClientSecret,
		RedirectURL:  Config.OAuth.RedirectURL,
		Scopes:       Config.OAuth.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  Config.OAuth.AuthURL,
			TokenURL: Config.OAuth.TokenExchangeURL,
		},
	}
}
