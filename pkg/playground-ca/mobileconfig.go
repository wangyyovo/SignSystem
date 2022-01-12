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

package ca

import "bytes"

import "crypto/sha1"
import "text/template"
import "encoding/hex"
import "encoding/base64"

var mobileConfigTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>{{.FileName}}</string>
      <key>PayloadContent</key>
      <data>
{{.P12Data}}
      </data>
      <key>PayloadDescription</key>
      <string>Configures certificate settings.</string>
      <key>PayloadDisplayName</key>
      <string>{{.IdentBase}}</string>
      <key>PayloadIdentifier</key>
      <string>{{.IdentBase}}.pkcs12</string>
      <key>PayloadType</key>
      <string>com.apple.security.pkcs12</string>
      <key>PayloadUUID</key>
      <string>{{.UUIDBase}}.pkcs12</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Password</key>
      <string>{{.Password}}</string>
    </dict>
    <dict>
      <key>AutoJoin</key>
      <true/>
      <key>EAPClientConfiguration</key>
      <dict>
        <key>AcceptEAPTypes</key>
        <array>
          <integer>13</integer>
        </array>
      </dict>
      <key>PayloadCertificateUUID</key>
      <string>{{.UUIDBase}}.pkcs12</string>
      <key>PayloadDescription</key>
      <string>Configures 802.1x Credentials</string>
      <key>PayloadDisplayName</key>
      <string>{{.Organization}} 802.1x config</string>
      <key>PayloadIdentifier</key>
      <string>{{.IdentBase}}.eth</string>
      <key>PayloadType</key>
      <string>com.apple.firstactiveethernet.managed</string>
      <key>PayloadUUID</key>
      <string>{{.UUIDBase}}.eth</string>
      <key>PayloadVersion</key>
      <real>1</real>
      <key>ProxyType</key>
      <string>None</string>
    </dict>
    <dict>
      <key>AutoJoin</key>
      <true/>
      <key>EAPClientConfiguration</key>
      <dict>
        <key>AcceptEAPTypes</key>
        <array>
          <integer>13</integer>
        </array>
      </dict>
      <key>PayloadCertificateUUID</key>
      <string>{{.UUIDBase}}.pkcs12</string>
      <key>PayloadDescription</key>
      <string>Configures Wifi Credentials</string>
      <key>PayloadDisplayName</key>
      <string>{{.Organization}} Wifi Config</string>
      <key>PayloadIdentifier</key>
      <string>{{.IdentBase}}.wifi</string>
      <key>PayloadType</key>
      <string>com.apple.wifi.managed</string>
      <key>PayloadUUID</key>
      <string>{{.UUIDBase}}.wifi</string>
      <key>PayloadVersion</key>
      <real>1</real>
      <key>ProxyType</key>
      <string>None</string>
      <key>EncryptionType</key>
      <string>WPA2</string>
      <key>SSID_STR</key>
      <string>{{.SSID}}</string>
      <key>HIDDEN_NETWORK</key>
      <false/>
      <key>IsHotspot</key>
      <false/>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>{{.IdentBase}}.mobileconfig</string>
  <key>PayloadIdentifier</key>
  <string>{{.IdentBase}}.mobileconfig</string>
  <key>PayloadOrganization</key>
  <string>{{.Organization}}</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{{.UUIDBase}}.xml</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  </dict>
</plist>
`

// PKCS12ToMobileConfig wraps a standard PKCS12 file in the proprietary XML-encoded wrapper used by
// Apple devices.
func PKCS12ToMobileConfig(p12Bytes []byte, username, password, ssid, orgName string) ([]byte, error) {
	sum := sha1.Sum(p12Bytes)

	p12b64 := base64.StdEncoding.EncodeToString(p12Bytes)

	params := struct {
		FileName     string
		IdentBase    string
		UUIDBase     string
		Organization string
		P12Data      string
		Password     string
		SSID         string
	}{
		FileName:     username,
		IdentBase:    username,
		UUIDBase:     hex.EncodeToString(sum[:]),
		Organization: orgName,
		P12Data:      p12b64,
		Password:     password,
		SSID:         ssid,
	}

	tmpl, err := template.New("tmpl").Parse(mobileConfigTmpl)
	if err != nil {
		return nil, err
	}

	buffer := &bytes.Buffer{}
	err = tmpl.Execute(buffer, params)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
