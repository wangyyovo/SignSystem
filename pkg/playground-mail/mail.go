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

package mail

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/smtp"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"warden/pkg/playground-log"
)

var templates map[string]*template.Template = make(map[string]*template.Template)
var senders map[string]string = make(map[string]string)

func loadTemplate(file string, name string) (*template.Template, error) {
	var err error
	path := path.Join(Config.TemplateRoot, file)
	if path, err = filepath.Abs(path); err != nil {
		log.Error("mail.loadTemplate", "template '"+path+"' does not resolve")
		return nil, err
	}
	if !strings.HasPrefix(path, Config.TemplateRoot) {
		log.Error("mail.loadTemplate", "requested file '"+file+"' is not a child of template root")
		return nil, errors.New("requested file is not a child of template root")
	}
	if stat, err := os.Stat(path); err != nil || (stat != nil && stat.IsDir()) {
		log.Error("mail.loadTemplate", "template '"+path+"' does not stat or is a directory", err)
		return nil, err
	}
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("mail.loadTemplate", "template '"+path+"' failed to load", err)
		return nil, err
	}
	tmpl, err := template.New(name).Parse(string(fileBytes))
	if err != nil {
		log.Error("mail.loadTemplate", "template '"+path+"' failed to parse", err)
		return nil, err
	}
	return tmpl, nil
}

// Send constructs an SMTP payload from the indicated template populated with the provided
// parameters, and transmits a single email via the configured SMTP MTA.
func Send(template string, rcpt []string, params interface{}) error {
	tmpl, t_ok := templates[template]
	sender, s_ok := senders[template]
	if !t_ok || !s_ok {
		log.Error("mail.Send", "unknown template '"+template+"' referenced by caller")
		return errors.New("unknown template")
	}

	var buf bytes.Buffer
	err := tmpl.Execute(&buf, params)
	if err != nil {
		log.Error("mail.Send", "template '"+template+"' failed to execute", err)
		return err
	}
	payload := buf.Bytes()
	log.Debug("mail.Send", "expanded template", string(payload))

	auth := smtp.PlainAuth("", Config.SMTP.User, Config.SMTP.Password, Config.SMTP.Server)
	err = smtp.SendMail(Config.SMTP.Server+":"+strconv.Itoa(Config.SMTP.Port), auth, sender, rcpt, payload)
	if err != nil {
		log.Error("mail.Send", "failed to send email", err)
		return err
	}

	return nil
}

func Ready() {
	// first resolve the canonical/absolute path of the templates base; used later to prevent ../../ attacks
	path, err := filepath.Abs(Config.TemplateRoot)
	if err != nil {
		log.Error("mail.Ready", "unable to resolve template root", err)
		panic("unable to resolve template root")
	}
	Config.TemplateRoot = path

	for _, tCfg := range Config.Templates {
		tmpl, err := loadTemplate(tCfg.File, tCfg.Name)
		if err != nil {
			log.Error("mail.Ready", "failed to load template '"+tCfg.Name+"'", err)
			panic("failed to load template")
		}
		templates[tCfg.Name] = tmpl
		senders[tCfg.Name] = tCfg.SenderEmail
	}
}
