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

type SMTPConfig struct {
	Server   string
	Port     int
	User     string
	Password string
}

type TemplateConfig struct {
	Name        string
	File        string
	SenderEmail string
}

type ConfigType struct {
	SMTP         *SMTPConfig
	TemplateRoot string
	Templates    []*TemplateConfig
}

var Config ConfigType = ConfigType{
	&SMTPConfig{
		"smtp.gmail.com",
		25,
		"noreply@domain.tld",
		"Sekr1tPassw0rd",
	},
	"./mails",
	[]*TemplateConfig{
		{
			"package",
			"package.tmpl",
			"noreply+reception@domain.tld",
		},
	},
}
