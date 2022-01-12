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

package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"warden/pkg/playground-log"
)

var Debug bool

var configPath string

/* Load unmarshals the contents of a JSON config file into the designated interface, which should
 * generally be a struct. The caller is expected to create a wrapper struct aggregating the config
 * objects of all modules it wants to load; passing such an instance will load the JSON config data
 * into the respective objects. */
func Load(dest interface{}) {
	LOGTAG := "config.Load"

	v := reflect.ValueOf(dest)

	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		err := errors.New("cannot load config into a non-struct type")
		log.Error(LOGTAG, "bad config", err)
		panic(err)
	}

	type flagHolder struct {
		name    string
		val     *reflect.Value
		flagVal interface{}
	}
	flags := make(map[string]*flagHolder)

	fields := v.NumField()
	for i := 0; i < fields; i++ {
		fv := v.Field(i)
		tag := v.Type().Field(i).Tag.Get("config")
		if tag != "" {
			chunks := strings.SplitN(tag, ";", 2)
			name := chunks[0]
			desc := ""
			if len(chunks) == 2 {
				desc = chunks[1]
			}
			var val interface{}
			switch fv.Kind() {
			case reflect.Slice:
				if fv.Type().Elem().Kind() == reflect.String {
					val = flag.String(name, "", desc)
				} else {
					log.Warn(LOGTAG, "only arrays of strings are supported")
				}
			case reflect.String:
				val = flag.String(name, "", desc)
			case reflect.Int:
				val = flag.Int(name, 0, desc)
			case reflect.Bool:
				val = flag.Bool(name, false, desc)
			default:
				val = nil
			}
			if val != nil {
				flags[name] = &flagHolder{name, &fv, val}
			}
		}
	}

	flag.StringVar(&configPath, "config", "", "location of the configuration JSON")
	flag.BoolVar(&Debug, "debug", false, "enable debug logging")
	flag.Parse()

	present := make(map[string]bool)
	flag.Visit(func(flag *flag.Flag) {
		present[flag.Name] = true
	})

	if configPath != "" {
		LoadDirect(configPath, dest)
	} else if flag.NFlag() == 0 {
		log.Warn(LOGTAG, "neither -config nor other flags provided; running with defaults")
	}

	for name, holder := range flags {
		if present[name] {
			wrapped := reflect.ValueOf(holder.flagVal).Elem()
			switch wrapped.Kind() {
			case reflect.String:
				if holder.val.Kind() == reflect.Slice {
					if holder.val.Type().Elem().Kind() == reflect.String {
						chunks := strings.Split(wrapped.String(), "~~")
						if holder.val.CanSet() {
							holder.val.Set(reflect.ValueOf(chunks))
						}
					}
					continue
				}

				fallthrough
			case reflect.Int:
				fallthrough
			case reflect.Bool:
				if holder.val.CanSet() {
					holder.val.Set(wrapped)
				}
			default:
			}
		}
	}
}

/* LoadDirect is like Load, but loads from the specified config file, bypassing command line
 * parameters. */
func LoadDirect(configFile string, dest interface{}) {
	var err error

	// validate config file input & load its contents if it looks good
	if configFile == "" {
		msg := "-config is required"
		log.Error("config.LoadDirect", msg)
		panic(msg)
	}
	if configFile, err = filepath.Abs(configFile); err != nil {
		msg := "-config value '" + configFile + "' does not resolve"
		log.Error("config.LoadDirect", msg)
		panic(msg)
	}
	if stat, err := os.Stat(configFile); (err != nil && !os.IsNotExist(err)) || (stat != nil && stat.IsDir()) {
		msg := "-config value '" + configFile + "' does not stat or is a directory"
		log.Error("config.LoadDirect", msg, err)
		panic(msg)
	}
	file, err := os.Open(configFile)
	if err != nil {
		msg := "failure opening -config file '" + configFile + "'"
		log.Error("config.LoadDirect", msg, err)
		panic(msg)
	}
	configContents, err := ioutil.ReadAll(file)
	if err != nil {
		msg := "failure reading -config file '" + configFile + "'"
		log.Error("config.LoadDirect", msg, err)
		panic(msg)
	}

	// having loaded the raw JSON config data, unmarshal it
	err = json.Unmarshal([]byte(configContents), dest)
	if err != nil {
		// if the error was a JSON syntax error, attempt to report line number it occured at
		if serr, ok := err.(*json.SyntaxError); ok {
			lines := strings.Split(string(configContents), "\n")
			target := int(serr.Offset)
			seen := 0
			for i, line := range lines {
				if target <= (seen + len(line) + 1) { // assume ASCII
					fmt.Println(line)
					msg := "JSON parse error at line " + strconv.Itoa(i+1) + ", column " + strconv.Itoa(target-seen)
					log.Error("config.LoadDirect", msg)
					panic(msg)
				}
				seen += len(line) + 1
			}
		}
		msg := "loading config failed on unmarshal "
		log.Error("config.LoadDirect", msg, err)
		panic(msg)
	}

	log.Status("config.LoadDirect", "Config loaded from '"+configFile+"'.")
}
