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

package log

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type LogLevel int

const (
	LEVEL_ERROR LogLevel = iota
	LEVEL_WARNING
	LEVEL_STATUS
	LEVEL_DEBUG
)

var currentLevel LogLevel = LEVEL_STATUS
var quietLog = false
var logger *log.Logger
//var useSystemd = false
var systemdID string

func init() {
	logger = log.New(os.Stdout, "", log.LstdFlags)
}

func SetLogLevel(newLevel LogLevel) {
	_, ok := levelMap[newLevel]
	if !ok {
		Warn("Logger", "someone tried to set invalid log level ", newLevel)
		return
	}
	currentLevel = newLevel
}

func SetQuiet(isQuiet bool) {
	quietLog = isQuiet
	if isQuiet {
		logger = log.New(os.Stdout, "", 0)
	} else {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}
}

func SetLogFile(fileName string) {
	if strings.HasPrefix(fileName, "systemd:") {
		//useSystemd = true
		systemdID = fileName[8:]
		return
	}
	var err error
	if fileName, err = filepath.Abs(fileName); err != nil {
		msg := "-log value '" + fileName + "' does not resolve"
		Error("log.SetLogFile", msg, err)
		panic(msg)
	}
	if stat, err := os.Stat(fileName); (err != nil && !os.IsNotExist(err)) || (stat != nil && stat.IsDir()) {
		msg := "-log value '" + fileName + "' does not stat or is a directory"
		Error("log.SetLogFile", msg, err)
		panic(msg)
	}
	if f, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660); err == nil {
		fmt.Println("Directing log to " + fileName + ".")
		logger = log.New(f, "", log.LstdFlags)
	} else {
		Warn("Logger", "failed to open log file ", fileName)
	}
}

var levelMap map[LogLevel]string = map[LogLevel]string{
	LEVEL_ERROR:   "ERROR",
	LEVEL_WARNING: "WARNING",
	LEVEL_STATUS:  "STATUS",
	LEVEL_DEBUG:   "DEBUG",
}

func doLog(level LogLevel, component string, extras ...interface{}) {
	if level > currentLevel {
		return
	}

	levelString, ok := levelMap[level]
	if !ok {
		levelString = "ERROR"
		Warn("Logger", "called with invalid level ", level)
	}

	//if useSystemd {
	//	var message string
	//	if _, ok := extras[0].(string); ok {
	//		message = fmt.Sprintf("(%s) %s ", component, extras[0])
	//		extras = extras[1:]
	//	} else {
	//		message = fmt.Sprintf("(%s) ", component)
	//	}
	//	pri, ok := map[LogLevel]journal.Priority{
	//		LEVEL_DEBUG:   journal.PriDebug,
	//		LEVEL_ERROR:   journal.PriErr,
	//		LEVEL_STATUS:  journal.PriNotice,
	//		LEVEL_WARNING: journal.PriWarning,
	//	}[level]
	//	if !ok {
	//		pri = journal.PriErr
	//	}
	//	message = fmt.Sprintf(message, extras...)
	//	journal.Send(message, pri, map[string]string{"SYSLOG_IDENTIFIER": systemdID})
	//	return
	//}

	var message string
	if _, ok := extras[0].(string); ok {
		if quietLog {
			if level < LEVEL_STATUS {
				message = fmt.Sprintf("%s %s ", levelString, extras[0])
			} else {
				message = fmt.Sprintf("%s ", extras[0])
			}
		} else {
			message = fmt.Sprintf("[%s] (%s) %s ", levelString, component, extras[0])
		}
		extras = extras[1:]
	} else {
		if quietLog {
			if level < LEVEL_STATUS {
				message = fmt.Sprintf("%s ", levelString)
			} else {
				message = fmt.Sprintf(" ")
			}
		} else {
			message = fmt.Sprintf("[%s] (%s) ", levelString, component)
		}
	}
	logger.Printf(message, extras...)
}

func Debug(component string, extras ...interface{}) {
	doLog(LEVEL_DEBUG, component, extras...)
}

func Error(component string, extras ...interface{}) {
	doLog(LEVEL_ERROR, component, extras...)
}

func Warn(component string, extras ...interface{}) {
	doLog(LEVEL_WARNING, component, extras...)
}

func Status(component string, extras ...interface{}) {
	doLog(LEVEL_STATUS, component, extras...)
}
