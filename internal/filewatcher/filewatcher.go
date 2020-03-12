package filewatcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hpcloud/tail"
	log "github.com/sirupsen/logrus"

	"github.com/terrycain/ssh-audit/internal/events"
)

// RegexFingerprintLine Fingerprint regex
var RegexFingerprintLine = regexp.MustCompile(`sshd\[(?P<pid>\d+)\]: Accepted publickey for (?P<username>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) ssh2: (?P<fp>.+)`)

// RegexEndSessionLine End session regex
var RegexEndSessionLine = regexp.MustCompile(`sshd\[(?P<pid>\d+)\]:.+session closed for user (?P<username>\w+)`)

// SSHStartSession data
type SSHStartSession struct {
	PID, User, FromIP, PublicKeyFP string
}

// SSHEndSession data
type SSHEndSession struct {
	PID, User string
}

// FileWatcher Internal data
type FileWatcher struct {
	StopChannel   chan bool
	PidSessionMap map[string]int64
}

// NewFileWatcher Creates a new event store
func NewFileWatcher() *FileWatcher {
	obj := FileWatcher{
		StopChannel:   make(chan bool),
		PidSessionMap: make(map[string]int64),
	}

	return &obj
}

// Close Closes filewatcher
func (f FileWatcher) Close() {
	log.Debug("Stopping filewatcher")
	f.StopChannel <- true

	select {
	case <-f.StopChannel:
		break
	case <-time.After(5 * time.Second):
		log.Warning("Filewatcher failed to stop gracefully ")
		break
	}

	log.Debug("Stopped filewatcher")
}

// Run Runs filewatcher
func (f FileWatcher) Run(filename string, matchChannel chan<- string) {
	go f.run(filename, matchChannel)
}

// Watch Watches SSH audit file
func (f FileWatcher) run(filename string, matchChannel chan<- string) {
	log.Debug("Starting filewatcher")
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	tailConfig := tail.Config{Location: &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END}, ReOpen: true,
		MustExist: true, Follow: true, Logger: tail.DiscardingLogger}
	t, err := tail.TailFile(filename, tailConfig)
	if err != nil {
		log.WithError(err).Error("Failed to tail " + filename)
		return
	}

	defer t.Cleanup()

Loop:
	for {
		select {
		case line := <-t.Lines:
			if sshStart, err := ParseStartLine(line.Text); err == nil {
				sessionID := GetSession(sshStart.PID)
				f.PidSessionMap[sshStart.PID] = sessionID

				// Ignoring error, as PID is \d+
				pidInt, _ := strconv.ParseUint(sshStart.PID, 10, 64)

				jsonEvent := events.SSHStartEvent{
					Time:           time.Now().UnixNano(),
					Event:          "session.start",
					Hostname:       hostname,
					Username:       sshStart.User,
					UID:            GetUID(sshStart.User),
					AddressRemote:  sshStart.FromIP,
					Pid:            pidInt,
					SessionID:      sessionID,
					SSHFingerprint: sshStart.PublicKeyFP,
				}
				jsonString, err := json.Marshal(jsonEvent)
				if err != nil {
					log.WithError(err).Error(fmt.Sprintf("Failed to convert SSH Start Event: %#v", jsonEvent))
				} else {
					select {
					case matchChannel <- string(jsonString):
						log.Debug("SSH Start: " + string(jsonString))
					case <-time.After(5 * time.Second):
						log.Warn("Failed to emit event for 5 seconds, giving up")
					}
				}

			} else if sshEnd, err := ParseEndLine(line.Text); err == nil {
				// Ignoring error, as PID is \d+
				pidInt, _ := strconv.ParseUint(sshEnd.PID, 10, 64)

				sessionID, keyExists := f.PidSessionMap[sshEnd.PID]
				if !keyExists {
					sessionID = -1
				} else {
					// Remove the SessionID  from the map as its no longer needed
					delete(f.PidSessionMap, sshEnd.PID)
				}

				jsonEvent := events.SSHEndEvent{
					Time:      time.Now().UnixNano(),
					Event:     "session.end",
					Hostname:  hostname,
					Username:  sshEnd.User,
					UID:       GetUID(sshEnd.User),
					Pid:       pidInt,
					SessionID: sessionID,
				}
				jsonString, err := json.Marshal(jsonEvent)
				if err != nil {
					log.WithError(err).Error(fmt.Sprintf("Failed to convert SSH Stop Event: %#v", jsonEvent))
				} else {
					select {
					case matchChannel <- string(jsonString):
						log.Debug("SSH End: " + string(jsonString))
					case <-time.After(5 * time.Second):
						log.Warn("Failed to emit event for 5 seconds, giving up")
					}
				}
			}

		case <-f.StopChannel:
			log.Info("Caught exit signal from channel")
			break Loop
		}
	}

	log.Debug("Exiting filewatcher")
	f.StopChannel <- true
	log.Debug("Exited filewatcher")
}

// GetSession gets sessionid from pid
func GetSession(pid string) int64 {
	path := "/proc/" + pid + "/sessionid"

	// Could probably write this better if i were better at go
	// Basically loop 5 times looking for decent session id
	counter := 0
	for {
		if data, err := ioutil.ReadFile(path); err == nil {
			if sessionid, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
				if sessionid == 4294967295 {
					counter++
					if counter >= 5 {
						break
					}
					<-time.After(10 * time.Millisecond)
					continue
				}
				return sessionid
			}
		}
		break
	}
	return -1
}

// GetUID get UID from username
func GetUID(username string) int64 {
	if userObj, err := user.Lookup(username); err == nil {
		if uid, err := strconv.ParseInt(userObj.Uid, 10, 64); err == nil {
			return uid
		}
	}
	return -1
}

// ParseStartLine convert string into SSHLogin event
func ParseStartLine(line string) (SSHStartSession, error) {
	if match := RegexFingerprintLine.FindStringSubmatch(line); match != nil {
		return SSHStartSession{
			PID:         match[1],
			User:        match[2],
			FromIP:      match[3],
			PublicKeyFP: match[5],
		}, nil
	}
	return SSHStartSession{}, errors.New("noMatch")
}

// ParseEndLine convert string into SSHLogin event
func ParseEndLine(line string) (SSHEndSession, error) {
	if match := RegexEndSessionLine.FindStringSubmatch(line); match != nil {
		return SSHEndSession{
			PID:  match[1],
			User: match[2],
		}, nil
	}
	return SSHEndSession{}, errors.New("noMatch")
}
