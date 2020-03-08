package eventstore

import "fmt"

// Mar  1 22:07:56 dns0 sshd[8751]: Accepted publickey for terry from 172.20.0.147 port 53710 ssh2: RSA SHA256:OvcoG14z07ciYYZspp1oFT9yf9jxXTSLRZYeAoJTbfg

// SSHLogin Contains details from the Accepted publickey line
type SSHLogin struct {
	PID, User, FromIP, FromPort, PublicKeyFP string
}

// EventStore Contains events to be sent and a map of PID -> SSHLogin
type EventStore struct {
	SSHLogins map[string]SSHLogin
	Logins    chan SSHLogin
	LoginEnd  chan bool
}

// NewEventStore Creates a new event store
func NewEventStore() *EventStore {
	obj := EventStore{
		SSHLogins: make(map[string]SSHLogin),
		Logins:    make(chan SSHLogin),
		LoginEnd:  make(chan bool),
	}

	return &obj
}

// AddSSHLogin adds an SSHLogin event to the map
func (e EventStore) AddSSHLogin(loginEvent SSHLogin) {
	e.SSHLogins[loginEvent.PID] = loginEvent
	fmt.Println(e.SSHLogins)
}

// ClearSSHLogins Clears all PIDs in the map, does so via iteration as map will be referenced
func (e EventStore) ClearSSHLogins() {
	for pid := range e.SSHLogins {
		delete(e.SSHLogins, pid)
	}
}

// ProcessLogins Takes ssh login events from channel and adds them to map
func (e EventStore) ProcessLogins() {
	for {
		select {
		case sshLogin := <-e.Logins:
			e.AddSSHLogin(sshLogin)
		case <-e.LoginEnd:
			fmt.Println("Caught exit signal from channel")
			break
		}
	}
}
