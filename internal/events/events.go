package events

// CommandEvent JSON Command event
type CommandEvent struct {
	Time      string `json:"timestamp"`
	Event     string `json:"event"`
	Hostname  string `json:"hostname"`
	Username  string `json:"username"`
	UID       int64  `json:"uid"`
	SessionID int64  `json:"session_id"`
	Command   string `json:"command"`
	Pid       uint64 `json:"pid"`
	ParentPid uint64 `json:"ppid"`
}

// SSHStartEvent JSON SSH Start event
type SSHStartEvent struct {
	Time           string `json:"timestamp"`
	Event          string `json:"event"`
	Hostname       string `json:"hostname"`
	Username       string `json:"username"`
	UID            int64  `json:"uid"`
	AddressRemote  string `json:"addr_remote"`
	Pid            uint64 `json:"pid"`
	SessionID      int64  `json:"session_id"`
	SSHFingerprint string `json:"ssh_fingerprint"`
}

// SSHEndEvent JSON SSH End event
type SSHEndEvent struct {
	Time      string `json:"timestamp"`
	Event     string `json:"event"`
	Hostname  string `json:"hostname"`
	Username  string `json:"username"`
	UID       int64  `json:"uid"`
	Pid       uint64 `json:"pid"`
	SessionID int64  `json:"session_id"`
}
