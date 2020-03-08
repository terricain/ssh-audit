# TODO

Line:
```
Mar  5 21:32:42 terry-HP-EliteBook-850-G1 sshd[10820]: Accepted publickey for terry from 127.0.0.1 port 54976 ssh2: RSA SHA256:OvcoG14z07ciYYZspp1oFT9yf9jxXTSLRZYeAoJTbfg
```

# Requirements

* Emit SSH start session events
* Emit command events
* Emit SSH end session events
* Sent events as JSON to a HTTP/S endpoint

# JSON Events
## SSH Start

```json
{
    "timestamp": "2020-03-06T22:11:50.94Z",
    "event": "session.start",
    "hostname": "server01.example.org",
    "username": "user1",
    "uid": 1000,
    "addr_remote": "8.8.8.8",
    "session_id": "751",
    "pid": 1234
    "ssh_fingerprint": "RSA SHA256:OvcoG14z07ciYYZspp1oFT9yf9jxXTSLRZYeAoJTbfg"
}
```

## SSH End

```json
{
    "timestamp": "2020-03-06T22:11:50.94Z",
    "event": "session.end",
    "hostname": "server01.example.org",
    "username": "user1",
    "uid": 1000,
    "pid": 1234,
    "session_id": "751",
}
```

## Command

```json
{
    "timestamp": "2020-03-06T22:11:50.94Z",
    "event": "session.command",
    "hostname": "server01.example.org",
    "username": "user1",
    "uid": 1000,
    "session_id": "751",
    "command": "ls -lah /root",
    "pid": 1235,
    "ppid": 1234
}
```

# Processing Logic
## SSH Start

Tail -f log that gets SSH events (auth.log on Ubuntu)
Match SSH pubkey accepted line
extract pid, username, fingerprint, remote ip
lookup uid (os/user) from username
lookup login session id (from cgroup file)
emit event

## SSH End

Tail f log that gets SSH events
Match Disconnected from user line
Extract username, pid from line
lookup uid (os/user) from username
lookup login session id (from cgroup file)
emit event

## Command

Get eBPF execve events
Call get task func and get the login session id from it
lookup username from uid
emit event


