# SSH Audit 

A simple go program to emit command and ssh login/logout JSON events to an API. Uses eBPF which is less resource intensive than auditd. 
The session ID is the same one used by auditd and should be unique per session, it remains the same even when using sudo and differentiates 
sessions of the same user. The main idea behind this was to have a simple binary which emits enough audit information about SSH usage which
also includes the SSH fingerprint used for the connection, useful when you want to share accounts following blogs like - https://engineering.fb.com/security/scalable-and-secure-access-with-ssh/

This is my first decent Go project so it'll probably have some issues. 

## Usage

```
Usage: main

Flags:
  --help                           Show context-sensitive help.
  --debug                          Enable debug logging
  --ssh-log="/var/log/auth.log"    Log file which contains SSH accepted
                                   publickey lines
  --event-buffer=5000              Event buffer size
  --disable-bpf                    Disable eBPF module
  --url=STRING                     URL to POST JSON events to
```

The `--ssh-log` argument points to the log file which contains SSH logs from syslog, the program will extract ssh fingerprints from that.

`--disable-bpf` will disable the eBPF logic which then means you'll only get ssh start and end events.

## Installation

Requires BCC >= 0.11.0 and a kernel > 4.12

Currently the iovisor bcc repo for Ubuntu has v0.10.0 so I'd recommend installing it from source until the repos have been updated.
BCC install instructions - https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source

```
# For 18.04 - Building BCC - Tested on an AWS t2.large
apt install -y bison build-essential cmake flex git libedit-dev libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev
# Install BCC
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build
cd bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
make install
cd ../..
rm -rf bcc
# Remove packages used to build bcc
apt remove -y bison build-essential cmake flex git libedit-dev llvm-6.0-dev libclang-6.0-dev zlib1g-dev libelf-dev

# Download ssh-audit
wget -o ssh-audit https://github.com/terrycain/ssh-audit/releases/download/v1.0.0/ssh-audit.linux-amd64
install -v -m 755 -o root -g root ssh-audit /usr/local/bin/ssh-audit
cat <<EOF > /etc/systemd/system/ssh-audit.service
[Unit]
Description=SSH Audit

[Service]
ExecStart=/usr/local/bin/ssh-audit

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ssh-audit
```


## JSON Events
### SSH Start

```json
{
    "timestamp": 1584286327710505558,
    "event": "session.start",
    "hostname": "server01.example.org",
    "username": "user1",
    "uid": 1000,
    "addr_remote": "8.8.8.8",
    "pid": 1234,    
    "session_id": 751,  
    "ssh_fingerprint": "RSA SHA256:OvcoG14z07ciYYZspp1oFT9yf9jxXTSLRZYeAoJTbfg"
}
```

### SSH End

```json
{
    "timestamp": 1584286327710505558,
    "event": "session.end",
    "hostname": "server01.example.org",
    "username": "user1",
    "uid": 1000,
    "session_id": 751,    
    "pid": 1234
}
```

### Command

```json
{
    "timestamp": 1584286327710505558,
    "event": "session.command",
    "hostname": "server01.example.org",
    "username": "user1",
    "uid": 1000,
    "session_id": 751,
    "command": "ls -lah /root",
    "pid": 1235,
    "ppid": 1234
}
```

## Processing Logic
### SSH Start

Tail -f log that gets SSH events (auth.log on Ubuntu)
Match SSH pubkey accepted line
extract pid, username, fingerprint, remote ip
lookup uid (os/user) from username
lookup login session id (from cgroup file)
emit event

### SSH End

Tail f log that gets SSH events
Match Disconnected from user line
Extract username, pid from line
lookup uid (os/user) from username
lookup login session id (from cgroup file)
emit event

### Command

Get eBPF execve events
Call get task func and get the login session id from it
lookup username from uid
emit event


