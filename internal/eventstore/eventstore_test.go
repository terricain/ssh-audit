package eventstore

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAddSSHLogin(t *testing.T) {
	es := NewEventStore()
	sshLogin := SSHLogin{PID: "1234", User: "root", FromIP: "1.1.1.1", FromPort: "10001", PublicKeyFP: "RSA SHA256:OvcoG14z07ciYYZspp1oFT9yf9jxXTSLRZYeAoJTbfg"}

	es.AddSSHLogin(sshLogin)

	if len(es.SSHLogins) != 1 {
		t.Error("SSHLogins length is not 1")
	}

	storedSSHLogin := es.SSHLogins["1234"]

	if !cmp.Equal(storedSSHLogin, sshLogin) {
		t.Error("Stored SSHLogin does not match the one provided")
	}
}

func TestClearSSHLogins(t *testing.T) {
	es := NewEventStore()
	sshLogin := SSHLogin{PID: "1234", User: "root", FromIP: "1.1.1.1", FromPort: "10001", PublicKeyFP: "RSA SHA256:OvcoG14z07ciYYZspp1oFT9yf9jxXTSLRZYeAoJTbfg"}

	es.AddSSHLogin(sshLogin)

	if len(es.SSHLogins) != 1 {
		t.Error("SSHLogins length is not 1")
	}

	es.ClearSSHLogins()

	if len(es.SSHLogins) != 0 {
		t.Error("SSHLogins should be 0")
	}
}
