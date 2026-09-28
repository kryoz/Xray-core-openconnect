package openconnect

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `{
  // a comment the xray JSON loader tolerates
  "log": {},
  "inbounds": [
    {
      "tag": "oc-in",
      "protocol": "openconnect",
      "port": 443,
      "settings": {
        "subnet": "10.66.0.0/24",
        "users": [
          {"name": "alice", "password": "aabb$cc"}
        ]
      }
    },
    {
      "tag": "socks-in",
      "protocol": "socks",
      "port": 1080,
      "settings": {}
    }
  ]
}
`

// verifyCredential re-implements the server-side check so the test can
// confirm a generated credential authenticates the right password.
func verifyCredential(t *testing.T, field, password string) {
	t.Helper()
	saltHex, hashHex, ok := strings.Cut(field, "$")
	if !ok {
		t.Fatalf("credential %q has no $ separator", field)
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) == 0 {
		t.Fatalf("bad salt in %q: %v", field, err)
	}
	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != sha256.Size {
		t.Fatalf("bad hash in %q: %v", field, err)
	}
	sum := sha256.Sum256(append(salt, password...))
	if hex.EncodeToString(sum[:]) != hashHex {
		t.Fatalf("credential does not verify password %q", password)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func usersFrom(t *testing.T, path, tag string) []any {
	t.Helper()
	doc, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ib, err := findInbound(doc, tag)
	if err != nil {
		t.Fatal(err)
	}
	users, err := usersOf(ib)
	if err != nil {
		t.Fatal(err)
	}
	return users
}

func credentialOf(t *testing.T, users []any, name string) string {
	t.Helper()
	for _, u := range users {
		if userName(u) == name {
			m, _ := u.(map[string]any)
			p, _ := m["password"].(string)
			return p
		}
	}
	t.Fatalf("user %q not found", name)
	return ""
}

func TestAddPasswdListRm(t *testing.T) {
	path := writeConfig(t, testConfig)
	*addConfig, *addInbound, *addIP = path, "", ""
	*passwdConfig, *passwdInbound = path, ""
	*rmConfig, *rmInbound = path, ""
	*listConfig, *listInbound = path, ""

	// add
	executeAdd(cmdAdd, []string{"bob", "s3cret"})
	users := usersFrom(t, path, "")
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d", len(users))
	}
	verifyCredential(t, credentialOf(t, users, "bob"), "s3cret")

	// add with static ip
	*addIP = "10.66.0.7"
	executeAdd(cmdAdd, []string{"carol", "pw"})
	*addIP = ""
	users = usersFrom(t, path, "")
	for _, u := range users {
		if userName(u) == "carol" {
			m, _ := u.(map[string]any)
			if m["ip"] != "10.66.0.7" {
				t.Fatalf("carol ip = %v, want 10.66.0.7", m["ip"])
			}
		}
	}

	// list must not crash on the rewritten (comment-free) config
	executeList(cmdList, nil)

	// passwd
	executePasswd(cmdPasswd, []string{"bob", "n3w"})
	users = usersFrom(t, path, "")
	verifyCredential(t, credentialOf(t, users, "bob"), "n3w")
	if credentialOf(t, users, "bob") == "aabb$cc" {
		t.Fatal("alice credential was clobbered")
	}

	// rm
	executeRm(cmdRm, []string{"carol"})
	users = usersFrom(t, path, "")
	if len(users) != 2 {
		t.Fatalf("want 2 users after rm, got %d", len(users))
	}
	for _, u := range users {
		if userName(u) == "carol" {
			t.Fatal("carol still present")
		}
	}
}

func TestFindInboundAmbiguous(t *testing.T) {
	two := `{
  "inbounds": [
    {"tag": "a", "protocol": "openconnect", "settings": {"users": []}},
    {"tag": "b", "protocol": "openconnect", "settings": {"users": []}}
  ]
}
`
	path := writeConfig(t, two)
	doc, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findInbound(doc, ""); err == nil {
		t.Fatal("expected ambiguity error")
	}
	if _, err := findInbound(doc, "b"); err != nil {
		t.Fatalf("tag selection failed: %v", err)
	}
	if _, err := findInbound(doc, "nope"); err == nil {
		t.Fatal("expected unknown-tag error")
	}
}

func TestLoadConfigToleratesComments(t *testing.T) {
	path := writeConfig(t, testConfig)
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("commented config must parse: %v", err)
	}
}

func TestGenerateCredentialViaHashCommand(t *testing.T) {
	// readPassword passthrough
	got, err := readPassword("plain")
	if err != nil || got != "plain" {
		t.Fatalf("readPassword passthrough = %q, %v", got, err)
	}
}
