package openconnect

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// hashPassword builds a "salt_hex$hash_hex" credential string for tests.
func hashPassword(t *testing.T, salt, password string) string {
	t.Helper()
	sum := sha256.Sum256(append([]byte(salt), password...))
	return hex.EncodeToString([]byte(salt)) + "$" + hex.EncodeToString(sum[:])
}

func TestCredentialCheck(t *testing.T) {
	field := hashPassword(t, "salty", "hunter2")
	cred, err := parseCredential(field)
	if err != nil {
		t.Fatalf("parseCredential: %v", err)
	}
	if !cred.check("hunter2") {
		t.Error("expected password to match")
	}
	if cred.check("wrong") {
		t.Error("expected password to not match")
	}
}

func TestParseCredentialRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"",
		"no-separator",
		"zz$00",         // bad salt hex
		"aabb$tooshort", // bad hash length
		"$" + hex.EncodeToString(make([]byte, sha256.Size)), // empty salt
	} {
		if _, err := parseCredential(bad); err == nil {
			t.Errorf("parseCredential(%q): expected error", bad)
		}
	}
}

func validConfig(t *testing.T) *OpenConnectInboundConfig {
	t.Helper()
	return &OpenConnectInboundConfig{
		Users:  []*User{{Name: "alice", Password: hashPassword(t, "s", "p")}},
		Subnet: "10.66.0.0/24",
		Mtu:    1400,
	}
}

func TestValidate(t *testing.T) {
	if err := validConfig(t).validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	c := validConfig(t)
	c.Users = nil
	if err := c.validate(); err == nil {
		t.Error("expected error for no users")
	}

	c = validConfig(t)
	c.Subnet = "not-a-subnet"
	if err := c.validate(); err == nil {
		t.Error("expected error for bad subnet")
	}

	c = validConfig(t)
	c.Users = append(c.Users, &User{Name: "alice", Password: hashPassword(t, "s", "p")})
	if err := c.validate(); err == nil {
		t.Error("expected error for duplicate user")
	}

	c = validConfig(t)
	c.Mtu = 100
	if err := c.validate(); err == nil {
		t.Error("expected error for mtu below min")
	}

	c = validConfig(t)
	c.Users[0].Ip = "10.66.0.5"
	if err := c.validate(); err != nil {
		t.Errorf("static ip should be accepted: %v", err)
	}
	c.Users[0].Ip = "bogus"
	if err := c.validate(); err == nil {
		t.Error("expected error for bad static ip")
	}

	c = validConfig(t)
	c.Routes = []string{"10.0.0.0/8", "192.168.1.0/24"}
	if err := c.validate(); err != nil {
		t.Errorf("routes should be accepted: %v", err)
	}
	c.Routes = append(c.Routes, "bogus")
	if err := c.validate(); err == nil {
		t.Error("expected error for bad route")
	}

	c = validConfig(t)
	c.Routes = []string{"fd00::/8"}
	if err := c.validate(); err == nil {
		t.Error("expected error for IPv6 route")
	}

	c = validConfig(t)
	c.CamouflageSecret = "forzarussia"
	c.CamouflageRealm = "Restricted area"
	if err := c.validate(); err != nil {
		t.Errorf("camouflage config should be accepted: %v", err)
	}
	c.CamouflageSecret = "a?b"
	if err := c.validate(); err == nil {
		t.Error("expected error for camouflage secret with '?'")
	}

	c = validConfig(t)
	c.CamouflageRealm = `he said "no"`
	if err := c.validate(); err == nil {
		t.Error("expected error for camouflage realm with quote")
	}
}
