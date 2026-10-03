package openconnect

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
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

func TestGenerateCredentialRoundtrip(t *testing.T) {
	field, err := GenerateCredential("hunter2")
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	cred, err := parseCredential(field)
	if err != nil {
		t.Fatalf("parseCredential(%q): %v", field, err)
	}
	if !cred.check("hunter2") {
		t.Error("expected generated credential to verify its password")
	}
	if cred.check("other") {
		t.Error("expected generated credential to reject a different password")
	}
	other, err := GenerateCredential("hunter2")
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if field == other {
		t.Error("expected distinct salts for successive generations")
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

// The MTU math that fixed the 2026-09-27 pps anomaly: both tunnel MTUs
// (advertised X-CSTP-MTU and gVisor NIC) must be base−cstpOverhead, so a
// maximal IP packet is a datagram of exactly the base MTU and both sides'
// MSS values line up (client MSS = X-CSTP-MTU−40).
func TestMTUMath(t *testing.T) {
	base := uint32(1500)
	if got := dataMTUOf(base); got != base-cstpOverhead {
		t.Errorf("dataMTUOf(%d) = %d, want %d", base, got, base-cstpOverhead)
	}
	if got := dataMTUOf(cstpOverhead - 1); got != cstpOverhead-1 {
		t.Errorf("dataMTUOf below overhead should pass through, got %d", got)
	}
	// Client MSS (X-CSTP-MTU−40) must reach a typical incoming segment size
	// (~1380 from a 1420-MTU wg path): 1500−78−40 = 1382.
	if mss := int(base - cstpOverhead - 40); mss < 1380 {
		t.Errorf("client MSS %d below 1380: sub-MSS segments would split", mss)
	}
}

func TestIfaceMTUOf(t *testing.T) {
	if got := ifaceMTUOf(nil); got != 0 {
		t.Errorf("ifaceMTUOf(nil) = %d, want 0", got)
	}
	if got := ifaceMTUOf(net.IPv4zero); got != 0 {
		t.Errorf("ifaceMTUOf(unspecified) = %d, want 0", got)
	}
	if got := ifaceMTUOf(net.IPv4(127, 0, 0, 1)); got == 0 {
		t.Error("ifaceMTUOf(127.0.0.1) = 0, want the loopback MTU")
	}
	// TEST-NET-3: no interface holds this address.
	if got := ifaceMTUOf(net.IPv4(203, 0, 113, 1)); got != 0 {
		t.Errorf("ifaceMTUOf(unassigned) = %d, want 0", got)
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
	c.Users[0].Ip = "10.66.0.1"
	if err := c.validate(); err == nil {
		t.Error("expected error for static ip on the gateway address")
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
	c.Users[0].Routes = []string{"172.16.10.0/24"}
	if err := c.validate(); err != nil {
		t.Errorf("user routes should be accepted: %v", err)
	}
	c.Users[0].Routes = []string{"bogus"}
	if err := c.validate(); err == nil {
		t.Error("expected error for bad user route")
	}
	c.Users[0].Routes = []string{"fd00::/8"}
	if err := c.validate(); err == nil {
		t.Error("expected error for IPv6 user route")
	}

	c = validConfig(t)
	c.Groups = []*Group{{Name: "split", Routes: []string{"10.0.0.0/8"}}}
	c.Users[0].Group = "split"
	if err := c.validate(); err != nil {
		t.Errorf("route group should be accepted: %v", err)
	}
	c.Groups[0].Name = ""
	if err := c.validate(); err == nil {
		t.Error("expected error for empty group name")
	}
	c.Groups = append(c.Groups, &Group{Name: "split"})
	if err := c.validate(); err == nil {
		t.Error("expected error for duplicate group name")
	}
	c.Groups = []*Group{{Name: "split", Routes: []string{"bogus"}}}
	if err := c.validate(); err == nil {
		t.Error("expected error for bad group route")
	}
	c.Groups = []*Group{{Name: "split", NoRoutes: []string{"0.0.0.0/0", "192.168.1.0/24"}}}
	if err := c.validate(); err != nil {
		t.Errorf("group no_routes should be accepted: %v", err)
	}
	c.Groups = []*Group{{Name: "split", NoRoutes: []string{"bogus"}}}
	if err := c.validate(); err == nil {
		t.Error("expected error for bad group no_route")
	}
	c.Groups = []*Group{{Name: "split", NoRoutes: []string{"fd00::/8"}}}
	if err := c.validate(); err == nil {
		t.Error("expected error for IPv6 group no_route")
	}
	c.Groups = []*Group{{Name: "split"}}
	c.Users[0].Group = "nope"
	if err := c.validate(); err == nil {
		t.Error("expected error for unknown user group")
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

func TestL3For(t *testing.T) {
	bp := func(b bool) *bool { return &b }
	c := &OpenConnectInboundConfig{Groups: []*Group{{Name: "split"}}}

	if c.l3For(nil) {
		t.Error("l3For(nil) = true, want false")
	}

	// User without a group and without an override: false (opt-in).
	if c.l3For(&User{}) {
		t.Error("l3For(user without group) = true, want false")
	}

	// User in a group with l3 unset: false (opt-in).
	if c.l3For(&User{Group: "split"}) {
		t.Error("l3For(group, l3 unset) = true, want false")
	}

	// Group enables L3: true.
	c.Groups[0].L3 = bp(true)
	if !c.l3For(&User{Group: "split"}) {
		t.Error("l3For(group l3=true) = false, want true")
	}

	// Group disables L3: false.
	c.Groups[0].L3 = bp(false)
	if c.l3For(&User{Group: "split"}) {
		t.Error("l3For(group l3=false) = true, want false")
	}

	// Per-user override true beats group false.
	c.Groups[0].L3 = bp(false)
	if !c.l3For(&User{Group: "split", L3: bp(true)}) {
		t.Error("l3For(user l3=true, group l3=false) = false, want true")
	}

	// Per-user override false beats group true.
	c.Groups[0].L3 = bp(true)
	if c.l3For(&User{Group: "split", L3: bp(false)}) {
		t.Error("l3For(user l3=false, group l3=true) = true, want false")
	}

	// Per-user override without a group.
	c.Groups = nil
	if c.l3For(&User{L3: bp(false)}) {
		t.Error("l3For(user l3=false, no group) = true, want false")
	}
	if !c.l3For(&User{L3: bp(true)}) {
		t.Error("l3For(user l3=true, no group) = false, want true")
	}
}
