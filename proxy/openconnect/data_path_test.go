package openconnect

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/stats"
)

// internetChecksum computes the RFC 1071 one's-complement checksum.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildICMPEchoRequest builds a valid IPv4 + ICMP echo request packet.
func buildICMPEchoRequest(src, dst net.IP, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8 // echo request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))

	ip := make([]byte, 20)
	ip[0] = 0x45 // IPv4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(icmp)))
	ip[8] = 64 // TTL
	ip[9] = 1  // ICMP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip))
	return append(ip, icmp...)
}

// fakeCounter is a minimal stats.Counter for test assertions.
type fakeCounter struct {
	n int64
}

func (c *fakeCounter) Add(v int64) int64 { c.n += v; return c.n }
func (c *fakeCounter) Value() int64      { return c.n }
func (c *fakeCounter) Set(v int64) int64 { o := c.n; c.n = v; return o }

// TestRelayL3 covers the relay decision matrix: relay between two l3 users
// (packet byte-identical, framed), per-user counters, regular stack path for
// non-l3 pairs, spoofed-source drop, and no relay to non-client destinations.
func TestRelayL3(t *testing.T) {
	pool, err := newIPPool("10.99.0.0/24")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	reg := newSessionRegistry(pool)
	uA := &User{Name: "a", Password: testPW("x"), Ip: "10.99.0.10", L3: boolP(true)}
	uB := &User{Name: "b", Password: testPW("x"), Ip: "10.99.0.11", L3: boolP(true)}
	uC := &User{Name: "c", Password: testPW("x"), Ip: "10.99.0.12"}
	sessA, err := reg.create("", uA, true)
	if err != nil {
		t.Fatalf("sessA: %v", err)
	}
	sessB, err := reg.create("", uB, true)
	if err != nil {
		t.Fatalf("sessB: %v", err)
	}
	sessC, err := reg.create("", uC, false)
	if err != nil {
		t.Fatalf("sessC: %v", err)
	}

	d := newOCDevice(1400)
	d.registry = reg
	up, down := &fakeCounter{}, &fakeCounter{}
	d.uplinkCounter, d.downlinkCounter = up, down
	var userUp, userDown string
	d.userCounter = func(email, dir string) stats.Counter {
		if dir == "uplink" {
			userUp = email
		} else {
			userDown = email
		}
		return up // shared counter suffices for attribution assertions
	}
	var relayed []byte
	d.register(sessB.ip, func(framed []byte) error {
		relayed = append([]byte(nil), framed...)
		return nil
	})

	ipA2B := buildICMPEchoRequest(sessA.ip.AsSlice(), sessB.ip.AsSlice(), 1, 1, []byte("hi"))
	if !d.relayL3(ocRxPkt{from: sessA.ip, frame: append([]byte{acPKTData}, ipA2B...)}) {
		t.Fatal("l3→l3 packet not relayed")
	}
	if want := append([]byte{acPKTData}, ipA2B...); !bytes.Equal(relayed, want) {
		t.Errorf("relayed frame = %v, want %v", relayed, want)
	}
	if userUp != "a" || userDown != "b" {
		t.Errorf("user attribution up=%q down=%q, want a/b", userUp, userDown)
	}
	if up.n == 0 || down.n == 0 {
		t.Errorf("relay bytes not counted: up=%d down=%d", up.n, down.n)
	}

	// Non-l3 pairs keep the regular stack path.
	relayed = nil
	for name, p := range map[string]ocRxPkt{
		"dst not l3":       {from: sessA.ip, frame: append([]byte{acPKTData}, buildICMPEchoRequest(sessA.ip.AsSlice(), sessC.ip.AsSlice(), 1, 2, []byte("hi"))...)},
		"src not l3":       {from: sessC.ip, frame: append([]byte{acPKTData}, buildICMPEchoRequest(sessC.ip.AsSlice(), sessB.ip.AsSlice(), 1, 3, []byte("hi"))...)},
		"dst not a client": {from: sessA.ip, frame: append([]byte{acPKTData}, buildICMPEchoRequest(sessA.ip.AsSlice(), net.IPv4(1, 1, 1, 1), 1, 4, []byte("hi"))...)},
		"dst is sender":    {from: sessA.ip, frame: append([]byte{acPKTData}, buildICMPEchoRequest(sessA.ip.AsSlice(), sessA.ip.AsSlice(), 1, 5, []byte("hi"))...)},
	} {
		if d.relayL3(p) {
			t.Errorf("%s: relayed, want regular stack path", name)
		}
		if relayed != nil {
			t.Errorf("%s: tunnel writer invoked", name)
		}
	}

	// Spoofed source between l3 users: consumed (dropped), never delivered.
	relayed = nil
	spoof := buildICMPEchoRequest(sessC.ip.AsSlice(), sessB.ip.AsSlice(), 1, 6, []byte("hi"))
	if !d.relayL3(ocRxPkt{from: sessA.ip, frame: append([]byte{acPKTData}, spoof...)}) {
		t.Error("spoofed src not consumed (would leak into the stack path)")
	}
	if relayed != nil {
		t.Error("spoofed src was relayed")
	}
}

// TestL3ClientToClientRelay drives the full path: two l3 users (A and B, both
// on CSTP/TCP), A's ICMP echo to B's virtual IP is relayed into B's tunnel,
// and B's reply is relayed back to A.
func TestL3ClientToClientRelay(t *testing.T) {
	s := newTestServer(t)
	s.conf.Users = []*User{
		{Name: "l3a", Password: testPW("pass1"), Ip: "10.99.0.10", L3: boolP(true)},
		{Name: "l3b", Password: testPW("pass2"), Ip: "10.99.0.11", L3: boolP(true)},
	}
	users, err := newUserStore(s.conf.Users)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	s.users = users

	// A: CONNECT (CSTP).
	cA, brA, sessA := ocConnectAs(t, s, "l3a", "pass1")
	defer func() { _ = cA.Close() }()

	// B: CONNECT (CSTP).
	cB, brB, sessB := ocConnectAs(t, s, "l3b", "pass2")
	defer func() { _ = cB.Close() }()

	// A → B: echo request must arrive framed on B's CSTP tunnel.
	ipA2B := buildICMPEchoRequest(sessA.ip.AsSlice(), sessB.ip.AsSlice(), 0x4242, 1, []byte("relay"))
	if _, err := cA.Write(cstFrame(acPKTData, ipA2B)); err != nil {
		t.Fatalf("cstp write: %v", err)
	}
	setDeadline(t, cB, 5*time.Second)
	typ, payload := readCstFrame(t, brB)
	for typ != acPKTData && typ != acPKTDisconnect && typ != acPKTTerm {
		typ, payload = readCstFrame(t, brB)
	}
	if typ != acPKTData || !bytes.Equal(payload, ipA2B) {
		t.Fatalf("B received type=%d payload=%v, want DATA %v", typ, payload, ipA2B)
	}

	// B → A: reply relayed back onto A's tunnel.
	ipB2A := buildICMPEchoRequest(sessB.ip.AsSlice(), sessA.ip.AsSlice(), 0x4242, 1, []byte("relay"))
	if _, err := cB.Write(cstFrame(acPKTData, ipB2A)); err != nil {
		t.Fatalf("cstp write: %v", err)
	}
	setDeadline(t, cA, 5*time.Second)
	typ, payload = readCstFrame(t, brA)
	for typ != acPKTData && typ != acPKTDisconnect && typ != acPKTTerm {
		typ, payload = readCstFrame(t, brA)
	}
	if typ != acPKTData || !bytes.Equal(payload, ipB2A) {
		t.Fatalf("A received type=%d payload=%v, want DATA %v", typ, payload, ipB2A)
	}
}

// TestConnectSplitRoutes verifies that split-routing networks are advertised
// as repeated X-CSTP-Split-Include header lines: libopenconnect collects one
// route per header line and does not parse comma-joined values.
func TestConnectSplitRoutes(t *testing.T) {
	s := newTestServer(t)
	s.conf.Routes = []string{"10.50.0.0/16", "192.168.100.0/24"}

	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	readResp(t, c1)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, c1)
	cookie := cookieValue(setCookies)
	_ = c1.Close()

	c2 := dialOC(t, s)
	defer func() { _ = c2.Close() }()
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	raw := readRawHead(t, c2)
	for _, want := range s.conf.Routes {
		if !strings.Contains(raw, "X-CSTP-Split-Include: "+want+"\r\n") {
			t.Errorf("missing split route %s in CONNECT response:\n%s", want, raw)
		}
	}
}

// TestConnectSplitExclude verifies group no-route exclusions are advertised
// as X-CSTP-Split-Exclude lines. With split routing the default-route
// exclusion 0.0.0.0/0 is the signal a split-routing router needs to send
// anything outside the include set via its own gateway; exclusions are also
// sent without any include (ocserv full-tunnel-minus-subnets parity).
func TestConnectSplitExclude(t *testing.T) {
	s := newTestServer(t)
	s.conf.Groups = []*Group{{
		Name:     "split",
		Routes:   []string{"10.50.0.0/16"},
		NoRoutes: []string{"0.0.0.0/0", "192.168.100.0/24"},
	}}
	s.conf.Users[0].Group = "split"

	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	readResp(t, c1)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, c1)
	cookie := cookieValue(setCookies)
	_ = c1.Close()

	c2 := dialOC(t, s)
	defer func() { _ = c2.Close() }()
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	raw := readRawHead(t, c2)
	if !strings.Contains(raw, "X-CSTP-Split-Include: 10.50.0.0/16\r\n") {
		t.Errorf("missing include route in CONNECT response:\n%s", raw)
	}
	for _, want := range []string{"0.0.0.0/0", "192.168.100.0/24"} {
		if !strings.Contains(raw, "X-CSTP-Split-Exclude: "+want+"\r\n") {
			t.Errorf("missing exclude route %s in CONNECT response:\n%s", want, raw)
		}
	}

	// Exclusions are sent even with no include routes (ocserv parity).
	s2 := newTestServer(t)
	s2.conf.Groups = []*Group{{Name: "exclude", NoRoutes: []string{"0.0.0.0/0"}}}
	s2.conf.Users[0].Group = "exclude"
	c3 := dialOC(t, s2)
	writeReq(c3, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	readResp(t, c3)
	writeReq(c3, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	_, _, setCookies, _ = readResp(t, c3)
	cookie = cookieValue(setCookies)
	_ = c3.Close()

	c4 := dialOC(t, s2)
	defer func() { _ = c4.Close() }()
	writeReq(c4, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	raw = readRawHead(t, c4)
	if !strings.Contains(raw, "X-CSTP-Split-Exclude: 0.0.0.0/0\r\n") {
		t.Errorf("missing exclude route in full-tunnel CONNECT response:\n%s", raw)
	}
}

// TestConnectPerUserRoutes verifies per-user split-routing: a user with
// non-empty routes gets them instead of the inbound-level policy, while a
// user without routes inherits the inbound policy.
func TestConnectPerUserRoutes(t *testing.T) {
	s := newTestServer(t)
	s.conf.Routes = []string{"10.50.0.0/16"}
	s.conf.Users = append(s.conf.Users, &User{
		Name: "router", Password: testPW("routerpass"), Routes: []string{"172.16.10.0/24"},
	})
	users, err := newUserStore(s.conf.Users)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	s.users = users

	connect := func(t *testing.T, user, pass string) string {
		t.Helper()
		c := dialOC(t, s)
		writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>`+user+`</username></auth></config-auth>`, "")
		readResp(t, c)
		writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>`+pass+`</password></auth></config-auth>`, "")
		_, _, setCookies, _ := readResp(t, c)
		cookie := cookieValue(setCookies)
		if cookie == "" {
			t.Fatalf("auth failed for %s", user)
		}
		_ = c.Close()
		cc := dialOC(t, s)
		defer func() { _ = cc.Close() }()
		writeReq(cc, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
		return readRawHead(t, cc)
	}

	raw := connect(t, "router", "routerpass")
	if !strings.Contains(raw, "X-CSTP-Split-Include: 172.16.10.0/24\r\n") {
		t.Errorf("router: missing per-user route in CONNECT response:\n%s", raw)
	}
	if strings.Contains(raw, "X-CSTP-Split-Include: 10.50.0.0/16") {
		t.Errorf("router: inbound route leaked into per-user override:\n%s", raw)
	}

	raw = connect(t, "testuser", "testpass")
	if !strings.Contains(raw, "X-CSTP-Split-Include: 10.50.0.0/16\r\n") {
		t.Errorf("testuser: expected inherited inbound route:\n%s", raw)
	}
	if strings.Contains(raw, "X-CSTP-Split-Include: 172.16.10.0/24") {
		t.Errorf("testuser: other user's route leaked:\n%s", raw)
	}
}

// TestConnectGroupRoutes verifies named route groups: a grouped user gets
// the group's networks, user routes are appended on top, and an ungrouped
// user with no inbound routes gets no split headers at all (full tunnel).
func TestConnectGroupRoutes(t *testing.T) {
	s := newTestServer(t)
	s.conf.Groups = []*Group{{Name: "split", Routes: []string{"10.60.0.0/16", "192.168.0.0/16"}}}
	s.conf.Users = append(s.conf.Users,
		&User{Name: "router", Password: testPW("grppass"), Group: "split"},
		&User{Name: "router-x", Password: testPW("grppass2"), Group: "split", Routes: []string{"172.21.0.0/16"}},
	)
	users, err := newUserStore(s.conf.Users)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	s.users = users

	connect := func(t *testing.T, user, pass string) string {
		t.Helper()
		c := dialOC(t, s)
		writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>`+user+`</username></auth></config-auth>`, "")
		readResp(t, c)
		writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>`+pass+`</password></auth></config-auth>`, "")
		_, _, setCookies, _ := readResp(t, c)
		cookie := cookieValue(setCookies)
		if cookie == "" {
			t.Fatalf("auth failed for %s", user)
		}
		_ = c.Close()
		cc := dialOC(t, s)
		defer func() { _ = cc.Close() }()
		writeReq(cc, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
		return readRawHead(t, cc)
	}

	raw := connect(t, "router", "grppass")
	for _, want := range []string{"10.60.0.0/16", "192.168.0.0/16"} {
		if !strings.Contains(raw, "X-CSTP-Split-Include: "+want+"\r\n") {
			t.Errorf("router: missing group route %s:\n%s", want, raw)
		}
	}
	if strings.Contains(raw, "X-CSTP-Split-Include: 172.21.0.0/16") {
		t.Errorf("router: other user's route leaked:\n%s", raw)
	}

	raw = connect(t, "router-x", "grppass2")
	for _, want := range []string{"10.60.0.0/16", "192.168.0.0/16", "172.21.0.0/16"} {
		if !strings.Contains(raw, "X-CSTP-Split-Include: "+want+"\r\n") {
			t.Errorf("router-x: missing route %s (group + user union):\n%s", want, raw)
		}
	}
	// Wire order of the repeated header lines must match the configured order
	// (group routes first, then the user's own), not be reversed.
	var gotRoutes []string
	for _, line := range strings.Split(raw, "\r\n") {
		if v, ok := strings.CutPrefix(line, "X-CSTP-Split-Include: "); ok {
			gotRoutes = append(gotRoutes, v)
		}
	}
	if want := []string{"10.60.0.0/16", "192.168.0.0/16", "172.21.0.0/16"}; !slices.Equal(gotRoutes, want) {
		t.Errorf("router-x: split-include wire order = %v, want %v", gotRoutes, want)
	}

	if raw := connect(t, "testuser", "testpass"); strings.Contains(raw, "X-CSTP-Split-Include") {
		t.Errorf("ungrouped user on route-less inbound must get no split headers:\n%s", raw)
	}
}

// TestControlQueryPath verifies that a query string in the request target
// (ocserv camouflage secret in the client's server URL, e.g.
// https://host/?forzarussia) is ignored: the auth flow must start instead of
// a 404.
func TestControlQueryPath(t *testing.T) {
	s := newTestServer(t)
	c := dialOC(t, s)
	defer func() { _ = c.Close() }()
	// First request carries the query (client's server URL path); the forms
	// point to /auth, so subsequent requests come without it.
	writeReq(c, "POST", "/?forzarussia", "", "")
	if st, _, _, _ := readResp(t, c); st != 200 {
		t.Fatalf("POST /?forzarussia: status %d, want 200", st)
	}
	writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	if st, _, _, body := readResp(t, c); st != 200 || !strings.Contains(body, "password") {
		t.Fatalf("POST /auth username: status %d, want 200 password form", st)
	}
	writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	if st, _, setCookies, _ := readResp(t, c); st != 200 || cookieValue(setCookies) == "" {
		t.Fatalf("auth after query request failed: status %d cookies %v", st, setCookies)
	}
}

// TestAuthCombinedForm reproduces the mobile (libopenconnect/AnyConnect)
// flow: the initial form must carry username AND password together like
// ocserv's main form, credentials are POSTed in one body, and a
// password-stage reply that re-includes the username must authenticate
// instead of re-asking for the password (that loop is what broke mobile
// clients).
func TestAuthCombinedForm(t *testing.T) {
	s := newTestServer(t)
	c := dialOC(t, s)
	defer func() { _ = c.Close() }()

	writeReq(c, "POST", "/", "", "")
	if st, _, _, body := readResp(t, c); st != 200 || !strings.Contains(body, `name="username"`) || !strings.Contains(body, `name="password"`) {
		t.Fatalf("initial form: status %d, want username+password inputs:\n%s", st, body)
	}

	// One-shot: both credentials in a single XML POST.
	writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth client="vpn" type="auth-reply"><auth><username>testuser</username><password>testpass</password></auth></config-auth>`, "")
	if st, _, setCookies, _ := readResp(t, c); st != 200 || cookieValue(setCookies) == "" {
		t.Fatalf("one-shot auth: status %d, cookies %v", st, setCookies)
	}

	// Wrong password in a one-shot POST must fail, not re-prompt.
	writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username><password>wrongpass</password></auth></config-auth>`, "")
	if st, _, _, body := readResp(t, c); st != 401 || strings.Contains(body, "Please enter your password") {
		t.Fatalf("wrong one-shot password: status %d, body %q", st, body)
	}
	_ = c.Close()

	// Split flow where libopenconnect re-sends the username with the
	// password-only form: must authenticate, not loop on the password form.
	c = dialOC(t, s)
	defer func() { _ = c.Close() }()
	writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	if st, _, _, body := readResp(t, c); st != 200 || !strings.Contains(body, "Please enter your password") {
		t.Fatalf("username stage: status %d, body %q", st, body)
	}
	writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username><password>testpass</password></auth></config-auth>`, "")
	if st, _, setCookies, _ := readResp(t, c); st != 200 || cookieValue(setCookies) == "" {
		t.Fatalf("password stage with username re-sent: status %d, cookies %v", st, setCookies)
	}
}

// TestCamouflage covers the ocserv-compatible camouflage check: without the
// secret (or a valid session cookie) the server answers like a plain web
// server and closes; with the secret the normal auth flow proceeds on the
// same connection.
func TestCamouflage(t *testing.T) {
	s := newTestServer(t)
	s.conf.CamouflageSecret = "s3cret"
	s.conf.CamouflageRealm = "Restricted area"

	// No secret → 401 with realm.
	c := dialOC(t, s)
	writeReq(c, "POST", "/", "", "")
	st, hdrs, _, _ := readResp(t, c)
	if st != 401 || hdrs["www-authenticate"] != `Basic realm="Restricted area"` {
		t.Fatalf("no secret: status %d, www-authenticate %q", st, hdrs["www-authenticate"])
	}
	_ = c.Close()

	// Wrong secret → same.
	c = dialOC(t, s)
	writeReq(c, "GET", "/?wrong", "", "")
	if st, _, _, _ := readResp(t, c); st != 401 {
		t.Fatalf("wrong secret: status %d, want 401", st)
	}
	_ = c.Close()

	// Correct secret → auth proceeds, and the pass stays for follow-up
	// requests without the query (forms point to /auth).
	c = dialOC(t, s)
	writeReq(c, "POST", "/?s3cret", "", "")
	if st, _, _, _ := readResp(t, c); st != 200 {
		t.Fatalf("POST /?s3cret: status %d, want 200", st)
	}
	writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	if st, _, _, _ := readResp(t, c); st != 200 {
		t.Fatalf("POST /auth username: status %d, want 200", st)
	}
	writeReq(c, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	st, _, setCookies, _ := readResp(t, c)
	if st != 200 || cookieValue(setCookies) == "" {
		t.Fatalf("auth after secret: status %d cookies %v", st, setCookies)
	}
	cookie := cookieValue(setCookies)
	_ = c.Close()

	// A valid session cookie passes without the secret (resume path).
	c = dialOC(t, s)
	writeReq(c, "POST", "/", "", "Cookie: webvpn="+cookie+"\r\n")
	if st, _, _, _ := readResp(t, c); st != 200 {
		t.Fatalf("resume with cookie: status %d, want 200", st)
	}
	_ = c.Close()

	// No realm configured → plain 404.
	s.conf.CamouflageRealm = ""
	c = dialOC(t, s)
	writeReq(c, "POST", "/", "", "")
	if st, _, _, _ := readResp(t, c); st != 404 {
		t.Fatalf("no realm: status %d, want 404", st)
	}
	_ = c.Close()
}

// readRawHead reads a response head up to the blank line. readResp collapses
// repeated headers into its map, so repeated lines must be checked on the wire.
func readRawHead(t *testing.T, c *tls.Conn) string {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	br := bufio.NewReader(c)
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read response head: %v", err)
		}
		sb.WriteString(line)
		if line == "\r\n" {
			return sb.String()
		}
	}
}

// TestL3RelayMixedOrderCSTPFirst reproduces the field layout: two l3 users
// behind one NAT (same client IP) connect in sequence; the relay must work in
// both directions regardless of connection order.
func TestL3RelayMixedOrderCSTPFirst(t *testing.T) {
	s := newTestServer(t)
	s.conf.Users = []*User{
		{Name: "l3a", Password: testPW("pass1"), Ip: "10.99.0.10", L3: boolP(true)},
		{Name: "l3b", Password: testPW("pass2"), Ip: "10.99.0.11", L3: boolP(true)},
	}
	users, err := newUserStore(s.conf.Users)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	s.users = users

	// B connects first.
	cB, brB, sessB := ocConnectAs(t, s, "l3b", "pass2")
	defer func() { _ = cB.Close() }()

	// A connects second (same client IP as B — one NAT).
	cA, brA, sessA := ocConnectAs(t, s, "l3a", "pass1")
	defer func() { _ = cA.Close() }()

	// A → B.
	ipA2B := buildICMPEchoRequest(sessA.ip.AsSlice(), sessB.ip.AsSlice(), 0x99, 1, []byte("m"))
	if _, err := cA.Write(cstFrame(acPKTData, ipA2B)); err != nil {
		t.Fatalf("cstp write: %v", err)
	}
	setDeadline(t, cB, 5*time.Second)
	typ, payload := readCstFrame(t, brB)
	for typ != acPKTData && typ != acPKTDisconnect && typ != acPKTTerm {
		typ, payload = readCstFrame(t, brB)
	}
	if typ != acPKTData || !bytes.Equal(payload, ipA2B) {
		t.Fatalf("B received type=%d payload=%v, want DATA %v", typ, payload, ipA2B)
	}

	// B → A.
	ipB2A := buildICMPEchoRequest(sessB.ip.AsSlice(), sessA.ip.AsSlice(), 0x99, 1, []byte("m"))
	if _, err := cB.Write(cstFrame(acPKTData, ipB2A)); err != nil {
		t.Fatalf("cstp write: %v", err)
	}
	setDeadline(t, cA, 5*time.Second)
	typ, payload = readCstFrame(t, brA)
	for typ != acPKTData && typ != acPKTDisconnect && typ != acPKTTerm {
		typ, payload = readCstFrame(t, brA)
	}
	if typ != acPKTData || !bytes.Equal(payload, ipB2A) {
		t.Fatalf("A received type=%d payload=%v, want DATA %v", typ, payload, ipB2A)
	}
}

// TestRelayWriterSurvivesStaleSessionTeardown covers two sessions sharing one
// static IP: the old session's CSTP teardown must not unregister the new
// live session's device writer (fix: unregister only the writer you own).
func TestRelayWriterSurvivesStaleSessionTeardown(t *testing.T) {
	s := newTestServer(t)
	s.conf.Users = []*User{
		{Name: "l3a", Password: testPW("pass1"), Ip: "10.99.0.10", L3: boolP(true)},
		{Name: "l3b", Password: testPW("pass2"), Ip: "10.99.0.11", L3: boolP(true)},
	}
	users, err := newUserStore(s.conf.Users)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	s.users = users

	// A: CSTP client (the relay source).
	cA, _, sessA := ocConnectAs(t, s, "l3a", "pass1")
	defer func() { _ = cA.Close() }()

	// B generation 1: CONNECT, then the client walks away.
	cB1, _, sessB1 := ocConnectAs(t, s, "l3b", "pass2")
	_ = cB1.Close()

	// B generation 2: fresh auth (new session) on the SAME static IP.
	cB2, brB, sessB2 := ocConnectAs(t, s, "l3b", "pass2")
	defer func() { _ = cB2.Close() }()
	if sessB2 == sessB1 {
		t.Fatal("expected a distinct session for the second auth")
	}

	// A -> B must still be relayed to the new session's CSTP writer.
	ipA2B := buildICMPEchoRequest(sessA.ip.AsSlice(), sessB2.ip.AsSlice(), 0x61, 1, []byte("g2"))
	if _, err := cA.Write(cstFrame(acPKTData, ipA2B)); err != nil {
		t.Fatalf("cstp write: %v", err)
	}
	setDeadline(t, cB2, 5*time.Second)
	typ, payload := readCstFrame(t, brB)
	for typ != acPKTData && typ != acPKTDisconnect && typ != acPKTTerm {
		typ, payload = readCstFrame(t, brB)
	}
	if typ != acPKTData || !bytes.Equal(payload, ipA2B) {
		t.Fatalf("B received type=%d payload=%v, want DATA", typ, payload)
	}
}
