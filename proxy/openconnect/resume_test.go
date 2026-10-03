package openconnect

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

// freePort returns a free localhost port (best-effort) for tcp or udp.
func freePort(t *testing.T, network string) int {
	t.Helper()
	var addr net.Addr
	var err error
	if network == "udp" {
		var pc net.PacketConn
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("freePort(udp): %v", err)
		}
		addr = pc.LocalAddr()
		_ = pc.Close()
	} else {
		var l net.Listener
		l, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("freePort(tcp): %v", err)
		}
		addr = l.Addr()
		_ = l.Close()
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.Port
	case *net.UDPAddr:
		return a.Port
	}
	t.Fatalf("freePort: unexpected addr type %T", addr)
	return 0
}

// testPW builds a valid "salt_hex$hash_hex" credential for the given password.
func testPW(password string) string {
	salt := []byte("testsalt")
	sum := sha256.Sum256(append(append([]byte{}, salt...), password...))
	return hex.EncodeToString(salt) + "$" + hex.EncodeToString(sum[:])
}

// boolP returns a pointer to a bool, for building optional proto fields in tests.
func boolP(v bool) *bool { return &v }

// newTestServer builds a Server with the default single test user.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerUsers(t, []*User{{Name: "testuser", Password: testPW("testpass")}})
}

// newTestServerUsers builds a Server on a free localhost port, bypassing the DI
// path (policy/dispatcher are unused by the control channel).
func newTestServerUsers(t *testing.T, users []*User) *Server {
	t.Helper()
	tcpPort := freePort(t, "tcp")

	conf := &OpenConnectInboundConfig{
		Users:         users,
		Subnet:        "10.99.0.0/24",
		Mtu:           1400,
		Dpd:           90,
		CookieTimeout: 300,
	}
	pool, err := newIPPool(conf.Subnet)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	store, err := newUserStore(conf.Users)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	cert, err := ephemeralCert()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}

	tctx, cancel := context.WithCancel(context.Background())
	registry := newSessionRegistry(pool)
	stack := newOCStack(tctx, nil, "openconnect", mtuOf(conf), registry, 0)
	s := &Server{
		conf:        conf,
		ctx:         tctx,
		cancel:      cancel,
		src:         xnet.DestinationFromAddr(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tcpPort}),
		cert:        cert,
		registry:    registry,
		users:       store,
		limiter:     newAuthLimiter(authFailMax),
		camoLimiter: newAuthLimiter(camoFailMax),

		stack:  stack,
		device: stack.device,
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// dialOC opens a TLS control connection to the server.
func dialOC(t *testing.T, s *Server) *tls.Conn {
	t.Helper()
	addr := s.src.Address.String() + ":" + strconv.Itoa(int(s.src.Port))
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	return tc
}

// writeReq writes a raw HTTP/1.1 request.
func writeReq(tc *tls.Conn, method, path, body, extraHdrs string) {
	req := method + " " + path + " HTTP/1.1\r\nHost: xray\r\n"
	if extraHdrs != "" {
		req += extraHdrs
	}
	if body != "" {
		req += "Content-Type: text/xml\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n"
	}
	req += "\r\n" + body
	if _, err := tc.Write([]byte(req)); err != nil {
		panic(err)
	}
}

// readResp reads one HTTP response: status, headers (lower-cased), set-cookies, body.
func readResp(t *testing.T, tc *tls.Conn) (int, map[string]string, []string, string) {
	t.Helper()
	br := bufio.NewReader(tc)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		t.Fatalf("bad status line: %q", line)
	}
	status, _ := strconv.Atoi(f[1])
	headers := map[string]string{}
	var setCookies []string
	for {
		hl, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		hl = strings.TrimRight(hl, "\r\n")
		if hl == "" {
			break
		}
		k, v, _ := strings.Cut(hl, ":")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k == "set-cookie" {
			setCookies = append(setCookies, v)
		} else {
			headers[k] = v
		}
	}
	var body string
	if cl := headers["content-length"]; cl != "" {
		n, _ := strconv.Atoi(cl)
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			t.Fatalf("read body: %v", err)
		}
		body = string(buf)
	}
	return status, headers, setCookies, body
}

// cookieValue extracts "webvpn=<v>" from a Set-Cookie list.
func cookieValue(setCookies []string) string {
	for _, c := range setCookies {
		if v, ok := strings.CutPrefix(c, "webvpn="); ok {
			if j := strings.IndexAny(v, "; \t"); j >= 0 {
				return v[:j]
			}
			return v
		}
	}
	return ""
}

// ocAuth posts the combined username+password form and returns the status and
// the session cookie.
func ocAuth(t *testing.T, s *Server, user, pass string) (int, string) {
	t.Helper()
	c := dialOC(t, s)
	body := `<?xml version="1.0"?><config-auth><auth><username>` + user + `</username><password>` + pass + `</password></auth></config-auth>`
	writeReq(c, "POST", "/auth", body, "")
	st, _, setCookies, _ := readResp(t, c)
	_ = c.Close()
	return st, cookieValue(setCookies)
}

// ocTunnel opens a CSTP tunnel for a cookie and returns the status plus the
// connection and its buffered reader (the tunnel stream).
func ocTunnel(t *testing.T, s *Server, cookie string) (int, *tls.Conn, *bufio.Reader) {
	t.Helper()
	c := dialOC(t, s)
	writeReq(c, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	br := bufio.NewReader(c)
	setDeadline(t, c, 10*time.Second)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("CONNECT status line: %v", err)
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		t.Fatalf("bad CONNECT status line: %q", line)
	}
	status, err := strconv.Atoi(f[1])
	if err != nil {
		t.Fatalf("bad CONNECT status line: %q", line)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("CONNECT headers: %v", err)
		}
		if h == "\r\n" {
			break
		}
	}
	return status, c, br
}

// waitDisconnected blocks until the server has observed the tunnel going down.
// A fixed sleep here flakes on slow CI.
func waitDisconnected(t *testing.T, sess *ocSession) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for sess.isConnected() {
		if time.Now().After(deadline) {
			t.Fatal("server did not observe the tunnel close in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestResumePreservesIP drives the full control channel: auth → cookie →
// CONNECT (IP1) → disconnect → reconnect with cookie → CONNECT (IP2), asserting
// the IP lease is preserved and no re-authentication is needed.
func TestResumePreservesIP(t *testing.T) {
	s := newTestServer(t)

	// Connection 1: authenticate (username then password on the same conn).
	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth client="vpn" type="auth-reply"><auth><username>testuser</username></auth></config-auth>`, "")
	st, _, _, _ := readResp(t, c1)
	if st != 200 {
		t.Fatalf("username step: status %d, want 200", st)
	}
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth client="vpn" type="auth-reply"><auth><password>testpass</password></auth></config-auth>`, "")
	st, _, setCookies, _ := readResp(t, c1)
	if st != 200 {
		t.Fatalf("password step: status %d, want 200", st)
	}
	cookie := cookieValue(setCookies)
	if cookie == "" {
		t.Fatalf("no webvpn cookie in %v", setCookies)
	}
	_ = c1.Close()

	// Connection 2: CONNECT with the cookie → get IP1, then close (tunnel down).
	c2 := dialOC(t, s)
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	st, hdrs, _, _ := readResp(t, c2)
	if st != 200 {
		t.Fatalf("first CONNECT: status %d, want 200", st)
	}
	ip1 := hdrs["x-cstp-address"]
	if ip1 == "" {
		t.Fatalf("no X-CSTP-Address in first CONNECT: %v", hdrs)
	}
	_ = c2.Close() // simulate tunnel disconnect

	// Wait until the server has actually retired the tunnel. A fixed sleep lets
	// the next CONNECT race past the disconnect: the request then goes through
	// the supersede path and the resume branch under test is never exercised.
	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil {
		t.Fatal("no session registered for cookie")
	}
	waitDisconnected(t, sess)

	// Connection 3: resume — CONNECT with the same cookie, no auth forms.
	c3 := dialOC(t, s)
	writeReq(c3, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	st, hdrs, _, _ = readResp(t, c3)
	if st != 200 {
		t.Fatalf("resume CONNECT: status %d, want 200", st)
	}
	ip2 := hdrs["x-cstp-address"]
	if ip2 != ip1 {
		t.Fatalf("resume changed IP: got %s, want %s", ip2, ip1)
	}
	_ = c3.Close()
}

// TestResumeExpiredRejects verifies that a cookie presented after the resume
// window has elapsed is rejected with 401.
func TestResumeExpiredRejects(t *testing.T) {
	s := newTestServer(t)
	// Shrink the resume window so we can expire it quickly.
	s.conf.CookieTimeout = 1

	// Authenticate to obtain a cookie.
	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	readResp(t, c1)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, c1)
	cookie := cookieValue(setCookies)
	if cookie == "" {
		t.Fatalf("no cookie: %v", setCookies)
	}
	_ = c1.Close()

	// CONNECT once (marks the session connected), then disconnect.
	c2 := dialOC(t, s)
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	if st, _, _, _ := readResp(t, c2); st != 200 {
		t.Fatalf("first CONNECT: %d", st)
	}
	_ = c2.Close()

	// Poll until the session is actually expired: the server must first observe
	// c2's close (markDisconnected) and then elapse the 1s resume window. A
	// fixed sleep here flakes on slow CI.
	sid, err := base64.StdEncoding.DecodeString(cookie)
	if err != nil {
		t.Fatalf("decode cookie: %v", err)
	}
	var key [32]byte
	copy(key[:], sid)
	deadline := time.Now().Add(5 * time.Second)
	for {
		sess := s.registry.getBySID(key)
		if sess != nil && sess.expired(time.Now(), time.Second) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session did not expire within timeout")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Resume should now be rejected.
	c3 := dialOC(t, s)
	writeReq(c3, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	st, _, _, _ := readResp(t, c3)
	if st != 401 {
		t.Fatalf("expired resume: status %d, want 401", st)
	}
	_ = c3.Close()
}

// TestRegistryRemoveKeepsSuccessor covers two sessions sharing one virtual IP
// (a static-IP user connecting twice): the old session's removal must not
// clobber the successor's index entry.
func TestRegistryRemoveKeepsSuccessor(t *testing.T) {
	pool, err := newIPPool("10.77.0.0/24")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	r := newSessionRegistry(pool)
	u := &User{Name: "alice", Ip: "10.77.0.50"}
	old, err := r.create("1.2.3.4", u, false)
	if err != nil {
		t.Fatalf("create old: %v", err)
	}
	fresh, err := r.create("1.2.3.4", u, false)
	if err != nil {
		t.Fatalf("create fresh: %v", err)
	}
	if old.ip != fresh.ip {
		t.Fatalf("static-IP sessions must share one address: got %v and %v", old.ip, fresh.ip)
	}
	r.remove(context.Background(), old, "test")
	if got := r.getByVirtIP(fresh.ip); got != fresh {
		t.Fatalf("byVirtIP after old remove: want fresh session, got %+v", got)
	}
	r.remove(context.Background(), fresh, "test")
	if got := r.getByVirtIP(fresh.ip); got != nil {
		t.Fatal("byVirtIP after fresh remove: want nil")
	}
}

// TestRegistryByVirtIP checks the virtual-IP index that attributes L4 flows
// to the authenticated user for per-user stats.
func TestRegistryByVirtIP(t *testing.T) {
	pool, err := newIPPool("10.77.0.0/24")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	r := newSessionRegistry(pool)
	user := &User{Name: "alice"}
	sess, err := r.create("1.2.3.4", user, false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := r.getByVirtIP(sess.ip); got == nil || got.user != user {
		t.Fatalf("getByVirtIP: want alice's session, got %+v", got)
	}
	r.remove(context.Background(), sess, "test")
	if got := r.getByVirtIP(sess.ip); got != nil {
		t.Fatal("getByVirtIP after remove: want nil")
	}
}

// TestReAuthReplacesZombieSession: with max_clients set, a cookie-less re-auth
// from the same peer must replace the disconnected session — otherwise the
// zombie lingers for the whole cookie window and a chatty reconnect loop
// exhausts max_clients for a single client. A live tunnel from the same peer
// is a real second client (NAT) and must be left alone, rejected by the
// max-clients check instead.
func TestReAuthReplacesZombieSession(t *testing.T) {
	const authBody = `<?xml version="1.0"?><config-auth client="vpn" type="auth-reply"><auth><username>testuser</username><password>testpass</password></auth></config-auth>`

	for _, tc := range []struct {
		name       string
		liveTunnel bool
		want       int
		wantCount  int
	}{
		{name: "disconnected session replaced", want: 200, wantCount: 1},
		{name: "live tunnel from same peer kept", liveTunnel: true, want: 503, wantCount: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			s.conf.MaxClients = 1

			// First auth (combined username+password form).
			c1 := dialOC(t, s)
			writeReq(c1, "POST", "/auth", authBody, "")
			st, _, setCookies, _ := readResp(t, c1)
			if st != 200 {
				t.Fatalf("first auth: status %d, want 200", st)
			}
			cookie := cookieValue(setCookies)
			if cookie == "" {
				t.Fatalf("no webvpn cookie in %v", setCookies)
			}
			_ = c1.Close()

			// Establish the tunnel.
			c2 := dialOC(t, s)
			writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
			if st, _, _, _ := readResp(t, c2); st != 200 {
				t.Fatalf("CONNECT: status %d, want 200", st)
			}

			if !tc.liveTunnel {
				_ = c2.Close()
				// Deterministic: wait until the server observed the disconnect.
				sid, err := base64.StdEncoding.DecodeString(cookie)
				if err != nil {
					t.Fatalf("decode cookie: %v", err)
				}
				var key [32]byte
				copy(key[:], sid)
				sess := s.registry.getBySID(key)
				deadline := time.Now().Add(5 * time.Second)
				for sess.isConnected() {
					if time.Now().After(deadline) {
						t.Fatal("server did not observe the disconnect in time")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}

			// Second full auth from the same peer IP, no cookie.
			c3 := dialOC(t, s)
			writeReq(c3, "POST", "/auth", authBody, "")
			st, _, _, _ = readResp(t, c3)
			if st != tc.want {
				t.Fatalf("re-auth: status %d, want %d", st, tc.want)
			}
			if got := s.registry.count(); got != tc.wantCount {
				t.Fatalf("registry count: got %d, want %d", got, tc.wantCount)
			}
			_ = c3.Close()
			if tc.liveTunnel {
				_ = c2.Close()
			}
		})
	}
}

// TestReAuthKeepsOtherUsersSession: behind a NAT two users share one peer IP,
// and the stale-session sweep is keyed by user, not by address. A cookie-less
// re-auth must supersede only its own user's sessions — the other user's
// resume cookie must survive.
func TestReAuthKeepsOtherUsersSession(t *testing.T) {
	s := newTestServerUsers(t, []*User{
		{Name: "alice", Password: testPW("pw-a")},
		{Name: "bob", Password: testPW("pw-b")},
	})

	auth := func(name, pw string) int {
		t.Helper()
		body := fmt.Sprintf(`<?xml version="1.0"?><config-auth client="vpn" type="auth-reply"><auth><username>%s</username><password>%s</password></auth></config-auth>`, name, pw)
		c := dialOC(t, s)
		defer func() { _ = c.Close() }()
		writeReq(c, "POST", "/auth", body, "")
		st, _, _, _ := readResp(t, c)
		return st
	}

	// Both users authenticate from the same peer address: the test server is
	// local, so one address carrying two users is the NAT case itself.
	for _, u := range []struct{ name, pw string }{{"alice", "pw-a"}, {"bob", "pw-b"}} {
		if st := auth(u.name, u.pw); st != 200 {
			t.Fatalf("auth %s: status %d, want 200", u.name, st)
		}
	}
	if got := s.registry.count(); got != 2 {
		t.Fatalf("registry count after two distinct users from one peer: got %d, want 2", got)
	}

	// Pick Bob's session out by SID so it can be looked up again below.
	var bobSID [32]byte
	s.registry.mu.RLock()
	for sid, sess := range s.registry.bySID {
		if sess.userName() == "bob" {
			bobSID = sid
		}
	}
	s.registry.mu.RUnlock()
	if bobSID == [32]byte{} {
		t.Fatal("bob's session not found in the registry")
	}

	// The claim under test: a cookie-less re-auth supersedes only its own
	// user's sessions. With the sweep keyed by peer address instead, this is
	// exactly the request that would drop Bob's resume cookie.
	if st := auth("alice", "pw-a"); st != 200 {
		t.Fatalf("re-auth alice: status %d, want 200", st)
	}
	if s.registry.getBySID(bobSID) == nil {
		t.Fatal("bob's session was superseded by alice's re-auth")
	}
	if got := s.registry.count(); got != 2 {
		t.Fatalf("registry count after alice's re-auth: got %d, want 2", got)
	}
}

// TestRegistryCreateRejectsNilUser pins the registry contract: every session
// belongs to a user, because remove/sweep release the IP lease through user.Ip.
func TestRegistryCreateRejectsNilUser(t *testing.T) {
	pool, err := newIPPool("10.99.0.0/24")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	r := newSessionRegistry(pool)
	if _, err := r.create("1.2.3.4", nil, false); err == nil {
		t.Fatal("create with nil user: want error, got nil")
	}
	if got := r.count(); got != 0 {
		t.Fatalf("registry count: got %d, want 0", got)
	}
}

// TestConnectReplacesPreviousTunnel: a second CONNECT with the same cookie takes
// over the tunnel (ocserv's worker does the same). The superseded pump must
// close, must not drop the session's connected state, and must not leave its
// device writer behind: the replacement tunnel carries traffic.
func TestConnectReplacesPreviousTunnel(t *testing.T) {
	s := newTestServer(t)
	st, cookie := ocAuth(t, s, "testuser", "testpass")
	if st != 200 || cookie == "" {
		t.Fatalf("auth: status %d, cookie %q", st, cookie)
	}
	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil {
		t.Fatal("no session registered for cookie")
	}

	oldC, oldBr := mustTunnel(t, s, cookie)
	defer func() { _ = oldC.Close() }()
	if !sess.isConnected() {
		t.Fatal("first tunnel: session not connected")
	}

	newC, newBr := mustTunnel(t, s, cookie)
	defer func() { _ = newC.Close() }()

	// The superseded tunnel is closed by the server.
	setDeadline(t, oldC, 5*time.Second)
	if _, err := oldBr.Read(make([]byte, 1)); err == nil {
		t.Fatal("superseded tunnel still open after the new CONNECT")
	}

	// The session stays connected through the handover: the replacement owns
	// the tunnel count and the writer slot.
	deadline := time.Now().Add(5 * time.Second)
	for !sess.isConnected() {
		if time.Now().After(deadline) {
			t.Fatal("session lost its tunnel during the replacement")
		}
		time.Sleep(10 * time.Millisecond)
	}

	ipReq := buildICMPEchoRequest(sess.ip.AsSlice(), net.IPv4(1, 1, 1, 1), 0x77, 1, []byte("repl"))
	if _, err := newC.Write(cstFrame(acPKTData, ipReq)); err != nil {
		t.Fatalf("send data on the replacement tunnel: %v", err)
	}
	setDeadline(t, newC, 20*time.Second)
	if typ, _ := readCstFrame(t, newBr); typ != acPKTData {
		t.Fatalf("replacement tunnel reply type = %d, want DATA %d", typ, acPKTData)
	}
}

// mustTunnel opens a tunnel and fails the test unless the CONNECT was accepted.
func mustTunnel(t *testing.T, s *Server, cookie string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	st, c, br := ocTunnel(t, s, cookie)
	if st != 200 {
		t.Fatalf("CONNECT: status %d, want 200", st)
	}
	return c, br
}

// TestMaxClientsCountsLiveTunnels: max_clients bounds live tunnels, not session
// records. A session inside its resume window without a tunnel holds an IP
// lease, so a second client must still get in; once that client's tunnel is up,
// the limit bites again.
func TestMaxClientsCountsLiveTunnels(t *testing.T) {
	s := newTestServerUsers(t, []*User{
		{Name: "alice", Password: testPW("pw-a")},
		{Name: "bob", Password: testPW("pw-b")},
	})
	s.conf.MaxClients = 1

	stA, cookieA := ocAuth(t, s, "alice", "pw-a")
	if stA != 200 {
		t.Fatalf("alice auth: status %d, want 200", stA)
	}
	tunA, _ := mustTunnel(t, s, cookieA)
	sessA := s.registry.getBySID(sidFromCookie(t, s, cookieA))
	if sessA == nil {
		t.Fatal("no session for alice")
	}
	_ = tunA.Close()
	waitDisconnected(t, sessA)

	// Alice's session record is still in the registry (resume window), but her
	// tunnel is down: bob must be admitted.
	stB, cookieB := ocAuth(t, s, "bob", "pw-b")
	if stB != 200 {
		t.Fatalf("bob auth with one disconnected session: status %d, want 200", stB)
	}
	tunB, _ := mustTunnel(t, s, cookieB)
	defer func() { _ = tunB.Close() }()

	// Bob's tunnel is live: the limit applies again.
	stA2, _ := ocAuth(t, s, "alice", "pw-a")
	if stA2 != 503 {
		t.Fatalf("alice re-auth with one live tunnel: status %d, want 503", stA2)
	}
}
