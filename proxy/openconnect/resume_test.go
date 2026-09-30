package openconnect

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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

// newTestServer builds a Server on a free localhost port, bypassing the DI path
// (policy/dispatcher are unused by the control channel).
func newTestServer(t *testing.T) *Server {
	t.Helper()
	tcpPort := freePort(t, "tcp")
	udpPort := freePort(t, "udp")

	conf := &OpenConnectInboundConfig{
		Users:         []*User{{Name: "testuser", Password: testPW("testpass")}},
		Subnet:        "10.99.0.0/24",
		Mtu:           1400,
		Dpd:           90,
		CookieTimeout: 300,
		DtlsPort:      uint32(udpPort),
	}
	pool, err := newIPPool(conf.Subnet)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	users, err := newUserStore(conf.Users)
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
		conf:     conf,
		ctx:      tctx,
		cancel:   cancel,
		src:      xnet.DestinationFromAddr(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tcpPort}),
		cert:     cert,
		registry: registry,
		users:    users,
		limiter:  newAuthLimiter(),

		stack:  stack,
		device: stack.device,
		pipes:  make(map[string]*ocPipe),
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

	// Give the server a moment to observe the disconnect.
	time.Sleep(50 * time.Millisecond)

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

// TestRegistryRemoveKeepsSuccessor covers two sessions sharing one client IP
// (static-IP user, or two clients behind one NAT): the old session's removal
// must not clobber the successor's index entries.
func TestRegistryRemoveKeepsSuccessor(t *testing.T) {
	pool, err := newIPPool("10.77.0.0/24")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	r := newSessionRegistry(pool)
	u := &User{Name: "alice"}
	old, err := r.create("app-old", "1.2.3.4", u, false)
	if err != nil {
		t.Fatalf("create old: %v", err)
	}
	fresh, err := r.create("app-new", "1.2.3.4", u, false)
	if err != nil {
		t.Fatalf("create fresh: %v", err)
	}
	r.remove(context.Background(), old, "test")
	if got := r.getByClientIP("1.2.3.4"); got != fresh {
		t.Fatalf("byClientIP after old remove: want fresh session, got %+v", got)
	}
	if got := r.getByAppID("app-new"); got != fresh {
		t.Fatal("successor byAppID lost")
	}
	r.remove(context.Background(), fresh, "test")
	if got := r.getByClientIP("1.2.3.4"); got != nil {
		t.Fatal("byClientIP after fresh remove: want nil")
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
	sess, err := r.create("", "1.2.3.4", user, false)
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
