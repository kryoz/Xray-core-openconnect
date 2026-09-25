package openconnect

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	// authTimeout bounds how long a control connection may idle during auth.
	authTimeout = 240 * time.Second
	// fallbackTimeout bounds the idle CSTP-fallback TCP connection after CONNECT.
	fallbackTimeout = 10 * time.Minute
	// dataMTUOverhead approximates UDP+IP overhead subtracted from the base MTU.
	dataMTUOverhead = 20
	// dtlsOverhead conservatively covers the DTLS record header + AEAD tag +
	// UDP/IP headers + the 1-byte OpenConnect framing. The gVisor NIC MTU is
	// clamped to baseMTU - dtlsOverhead so outgoing IP packets always fit the
	// DTLS tunnel (the client's own data MTU is a few bytes larger).
	dtlsOverhead = 80
	// cstpKeepalive is the keepalive interval advertised to the client.
	cstpKeepalive = 10
	// gcInterval is how often the session sweeper reaps expired sessions.
	gcInterval = 30 * time.Second
)

// serverRandomSniffer tees the first server→client TLS flight to capture the
// ServerHello random. Go's tls package does not export the server random, but
// the DTLS PSK derivation needs it (gnutls_prf seeds with client_random ||
// server_random).
type serverRandomSniffer struct {
	net.Conn
	mu           sync.Mutex
	serverRandom []byte
}

// Write captures the random from the first flight, then forwards.
// Offsets: record header 5 (type+version+length), handshake type+length 4,
// protocol version 2 → random at 11, 32 bytes.
func (h *serverRandomSniffer) Write(b []byte) (int, error) {
	n, err := h.Conn.Write(b)
	h.mu.Lock()
	if h.serverRandom == nil && len(b) >= 43 && b[0] == 0x16 && b[5] == 0x02 {
		h.serverRandom = append([]byte(nil), b[11:43]...)
	}
	h.mu.Unlock()
	return n, err
}

func (s *Server) acceptLoop() {
	for {
		raw, err := s.tcpLn.Accept()
		if err != nil {
			return
		}
		go s.handleControl(raw)
	}
}

// handleControl runs the TLS control channel for one client connection.
func (s *Server) handleControl(raw net.Conn) {
	defer raw.Close()
	peer := raw.RemoteAddr().String()
	peerIP := hostFromAddr(raw)

	kl := &keyLog{}
	sniff := &serverRandomSniffer{Conn: raw}
	// TLS 1.2 only: the DTLS PSK is derived from the TLS master secret via
	// the RFC 5705 exporter; Go's KeyLogWriter never exposes the TLS 1.3
	// exporter_master_secret, so 1.3 sessions cannot yield a PSK.
	tc := tls.Server(sniff, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		KeyLogWriter: kl,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(s.ctx); err != nil {
		errors.LogDebug(s.ctx, fmt.Sprintf("openconnect: TLS handshake from %s failed: %s", peer, err))
		return
	}
	defer tc.Close()
	kl.setServerRandom(sniff.serverRandom)

	// One bufio.Reader for the whole control connection: reusing it preserves
	// any bytes the reader buffered past the current request.
	br := bufio.NewReaderSize(tc, 8192)
	for {
		tc.SetReadDeadline(time.Now().Add(authTimeout))
		req, err := readHTTP(br)
		if err != nil {
			return
		}
		done := s.dispatch(tc, req, peerIP, kl)
		if done {
			return
		}
	}
}

// dispatch routes one control request. It returns true when the connection's
// control phase is over (e.g. after CONNECT, which keeps the socket open).
func (s *Server) dispatch(tc *tls.Conn, req *httpReq, peerIP string, kl *keyLog) bool {
	switch {
	case (req.method == "GET" || req.method == "POST") && (req.path == "/" || req.path == "/index.html"):
		// ocserv answers both GET / and the client's initial POST / with the login form.
		_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", nil, loginForm)
	case req.method == "POST" && req.path == "/auth":
		s.handleAuth(tc, req, peerIP, kl)
	case req.method == "CONNECT":
		s.handleConnect(tc, req, kl)
		return true
	default:
		_ = writeHTTP(tc, 404, "text/plain", nil, "not found")
	}
	return false
}

func (s *Server) handleAuth(tc *tls.Conn, req *httpReq, peerIP string, kl *keyLog) {
	if s.limiter.blocked(peerIP) {
		_ = writeHTTP(tc, 401, "text/xml; charset=utf-8", nil, failMsg)
		return
	}
	vals := parseForm(req.body)

	if u, ok := vals["username"]; ok {
		s.setPendingUser(peerIP, u)
		_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", nil, passwdForm)
		return
	}

	pw, hasPw := vals["password"]
	if !hasPw {
		_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", nil, loginForm)
		return
	}

	user := s.takePendingUser(peerIP)
	if user == "" || !s.users.check(user, pw) {
		s.limiter.recordFailure(peerIP)
		errors.LogWarning(s.ctx, fmt.Sprintf("openconnect: auth failed for %q from %s", user, peerIP))
		_ = writeHTTP(tc, 401, "text/xml; charset=utf-8", nil, failMsg)
		return
	}
	s.limiter.reset(peerIP)

	if s.conf.MaxClients > 0 && s.registry.count() >= int(s.conf.MaxClients) {
		errors.LogWarning(s.ctx, fmt.Sprintf("openconnect: max clients reached, rejecting %s", peerIP))
		_ = writeHTTP(tc, 503, "text/plain", nil, "too many clients")
		return
	}

	// The App-ID is an opaque correlation token echoed back in the DTLS
	// ClientHello: a fresh random value is fine (and better than ocserv's
	// TLS-session-ID, which Go's TLS 1.2 server never issues anyway).
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		_ = writeHTTP(tc, 500, "text/plain", nil, "internal error")
		return
	}
	sess, err := s.registry.create(hex.EncodeToString(raw), peerIP, s.users.userByName(user))
	if err != nil {
		_ = writeHTTP(tc, 500, "text/plain", nil, "internal error")
		return
	}
	psk, err := kl.pskKey()
	if err != nil {
		s.registry.remove(sess)
		_ = writeHTTP(tc, 500, "text/plain", nil, "internal error")
		return
	}
	sess.setPSK(psk)
	errors.LogInfo(s.ctx, fmt.Sprintf("openconnect: auth OK user=%s ip=%s appID=%s", user, sess.ip, sess.appID))

	// ocserv sets both webvpncontext (new) and webvpn (legacy); libopenconnect
	// echoes back "webvpn", so we set both to the same SID.
	sidB64 := base64.StdEncoding.EncodeToString(sess.sid[:])
	maxAge := int64(s.cookieTimeoutSecs())
	cookies := "Set-Cookie: webvpncontext=" + sidB64 + "; Max-Age=" + strconv.FormatInt(maxAge, 10) + "; Secure; HttpOnly\r\n" +
		"Set-Cookie: webvpn=" + sidB64 + "; Secure; HttpOnly"
	_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", map[string]string{"Set-Cookie": cookies}, successMsg)
}

func (s *Server) handleConnect(tc *tls.Conn, req *httpReq, kl *keyLog) {
	sess := s.sessFromCookie(req.headers["cookie"])
	if sess == nil {
		_ = writeHTTP(tc, 401, "text/plain", nil, "unauthorized")
		return
	}
	// Resume: a valid cookie lets the client skip the auth forms. Reject once
	// the cookie/resume window (cookie_timeout after the last disconnect) has elapsed.
	if sess.expired(time.Now(), time.Duration(s.cookieTimeoutSecs())*time.Second) {
		s.registry.remove(sess)
		_ = writeHTTP(tc, 401, "text/plain", nil, "unauthorized")
		return
	}
	// The client re-keyed on a fresh TLS handshake, so re-derive the DTLS PSK
	// from THIS connection's TLS session, not the stale one. The App-ID is
	// a server-chosen token and stays stable across resumes.
	psk, err := kl.pskKey()
	if err != nil {
		_ = writeHTTP(tc, 500, "text/plain", nil, "internal error")
		return
	}
	sess.setPSK(psk)
	sess.markConnected()
	errors.LogInfo(s.ctx, fmt.Sprintf("openconnect: CONNECT tunnel ip=%s appID=%s", sess.ip, sess.appID))
	// ocserv sends NO body after the blank line; the client reads the rest as
	// tunnel data. The TCP connection then stays open as the CSTP fallback.
	_ = writeHTTP(tc, 200, "", s.connectHeaders(sess), "")
	s.keepOpen(tc)
	sess.markDisconnected()
}

// keepOpen holds the connection open as the CSTP fallback channel, discarding
// data, until the client closes it or it idles past fallbackTimeout.
// ponytail: discards CSTP/TCP-fallback traffic; real TCP fallback lands in Phase 4.
func (s *Server) keepOpen(tc *tls.Conn) {
	buf := make([]byte, 4096)
	for {
		tc.SetReadDeadline(time.Now().Add(fallbackTimeout))
		if _, err := tc.Read(buf); err != nil {
			return
		}
	}
}

// gcLoop periodically reaps disconnected sessions whose resume window elapsed,
// freeing their dynamic IPs. Runs until the server context is cancelled.
func (s *Server) gcLoop() {
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if n := s.registry.sweep(time.Duration(s.cookieTimeoutSecs()) * time.Second); n > 0 {
				errors.LogInfo(s.ctx, fmt.Sprintf("openconnect: gc swept %d expired session(s)", n))
			}
		}
	}
}

func (s *Server) connectHeaders(sess *ocSession) map[string]string {
	baseMTU := s.conf.Mtu
	if baseMTU == 0 {
		baseMTU = DefaultMTU
	}
	dpd := s.conf.Dpd
	if dpd == 0 {
		dpd = DefaultDPD
	}
	udpPort := int(s.src.Port)
	if s.conf.DtlsPort != 0 {
		udpPort = int(s.conf.DtlsPort)
	}
	hdrs := map[string]string{
		"X-CSTP-Address":     sess.ip.String(),
		"X-CSTP-Netmask":     s.registry.pool.netmask(),
		"X-CSTP-Base-MTU":    strconv.FormatUint(uint64(baseMTU), 10),
		"X-CSTP-MTU":         strconv.FormatUint(uint64(baseMTU-dataMTUOverhead), 10),
		"X-CSTP-Keepalive":   strconv.Itoa(cstpKeepalive),
		"X-CSTP-DPD":         strconv.FormatUint(uint64(dpd), 10),
		"X-CSTP-Rekey-Time":  "0",
		"X-DTLS-Port":        strconv.Itoa(udpPort),
		"X-DTLS-App-ID":      sess.appID,
		"X-DTLS-CipherSuite": "PSK-NEGOTIATE",
	}
	if len(s.conf.Dns) > 0 {
		hdrs["X-CSTP-DNS"] = strings.Join(s.conf.Dns, ",")
	}
	// No X-DTLS-Content-Encoding: ocserv omits it when compression is off.
	return hdrs
}

// sessFromCookie resolves "webvpncontext=<base64(sid)>" or "webvpn=<base64(sid)>"
// to a session.
func (s *Server) sessFromCookie(cookieHdr string) *ocSession {
	name := "webvpn="
	if i := strings.Index(cookieHdr, "webvpncontext="); i >= 0 {
		name = "webvpncontext="
	}
	i := strings.Index(cookieHdr, name)
	if i < 0 {
		return nil
	}
	v := cookieHdr[i+len(name):]
	if j := strings.IndexAny(v, "; \t"); j >= 0 {
		v = v[:j]
	}
	sid, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(sid) != 32 {
		return nil
	}
	var key [32]byte
	copy(key[:], sid)
	return s.registry.getBySID(key)
}

func (s *Server) setPendingUser(peerIP, user string) {
	s.pendingMu.Lock()
	s.pendingUser[peerIP] = user
	s.pendingMu.Unlock()
}

// takePendingUser returns and removes the username staged for the client IP.
// It is consumed exactly once, at the password step, so a stale username can
// never be replayed by a later password-only POST from the same IP.
func (s *Server) takePendingUser(peerIP string) string {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	u := s.pendingUser[peerIP]
	delete(s.pendingUser, peerIP)
	return u
}

func (s *Server) cookieTimeoutSecs() uint32 {
	if s.conf.CookieTimeout == 0 {
		return DefaultCookieTimeout
	}
	return s.conf.CookieTimeout
}

// hostFromAddr extracts the IP (no port) from a connection's remote address.
func hostFromAddr(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

// Forms mirror ocserv src/worker-auth.c constants.
const loginForm = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
<auth id="main">
<message>Please enter your username and password.</message>
<form method="post" action="/auth">
<input type="text" name="username" label="Username:" />
</form></auth>
</config-auth>`

const passwdForm = `<?xml version="1.0" encoding="UTF-8"?>
<auth id="passwd">
<message>Please enter your password.</message>
<form method="post" action="/auth">
<input type="password" name="password" label="Password:" />
</form></auth>`

const successMsg = `<?xml version="1.0" encoding="UTF-8"?>
<auth id="success">
<title>SSL VPN Service</title>
</auth>
`

const failMsg = `<?xml version="1.0" encoding="UTF-8"?>
<auth id="fail">
<message>Authentication failed.</message>
</auth>
`
