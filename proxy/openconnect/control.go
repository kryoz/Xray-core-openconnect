package openconnect

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	stderrors "errors"

	"github.com/xtls/xray-core/common/errors"
)

const (
	// authTimeout bounds how long a control connection may idle during auth.
	authTimeout = 240 * time.Second
	// dtlsOverhead is the exact wire cost of one CSTP frame inside a DTLS 1.2
	// AEAD record: 13 record header + 8 explicit nonce + 16 AEAD tag + 1 CSTP
	// type byte + 20 IPv4 + 8 UDP. Both the advertised X-CSTP-MTU and the
	// gVisor NIC MTU are baseMTU - dtlsOverhead, so a maximal IP packet in
	// either direction is a datagram of exactly the base MTU: no outer
	// fragmentation, and the client-side MSS (X-CSTP-MTU - 40) lines up with
	// the server-side one — sub-MSS incoming segments no longer split into
	// two datagrams each (the ~1.4x pps anomaly of the 2026-09-27 report).
	dtlsOverhead = 66
	// cstpKeepalive is the keepalive interval advertised to the client and
	// used by the server-side CSTP keepalive timer (cstpPump).
	cstpKeepalive = 10
	// gcInterval is how often the session sweeper reaps expired sessions.
	gcInterval = 30 * time.Second
	// cstpCoalesceWindow bounds how long a negotiated multi-frame session's
	// downlink frames wait for more frames before one coalesced TLS write.
	// The fifo qdisc drains eagerly (a single bulk flow yields 1–2 packets
	// per WritePackets call), so without a window the batches stay tiny and
	// the write(2) count barely drops (2026-10-03 profile: write path −44%,
	// syscalls only −28%). 200µs adds at most one window of latency per
	// burst and gathers ~10 frames at bulk rates. The earlier 500µs timer
	// regression was the stock client's framing — this writer is installed
	// only for sessions that negotiated multi-frame.
	cstpCoalesceWindow = 200 * time.Microsecond
	// cstpCoalesceMaxBytes flushes early once the pending buffer holds two
	// TLS records (2 × 16KiB): under line-rate bursts the cap, not the
	// timer, drives flushing — near-zero added latency, bounded memory.
	cstpCoalesceMaxBytes = 32 * 1024

	// hdrMultiFrame is the CSTP multi-frame negotiation header. A client
	// whose CONNECT carries "X-CSTP-Multi-Frame-Capability: true" parses
	// several STF frames per TLS record (length-prefixed stream), so the
	// server coalesces that session's downlink frames into one TLS write;
	// every other client gets one frame per record, which stock openconnect
	// (cstp.c cstp_mainloop) requires. The server always answers with the
	// same header: its read path (readCSTPFrame) is stream-oriented, so
	// such clients may batch their uplink frames too.
	hdrMultiFrame = "X-CSTP-Multi-Frame-Capability"
)

// serverRandomSniffer tees the first server→client TLS flight to capture the
// ServerHello random. Go's tls package does not export the server random, but
// the DTLS PSK derivation needs it (gnutls_prf seeds with client_random ||
// server_random).
type serverRandomSniffer struct {
	net.Conn
	// serverRandom is captured once from the first ServerHello flight and
	// never changes after: an atomic.Pointer keeps the hot Write path free of
	// a mutex on every packet once the random is already captured.
	serverRandom atomic.Pointer[[]byte]
}

// Write captures the random from the first flight, then forwards.
// Offsets: record header 5 (type+version+length), handshake type+length 4,
// protocol version 2 → random at 11, 32 bytes.
func (h *serverRandomSniffer) Write(b []byte) (int, error) {
	n, err := h.Conn.Write(b)
	if h.serverRandom.Load() == nil && len(b) >= 43 && b[0] == 0x16 && b[5] == 0x02 {
		r := append([]byte(nil), b[11:43]...)
		h.serverRandom.Store(&r)
	}
	return n, err
}

func (s *Server) acceptLoop() {
	for {
		raw, err := s.tcpLn.Accept()
		if err != nil {
			// A transient error (e.g. EMFILE) must not disappear silently:
			// the control channel is down until the process restarts.
			if !stderrors.Is(err, net.ErrClosed) {
				errors.LogError(s.ctx, "openconnect: TCP accept loop stopped: ", err)
			}
			return
		}
		go s.handleControl(raw)
	}
}

// handleControl runs the TLS control channel for one client connection.
func (s *Server) handleControl(raw net.Conn) {
	defer func() { _ = raw.Close() }()
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
		// SHA-256-PRF suites only: the DTLS PSK is derived via the RFC 5705
		// exporter, whose PRF is the negotiated suite's — derivePSK12 hardcodes
		// P_SHA256, so a SHA-384 suite would silently desync the PSK and push
		// every such client onto the TCP fallback.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	})
	if err := tc.HandshakeContext(s.ctx); err != nil {
		errors.LogDebug(s.ctx, fmt.Sprintf("openconnect: TLS handshake from %s failed: %s", peer, err))
		return
	}
	defer func() { _ = tc.Close() }()
	if sr := sniff.serverRandom.Load(); sr != nil {
		kl.setServerRandom(*sr)
	}

	// One bufio.Reader for the whole control connection: reusing it preserves
	// any bytes the reader buffered past the current request.
	br := bufio.NewReaderSize(tc, 8192)
	var camoOK bool // camouflage passed on this connection (secret or cookie)
	// pendingUser is connection-local: the username and password POSTs arrive
	// on the same TLS connection, so the staged name lives here — not in a
	// server-wide map keyed by peer IP — and dies with the connection.
	var pendingUser string
	for {
		_ = tc.SetReadDeadline(time.Now().Add(authTimeout))
		req, err := readHTTP(br)
		if err != nil {
			return
		}
		// ocserv-compatible camouflage: until the check passes on this
		// connection, GET/POST without the secret look like a plain web
		// server. CONNECT is exempt (it already requires a session cookie).
		if s.conf.CamouflageSecret != "" && !camoOK && req.method != "CONNECT" {
			if s.sessFromCookie(req.headers["cookie"]) != nil || req.query == s.conf.CamouflageSecret {
				camoOK = true
			} else {
				// The secret is a credential too: feed the same limiter as /auth,
				// else it stays an unlimited brute-force hole next to a limited one.
				s.noteAuthFailure(peerIP)
				errors.LogInfo(s.ctx, fmt.Sprintf("openconnect: camouflage: secret not found in URL from %s, declining", peerIP))
				s.rejectCamouflage(tc)
				return
			}
		}
		done := s.dispatch(tc, br, req, peerIP, kl, &pendingUser)
		if done {
			return
		}
	}
}

// rejectCamouflage answers a request that failed the camouflage check the way
// ocserv does: a browser-facing 401 with the configured realm, or a plain 404.
// Both close the connection.
func (s *Server) rejectCamouflage(tc *tls.Conn) {
	if realm := s.conf.CamouflageRealm; realm != "" {
		_ = writeHTTP(tc, 401, "",
			map[string][]string{"WWW-Authenticate": {`Basic realm="` + realm + `"`}},
			"<html><body><h1>401 Unauthorized</h1></body></html>\r\n")
		return
	}
	_ = writeHTTP(tc, 404, "", nil, "<html><body><h1>404 Not Found</h1></body></html>\r\n")
}

// dispatch routes one control request. It returns true when the connection's
// control phase is over (e.g. after CONNECT, which keeps the socket open).
func (s *Server) dispatch(tc *tls.Conn, br *bufio.Reader, req *httpReq, peerIP string, kl *keyLog, pending *string) bool {
	switch {
	case (req.method == "GET" || req.method == "POST") && (req.path == "/" || req.path == "/index.html"):
		// ocserv answers both GET / and the client's initial POST / with the login form.
		_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", nil, loginForm)
	case req.method == "POST" && req.path == "/auth":
		s.handleAuth(tc, req, peerIP, kl, pending)
	case req.method == "CONNECT":
		s.handleConnect(tc, br, req, kl)
		return true
	default:
		_ = writeHTTP(tc, 404, "text/plain", nil, "not found")
	}
	return false
}

func (s *Server) handleAuth(tc *tls.Conn, req *httpReq, peerIP string, kl *keyLog, pending *string) {
	if s.limiter.blocked(peerIP) {
		_ = writeHTTP(tc, 401, "text/xml; charset=utf-8", nil, failMsg)
		return
	}
	vals := parseForm(req.body)
	user, hasUser := vals["username"]
	pw, hasPw := vals["password"]

	if hasUser {
		// User names are short by construction; reject pathologically long
		// ones outright instead of carrying them around.
		if len(user) > 255 {
			s.noteAuthFailure(peerIP)
			_ = writeHTTP(tc, 401, "text/xml; charset=utf-8", nil, failMsg)
			return
		}
	}

	switch {
	case hasUser && hasPw:
		// ocserv parity: the main form asks for username and password
		// together, and clients (libopenconnect also re-sends the username
		// with the password-only form) submit both in one POST —
		// authenticate in a single round instead of re-asking.
	case hasUser:
		// Split flow: stage the username; the password POST arrives on this
		// same TLS connection.
		*pending = user
		_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", nil, passwdForm)
		return
	case hasPw:
		user = *pending
	default:
		_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", nil, loginForm)
		return
	}

	if user == "" {
		// Password arrived without a staged username on this connection: a
		// broken client flow, not a wrong credential — don't burn a strike.
		_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", nil, loginForm)
		return
	}
	if !s.users.check(user, pw) {
		s.noteAuthFailure(peerIP)
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
	u := s.users.userByName(user)
	sess, err := s.registry.create(hex.EncodeToString(raw), peerIP, u, s.conf.l3For(u))
	if err != nil {
		_ = writeHTTP(tc, 500, "text/plain", nil, "internal error")
		return
	}
	psk, err := kl.pskKey()
	if err != nil {
		s.registry.remove(s.ctx, sess, "psk derivation failed")
		_ = writeHTTP(tc, 500, "text/plain", nil, "internal error")
		return
	}
	sess.setPSK(psk)
	sess.logSessionStart(s.ctx, s.conf.dtlsFor(u))

	// ocserv sets both webvpncontext (new) and webvpn (legacy); libopenconnect
	// echoes back "webvpn", so we set both to the same SID.
	sidB64 := base64.StdEncoding.EncodeToString(sess.sid[:])
	maxAge := int64(s.cookieTimeoutSecs())
	cookies := "Set-Cookie: webvpncontext=" + sidB64 + "; Max-Age=" + strconv.FormatInt(maxAge, 10) + "; Secure; HttpOnly\r\n" +
		"Set-Cookie: webvpn=" + sidB64 + "; Secure; HttpOnly"
	_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", map[string][]string{"Set-Cookie": {cookies}}, successMsg)
}

func (s *Server) handleConnect(tc *tls.Conn, br *bufio.Reader, req *httpReq, kl *keyLog) {
	sess := s.sessFromCookie(req.headers["cookie"])
	if sess == nil {
		_ = writeHTTP(tc, 401, "text/plain", nil, "unauthorized")
		return
	}
	// Resume: a valid cookie lets the client skip the auth forms. Reject once
	// the cookie/resume window (cookie_timeout after the last disconnect) has elapsed.
	if sess.expired(time.Now(), time.Duration(s.cookieTimeoutSecs())*time.Second) {
		s.registry.remove(s.ctx, sess, "cookie/resume window expired")
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
	// Multi-frame support is per-connection: each CONNECT (including resume
	// and rekey) re-negotiates it from the request headers.
	multiFrame := strings.EqualFold(req.headers["x-cstp-multi-frame-capability"], "true")
	// Paired with "tunnel closed" from cstpPump: open/close per CSTP
	// connection, while "session start"/"session end" bracket the whole
	// cookie lifetime.
	errors.LogInfo(s.ctx, fmt.Sprintf("openconnect: tunnel open user=%s ip=%s peer=%s appID=%s multiFrame=%t",
		sess.userName(), sess.ip, sess.clientIP, sess.appID, multiFrame))
	// ocserv sends NO body after the blank line; the client reads the rest as
	// tunnel data. The TCP connection then stays open as the CSTP fallback.
	_ = writeHTTP(tc, 200, "", s.connectHeaders(sess), "")
	s.cstpPump(sess, tc, br, multiFrame)
}

// stfBatch packs several [acPKTData]+IP frames into one CSTP/TCP buffer, each
// as an "STF\x1"+len+type frame, so a single tls.Conn.Write carries several
// DATA packets (crypto/tls still splits the buffer into ≤16KiB records; a
// multi-frame client parses them as a length-prefixed stream). It is
// installed only for sessions that sent X-CSTP-Multi-Frame-Capability in
// their CONNECT: the stock openconnect client (cstp.c cstp_mainloop) requires
// len == 8 + payload_len per SSL_read, and several frames in one TLS record
// break it with "Unexpected packet length".
func stfBatch(frames [][]byte) []byte {
	total := 0
	for _, f := range frames {
		total += 8 + len(f) - 1 // header + IP payload (f[1:])
	}
	buf := make([]byte, total)
	off := 0
	for _, f := range frames {
		copy(buf[off:], "STF\x01")
		binary.BigEndian.PutUint16(buf[off+4:off+6], uint16(len(f)-1))
		buf[off+6] = acPKTData
		off += 8
		off += copy(buf[off:], f[1:])
	}
	return buf
}

// cstpCoalescer buffers the downlink frames of one negotiated multi-frame
// CSTP session and flushes them as a single TLS write when the window
// elapses or the pending buffer reaches max. Timer-fired and synchronous
// (cap) flushes race safely: pending is swapped under mu, the writer is
// serialized by the caller's wmu. Write errors are ignored — the pump's
// read side owns tunnel teardown.
type cstpCoalescer struct {
	window time.Duration
	max    int
	write  func(frames [][]byte) error

	mu      sync.Mutex
	pending [][]byte
	bytes   int
	timer   *time.Timer
	closed  bool
}

// add buffers frames and arms the window (measured from the first pending
// frame, so latency is bounded); a full buffer flushes synchronously so
// bursts never wait out the timer.
func (c *cstpCoalescer) add(frames [][]byte) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.pending = append(c.pending, frames...)
	for _, f := range frames {
		c.bytes += len(f) - 1 // IP payload; the acPKTData byte is noise
	}
	full := c.bytes >= c.max
	if c.timer == nil {
		c.timer = time.AfterFunc(c.window, c.flush)
	}
	c.mu.Unlock()
	if full {
		c.flush()
	}
}

// flush writes and clears the pending frames. Concurrent calls are safe: the
// loser observes an empty buffer; after close nothing is written.
func (c *cstpCoalescer) flush() {
	c.mu.Lock()
	frames := c.pending
	c.pending = nil
	c.bytes = 0
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
	if len(frames) > 0 {
		_ = c.write(frames)
	}
}

// close stops the timer and drops pending frames. A flush that already
// swapped its frames may still write once; a failing write is ignored.
func (c *cstpCoalescer) close() {
	c.mu.Lock()
	c.closed = true
	c.pending = nil
	c.bytes = 0
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
}

// cstpPump runs the CSTP/TCP channel after CONNECT. It parses STF-framed
// packets, feeds DATA into the device (for clients without DTLS — CGNAT with
// UDP blocked — this is the only data path), answers DPD, and mirrors the DTLS
// liveness machine over TCP: AC_PKT_KEEPALIVE every cstpKeepalive seconds of
// idle, AC_PKT_DPD_OUT after dpd seconds, teardown after 2×dpd without any
// frame (ocserv src/worker-vpn.c timers). With multiFrame set (the client
// negotiated X-CSTP-Multi-Frame-Capability), the downlink frames of one
// gVisor flush are coalesced into a single TLS write; otherwise each frame is
// its own TLS record, which stock clients require.
func (s *Server) cstpPump(sess *ocSession, tc *tls.Conn, br *bufio.Reader, multiFrame bool) {
	// The device writer (gVisor goroutine) and the keepalive/DPD timers below
	// both write to the TLS connection; crypto/tls does not document
	// concurrent Write as safe, so serialize frames here.
	var wmu sync.Mutex
	writeFrame := func(typ byte, payload []byte) error {
		f := make([]byte, 8+len(payload))
		copy(f, "STF\x01")
		binary.BigEndian.PutUint16(f[4:6], uint16(len(payload)))
		f[6] = typ
		copy(f[8:], payload)
		wmu.Lock()
		defer wmu.Unlock()
		_, err := tc.Write(f)
		return err
	}
	deviceWriter := func(framed []byte) error { // device contract: [acPKTData]+ip
		return writeFrame(acPKTData, framed[1:])
	}
	// Coalescing batch writer for negotiated sessions: frames buffer for one
	// cstpCoalesceWindow (or until two TLS records are pending) and leave as
	// a single tc.Write — stfBatch concatenates the STF frames and a
	// multi-frame client decodes them as a stream. The 2026-10-03 profile
	// showed the fifo qdisc's eager drain keeps per-flush batches at 1–2
	// frames, so the window is what actually gathers them. Stock sessions
	// never see this writer: they need one frame per TLS record.
	var coalescer cstpCoalescer
	batchWriter := func(frames [][]byte) error {
		coalescer.add(frames)
		return nil
	}
	if multiFrame {
		coalescer.window = cstpCoalesceWindow
		coalescer.max = cstpCoalesceMaxBytes
		coalescer.write = func(frames [][]byte) error {
			wmu.Lock()
			defer wmu.Unlock()
			_, err := tc.Write(stfBatch(frames))
			return err
		}
		defer coalescer.close()
	}
	// registerCSTP installs this pump as the session's device writer,
	// batch-capable only when the client negotiated multi-frame support.
	registerCSTP := func() *ocWriter {
		if multiFrame {
			return s.device.registerBatch(sess.ip, deviceWriter, batchWriter)
		}
		return s.device.register(sess.ip, deviceWriter)
	}

	// Registered BEFORE the writer-cleanup defer below so it runs after it
	// (defers are LIFO): by logging time the cleanup has already set
	// connected=false, so the line reflects the settled state.
	started := time.Now()
	closeReason := "client closed CSTP"
	defer func() { sess.logTunnelClosed(s.ctx, closeReason, started) }()

	// Own the device writer unless DTLS already took it over; when DTLS later
	// tears down, teardownDTLS falls back to this writer. The token is kept
	// in sess.dtlsWriter — the single "current registration" slot — so every
	// takeover (DTLS start, CSTP-DATA steal, DTLS-teardown handback) and this
	// defer remove exactly the entry that is live.
	sess.mu.Lock()
	sess.cstpWrite = deviceWriter
	if multiFrame {
		sess.cstpBatch = batchWriter
	} else {
		// nil keeps the DTLS-teardown handback on the per-frame path.
		sess.cstpBatch = nil
	}
	if sess.dtlsConn == nil {
		sess.dtlsWriter = registerCSTP()
	}
	sess.mu.Unlock()
	defer func() {
		sess.mu.Lock()
		sess.cstpWrite = nil
		sess.cstpBatch = nil
		if sess.dtlsConn == nil {
			s.device.unregisterIf(sess.ip, sess.dtlsWriter)
			sess.dtlsWriter = nil
			sess.connected = false
			sess.lastDisc = time.Now()
		}
		sess.mu.Unlock()
	}()

	ka := time.Duration(cstpKeepalive) * time.Second
	dpd := time.Duration(s.dpdSecs()) * time.Second
	buf := make([]byte, 65536)
	lastRead := time.Now()
	from := sess.ip
	for {
		select {
		case <-s.ctx.Done():
			closeReason = "server shutdown"
			return
		default:
		}
		_ = tc.SetReadDeadline(time.Now().Add(ka))
		typ, payload, err := readCSTPFrame(tc, br, buf)
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				switch idle := time.Since(lastRead); {
				case idle >= 2*dpd:
					closeReason = fmt.Sprintf("DPD timeout (no frame for %s)", idle.Round(time.Second))
					errors.LogWarning(s.ctx, "openconnect: CSTP DPD timeout for ", sess.ip, " (user ", sess.userName(), ", peer ", sess.clientIP, ")")
					return
				case idle >= dpd:
					_ = writeFrame(acPKTDPDOut, nil)
				default:
					_ = writeFrame(acPKTKeepalive, nil)
				}
				continue
			}
			if err != io.EOF {
				closeReason = "read error: " + err.Error()
				// A read error is the normal consequence of the client's path
				// going away (NAT rebind, mobile handover, ISP drop) and the
				// single most useful clue when a client "cannot connect" —
				// hence Warning, not Info.
				errors.LogWarning(s.ctx, "openconnect: CSTP read error for ", sess.ip, " (user ", sess.userName(), ", peer ", sess.clientIP, "): ", err)
			} else {
				closeReason = "client closed TCP (EOF)"
			}
			return
		}
		lastRead = time.Now()
		switch typ {
		case acPKTData:
			if len(payload) == 0 || len(payload) > int(s.mtu()) {
				errors.LogWarning(s.ctx, "openconnect: dropping bad data frame from ", sess.ip, " (", len(payload), " bytes)")
				continue
			}
			// Data over TCP while a DTLS tunnel is registered means the
			// client fell back to CSTP (resume without DTLS, UDP black-holed)
			// and no longer reads its DTLS socket: take the device writer
			// back or the tunnel keeps draining relayed packets into it.
			sess.mu.Lock()
			if stale := sess.dtlsConn; stale != nil {
				sess.dtlsConn = nil
				sess.dtlsWriter = registerCSTP()
				sess.mu.Unlock()
				// Capture the dead generation's pipe before closing: a newer
				// generation may register its own pipe in the meantime
				// (sess.pipe is guarded by dmuMu, not sess.mu), and dropping
				// by pointer cannot kill it.
				s.dmuMu.Lock()
				stalePipe := sess.pipe
				s.dmuMu.Unlock()
				_ = stale.Close()
				// Drop the dead DTLS pipe or it stays in s.pipes and swallows
				// the client's next DTLS ClientHello (C3).
				if stalePipe != nil {
					s.dropPipe(sess, stalePipe)
				}
				errors.LogInfo(s.ctx, "openconnect: CSTP data with live DTLS for ", sess.ip, ", falling back to CSTP writer")
			} else {
				sess.mu.Unlock()
			}
			// Copy once into a frame [acPKTData]+IP the L3 relay can hand to
			// the peer tunnel as-is.
			frame := make([]byte, 1+len(payload))
			frame[0] = acPKTData
			copy(frame[1:], payload)
			select {
			case s.device.rxCh <- ocRxPkt{from: from, frame: frame}:
			default:
			}
		case acPKTDPDOut:
			_ = writeFrame(acPKTDPDResp, nil)
		case acPKTDPDResp, acPKTKeepalive:
			// liveness only; lastRead already recorded
		case acPKTDisconnect, acPKTTerm:
			closeReason = "client sent CSTP disconnect"
			return
		default:
			closeReason = fmt.Sprintf("unknown CSTP frame type %d", typ)
			errors.LogWarning(s.ctx, "openconnect: unknown CSTP frame type ", typ, " from ", sess.ip, " (user ", sess.userName(), ", peer ", sess.clientIP, ")")
			return
		}
	}
}

// readCSTPFrame reads one STF-framed CSTP packet from the TLS stream. The
// 8-byte header ("STF\x1", big-endian payload length, type, reserved zero)
// exists only over TCP; DTLS uses bare 1-byte types. A read deadline that
// fires before the first byte of the frame arrives is returned as a timeout
// error so the caller can run its keepalive/DPD timers; a timeout or garbage
// mid-frame returns a non-timeout error — the stream cannot be resynced, so
// the connection is torn down.
func readCSTPFrame(tc *tls.Conn, br *bufio.Reader, buf []byte) (byte, []byte, error) {
	started := false
	read := func(p []byte) error {
		for len(p) > 0 {
			n, err := br.Read(p)
			p = p[n:]
			if n > 0 {
				started = true
			}
			if err != nil {
				if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
					if br.Buffered() > 0 {
						continue // buffered bytes remain; the deadline does not apply
					}
					if started {
						return fmt.Errorf("stalled mid-frame: %w", err)
					}
				}
				return err
			}
		}
		return nil
	}
	var hdr [8]byte
	if err := read(hdr[:]); err != nil {
		return 0, nil, err
	}
	if string(hdr[:4]) != "STF\x01" || hdr[7] != 0 {
		return 0, nil, errors.New("malformed CSTP frame header")
	}
	n := int(binary.BigEndian.Uint16(hdr[4:6]))
	if n > len(buf) {
		return 0, nil, errors.New("oversized CSTP frame: ", n)
	}
	if n == 0 {
		return hdr[6], nil, nil
	}
	if err := read(buf[:n]); err != nil {
		return 0, nil, err
	}
	return hdr[6], buf[:n], nil
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
			if n := s.registry.sweep(s.ctx, time.Duration(s.cookieTimeoutSecs())*time.Second); n > 0 {
				errors.LogInfo(s.ctx, fmt.Sprintf("openconnect: gc swept %d expired session(s)", n))
			}
		}
	}
}

func (s *Server) connectHeaders(sess *ocSession) map[string][]string {
	baseMTU := s.mtu()
	dpd := s.dpdSecs()
	udpPort := int(s.src.Port)
	if s.conf.DtlsPort != 0 {
		udpPort = int(s.conf.DtlsPort)
	}
	hdrs := map[string][]string{
		"X-CSTP-Address":    {sess.ip.String()},
		"X-CSTP-Netmask":    {s.registry.pool.netmask()},
		"X-CSTP-Base-MTU":   {strconv.FormatUint(uint64(baseMTU), 10)},
		"X-CSTP-MTU":        {strconv.FormatUint(uint64(baseMTU-dtlsOverhead), 10)},
		"X-CSTP-Keepalive":  {strconv.Itoa(cstpKeepalive)},
		"X-CSTP-DPD":        {strconv.FormatUint(uint64(dpd), 10)},
		"X-CSTP-Rekey-Time": {"0"},
		// Always advertised: readCSTPFrame parses length-prefixed frames
		// regardless of TLS record boundaries, so multi-frame clients may
		// batch their uplink frames into one TLS write too.
		hdrMultiFrame: {"true"},
	}
	// DTLS offer is group-gated: omitting the X-DTLS-* headers keeps the
	// client CSTP-only (ocserv without DTLS behaves the same), for groups
	// where UDP is throttled anyway.
	if s.conf.dtlsFor(sess.user) {
		hdrs["X-DTLS-Port"] = []string{strconv.Itoa(udpPort)}
		hdrs["X-DTLS-App-ID"] = []string{sess.appID}
		hdrs["X-DTLS-CipherSuite"] = []string{"PSK-NEGOTIATE"}
	}
	if len(s.conf.Dns) > 0 {
		hdrs["X-CSTP-DNS"] = []string{strings.Join(s.conf.Dns, ",")}
	}
	// Split routing: each network is a separate repeated header line, as the
	// client (libopenconnect/vpnc-script) collects routes per header line.
	// Per-user/group routes override the inbound policy; empty inherits it.
	if routes := s.conf.routesFor(sess.user); len(routes) > 0 {
		hdrs["X-CSTP-Split-Include"] = routes
	}
	// Split exclusions (no-route) are advertised unconditionally, matching
	// ocserv: X-CSTP-Split-Exclude: 0.0.0.0/0 is the signal a split-routing
	// router uses to send anything outside X-CSTP-Split-Include via its own
	// gateway rather than the tunnel. They come from the user's group.
	if noRoutes := s.conf.noRoutesFor(sess.user); len(noRoutes) > 0 {
		hdrs["X-CSTP-Split-Exclude"] = noRoutes
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

// Forms mirror ocserv src/worker-auth.c (OC_LOGIN_*, oc_success_msg_*): the
// main form carries username AND password — AnyConnect/mobile clients submit
// both in one POST and expect to authenticate in a single round; the
// password-only form is the second stage of the split flow and is still
// wrapped in <config-auth> with auth id="main" (id="passwd" is a v3-client
// special case in ocserv that regular clients do not expect).
const loginForm = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
<version who="sg">0.1(1)</version>
<auth id="main">
<message>Please enter your username and password.</message>
<form method="post" action="/auth">
<input type="text" name="username" label="Username:" />
<input type="password" name="password" label="Password:" />
</form></auth>
</config-auth>`

const passwdForm = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
<version who="sg">0.1(1)</version>
<auth id="main">
<message>Please enter your password.</message>
<form method="post" action="/auth">
<input type="password" name="password" label="Password:" />
</form></auth>
</config-auth>`

const successMsg = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
<version who="sg">0.1(1)</version>
<auth id="success">
<title>SSL VPN Service</title></auth></config-auth>
`

const failMsg = `<?xml version="1.0" encoding="UTF-8"?>
<auth id="fail">
<message>Authentication failed.</message>
</auth>
`
