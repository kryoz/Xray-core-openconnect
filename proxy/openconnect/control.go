package openconnect

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	stderrors "errors"

	"github.com/xtls/xray-core/common/errors"
)

const (
	// authTimeout bounds how long a control connection may idle during auth.
	authTimeout = 240 * time.Second
	// cstpOverhead is the wire cost of one CSTP frame over the TLS control
	// channel, taken at its worst case: the 8-byte STF header ("STF" + 0x01 +
	// length + type + reserved, see writeFrame) + 5 TLS record header + 16 IV
	// + 16 AEAD tag + 20 TCP + 20 IPv4. TLS 1.2 AEAD carries an explicit
	// 16-byte IV; TLS 1.3 does not (70 there — its content type byte moves
	// inside the encrypted payload), and the control channel accepts either, so
	// the constant is deliberately the pessimistic one: both the advertised
	// X-CSTP-MTU and the gVisor NIC MTU are baseMTU - cstpOverhead, so a
	// maximal IP packet in either direction is a datagram of at most the base
	// MTU on any allowed TLS version: no outer fragmentation. The client-side
	// MSS (X-CSTP-MTU - 40) then lines up with the server-side one — sub-MSS
	// incoming segments no longer split into two datagrams each (the ~1.4x pps
	// anomaly of the 2026-09-27 report). Counting only the CSTP type byte
	// (78) leaves the outer datagram 7 bytes over the base MTU and puts that
	// anomaly back.
	// The value is per-server, not per-session: the gVisor NIC MTU is one value
	// for the whole shared stack, and X-CSTP-MTU has to match the server-side
	// inner MSS. Adapting it to the negotiated TLS version would need a
	// per-client NIC, which costs more than the 16 bytes it saves.
	cstpOverhead = 85

	// OpenConnect CSTP data-packet types (ocserv src/vpn.h).
	acPKTData       = 0 // AC_PKT_DATA: raw IP payload
	acPKTDPDOut     = 3 // AC_PKT_DPD_OUT: dead-peer detection ping
	acPKTDPDResp    = 4 // AC_PKT_DPD_RESP: DPD reply
	acPKTDisconnect = 5 // AC_PKT_DISCONNECT: client teardown
	acPKTKeepalive  = 7 // AC_PKT_KEEPALIVE
	acPKTCompressed = 8 // AC_PKT_COMPRESSED (unused; we negotiate identity)
	acPKTTerm       = 9 // AC_PKT_TERM_SERVER: server teardown
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

	tc := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(s.ctx); err != nil {
		errors.LogDebug(s.ctx, fmt.Sprintf("openconnect: TLS handshake from %s failed: %s", peer, err))
		return
	}
	defer func() { _ = tc.Close() }()

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
				// The secret is a credential too, so it needs a limiter — but not
				// the /auth one. The camouflage URL is browsed by ordinary
				// browsers behind shared NATs, and five decor misses must not
				// lock the VPN out for every user behind that address. Past its
				// own budget the IP stops being answered at all: a brute-forcer
				// then pays a fresh handshake for nothing.
				s.noteCamouflageFailure(peerIP)
				if s.camoLimiter.blocked(peerIP) {
					return
				}
				errors.LogInfo(s.ctx, fmt.Sprintf("openconnect: camouflage: secret not found in URL from %s, declining", peerIP))
				s.rejectCamouflage(tc)
				return
			}
		}
		done := s.dispatch(tc, br, req, peerIP, &pendingUser)
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
func (s *Server) dispatch(tc *tls.Conn, br *bufio.Reader, req *httpReq, peerIP string, pending *string) bool {
	switch {
	case (req.method == "GET" || req.method == "POST") && (req.path == "/" || req.path == "/index.html"):
		// ocserv answers both GET / and the client's initial POST / with the login form.
		_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", nil, loginForm)
	case req.method == "POST" && req.path == "/auth":
		s.handleAuth(tc, req, peerIP, pending)
	case req.method == "CONNECT":
		s.handleConnect(tc, br, req)
		return true
	default:
		_ = writeHTTP(tc, 404, "text/plain", nil, "not found")
	}
	return false
}

func (s *Server) handleAuth(tc *tls.Conn, req *httpReq, peerIP string, pending *string) {
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

	// max_clients bounds live tunnels, not session records: a session inside its
	// resume window without a tunnel holds an IP lease, not a client slot.
	// Checked before the stale-session sweep below: a rejected client must not
	// pay for the rejection by losing the session it could still resume into
	// once a slot frees. The user's own disconnected sessions are not counted
	// here, so the order does not change whether the limit bites.
	if s.conf.MaxClients > 0 && s.registry.countConnected() >= int(s.conf.MaxClients) {
		errors.LogWarning(s.ctx, fmt.Sprintf("openconnect: max clients reached, rejecting %s", peerIP))
		_ = writeHTTP(tc, 503, "text/plain", nil, "too many clients")
		return
	}

	// A cookie-less re-auth (app restart, VPN toggle, lost cookie, changed
	// source address) must not leave the previous session behind: every attempt
	// would hold a dynamic IP for the whole cookie window. Keyed by user, not
	// by peer address — behind a NAT one address is several users, and a mobile
	// client changes it on every attempt.
	s.registry.supersedeStale(s.ctx, user)

	u := s.users.userByName(user)
	sess, err := s.registry.create(peerIP, u, s.conf.l3For(u))
	if err != nil {
		// Pool exhaustion or a bad static IP: without this line the client
		// just sees a 500 and the cause is invisible.
		errors.LogWarning(s.ctx, "openconnect: session create failed for ", user, ": ", err)
		_ = writeHTTP(tc, 500, "text/plain", nil, "internal error")
		return
	}
	sess.logSessionStart(s.ctx)

	// ocserv sets both webvpncontext (new) and webvpn (legacy); libopenconnect
	// echoes back "webvpn", so we set both to the same SID.
	sidB64 := base64.StdEncoding.EncodeToString(sess.sid[:])
	maxAge := int64(s.cookieTimeoutSecs())
	cookies := "Set-Cookie: webvpncontext=" + sidB64 + "; Max-Age=" + strconv.FormatInt(maxAge, 10) + "; Secure; HttpOnly\r\n" +
		"Set-Cookie: webvpn=" + sidB64 + "; Secure; HttpOnly"
	_ = writeHTTP(tc, 200, "text/xml; charset=utf-8", map[string][]string{"Set-Cookie": {cookies}}, successMsg)
}

func (s *Server) handleConnect(tc *tls.Conn, br *bufio.Reader, req *httpReq) {
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
	// One tunnel per session: a new CONNECT replaces the previous one, as
	// ocserv's worker does. Otherwise a reconnect after a dropped path leaves
	// the old pump half-open, holding the device writer slot and the IP lease
	// while the session looks disconnected.
	gen := sess.openTunnel(tc)
	// Multi-frame support is per-connection: each CONNECT (including resume
	// and rekey) re-negotiates it from the request headers, and the result
	// lives only in this cstpPump run.
	multiFrame := strings.EqualFold(req.headers["x-cstp-multi-frame-capability"], "true")
	// Paired with "tunnel closed" from cstpPump: open/close per CSTP
	// connection, while "session start"/"session end" bracket the whole
	// cookie lifetime.
	errors.LogInfo(s.ctx, fmt.Sprintf("openconnect: tunnel open user=%s ip=%s peer=%s multiFrame=%t",
		sess.userName(), sess.ip, sess.clientIP, multiFrame))
	// ocserv sends NO body after the blank line; the client reads the rest as
	// tunnel data. The TCP connection then stays open as the CSTP data channel.
	_ = writeHTTP(tc, 200, "", s.connectHeaders(sess), "")
	s.cstpPump(sess, tc, br, multiFrame, gen)
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
// packets, feeds DATA into the device, answers DPD, and runs the liveness
// machine: AC_PKT_KEEPALIVE every cstpKeepalive seconds of idle,
// AC_PKT_DPD_OUT after dpd seconds, teardown after 2×dpd without any frame
// (ocserv src/worker-vpn.c timers). With multiFrame set (the client
// negotiated X-CSTP-Multi-Frame-Capability), the downlink frames of one
// gVisor flush are coalesced into a single TLS write; otherwise each frame is
// its own TLS record, which stock clients require. gen is the tunnel generation
// from openTunnel: when a newer CONNECT supersedes this tunnel its connection
// is closed, and the pump exits through the read error.
func (s *Server) cstpPump(sess *ocSession, tc *tls.Conn, br *bufio.Reader, multiFrame bool, gen uint64) {
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
		if err != nil {
			// A failed write means the tunnel is gone: crypto/tls does not
			// recover from a write error, and without this the downlink stays
			// a black hole until the DPD timer fires. Closing the connection
			// makes the read loop exit at once.
			_ = tc.Close()
		}
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
			if err != nil {
				_ = tc.Close() // same rule as writeFrame: a dead write ends the tunnel
			}
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
	// (defers are LIFO): by logging time the cleanup has already released the
	// tunnel, so the line reflects the settled state.
	started := time.Now()
	closeReason := "client closed CSTP"
	defer func() { sess.logTunnelClosed(s.ctx, closeReason, started) }()

	// Register the device writer for this tunnel. The defer below unregisters
	// exactly the token this pump installed: a superseded pump, or a stale
	// session of one user sharing a static virtual IP, must not steal the
	// successor's slot.
	myWriter := registerCSTP()
	sess.mu.Lock()
	sess.writer = myWriter
	sess.mu.Unlock()
	defer func() {
		// Release by token, unconditionally: unregisterIf compares identity
		// inside the device map, so this can never steal a successor's slot.
		// Guarding the call with sess.writer was wrong — when two CONNECTs
		// race, the superseded pump can clear sess.writer after the successor
		// set it, and then the successor's token is never removed from
		// ocDevice.tunnels and keeps receiving downlink packets after its
		// tunnel is gone.
		s.device.unregisterIf(sess.ip, myWriter)
		sess.mu.Lock()
		if sess.writer == myWriter {
			sess.writer = nil
		}
		sess.mu.Unlock()
		sess.closeTunnel(gen)
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
			if sess.isSuperseded(gen) {
				// Our own connection was closed by openTunnel: expected, not a
				// client-path failure.
				closeReason = "superseded by a newer CONNECT"
				errors.LogDebug(s.ctx, "openconnect: CSTP tunnel superseded for ", sess.ip, " (user ", sess.userName(), ")")
				return
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
// exists only over the TCP channel. A read deadline that
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
	hdrs := map[string][]string{
		"X-CSTP-Address":    {sess.ip.String()},
		"X-CSTP-Netmask":    {s.registry.pool.netmask()},
		"X-CSTP-Base-MTU":   {strconv.FormatUint(uint64(baseMTU), 10)},
		"X-CSTP-MTU":        {strconv.FormatUint(uint64(dataMTUOf(baseMTU)), 10)},
		"X-CSTP-Keepalive":  {strconv.Itoa(cstpKeepalive)},
		"X-CSTP-DPD":        {strconv.FormatUint(uint64(dpd), 10)},
		"X-CSTP-Rekey-Time": {"0"},
		// Always advertised: readCSTPFrame parses length-prefixed frames
		// regardless of TLS record boundaries, so multi-frame clients may
		// batch their uplink frames into one TLS write too.
		hdrMultiFrame: {"true"},
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

// dpdSecs returns the configured DPD interval in seconds (default applied).
func (s *Server) dpdSecs() uint32 {
	if s.conf.Dpd == 0 {
		return DefaultDPD
	}
	return s.conf.Dpd
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
