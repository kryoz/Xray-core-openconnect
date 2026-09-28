package openconnect

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"

	stderrors "errors"
	"github.com/pion/dtls/v3"

	"github.com/xtls/xray-core/common/errors"
)

// dtlsHandshakeTimeout bounds a single DTLS handshake. Without it pion/dtls
// retransmits forever and a stalled ClientHello would pin a goroutine and a
// pipe entry until server shutdown.
const dtlsHandshakeTimeout = 30 * time.Second

// OpenConnect DTLS data-packet types (ocserv src/vpn.h).
const (
	acPKTData       = 0 // AC_PKT_DATA: raw IP payload
	acPKTDPDOut     = 3 // AC_PKT_DPD_OUT: dead-peer detection ping
	acPKTDPDResp    = 4 // AC_PKT_DPD_RESP: DPD reply
	acPKTDisconnect = 5 // AC_PKT_DISCONNECT: client teardown
	acPKTKeepalive  = 7 // AC_PKT_KEEPALIVE
	acPKTCompressed = 8 // AC_PKT_COMPRESSED (unused; we negotiate identity)
	acPKTTerm       = 9 // AC_PKT_TERM_SERVER: server teardown
)

const pskNegotiate = "PSK-NEGOTIATE"

// ocPipe is the per-session UDP packet channel fed by the demux loop.
// addr is the current peer address: written by the NAT-rebinding path in
// routeUDPPacket, read by sessionConn.WriteTo, hence the atomic pointer.
type ocPipe struct {
	addr atomic.Pointer[net.UDPAddr]
	ch   chan ocUDPPkt
}

type ocUDPPkt struct {
	data []byte
	from *net.UDPAddr
}

func newOCPipe(addr *net.UDPAddr) *ocPipe {
	p := &ocPipe{ch: make(chan ocUDPPkt, 64)}
	p.addr.Store(addr)
	return p
}

// curAddr returns the address outgoing DTLS records must be written to.
// pion/dtls caches the handshake-time peer address and only re-learns it on
// Connection-ID records (RFC 9146), which this inbound never negotiates — so
// WriteTo ignores the addr pion passes and writes to the rebind-tracked one.
func (p *ocPipe) curAddr() net.Addr { return p.addr.Load() }
func (p *ocPipe) key() string       { return p.addr.Load().String() }

// sessionConn is a net.PacketConn view of one session's UDP traffic. pion/dtls
// uses ReadFrom/WriteTo on it: ReadFrom drains the session's pipe, WriteTo goes
// out the shared UDP socket. Deadlines are not enforced (pion/dtls drives
// retransmission with its own timers).
// ponytail: no read deadline enforcement; add a timer in ReadFrom if DTLS
// retransmission stalls on a dead peer.
type sessionConn struct {
	pipe *ocPipe
	ln   net.PacketConn
}

func (sc *sessionConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p, ok := <-sc.pipe.ch
	if !ok {
		return 0, nil, io.EOF
	}
	n := copy(b, p.data)
	return n, p.from, nil
}

func (sc *sessionConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return sc.ln.WriteTo(b, sc.pipe.curAddr())
}

func (sc *sessionConn) Close() error                  { return nil }
func (sc *sessionConn) LocalAddr() net.Addr           { return sc.ln.LocalAddr() }
func (sc *sessionConn) SetDeadline(_ time.Time) error { return nil }
func (sc *sessionConn) SetReadDeadline(_ time.Time) error {
	return nil
}
func (sc *sessionConn) SetWriteDeadline(_ time.Time) error { return nil }

// isDTLSClientHello reports whether the packet is a DTLS handshake ClientHello.
// DTLS record header is 13 bytes; the handshake type (1 = ClientHello) is at
// offset 13.
func isDTLSClientHello(pkt []byte) bool {
	return len(pkt) >= 14 && pkt[0] == 22 && pkt[13] == 1
}

// udpLoop reads from the shared UDP socket and fans packets out to sessions.
func (s *Server) udpLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := s.udpLn.ReadFrom(buf)
		if err != nil {
			if !stderrors.Is(err, net.ErrClosed) {
				errors.LogError(s.ctx, "openconnect: UDP read loop stopped: ", err)
			}
			return
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok || n == 0 {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		s.routeUDPPacket(data, ua)
	}
}

// routeUDPPacket delivers a packet to the session's pipe, starting a DTLS
// handshake on the first ClientHello from a new peer.
//
// The whole dispatch holds dmuMu so a send to pipe.ch can never race with
// dropPipe's close(pipe.ch): the send is non-blocking, so the lock is not held
// while blocked. dmuMu serializes send vs close (the only unsafe channel pair).
func (s *Server) routeUDPPacket(data []byte, ua *net.UDPAddr) {
	key := ua.String()
	s.dmuMu.Lock()
	defer s.dmuMu.Unlock()

	if pipe, known := s.pipes[key]; known {
		s.pushPipe(pipe, data, ua)
		return
	}

	if isDTLSClientHello(data) {
		sess := s.resolveSession(ua, data)
		if sess == nil {
			// The only silent dead end on the DTLS path: a ClientHello we
			// cannot map to a session (stale App-ID and unknown source IP).
			// Logged, not dropped quietly — this was undiagnosable in the
			// 2026-09-27 CSTP-fallback investigation on the gate.
			appID, _ := extractAppID(data)
			errors.LogWarning(s.ctx, "openconnect: ClientHello from ", ua, " matches no session (appID=", appID, "), dropping")
			return
		}
		// Group with DTLS disabled: the client never received the X-DTLS-*
		// headers, so a ClientHello here is UDP throttling noise. Drop it
		// silently — a per-packet warning would spam the log.
		if !s.conf.dtlsFor(sess.user) {
			return
		}
		pipe := newOCPipe(ua)
		s.pipes[key] = pipe
		sess.pipe = pipe
		s.pushPipe(pipe, data, ua)
		go s.startDTLSSession(sess, pipe, ua)
		return
	}

	// Non-ClientHello from an unknown source port: NAT rebinding. The client
	// kept its DTLS session but changed its UDP port; re-key the session's
	// existing pipe to the new addr so both reads (pipe) and writes
	// (curAddr) follow the client.
	sess := s.registry.getByClientIP(ua.IP.String())
	if sess == nil || sess.pipe == nil {
		return
	}
	if oldKey := sess.pipe.key(); oldKey != key {
		if cur, ok := s.pipes[oldKey]; !ok || cur == sess.pipe {
			delete(s.pipes, oldKey)
		}
	}
	sess.pipe.addr.Store(ua)
	s.pipes[key] = sess.pipe
	s.pushPipe(sess.pipe, data, ua)
}

// pushPipe enqueues one UDP packet into a pipe, dropping it when the pipe is
// full. It is non-blocking so it is safe to call while holding dmuMu.
func (s *Server) pushPipe(pipe *ocPipe, data []byte, ua *net.UDPAddr) {
	select {
	case pipe.ch <- ocUDPPkt{data: data, from: ua}:
	default:
		// pipe full; drop (backpressure)
	}
}

// resolveSession maps a UDP source to a session. App-ID is matched first when
// present in the ClientHello: it is unique per session, whereas byClientIP is a
// last-writer map that cannot distinguish two clients behind one NAT IP.
func (s *Server) resolveSession(ua *net.UDPAddr, data []byte) *ocSession {
	if appID, ok := extractAppID(data); ok {
		if sess := s.registry.getByAppID(appID); sess != nil {
			return sess
		}
	}
	return s.registry.getByClientIP(ua.IP.String())
}

// startDTLSSession runs the DTLS handshake for a session and, on success,
// registers its tunnel with the device and starts the read pump. addr is the
// client source address captured at demux time; pipe.addr may be re-keyed by a
// concurrent NAT-rebinding, so it must not be read here.
func (s *Server) startDTLSSession(sess *ocSession, pipe *ocPipe, addr *net.UDPAddr) {
	// pion picks the suite following the client's preference order, so the
	// only way to steer it is to restrict the offer. Both suites by default;
	// "aes128gcm"/"chacha20poly1305" pin one (AES-GCM wins by a wide margin
	// on AES-NI hosts).
	suites := []dtls.CipherSuiteID{
		dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	}
	switch s.conf.Cipher {
	case "aes128gcm":
		suites = suites[:1]
	case "chacha20poly1305":
		suites = suites[1:]
	}
	sc := &sessionConn{pipe: pipe, ln: s.udpLn}
	dc, err := dtls.ServerWithOptions(sc, addr,
		dtls.WithPSK(func(_ []byte) ([]byte, error) {
			return sess.getPSK(), nil
		}),
		dtls.WithPSKIdentityHint([]byte(pskNegotiate)),
		dtls.WithCipherSuites(suites...),
		// OpenSSL-built openconnect clients send a DTLS 1.0 client_version
		// (fake SSL_SESSION quirk); accept it and still negotiate 1.2.
		dtls.WithLegacyClientHello(),
	)
	if err != nil {
		s.dropPipe(sess, pipe)
		return
	}
	hsCtx, cancel := context.WithTimeout(s.ctx, dtlsHandshakeTimeout)
	err = dc.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		_ = dc.Close()
		s.dropPipe(sess, pipe)
		errors.LogInfo(s.ctx, "openconnect: DTLS handshake failed for ", sess.ip, ": ", err)
		return
	}
	dtlsWriter := func(framed []byte) error {
		_, err := dc.Write(framed)
		return err
	}
	// Batch the frames of one gVisor flush into a single WriteBatch: pion
	// packs several records into one datagram, cutting a sendto per record.
	batchWriter := func(frames [][]byte) error {
		return dc.WriteBatch(frames)
	}
	sess.mu.Lock()
	sess.dtlsConn = dc
	sess.dtlsWriter = s.device.registerBatch(sess.ip, dtlsWriter, batchWriter)
	sess.mu.Unlock()
	errors.LogInfo(s.ctx, "openconnect: DTLS established for ", sess.ip)
	sess.touchActivity()
	s.dtlsReadPump(sess, dc)
	s.teardownDTLS(sess, pipe, dc)
}

// dtlsReadPump reads framed packets from the DTLS connection and feeds data
// packets into the device, answering DPD and handling teardown. A read deadline
// equal to the DPD interval turns an idle tunnel into a liveness probe: after
// dpd seconds of silence it sends DPD_OUT, and after 2×dpd it kicks the peer.
func (s *Server) dtlsReadPump(sess *ocSession, dc *dtls.Conn) {
	dpd := time.Duration(s.dpdSecs()) * time.Second
	// Full DTLS-record headroom: a record larger than the MTU must be dropped,
	// not kill the tunnel as a read error.
	buf := make([]byte, 65536)
	from := sess.ip
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		_ = dc.SetReadDeadline(time.Now().Add(dpd))
		n, err := dc.Read(buf)
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				if time.Since(sess.lastActivity()) >= 2*dpd {
					errors.LogInfo(s.ctx, "openconnect: DPD timeout for ", sess.ip)
					return
				}
				_, _ = dc.Write([]byte{acPKTDPDOut, 0})
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		sess.touchActivity()
		switch buf[0] {
		case acPKTData:
			if n > 1 {
				if n-1 > int(s.mtu()) {
					errors.LogWarning(s.ctx, "openconnect: dropping oversized data packet from ", sess.ip, " (", n-1, " bytes)")
					continue
				}
				// The copied slice keeps the full wire frame [acPKTData]+IP:
				// the L3 relay hands it to the peer tunnel as-is, zero-copy.
				frame := make([]byte, n)
				copy(frame, buf[:n])
				select {
				case s.device.rxCh <- ocRxPkt{from: from, frame: frame}:
				default:
				}
			}
		case acPKTDPDOut:
			// Echo the full padded probe with the type rewritten to DPD_RESP:
			// openconnect's MTU detection (dtls_detect_mtu) requires the reply
			// to match the probe length exactly.
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[0] = acPKTDPDResp
			_, _ = dc.Write(resp)
		case acPKTDPDResp, acPKTKeepalive:
			// liveness only; activity already recorded above
		case acPKTDisconnect, acPKTTerm:
			return
		}
	}
}

// teardownDTLS detaches this DTLS generation from the device. Ownership is
// checked against the session's current dtlsConn so that a superseded (older)
// generation tears down without clobbering the one that replaced it: it closes
// only its own dc, unregisters/marks-disconnected only if it is still current,
// and always drops its own pipe. When the CSTP/TCP fallback link is still
// alive, the device writer is handed back to it instead of unregistering —
// ocserv keeps serving data over CSTP after DTLS dies.
func (s *Server) teardownDTLS(sess *ocSession, pipe *ocPipe, dc *dtls.Conn) {
	// Drop the pipe before clearing dtlsConn: a reconnecting client's
	// ClientHello must never land on a stale pipe, and dtlsConn==nil is
	// only observable after the pipe is gone.
	s.dropPipe(sess, pipe)

	sess.mu.Lock()
	mine := sess.dtlsConn == dc
	if mine {
		sess.dtlsConn = nil
		if sess.cstpWrite != nil {
			// Hand the device writer back to the live CSTP pump. The token
			// becomes the session's current registration so the pump's own
			// teardown removes exactly this entry.
			sess.dtlsWriter = s.device.register(sess.ip, sess.cstpWrite)
		} else {
			s.device.unregisterIf(sess.ip, sess.dtlsWriter)
			sess.dtlsWriter = nil
			sess.connected = false
			sess.lastDisc = time.Now()
		}
	}
	sess.mu.Unlock()

	_ = dc.Close()
}

// dropPipe removes and closes a session's pipe, but only if it is still the
// pipe registered for that source addr and for the session.
func (s *Server) dropPipe(sess *ocSession, pipe *ocPipe) {
	s.dmuMu.Lock()
	defer s.dmuMu.Unlock()
	if cur, ok := s.pipes[pipe.key()]; ok && cur == pipe {
		delete(s.pipes, pipe.key())
		close(pipe.ch)
	}
	if sess.pipe == pipe {
		sess.pipe = nil
	}
}

// extractAppID pulls the App-ID from a DTLS ClientHello: extension 48018
// (data = 1-byte length + ID) or, as fallback, the session_id field.
func extractAppID(pkt []byte) (string, bool) {
	pos := 25 // 13 record + 12 handshake header
	if len(pkt) < pos+2+32+1 {
		return "", false
	}
	pos += 2  // protocol version
	pos += 32 // random
	sidLen := int(pkt[pos])
	pos++
	sid := ""
	if sidLen > 0 {
		if pos+sidLen > len(pkt) {
			// Truncated session_id: cannot reliably parse what follows.
			return "", false
		}
		sid = string(pkt[pos : pos+sidLen])
		pos += sidLen
	}
	if pos >= len(pkt) {
		return "", false
	}
	pos += 1 + int(pkt[pos]) // cookie
	if pos+2 > len(pkt) {
		return sid, sid != ""
	}
	cipherLen := int(pkt[pos])<<8 | int(pkt[pos+1])
	pos += 2 + cipherLen
	if pos+1 > len(pkt) {
		return sid, sid != ""
	}
	pos += 1 + int(pkt[pos]) // compression methods
	if pos+2 > len(pkt) {
		return sid, sid != ""
	}
	extLen := int(pkt[pos])<<8 | int(pkt[pos+1])
	pos += 2
	end := pos + extLen
	if end > len(pkt) {
		end = len(pkt)
	}
	for pos+4 <= end {
		extType := int(pkt[pos])<<8 | int(pkt[pos+1])
		extLen := int(pkt[pos+2])<<8 | int(pkt[pos+3])
		pos += 4
		if pos+extLen > end {
			break
		}
		if extType == 48018 && extLen >= 2 {
			idLen := int(pkt[pos])
			if idLen > 0 && 1+idLen <= extLen {
				return string(pkt[pos+1 : pos+1+idLen]), true
			}
		}
		pos += extLen
	}
	return sid, sid != ""
}

// dpdSecs returns the configured DPD interval in seconds (default applied).
func (s *Server) dpdSecs() uint32 {
	if s.conf.Dpd == 0 {
		return DefaultDPD
	}
	return s.conf.Dpd
}
