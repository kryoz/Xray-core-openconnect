package openconnect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
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

// TestDTLSDataPath drives the full in-process data path: control-channel auth →
// DTLS handshake (PSK) → ICMP echo request → gVisor local echo reply → back
// through the DTLS tunnel. It exercises the UDP demux, read pump framing, gVisor
// ICMP handler, and device write path without needing the dispatcher or a real
// openconnect client.
func TestDTLSDataPath(t *testing.T) {
	s := newTestServer(t)

	// 1. Control channel: authenticate and CONNECT to create the session + PSK.
	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	readResp(t, c1)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, c1)
	cookie := cookieValue(setCookies)
	if cookie == "" {
		t.Fatalf("no webvpn cookie in %v", setCookies)
	}
	_ = c1.Close()

	c2 := dialOC(t, s)
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	if st, hdrs, _, _ := readResp(t, c2); st != 200 {
		t.Fatalf("CONNECT: status %d", st)
	} else if hdrs["x-cstp-address"] == "" {
		t.Fatalf("CONNECT: missing X-CSTP-Address")
	}
	defer func() { _ = c2.Close() }()

	sess := s.registry.getByClientIP("127.0.0.1")
	if sess == nil {
		t.Fatal("no session registered for client IP")
	}
	psk := sess.getPSK()
	if len(psk) != 32 {
		t.Fatalf("PSK length = %d, want 32", len(psk))
	}

	// 2. DTLS client handshake against the server's UDP port.
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(s.conf.DtlsPort)}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()

	dc, err := dtls.ClientWithOptions(pc, udpAddr,
		dtls.WithPSK(func(_ []byte) ([]byte, error) { return psk, nil }),
		dtls.WithPSKIdentityHint([]byte("psk")),
		dtls.WithCipherSuites(
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
		),
	)
	if err != nil {
		t.Fatalf("dtls client: %v", err)
	}
	defer func() { _ = dc.Close() }()
	if err := dc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("dtls handshake: %v", err)
	}

	// 3. Send a framed ICMP echo request from the client's virtual IP.
	const (
		echoID  = 0x1234
		echoSeq = 1
	)
	ipReq := buildICMPEchoRequest(sess.ip.AsSlice(), net.IPv4(1, 1, 1, 1), echoID, echoSeq, []byte("ping"))
	framed := append([]byte{acPKTData}, ipReq...)
	if _, err := dc.Write(framed); err != nil {
		t.Fatalf("dtls write: %v", err)
	}

	// 4. Read the reply and verify it is a framed ICMP echo reply.
	_ = dc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("dtls read: %v", err)
	}
	if n < 1 || buf[0] != acPKTData {
		t.Fatalf("reply type = %d, want %d", buf[0], acPKTData)
	}
	reply := buf[1:n]
	if len(reply) < 28 || reply[0]>>4 != 4 {
		t.Fatalf("reply is not a valid IPv4 packet (%d bytes)", len(reply))
	}
	if reply[9] != 1 || reply[20] != 0 {
		t.Fatalf("reply is not an ICMP echo reply (proto=%d type=%d)", reply[9], reply[20])
	}
	if got := binary.BigEndian.Uint16(reply[24:26]); got != echoID {
		t.Errorf("echo id = %#x, want %#x", got, echoID)
	}
	if got := binary.BigEndian.Uint16(reply[26:28]); got != echoSeq {
		t.Errorf("echo seq = %d, want %d", got, echoSeq)
	}
	if !bytes.Equal(reply[12:16], net.IPv4(1, 1, 1, 1).To4()) {
		t.Errorf("reply src = %v, want 1.1.1.1", net.IP(reply[12:16]))
	}
	if !bytes.Equal(reply[16:20], sess.ip.AsSlice()) {
		t.Errorf("reply dst = %v, want %s", net.IP(reply[16:20]), sess.ip)
	}
}

// TestDTLSMultiFrameWriterGating verifies the DTLS writer honors the
// multi-frame negotiation: a stock session's DTLS tunnel registers without a
// batch function (one record per datagram — dtls_mainloop reads one record
// per poll event), a negotiated session's with one.
func TestDTLSMultiFrameWriterGating(t *testing.T) {
	s := newTestServer(t)

	for _, tt := range []struct {
		name       string
		multiFrame bool
	}{
		{"stock", false},
		{"negotiated", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var c2 *tls.Conn
			var sess *ocSession
			if tt.multiFrame {
				c2, _, sess = ocConnectMF(t, s, true)
			} else {
				c2, _, sess = ocConnect(t, s)
			}
			defer func() { _ = c2.Close() }()

			udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(s.conf.DtlsPort)}
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen udp: %v", err)
			}
			defer func() { _ = pc.Close() }()

			dc, err := dtls.ClientWithOptions(pc, udpAddr,
				dtls.WithPSK(func(_ []byte) ([]byte, error) { return sess.getPSK(), nil }),
				dtls.WithPSKIdentityHint([]byte("psk")),
				dtls.WithCipherSuites(
					dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
					dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
				),
			)
			if err != nil {
				t.Fatalf("dtls client: %v", err)
			}
			defer func() { _ = dc.Close() }()
			if err := dc.HandshakeContext(context.Background()); err != nil {
				t.Fatalf("dtls handshake: %v", err)
			}

			// Wait for the server to register this DTLS generation (dtlsConn
			// is set in the same locked section as the writer), then check
			// the registered writer's batch capability.
			deadline := time.Now().Add(5 * time.Second)
			for {
				sess.mu.Lock()
				up := sess.dtlsConn != nil
				sess.mu.Unlock()
				if up {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("DTLS not established on the server in time")
				}
				time.Sleep(5 * time.Millisecond)
			}
			s.device.mu.RLock()
			w := s.device.tunnels[sess.ip]
			s.device.mu.RUnlock()
			if w == nil {
				t.Fatal("no tunnel writer registered")
			}
			if tt.multiFrame && w.batch == nil {
				t.Error("negotiated session: DTLS writer has no batch function")
			}
			if !tt.multiFrame && w.batch != nil {
				t.Error("stock session: DTLS writer must not batch (one record per datagram)")
			}
		})
	}
}

// TestDTLSMultiFrameBurst proves the negotiated DTLS path keeps the classic
// one-byte Cisco framing per record: a burst of echo requests must produce
// classic-framed replies ([acPKTData]+IP), never STF-framed bytes ("STF"
// over DTLS is not a thing this server sends — stfBatch is CSTP/TCP-only),
// regardless of how many records share a datagram (pion's Read returns one
// record payload per call, so record-layer delimiting is exercised too).
func TestDTLSMultiFrameBurst(t *testing.T) {
	s := newTestServer(t)
	c2, _, sess := ocConnectMF(t, s, true) // negotiated: batch writer active
	defer func() { _ = c2.Close() }()

	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(s.conf.DtlsPort)}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()

	dc, err := dtls.ClientWithOptions(pc, udpAddr,
		dtls.WithPSK(func(_ []byte) ([]byte, error) { return sess.getPSK(), nil }),
		dtls.WithPSKIdentityHint([]byte("psk")),
		dtls.WithCipherSuites(
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
		),
	)
	if err != nil {
		t.Fatalf("dtls client: %v", err)
	}
	defer func() { _ = dc.Close() }()
	if err := dc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("dtls handshake: %v", err)
	}

	const n = 3
	for i := 0; i < n; i++ {
		ip := buildICMPEchoRequest(sess.ip.AsSlice(), net.IPv4(1, 1, 1, 1), 0x123, uint16(i), []byte("burst"))
		if _, err := dc.Write(append([]byte{acPKTData}, ip...)); err != nil {
			t.Fatalf("dtls write %d: %v", i, err)
		}
	}

	buf := make([]byte, 2048)
	got := 0
	_ = dc.SetReadDeadline(time.Now().Add(5 * time.Second))
	for got < n {
		rn, err := dc.Read(buf)
		if err != nil {
			t.Fatalf("dtls read %d: %v", got, err)
		}
		if rn < 1 || buf[0] != acPKTData {
			t.Fatalf("reply %d starts with %#x, want classic acPKTData (0) — STF bytes must never appear over DTLS", got, buf[0])
		}
		reply := buf[1:rn]
		if len(reply) < 28 || reply[9] != 1 || reply[20] != 0 {
			t.Fatalf("reply %d is not an ICMP echo reply (%d bytes)", got, len(reply))
		}
		if seq := binary.BigEndian.Uint16(reply[26:28]); seq != uint16(got) {
			t.Fatalf("reply %d seq = %d, want %d", got, seq, got)
		}
		got++
	}
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
	sessA, err := reg.create("", "", uA, true)
	if err != nil {
		t.Fatalf("sessA: %v", err)
	}
	sessB, err := reg.create("", "", uB, true)
	if err != nil {
		t.Fatalf("sessB: %v", err)
	}
	sessC, err := reg.create("", "", uC, false)
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

// TestL3ClientToClientRelay drives the full path: two l3 users (A on DTLS,
// B on CSTP/TCP), A's ICMP echo to B's virtual IP is relayed into B's tunnel,
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

	// A: CONNECT + DTLS tunnel.
	cA, _, sessA := ocConnectAs(t, s, "l3a", "pass1")
	defer func() { _ = cA.Close() }()
	dc := dialDTLS(t, s, sessA.getPSK())
	defer func() { _ = dc.Close() }()

	// B: CONNECT (CSTP-only, no DTLS).
	cB, brB, sessB := ocConnectAs(t, s, "l3b", "pass2")
	defer func() { _ = cB.Close() }()

	// A → B: echo request must arrive framed on B's CSTP tunnel.
	ipA2B := buildICMPEchoRequest(sessA.ip.AsSlice(), sessB.ip.AsSlice(), 0x4242, 1, []byte("relay"))
	if _, err := dc.Write(append([]byte{acPKTData}, ipA2B...)); err != nil {
		t.Fatalf("dtls write: %v", err)
	}
	setDeadline(t, cB, 5*time.Second)
	typ, payload := readCstFrame(t, brB)
	if typ != acPKTData || !bytes.Equal(payload, ipA2B) {
		t.Fatalf("B received type=%d payload=%v, want DATA %v", typ, payload, ipA2B)
	}

	// B → A: reply relayed back onto A's DTLS tunnel.
	ipB2A := buildICMPEchoRequest(sessB.ip.AsSlice(), sessA.ip.AsSlice(), 0x4242, 1, []byte("relay"))
	if _, err := cB.Write(cstFrame(acPKTData, ipB2A)); err != nil {
		t.Fatalf("cstp write: %v", err)
	}
	_ = dc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("dtls read: %v", err)
	}
	if n < 1 || buf[0] != acPKTData || !bytes.Equal(buf[1:n], ipB2A) {
		t.Fatalf("A received %v, want DATA %v", buf[:n], ipB2A)
	}
}

// dialDTLS establishes a client DTLS PSK handshake against the server's UDP
// port and returns the connection.
func dialDTLS(t *testing.T, s *Server, psk []byte) *dtls.Conn {
	t.Helper()
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(s.conf.DtlsPort)}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	dc, err := dtls.ClientWithOptions(pc, udpAddr,
		dtls.WithPSK(func(_ []byte) ([]byte, error) { return psk, nil }),
		dtls.WithPSKIdentityHint([]byte("psk")),
		dtls.WithCipherSuites(
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
		),
	)
	if err != nil {
		_ = pc.Close()
		t.Fatalf("dtls client: %v", err)
	}
	if err := dc.HandshakeContext(context.Background()); err != nil {
		_ = dc.Close()
		t.Fatalf("dtls handshake: %v", err)
	}
	return dc
}

// TestDTLSReconnectAfterDisconnect verifies that after a DTLS tunnel tears down,
// a fresh ClientHello starts a new handshake: teardown must drop the pipe, not
// leave it in s.pipes to swallow the reconnect ClientHello (C3).
func TestDTLSReconnectAfterDisconnect(t *testing.T) {
	s := newTestServer(t)

	// Control channel: auth + CONNECT to create the session and PSK.
	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	readResp(t, c1)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, c1)
	cookie := cookieValue(setCookies)
	if cookie == "" {
		t.Fatalf("no webvpn cookie in %v", setCookies)
	}
	_ = c1.Close()

	c2 := dialOC(t, s)
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	if st, _, _, _ := readResp(t, c2); st != 200 {
		t.Fatalf("CONNECT: status %d", st)
	}
	defer func() { _ = c2.Close() }()

	sess := s.registry.getByClientIP("127.0.0.1")
	if sess == nil {
		t.Fatal("no session registered for client IP")
	}
	psk := sess.getPSK()

	// First DTLS handshake, then a graceful BYE so the server tears down now
	// (rather than waiting out the DPD deadline).
	dc1 := dialDTLS(t, s, psk)
	if _, err := dc1.Write([]byte{acPKTDisconnect}); err != nil {
		t.Fatalf("send disconnect: %v", err)
	}
	_ = dc1.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		sess.mu.Lock()
		down := sess.dtlsConn == nil
		sess.mu.Unlock()
		if down {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first DTLS session did not tear down in time")
		}
		time.Sleep(25 * time.Millisecond)
	}
	s.dmuMu.Lock()
	pipeDropped := sess.pipe == nil
	s.dmuMu.Unlock()
	if !pipeDropped {
		t.Fatal("session pipe was not dropped after DTLS teardown")
	}

	// A fresh ClientHello must start a new handshake, not be swallowed by a
	// stale pipe.
	dc2 := dialDTLS(t, s, psk)
	_ = dc2.Close()
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

// TestL3RelayMixedOrderCSTPFirst reproduces the field layout: the CSTP-only
// user connects first, the DTLS user second (same client IP for both — one
// NAT), and the CSTP user's failed DTLS attempt (no App-ID in ClientHello,
// OpenSSL-style) must not disturb the relay in either direction.
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

	// B (CSTP-only) connects first.
	cB, brB, sessB := ocConnectAs(t, s, "l3b", "pass2")
	defer func() { _ = cB.Close() }()

	// A connects second and brings up DTLS (resolves via byClientIP → A).
	cA, _, sessA := ocConnectAs(t, s, "l3a", "pass1")
	defer func() { _ = cA.Close() }()
	dc := dialDTLS(t, s, sessA.getPSK())
	defer func() { _ = dc.Close() }()

	// A failed DTLS attempt with a wrong PSK from the same client IP: the
	// ClientHello carries no App-ID (pion, like OpenSSL), so it resolves to
	// the newest session (A) and fails the handshake — mirroring the CSTP
	// user behind the same NAT trying DTLS. It must leave A's live tunnel
	// and the relay intact.
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(s.conf.DtlsPort)}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()
	bad, err := dtls.ClientWithOptions(pc, udpAddr,
		dtls.WithPSK(func(_ []byte) ([]byte, error) { return []byte("wrong-psk-wrong-psk-wrong-psk!!"), nil }),
		dtls.WithPSKIdentityHint([]byte("psk")),
		dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_GCM_SHA256),
	)
	if err != nil {
		t.Fatalf("dtls client: %v", err)
	}
	hctx, hcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer hcancel()
	if err := bad.HandshakeContext(hctx); err == nil {
		_ = bad.Close()
		t.Fatal("handshake with wrong PSK unexpectedly succeeded")
	}

	// Relay must still work both ways across the DTLS/CSTP pair.
	ipA2B := buildICMPEchoRequest(sessA.ip.AsSlice(), sessB.ip.AsSlice(), 0x99, 1, []byte("m"))
	if _, err := dc.Write(append([]byte{acPKTData}, ipA2B...)); err != nil {
		t.Fatalf("dtls write: %v", err)
	}
	// The failed handshake stalls this leg for >10s, so B's idle CSTP timer
	// emits keepalives first — skip liveness frames until DATA arrives.
	setDeadline(t, cB, 35*time.Second)
	typ, payload := readCstFrame(t, brB)
	for typ != acPKTData && typ != acPKTDisconnect && typ != acPKTTerm {
		typ, payload = readCstFrame(t, brB)
	}
	if typ != acPKTData || !bytes.Equal(payload, ipA2B) {
		t.Fatalf("B received type=%d payload=%v, want DATA %v", typ, payload, ipA2B)
	}

	ipB2A := buildICMPEchoRequest(sessB.ip.AsSlice(), sessA.ip.AsSlice(), 0x99, 1, []byte("m"))
	if _, err := cB.Write(cstFrame(acPKTData, ipB2A)); err != nil {
		t.Fatalf("cstp write: %v", err)
	}
	_ = dc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("dtls read: %v", err)
	}
	if n < 1 || buf[0] != acPKTData || !bytes.Equal(buf[1:n], ipB2A) {
		t.Fatalf("A received %v, want DATA %v", buf[:n], ipB2A)
	}
}

// TestRelayAfterResumeWithoutDTLS reproduces the field bug: a client with a
// live server-side DTLS tunnel reconnects over CSTP (resume, DTLS disabled
// client-side). The stale DTLS writer must not swallow relayed packets for
// 2xDPD after the reconnect: CSTP data means the client fell back to TCP.
func TestRelayAfterResumeWithoutDTLS(t *testing.T) {
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

	// A: DTLS client.
	cA, _, sessA := ocConnectAs(t, s, "l3a", "pass1")
	defer func() { _ = cA.Close() }()
	dcA := dialDTLS(t, s, sessA.getPSK())
	defer func() { _ = dcA.Close() }()

	// B: auth once, keep the cookie; CONNECT + DTLS (both channels up).
	cAuth := dialOC(t, s)
	writeReq(cAuth, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>l3b</username></auth></config-auth>`, "")
	readResp(t, cAuth)
	writeReq(cAuth, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>pass2</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, cAuth)
	cookie := cookieValue(setCookies)
	if cookie == "" {
		t.Fatalf("no cookie in %v", setCookies)
	}
	_ = cAuth.Close()

	cB1 := dialOC(t, s)
	writeReq(cB1, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	readRawHead(t, cB1)
	sessB := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sessB == nil {
		t.Fatal("no session for cookie")
	}
	dcB := dialDTLS(t, s, sessB.getPSK())
	_ = dcB // deliberately not closed: the server keeps its DTLS writer alive
	// NOTE: dcB is deliberately NOT closed: the client walks away from its
	// DTLS socket (disabled DTLS, reconnect), so the server keeps seeing a
	// live tunnel and its writer — the exact field condition.

	// B reconnects over CSTP only (resume without DTLS).
	_ = cB1.Close()
	cB2 := dialOC(t, s)
	defer func() { _ = cB2.Close() }()
	writeReq(cB2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	brB := bufio.NewReader(cB2)
	for {
		line, err := brB.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT head: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// B sends its own traffic over the new CSTP channel (ping to A): this
	// is the DATA frame that must repossess the device writer from the
	// stale DTLS tunnel.
	ipB2A := buildICMPEchoRequest(sessB.ip.AsSlice(), sessA.ip.AsSlice(), 0x51, 1, []byte("r"))
	if _, err := cB2.Write(cstFrame(acPKTData, ipB2A)); err != nil {
		t.Fatalf("cstp write: %v", err)
	}
	_ = dcA.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := dcA.Read(buf)
	if err != nil {
		t.Fatalf("dtls read: %v", err)
	}
	if n < 1 || buf[0] != acPKTData || !bytes.Equal(buf[1:n], ipB2A) {
		t.Fatalf("A received %v, want DATA", buf[:n])
	}

	// Now A's reply must reach B over CSTP, not vanish into the stale DTLS.
	ipA2B := buildICMPEchoRequest(sessA.ip.AsSlice(), sessB.ip.AsSlice(), 0x51, 1, []byte("r"))
	if _, err := dcA.Write(append([]byte{acPKTData}, ipA2B...)); err != nil {
		t.Fatalf("dtls write: %v", err)
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

// TestRelayWriterSurvivesStaleSessionTeardown covers two sessions sharing one
// static IP: the old session's DTLS teardown must not unregister the new
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

	// A: DTLS client (the relay source).
	cA, _, sessA := ocConnectAs(t, s, "l3a", "pass1")
	defer func() { _ = cA.Close() }()
	dcA := dialDTLS(t, s, sessA.getPSK())
	defer func() { _ = dcA.Close() }()

	// B generation 1: CSTP + DTLS, then the client walks away (old session
	// stays "live" server-side until DPD notices).
	cB1, _, sessB1 := ocConnectAs(t, s, "l3b", "pass2")
	dcB1 := dialDTLS(t, s, sessB1.getPSK())
	_ = dcB1
	_ = cB1.Close()

	// B generation 2: fresh auth (new session) on the SAME static IP, CSTP.
	cB2, brB, sessB2 := ocConnectAs(t, s, "l3b", "pass2")
	defer func() { _ = cB2.Close() }()
	if sessB2 == sessB1 {
		t.Fatal("expected a distinct session for the second auth")
	}

	// The old generation's DTLS dies (close_notify arrives late, after the
	// new session registered its CSTP writer).
	deadline := time.Now().Add(10 * time.Second)
	for {
		sessB1.mu.Lock()
		oldDC := sessB1.dtlsConn
		sessB1.mu.Unlock()
		if oldDC != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Skip("old session DTLS already gone; race in teardown window")
		}
		time.Sleep(25 * time.Millisecond)
	}
	sessB1.mu.Lock()
	oldDC := sessB1.dtlsConn
	sessB1.mu.Unlock()
	if err := oldDC.Close(); err != nil && err.Error() != "connection already closed" {
		t.Logf("old dc close: %v", err)
	}

	// A -> B must still be relayed to the new session's CSTP writer.
	ipA2B := buildICMPEchoRequest(sessA.ip.AsSlice(), sessB2.ip.AsSlice(), 0x61, 1, []byte("g2"))
	if _, err := dcA.Write(append([]byte{acPKTData}, ipA2B...)); err != nil {
		t.Fatalf("dtls write: %v", err)
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

// TestTeardownHandbackRemovesWriter covers the DTLS→CSTP writer handback and
// its cleanup: after DTLS dies with a live CSTP pump, teardownDTLS registers
// the CSTP writer under a NEW token; when the CSTP connection later closes,
// the pump's defer must remove exactly that entry. With the old (dropped-token)
// code the map kept a dead writer forever and every relayed packet drained
// into a closed tls.Conn.
func TestTeardownHandbackRemovesWriter(t *testing.T) {
	s := newTestServer(t)

	// Auth + CONNECT: the CSTP pump owns the device writer.
	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	readResp(t, c1)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, c1)
	cookie := cookieValue(setCookies)
	if cookie == "" {
		t.Fatal("no webvpn cookie")
	}
	_ = c1.Close()

	c2 := dialOC(t, s)
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	if st, _, _, _ := readResp(t, c2); st != 200 {
		t.Fatalf("CONNECT: status != 200")
	}
	sess := s.registry.getByClientIP("127.0.0.1")
	if sess == nil {
		t.Fatal("no session")
	}

	waitFor := func(cond func() bool, what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}

	// DTLS up: the tunnel writer moves to the DTLS connection.
	dc := dialDTLS(t, s, sess.getPSK())
	t.Cleanup(func() { _ = dc.Close() })
	waitFor(func() bool {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		return sess.dtlsConn != nil
	}, "DTLS not established in time")

	// Graceful DTLS teardown with a live CSTP writer → handback registers the
	// CSTP writer under a new token.
	_, _ = dc.Write([]byte{acPKTDisconnect})
	waitFor(func() bool {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		return sess.dtlsConn == nil
	}, "DTLS not torn down in time")

	// CSTP closes: the pump's defer must remove the handback registration.
	_ = c2.Close()
	waitFor(func() bool {
		s.device.mu.Lock()
		defer s.device.mu.Unlock()
		_, ok := s.device.tunnels[sess.ip]
		return !ok
	}, "device writer leaked after CSTP close")
}
