package openconnect

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// TestClientHelloIgnoredForNoDTLSGroup covers the group-level DTLS kill
// switch on the UDP path: a ClientHello mapped to a session of a dtls:false
// group is silently dropped — no pipe, no handshake goroutine.
func TestClientHelloIgnoredForNoDTLSGroup(t *testing.T) {
	s := newTestServer(t)
	no := false
	s.conf.Groups = []*Group{{Name: "mobile", Dtls: &no}}
	s.conf.Users[0].Group = "mobile"
	tc, _, sess := ocConnectAs(t, s, "testuser", "testpass")
	defer func() { _ = tc.Close() }()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()
	ch := buildClientHello(nil, appIDExtension(sess.appID))
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(s.conf.DtlsPort)}
	if _, err := pc.WriteTo(ch, udpAddr); err != nil {
		t.Fatalf("send ClientHello: %v", err)
	}

	// A pipe for this source would appear within milliseconds of the write
	// and live until the 30s handshake timeout; a fixed grace is enough.
	time.Sleep(200 * time.Millisecond)
	s.dmuMu.Lock()
	_, hasPipe := s.pipes[pc.LocalAddr().String()]
	s.dmuMu.Unlock()
	if hasPipe {
		t.Fatal("ClientHello of a no-dtls group session created a DTLS pipe")
	}
}

// TestSessionConnWritesToReboundAddr covers the NAT-rebinding write target:
// pion/dtls caches the handshake-time peer address and never re-learns it
// without Connection IDs, so sessionConn.WriteTo must write to the pipe's
// current address (curAddr), not the stale one pion passes in.
func TestSessionConnWritesToReboundedAddr(t *testing.T) {
	oldAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1111}
	newAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2222}
	ln := &fakePacketConn{}
	pipe := newOCPipe(oldAddr)
	sc := &sessionConn{pipe: pipe, ln: ln}

	if _, err := sc.WriteTo([]byte("x"), oldAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	if ln.addr.String() != oldAddr.String() {
		t.Fatalf("initial write went to %v, want %v", ln.addr, oldAddr)
	}

	pipe.addr.Store(newAddr) // NAT rebind
	if _, err := sc.WriteTo([]byte("x"), oldAddr); err != nil {
		t.Fatalf("write after rebind: %v", err)
	}
	if ln.addr.String() != newAddr.String() {
		t.Fatalf("write after rebind went to %v, want %v", ln.addr, newAddr)
	}
}

type fakePacketConn struct {
	addr net.Addr
}

// legacyClientHelloHook builds the ClientHello the way an OpenSSL-built
// openconnect client sends it: client_version is DTLS 1.0 (0xFEFF) even
// though the client negotiates 1.2 (fake SSL_SESSION quirk, openssl-dtls.c).
// The hook (rather than rewriting wire bytes) keeps the client's handshake
// transcript consistent with what it sends.
func legacyClientHelloHook(ch handshake.MessageClientHello) handshake.Message {
	ch.Version = protocol.Version1_0

	return &ch
}

// TestDTLSLegacyVersionClientAccepted covers the pion fork: a ClientHello
// whose client_version is DTLS 1.0 is tolerated by the server (WithLegacyClientHello
// is always on for this inbound) and the handshake completes at 1.2.
func TestDTLSLegacyVersionClientAccepted(t *testing.T) {
	s := newTestServer(t)
	_, _, sess := ocConnectAs(t, s, "testuser", "testpass")
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(s.conf.DtlsPort)}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()
	dc, err := dtls.ClientWithOptions(pc, udpAddr,
		dtls.WithPSK(func(_ []byte) ([]byte, error) { return sess.getPSK(), nil }),
		dtls.WithPSKIdentityHint([]byte(pskNegotiate)),
		dtls.WithCipherSuites(dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256),
		dtls.WithClientHelloMessageHook(legacyClientHelloHook),
	)
	if err != nil {
		t.Fatalf("dtls client: %v", err)
	}
	defer func() { _ = dc.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := dc.HandshakeContext(ctx); err != nil {
		t.Fatalf("handshake with DTLS 1.0 client_version failed: %v", err)
	}
}

func (f *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	f.addr = addr
	return len(b), nil
}
func (f *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (f *fakePacketConn) Close() error                           { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                    { return nil }
func (f *fakePacketConn) SetDeadline(time.Time) error            { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error        { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error       { return nil }

// buildClientHello constructs a minimal DTLS 1.2 ClientHello with the given
// session_id and trailing extensions bytes (the record/handshake length fields
// are zeroed; extractAppID only reads fixed offsets).
func buildClientHello(sid, extensions []byte) []byte {
	var b []byte
	// Record header (13): content type 22, version DTLS1.2, epoch 0, seq 0, len 0.
	b = append(b, 22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	// Handshake header (12): msg_type 1 (ClientHello), len/seq/frag 0.
	b = append(b, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	// Body: client version (2) + random (32).
	b = append(b, 0xFE, 0xFD)
	b = append(b, make([]byte, 32)...)
	// session_id_len + session_id.
	b = append(b, byte(len(sid)))
	b = append(b, sid...)
	// cookie (0), cipher suites (0), compression (0).
	b = append(b, 0)
	b = append(b, 0, 0)
	b = append(b, 0)
	// extensions total length + extensions.
	b = append(b, byte(len(extensions)>>8), byte(len(extensions)))
	b = append(b, extensions...)
	return b
}

// appIDExtension builds extension 48018 carrying id (1-byte length + id).
func appIDExtension(id string) []byte {
	ext := []byte{0xBB, 0x92} // type 48018
	data := append([]byte{byte(len(id))}, id...)
	ext = append(ext, byte(len(data)>>8), byte(len(data)))
	ext = append(ext, data...)
	return ext
}

func TestExtractAppID(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want string
		ok   bool
	}{
		{"extension 48018", buildClientHello(nil, appIDExtension("abc")), "abc", true},
		{"session_id fallback", buildClientHello([]byte("sid123"), nil), "sid123", true},
		{"empty", buildClientHello(nil, nil), "", false},
		{"too short", []byte{22, 0xFE, 0xFD}, "", false},
		{"not handshake", []byte{23, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := extractAppID(c.pkt)
			if got != c.want || ok != c.ok {
				t.Errorf("extractAppID = (%q, %v), want (%q, %v)", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestIsDTLSClientHello(t *testing.T) {
	if !isDTLSClientHello(buildClientHello(nil, nil)) {
		t.Error("expected ClientHello to be detected")
	}
	// Application-data record (content type 23) is not a ClientHello.
	data := []byte{23, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}
	if isDTLSClientHello(data) {
		t.Error("application data misdetected as ClientHello")
	}
}

func TestIPPool(t *testing.T) {
	// /30: one dynamic address — network, gateway (base+1) and broadcast
	// are skipped by the pool.
	p, err := newIPPool("10.66.0.0/30")
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}
	a1, err := p.alloc()
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if a1 != netip.MustParseAddr("10.66.0.2") {
		t.Errorf("alloc returned %s, want 10.66.0.2 (gateway skipped)", a1)
	}
	if _, err := p.alloc(); err == nil {
		t.Error("expected exhaustion error")
	}
	p.release(a1)
	a3, err := p.alloc()
	if err != nil {
		t.Fatalf("realloc: %v", err)
	}
	if a3 != a1 {
		t.Errorf("expected reuse of %s, got %s", a1, a3)
	}
}

func TestIPPoolReserve(t *testing.T) {
	p, _ := newIPPool("10.66.0.0/29")
	static := netip.MustParseAddr("10.66.0.2")
	p.reserve(static)
	a, err := p.alloc()
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if a == static {
		t.Errorf("alloc returned reserved IP %s", static)
	}
}

func TestIPPoolRejectsSmall(t *testing.T) {
	for _, subnet := range []string{"10.66.0.0/31", "10.66.0.0/32"} {
		if _, err := newIPPool(subnet); err == nil {
			t.Errorf("newIPPool(%s): expected error", subnet)
		}
	}
}
