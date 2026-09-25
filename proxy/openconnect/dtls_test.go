package openconnect

import (
	"net/netip"
	"testing"
)

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
	p, err := newIPPool("10.66.0.0/30") // 2 usable addresses
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}
	a1, err := p.alloc()
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	a2, err := p.alloc()
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if a1 == a2 {
		t.Errorf("alloc returned %s twice", a1)
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
	p, _ := newIPPool("10.66.0.0/30")
	static := netip.MustParseAddr("10.66.0.1")
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
