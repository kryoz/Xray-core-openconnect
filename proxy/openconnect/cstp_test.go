package openconnect

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// cstFrame builds one wire-format CSTP/TCP frame: "STF\x1" + BE16 payload
// length + type + reserved zero byte + payload (libopenconnect cstp.c).
func cstFrame(typ byte, payload []byte) []byte {
	f := make([]byte, 8+len(payload))
	copy(f, "STF\x01")
	binary.BigEndian.PutUint16(f[4:6], uint16(len(payload)))
	f[6] = typ
	copy(f[8:], payload)
	return f
}

// setDeadline sets the tunnel read deadline, failing fast on error.
func setDeadline(t *testing.T, c *tls.Conn, d time.Duration) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
}

// readCstFrame reads one CSTP frame from the tunnel stream.
func readCstFrame(t *testing.T, br *bufio.Reader) (byte, []byte) {
	t.Helper()
	var hdr [8]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[4:6]))
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		t.Fatalf("read frame payload: %v", err)
	}
	return hdr[6], payload
}

// ocConnect drives the auth forms and CONNECT, returning the tunnel
// connection with the CONNECT response head consumed; br reads tunnel frames.
func ocConnect(t *testing.T, s *Server) (*tls.Conn, *bufio.Reader, *ocSession) {
	return ocConnectAs(t, s, "testuser", "testpass")
}

// ocConnectAs is ocConnect for an arbitrary user; the session is resolved by
// the authenticated user's name via the SID cookie.
func ocConnectAs(t *testing.T, s *Server, user, pass string) (*tls.Conn, *bufio.Reader, *ocSession) {
	t.Helper()
	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>`+user+`</username></auth></config-auth>`, "")
	readResp(t, c1)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>`+pass+`</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, c1)
	cookie := cookieValue(setCookies)
	if cookie == "" {
		t.Fatalf("no cookie in %v", setCookies)
	}
	_ = c1.Close()

	c2 := dialOC(t, s)
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	br := bufio.NewReader(c2)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT head: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil {
		t.Fatal("no session registered for cookie")
	}
	return c2, br, sess
}

// sidFromCookie decodes the base64 webvpn cookie back to a session SID.
func sidFromCookie(t *testing.T, s *Server, cookie string) [32]byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(cookie)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad cookie %q: %v", cookie, err)
	}
	var sid [32]byte
	copy(sid[:], raw)
	return sid
}

// TestCSTPKeepaliveDPDAndData verifies the CSTP/TCP channel after CONNECT:
// the server sends AC_PKT_KEEPALIVE on idle (the NAT/CGNAT fix), answers
// client DPD_OUT, passes DATA both ways, and closes on client DISCONNECT.
func TestCSTPKeepaliveDPDAndData(t *testing.T) {
	s := newTestServer(t)
	c2, br, sess := ocConnect(t, s)
	defer func() { _ = c2.Close() }()

	// 1. Idle: keepalive must arrive within one interval (+grace).
	setDeadline(t, c2, 20*time.Second)
	if typ, _ := readCstFrame(t, br); typ != acPKTKeepalive {
		t.Fatalf("idle frame type = %d, want keepalive %d", typ, acPKTKeepalive)
	}

	// 2. Client DPD_OUT → DPD_RESP.
	if _, err := c2.Write(cstFrame(acPKTDPDOut, nil)); err != nil {
		t.Fatalf("send DPD_OUT: %v", err)
	}
	setDeadline(t, c2, 5*time.Second)
	if typ, _ := readCstFrame(t, br); typ != acPKTDPDResp {
		t.Fatalf("reply to DPD_OUT type = %d, want %d", typ, acPKTDPDResp)
	}

	// 3. Data path over CSTP: ICMP echo request → local echo reply over TCP.
	ipReq := buildICMPEchoRequest(sess.ip.AsSlice(), net.IPv4(1, 1, 1, 1), 0x77, 1, []byte("cstp"))
	if _, err := c2.Write(cstFrame(acPKTData, ipReq)); err != nil {
		t.Fatalf("send data frame: %v", err)
	}
	setDeadline(t, c2, 5*time.Second)
	typ, reply := readCstFrame(t, br)
	if typ != acPKTData || len(reply) < 28 || reply[0]>>4 != 4 || reply[9] != 1 || reply[20] != 0 {
		t.Fatalf("echo reply: type=%d len=%d (want DATA, valid IPv4 ICMP echo reply)", typ, len(reply))
	}
	if got := binary.BigEndian.Uint16(reply[24:26]); got != 0x77 {
		t.Errorf("echo id = %#x, want %#x", got, 0x77)
	}

	// 4. Client BYE → server closes the tunnel.
	if _, err := c2.Write(cstFrame(acPKTDisconnect, nil)); err != nil {
		t.Fatalf("send disconnect: %v", err)
	}
	setDeadline(t, c2, 5*time.Second)
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("expected EOF after disconnect, got %v", err)
	}
}

// TestCSTPDPDKillsIdleSession verifies the server-side CSTP DPD machine: with
// dpd=1 the first keepalive tick (10s) already exceeds 2×dpd of silence, so
// the tunnel must be torn down and the session marked disconnected.
func TestCSTPDPDKillsIdleSession(t *testing.T) {
	s := newTestServer(t)
	s.conf.Dpd = 1
	c2, br, sess := ocConnect(t, s)
	defer func() { _ = c2.Close() }()

	setDeadline(t, c2, 20*time.Second)
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("expected EOF from CSTP DPD timeout, got %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		sess.mu.Lock()
		disconnected := !sess.connected
		sess.mu.Unlock()
		if disconnected {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("session not marked disconnected after CSTP DPD kill")
		}
		time.Sleep(25 * time.Millisecond)
	}
}
