package openconnect

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
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

// connectHeadersFor drives the auth forms and CONNECT, returning the CONNECT
// response headers (lower-cased keys).
func connectHeadersFor(t *testing.T, s *Server) map[string]string {
	t.Helper()
	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	readResp(t, c1)
	writeReq(c1, "POST", "/auth", `<config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, c1)
	cookie := cookieValue(setCookies)
	if cookie == "" {
		t.Fatalf("no cookie in %v", setCookies)
	}
	_ = c1.Close()

	c2 := dialOC(t, s)
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	st, hdrs, _, _ := readResp(t, c2)
	if st != 200 {
		t.Fatalf("CONNECT status %d, want 200", st)
	}
	_ = c2.Close()
	return hdrs
}

// TestConnectHeadersGroupDTLS verifies the group-level DTLS kill switch on
// the control channel: users of a dtls:false group get a CSTP-only CONNECT
// response (no X-DTLS-* headers, group split-routes intact), while a group
// without the flag and a user without a group keep the DTLS offer.
func TestConnectHeadersGroupDTLS(t *testing.T) {
	no := false
	s := newTestServer(t)
	s.conf.Groups = []*Group{{Name: "mobile", Routes: []string{"10.0.0.0/8"}, Dtls: &no}}
	s.conf.Users[0].Group = "mobile"
	hdrs := connectHeadersFor(t, s)
	for _, h := range []string{"x-dtls-port", "x-dtls-app-id", "x-dtls-ciphersuite"} {
		if _, ok := hdrs[h]; ok {
			t.Errorf("%s advertised to dtls:false group", h)
		}
	}
	if hdrs["x-cstp-address"] == "" || hdrs["x-cstp-mtu"] == "" {
		t.Error("CSTP headers missing from CONNECT response")
	}
	if got := hdrs["x-cstp-split-include"]; got != "10.0.0.0/8" {
		t.Errorf("group split route = %q, want 10.0.0.0/8", got)
	}

	s2 := newTestServer(t)
	s2.conf.Groups = []*Group{{Name: "corp", Routes: []string{"10.0.0.0/8"}}}
	s2.conf.Users[0].Group = "corp"
	if hdrs := connectHeadersFor(t, s2); hdrs["x-dtls-port"] == "" {
		t.Error("X-DTLS-Port missing for group without the dtls flag")
	}

	s3 := newTestServer(t)
	if hdrs := connectHeadersFor(t, s3); hdrs["x-dtls-port"] == "" {
		t.Error("X-DTLS-Port missing for user without a group")
	}
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

// TestSTFBatch verifies stfBatch packs several [acPKTData]+IP frames into one
// CSTP/TCP buffer that readCstFrame decodes back, in order, with no trailing
// bytes — the multi-frame DATA path used by the batch writer.
func TestSTFBatch(t *testing.T) {
	payloads := [][]byte{
		[]byte("first"),
		[]byte("second"),
		{0x45, 0x00, 0x00}, // binary payload with embedded zeros
	}
	frames := make([][]byte, len(payloads))
	for i, p := range payloads {
		frames[i] = append([]byte{acPKTData}, p...)
	}

	buf := stfBatch(frames)
	br := bufio.NewReader(bytes.NewReader(buf))
	for i, want := range payloads {
		typ, got := readCstFrame(t, br)
		if typ != acPKTData {
			t.Fatalf("frame %d type = %d, want %d", i, typ, acPKTData)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d payload = %x, want %x", i, got, want)
		}
	}
	if br.Buffered() != 0 {
		t.Fatalf("%d trailing bytes after batch", br.Buffered())
	}
}

// TestCSTPDataBatch drives several DATA frames back-to-back through the CSTP
// coalescer: the server must not drop or reorder them across timer-driven
// flushes, and readCstFrame must decode each reply in order.
func TestCSTPDataBatch(t *testing.T) {
	s := newTestServer(t)
	c2, br, sess := ocConnect(t, s)
	defer func() { _ = c2.Close() }()

	// Consume the idle keepalive frame.
	setDeadline(t, c2, 20*time.Second)
	if typ, _ := readCstFrame(t, br); typ != acPKTKeepalive {
		t.Fatalf("idle frame type = %d, want keepalive %d", typ, acPKTKeepalive)
	}

	const n = 3
	for i := 0; i < n; i++ {
		ip := buildICMPEchoRequest(sess.ip.AsSlice(), net.IPv4(1, 1, 1, 1), 0x77, uint16(i), []byte("batch"))
		if _, err := c2.Write(cstFrame(acPKTData, ip)); err != nil {
			t.Fatalf("send data %d: %v", i, err)
		}
	}

	setDeadline(t, c2, 10*time.Second)
	for i := 0; i < n; i++ {
		typ, reply := readCstFrame(t, br)
		if typ != acPKTData {
			t.Fatalf("reply %d type = %d, want DATA", i, typ)
		}
		if got := binary.BigEndian.Uint16(reply[24:26]); got != 0x77 {
			t.Fatalf("reply %d id = %#x, want %#x", i, got, 0x77)
		}
		if got := binary.BigEndian.Uint16(reply[26:28]); got != uint16(i) {
			t.Fatalf("reply %d seq = %d, want %d", i, got, i)
		}
	}
}

// ocConnectMF is ocConnect with the CSTP multi-frame capability header
// optionally sent in CONNECT; it also asserts the server echoes the
// capability in the response (its read path is stream-oriented).
func ocConnectMF(t *testing.T, s *Server, multiFrame bool) (*tls.Conn, *bufio.Reader, *ocSession) {
	t.Helper()
	c1 := dialOC(t, s)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><username>testuser</username></auth></config-auth>`, "")
	readResp(t, c1)
	writeReq(c1, "POST", "/auth", `<?xml version="1.0"?><config-auth><auth><password>testpass</password></auth></config-auth>`, "")
	_, _, setCookies, _ := readResp(t, c1)
	cookie := cookieValue(setCookies)
	if cookie == "" {
		t.Fatalf("no cookie in %v", setCookies)
	}
	_ = c1.Close()

	c2 := dialOC(t, s)
	extra := "Cookie: webvpn=" + cookie + "\r\n"
	if multiFrame {
		extra += hdrMultiFrame + ": true\r\n"
	}
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", extra)
	br := bufio.NewReader(c2)
	capability := ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT head: %v", err)
		}
		if line == "\r\n" {
			break
		}
		if k, v, ok := strings.Cut(strings.TrimRight(line, "\r\n"), ":"); ok && strings.EqualFold(strings.TrimSpace(k), hdrMultiFrame) {
			capability = strings.TrimSpace(v)
		}
	}
	if capability != "true" {
		t.Errorf("CONNECT response %s = %q, want %q", hdrMultiFrame, capability, "true")
	}
	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil {
		t.Fatal("no session registered for cookie")
	}
	return c2, br, sess
}

// waitTunnelWriter polls the device until the session's tunnel writer is
// registered (cstpPump installs it right after the CONNECT response).
func waitTunnelWriter(t *testing.T, s *Server, sess *ocSession) *ocWriter {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.device.mu.RLock()
		w := s.device.tunnels[sess.ip]
		s.device.mu.RUnlock()
		if w != nil {
			return w
		}
		if time.Now().After(deadline) {
			t.Fatal("tunnel writer not registered in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestCSTPMultiFrameNegotiation verifies the X-CSTP-Multi-Frame-Capability
// contract: the batch writer is registered only for sessions that negotiated
// it, a standard session keeps the per-frame writer, and data flows on both.
func TestCSTPMultiFrameNegotiation(t *testing.T) {
	s := newTestServer(t)

	// Standard client: no header → per-frame writer.
	c, br, sess := ocConnectMF(t, s, false)
	defer func() { _ = c.Close() }()
	if w := waitTunnelWriter(t, s, sess); w.batch != nil {
		t.Error("standard client got a batch writer; want per-frame writes")
	}
	ipReq := buildICMPEchoRequest(sess.ip.AsSlice(), net.IPv4(1, 1, 1, 1), 0x99, 1, []byte("mf"))
	if _, err := c.Write(cstFrame(acPKTData, ipReq)); err != nil {
		t.Fatalf("send data: %v", err)
	}
	setDeadline(t, c, 5*time.Second)
	if typ, reply := readCstFrame(t, br); typ != acPKTData || len(reply) < 28 || reply[20] != 0 {
		t.Fatalf("per-frame echo reply: type=%d len=%d", typ, len(reply))
	}

	// Negotiated client: header → batch writer, data still decodes.
	c2, br2, sess2 := ocConnectMF(t, s, true)
	defer func() { _ = c2.Close() }()
	if w := waitTunnelWriter(t, s, sess2); w.batch == nil {
		t.Error("negotiated client got no batch writer")
	}
	ipReq2 := buildICMPEchoRequest(sess2.ip.AsSlice(), net.IPv4(1, 1, 1, 1), 0x9a, 1, []byte("mf2"))
	if _, err := c2.Write(cstFrame(acPKTData, ipReq2)); err != nil {
		t.Fatalf("send data: %v", err)
	}
	setDeadline(t, c2, 5*time.Second)
	if typ, reply := readCstFrame(t, br2); typ != acPKTData || len(reply) < 28 || reply[20] != 0 {
		t.Fatalf("batched echo reply: type=%d len=%d", typ, len(reply))
	}
}

// TestCSTPCoalescerWindow: frames added inside the window leave as one
// write; nothing more follows until new frames arrive.
func TestCSTPCoalescerWindow(t *testing.T) {
	writes := make(chan int, 8)
	c := &cstpCoalescer{
		window: 30 * time.Millisecond,
		max:    1 << 20,
		write: func(frames [][]byte) error {
			writes <- len(frames)
			return nil
		},
	}
	c.add([][]byte{{acPKTData, 1}, {acPKTData, 2}})
	c.add([][]byte{{acPKTData, 3}})
	select {
	case n := <-writes:
		t.Fatalf("flush before window elapsed: %d frames", n)
	case <-time.After(10 * time.Millisecond):
	}
	if n := <-writes; n != 3 {
		t.Fatalf("coalesced write = %d frames, want 3", n)
	}
	select {
	case n := <-writes:
		t.Fatalf("unexpected extra write: %d frames", n)
	case <-time.After(60 * time.Millisecond):
	}
	c.close()
}

// TestCSTPCoalescerCap: a full buffer flushes synchronously — bursts never
// wait out the window.
func TestCSTPCoalescerCap(t *testing.T) {
	writes := make(chan int, 8)
	c := &cstpCoalescer{
		window: time.Hour, // only the cap can flush
		max:    16,
		write: func(frames [][]byte) error {
			writes <- len(frames)
			return nil
		},
	}
	c.add([][]byte{make([]byte, 10), make([]byte, 10)}) // 9+9 ≥ 16
	select {
	case n := <-writes:
		if n != 2 {
			t.Fatalf("cap flush = %d frames, want 2", n)
		}
	case <-time.After(time.Second):
		t.Fatal("no synchronous flush at cap")
	}
	c.close()
}

// TestCSTPCoalescerClose: close drops pending frames and stops the timer;
// later adds are dropped silently.
func TestCSTPCoalescerClose(t *testing.T) {
	writes := make(chan int, 8)
	c := &cstpCoalescer{
		window: time.Hour,
		max:    1 << 20,
		write: func(frames [][]byte) error {
			writes <- len(frames)
			return nil
		},
	}
	c.add([][]byte{{acPKTData, 1}})
	c.close()
	select {
	case n := <-writes:
		t.Fatalf("write after close: %d frames", n)
	case <-time.After(50 * time.Millisecond):
	}
	c.add([][]byte{{acPKTData, 2}})
	select {
	case n := <-writes:
		t.Fatalf("write after close+add: %d frames", n)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestCSTPMultiFrameCoalescedData drives a burst of requests through a
// negotiated session: replies may share one TLS write, and the stream parser
// must decode every frame in order with none lost.
func TestCSTPMultiFrameCoalescedData(t *testing.T) {
	s := newTestServer(t)
	c2, br, sess := ocConnectMF(t, s, true)
	defer func() { _ = c2.Close() }()

	const n = 5
	for i := 0; i < n; i++ {
		ip := buildICMPEchoRequest(sess.ip.AsSlice(), net.IPv4(1, 1, 1, 1), 0x9b, uint16(i), []byte("coal"))
		if _, err := c2.Write(cstFrame(acPKTData, ip)); err != nil {
			t.Fatalf("send data %d: %v", i, err)
		}
	}
	setDeadline(t, c2, 5*time.Second)
	for i := 0; i < n; i++ {
		typ, reply := readCstFrame(t, br)
		if typ != acPKTData {
			t.Fatalf("reply %d type = %d, want DATA", i, typ)
		}
		if got := binary.BigEndian.Uint16(reply[26:28]); got != uint16(i) {
			t.Fatalf("reply %d seq = %d, want %d", i, got, i)
		}
	}
}
