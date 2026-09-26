package openconnect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
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
	c1.Close()

	c2 := dialOC(t, s)
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	if st, hdrs, _, _ := readResp(t, c2); st != 200 {
		t.Fatalf("CONNECT: status %d", st)
	} else if hdrs["x-cstp-address"] == "" {
		t.Fatalf("CONNECT: missing X-CSTP-Address")
	}
	defer c2.Close()

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
	defer pc.Close()

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
	defer dc.Close()
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
	dc.SetReadDeadline(time.Now().Add(5 * time.Second))
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
		pc.Close()
		t.Fatalf("dtls client: %v", err)
	}
	if err := dc.HandshakeContext(context.Background()); err != nil {
		dc.Close()
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
	c1.Close()

	c2 := dialOC(t, s)
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	if st, _, _, _ := readResp(t, c2); st != 200 {
		t.Fatalf("CONNECT: status %d", st)
	}
	defer c2.Close()

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
	dc1.Close()

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
	dc2.Close()
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
	c1.Close()

	c2 := dialOC(t, s)
	defer c2.Close()
	writeReq(c2, "CONNECT", "/CSCOSSLC/tunnel", "", "Cookie: webvpn="+cookie+"\r\n")
	raw := readRawHead(t, c2)
	for _, want := range s.conf.Routes {
		if !strings.Contains(raw, "X-CSTP-Split-Include: "+want+"\r\n") {
			t.Errorf("missing split route %s in CONNECT response:\n%s", want, raw)
		}
	}
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
