package openconnect

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestParseFormXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?><config-auth client="vpn" type="auth-reply"><auth><username>testuser</username></auth></config-auth>`)
	v := parseForm(body)
	if v["username"] != "testuser" {
		t.Errorf("username = %q, want %q", v["username"], "testuser")
	}
	if _, ok := v["password"]; ok {
		t.Error("unexpected password field")
	}

	// XML entities must be unescaped.
	body2 := []byte(`<config-auth><auth><password>a&amp;b&lt;c&gt;</password></auth></config-auth>`)
	if got := parseForm(body2)["password"]; got != "a&b<c>" {
		t.Errorf("unescaped password = %q, want %q", got, "a&b<c>")
	}
}

func TestParseFormURLEncoded(t *testing.T) {
	v := parseForm([]byte("username=alice&password=hunter2"))
	if v["username"] != "alice" || v["password"] != "hunter2" {
		t.Errorf("parseForm = %v, want alice/hunter2", v)
	}
}

func TestReadHTTP(t *testing.T) {
	raw := "POST /auth HTTP/1.1\r\nHost: xray\r\nContent-Length: 5\r\n\r\nhello"
	req, err := readHTTP(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("readHTTP: %v", err)
	}
	if req.method != "POST" || req.path != "/auth" {
		t.Errorf("method/path = %q %q", req.method, req.path)
	}
	if string(req.body) != "hello" {
		t.Errorf("body = %q, want %q", req.body, "hello")
	}
	if req.headers["host"] != "xray" {
		t.Errorf("host header = %q", req.headers["host"])
	}

	// No Content-Length → empty body.
	req, err = readHTTP(bufio.NewReader(strings.NewReader("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nCookie: webvpn=x\r\n\r\n")))
	if err != nil {
		t.Fatalf("readHTTP (no body): %v", err)
	}
	if len(req.body) != 0 {
		t.Errorf("body = %q, want empty", req.body)
	}

	// Oversized Content-Length → error.
	if _, err := readHTTP(bufio.NewReader(strings.NewReader("POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\n"))); err == nil {
		t.Error("expected error for oversized body")
	}
}

func TestWriteHTTPConnectEmptyBody(t *testing.T) {
	var buf bytes.Buffer
	if err := writeHTTP(&buf, 200, "", nil, ""); err != nil {
		t.Fatalf("writeHTTP: %v", err)
	}
	s := buf.String()
	if !strings.HasSuffix(s, "\r\n\r\n") {
		t.Errorf("CONNECT response must end with empty body, got %q", s)
	}
	if !strings.Contains(s, "Content-Length: 0\r\n") {
		t.Errorf("expected Content-Length: 0, got %q", s)
	}
	if !strings.HasPrefix(s, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("bad status line: %q", s)
	}
}

func TestWriteHTTPMultiValueHeaders(t *testing.T) {
	var buf bytes.Buffer
	hdrs := map[string][]string{"X-CSTP-Split-Include": {"10.0.0.0/8", "192.168.0.0/16"}}
	if err := writeHTTP(&buf, 200, "", hdrs, ""); err != nil {
		t.Fatalf("writeHTTP: %v", err)
	}
	s := buf.String()
	want := "X-CSTP-Split-Include: 10.0.0.0/8\r\nX-CSTP-Split-Include: 192.168.0.0/16\r\n"
	if !strings.Contains(s, want) {
		t.Errorf("repeated header lines missing, got:\n%s", s)
	}
}
