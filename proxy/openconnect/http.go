package openconnect

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

// maxBodyLimit bounds the control-channel request body (forms are tiny).
const maxBodyLimit = 16 * 1024

// httpReq is a parsed OpenConnect control-channel request.
type httpReq struct {
	method  string
	path    string
	query   string // request-target query without the leading '?'
	headers map[string]string
	body    []byte
}

// readHTTP reads a single HTTP/1.1 request from a shared bufio.Reader. Only the
// OpenConnect control flow is supported; anything else yields an error.
// ReadSlice bounds every line to the reader's buffer size, so a hostile client
// cannot grow an unbounded request/header line into memory.
func readHTTP(br *bufio.Reader) (*httpReq, error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		if err == bufio.ErrBufferFull {
			return nil, errors.New("request line too long").AtError()
		}
		return nil, errors.New("read request line").Base(err).AtError()
	}
	f := strings.Fields(strings.TrimRight(string(line), "\r\n"))
	if len(f) != 3 {
		return nil, errors.New("bad request line: ", string(line)).AtError()
	}
	headers := make(map[string]string, 8)
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			if err == bufio.ErrBufferFull {
				return nil, errors.New("header line too long").AtError()
			}
			return nil, errors.New("read headers").Base(err).AtError()
		}
		lineStr := strings.TrimRight(string(line), "\r\n")
		if lineStr == "" {
			break
		}
		k, v, _ := strings.Cut(lineStr, ":")
		headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	var body []byte
	if cl := headers["content-length"]; cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil || n < 0 || n > maxBodyLimit {
			return nil, errors.New("bad content-length: ", cl).AtError()
		}
		body = make([]byte, n)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, errors.New("read body").Base(err).AtError()
		}
	}
	// Split off the query string: openconnect clients may carry a camouflage
	// argument from their server URL (e.g. "POST /?<secret>", ocserv
	// camouflage_secret). Path comparisons need it stripped; the camouflage
	// check compares the raw query against the configured secret.
	path := f[1]
	query := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], path[i+1:]
	}
	return &httpReq{method: f[0], path: path, query: query, headers: headers, body: body}, nil
}

// writeHTTP writes an HTTP/1.1 response. body may be empty (the CONNECT
// response must have no body after the blank line). A header key with several
// values is written as repeated header lines (e.g. X-CSTP-Split-Include).
func writeHTTP(w io.Writer, code int, contentType string, hdrs map[string][]string, body string) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", code, httpStatusText(code))
	if contentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	}
	for k, vs := range hdrs {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	// No Connection header: HTTP/1.1 defaults to keep-alive, which is what this
	// control channel does (handleControl loops over multiple requests, and
	// CONNECT hands the socket off to keepOpen).
	b.WriteString("\r\n")
	b.WriteString(body)
	_, err := w.Write(b.Bytes())
	return err
}

func httpStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 401:
		return "Unauthorized"
	case 404:
		return "Not Found"
	case 408:
		return "Request Timeout"
	case 500:
		return "Internal Server Error"
	case 503:
		return "Service Unavailable"
	default:
		return "OK"
	}
}

// xmlEntityUnescape reverses the five XML predefined entities.
var xmlEntityUnescape = strings.NewReplacer(
	"&lt;", "<", "&gt;", ">", "&quot;", "\"", "&apos;", "'", "&amp;", "&",
)

// parseForm extracts username/password from a form-urlencoded or XML POST body.
// libopenconnect submits XML: <config-auth ...><auth><username>..</username>
// ..</auth></config-auth>; the password POST carries only <password>.
func parseForm(body []byte) map[string]string {
	out := make(map[string]string, 2)
	if bytes.Contains(body, []byte("<config-auth")) {
		for _, tag := range []string{"username", "password"} {
			open := "<" + tag + ">"
			start := bytes.Index(body, []byte(open))
			if start < 0 {
				continue
			}
			start += len(open)
			end := bytes.Index(body[start:], []byte("</"+tag+">"))
			if end < 0 {
				continue
			}
			out[tag] = xmlEntityUnescape.Replace(string(body[start : start+end]))
		}
		return out
	}
	vals, _ := url.ParseQuery(string(body))
	for k, v := range vals {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}
