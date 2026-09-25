package openconnect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
)

// pskLabel is the exporter label used by ocserv (src/worker-vpn.c).
const pskLabel = "EXPORTER-openconnect-psk"

// errNoTLSSecret is returned when no TLS secret was captured for PSK derivation.
var errNoTLSSecret = errors.New("no TLS secret captured for PSK derivation")

// derivePSK12 mirrors gnutls_prf(session, pskLabel, 0, 0, 0, 32, out) for a
// TLS 1.2 session: gnutls_prf seeds the PRF with client_random ||
// server_random, and the session PRF for our SHA256-based suites is P_SHA256
// (RFC 5705). PSK_KEY_SIZE equals the SHA-256 digest size, so a single
// P_SHA256 iteration suffices.
// ponytail: assumes the negotiated suite uses a SHA-256 PRF; track the
// ServerHello cipher suite in the sniffer if non-SHA256 suites are ever offered.
func derivePSK12(masterSecret, clientRandom, serverRandom []byte) []byte {
	mac := func(parts ...[]byte) []byte {
		m := hmac.New(sha256.New, masterSecret)
		for _, p := range parts {
			m.Write(p)
		}
		return m.Sum(nil)
	}
	seed := make([]byte, 0, len(pskLabel)+len(clientRandom)+len(serverRandom))
	seed = append(seed, pskLabel...)
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)
	a := mac(seed)
	return mac(a, seed)
}

// keyLog implements tls.Config.KeyLogWriter (NSS key log format) and keeps the
// TLS 1.2 secrets needed to derive the DTLS PSK. Secrets stay in memory only.
// The control channel is TLS 1.2 only, so CLIENT_RANDOM lines (client random +
// master secret) plus the server random sniffed from the ServerHello are all we
// need.
type keyLog struct {
	mu           sync.Mutex
	clientRandom []byte
	masterSecret []byte
	serverRandom []byte
}

func (k *keyLog) Write(p []byte) (int, error) {
	fields := strings.Fields(string(p))
	if len(fields) != 3 || fields[0] != "CLIENT_RANDOM" {
		return len(p), nil
	}
	cr, err1 := hex.DecodeString(fields[1])
	ms, err2 := hex.DecodeString(fields[2])
	if err1 == nil && err2 == nil {
		k.mu.Lock()
		k.clientRandom, k.masterSecret = cr, ms
		k.mu.Unlock()
	}
	return len(p), nil
}

// setServerRandom records the ServerHello random sniffed off the connection.
func (k *keyLog) setServerRandom(b []byte) {
	k.mu.Lock()
	k.serverRandom = b
	k.mu.Unlock()
}

// pskKey derives the 32-byte DTLS PSK key from the captured secrets.
func (k *keyLog) pskKey() ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.masterSecret == nil || k.serverRandom == nil {
		return nil, errNoTLSSecret
	}
	return derivePSK12(k.masterSecret, k.clientRandom, k.serverRandom), nil
}
