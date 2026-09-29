package openconnect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// loadCert loads the TLS certificate/key from files, or generates an ephemeral
// self-signed certificate when none is configured (useful for testing).
func loadCert(ctx context.Context, certFile, keyFile string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return tls.Certificate{}, errors.New("load TLS cert/key").Base(err).AtError()
		}
		return cert, nil
	}
	errors.LogWarning(ctx, "openconnect: no certFile/keyFile configured; using an ephemeral self-signed certificate (clients pinning pin-sha256 will need re-pinning after every restart)")
	return ephemeralCert()
}

func ephemeralCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "xray-openconnect"},
		NotBefore:    time.Now().Add(-time.Hour),
		// 90 days: an ephemeral cert dying after 24h takes the inbound down
		// with it once clients start rejecting the handshake.
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
