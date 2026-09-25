package openconnect

import (
	"encoding/hex"
	"testing"
)

// TestDerivePSK12GnuTLSVector is a real vector captured from a live TLS 1.2
// session: the expected PSK is the output of GnuTLS's gnutls_prf() on the
// client side of the very same session (randoms and master secret from the
// server side).
func TestDerivePSK12GnuTLSVector(t *testing.T) {
	cr, _ := hex.DecodeString("1f88c73bcea216c727430961e3e5934032c4b0321a2e2f80a8802a227e08047a")
	sr, _ := hex.DecodeString("055bdf04c646fce935fc9c7d29dfe1db159375a23945317980a477e7824d4105")
	ms, _ := hex.DecodeString("b36d53b35554a7d84c7a558ff298b275196eb57e24118c92840257662cd13ab3abed3c712b7d385282b91ae4d7fd386f")
	want := "dbf8e86df2e0485fed96e3b6903577cf7b702e020eaa91f5caa777bce2fdd5da"
	if got := hex.EncodeToString(derivePSK12(ms, cr, sr)); got != want {
		t.Errorf("derivePSK12 = %s, want %s", got, want)
	}
}
