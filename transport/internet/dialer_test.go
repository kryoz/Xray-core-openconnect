package internet_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	. "github.com/xtls/xray-core/transport/internet"
)

func TestDialWithLocalAddr(t *testing.T) {
	server := &tcp.Server{}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	conn, err := DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), nil)
	common.Must(err)
	if r := cmp.Diff(conn.RemoteAddr().String(), "127.0.0.1:"+dest.Port.String()); r != "" {
		t.Error(r)
	}
	conn.Close()
}

func TestDialFailsWhenEgressInterfaceMissing(t *testing.T) {
	// Regression: a missing egress interface must fail the dial instead of
	// silently falling back to the host's default route. The old soft-fail
	// hid AWG tunnel death from observatory (probes "succeeded" via the
	// host's own egress) and leaked VPN traffic to the host IP.
	_, err := DialSystem(context.Background(), net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), 443), &SocketConfig{Interface: "no-such-iface-xray"})
	if err == nil {
		t.Fatal("want dial error when the egress interface is missing, got nil")
	}
}
