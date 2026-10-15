package api

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/openconnect"
	"google.golang.org/protobuf/proto"
)

// TestExtractInboundUsers covers the mapping "api adu" needs to add an account
// to an OpenConnect inbound: its users are the inbound's own message, so the
// name has to travel as the email the operation addresses, and the block flag
// has to travel with it.
func TestExtractInboundUsers(t *testing.T) {
	conf := &openconnect.OpenConnectInboundConfig{
		Subnet: "10.66.0.0/24",
		Users: []*openconnect.User{
			{Name: "alice", Password: "00$11", Ip: "10.66.0.5", Group: "split"},
			{Name: "bob", Password: "01$12", Disabled: proto.Bool(true)},
		},
	}

	tests := []struct {
		name string
		inb  *core.InboundHandlerConfig
		want []*protocol.User
	}{
		{name: "no inbound has no users", inb: nil},
		{
			name: "an OpenConnect inbound maps name to email",
			inb:  &core.InboundHandlerConfig{ProxySettings: cserial.ToTypedMessage(conf)},
			want: []*protocol.User{{Email: "alice"}, {Email: "bob", Disabled: true}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractInboundUsers(tc.inb)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d user(s) %v, want %d", len(got), got, len(tc.want))
			}
			for i, u := range got {
				if u.Email != tc.want[i].Email || u.Disabled != tc.want[i].Disabled {
					t.Fatalf("user %d = (%q, disabled %t), want (%q, disabled %t)",
						i, u.Email, u.Disabled, tc.want[i].Email, tc.want[i].Disabled)
				}
				if u.Account == nil {
					t.Fatalf("user %q has no account to add", u.Email)
				}
			}
		})
	}

	t.Run("the account survives the mapping unchanged", func(t *testing.T) {
		got := extractInboundUsers(&core.InboundHandlerConfig{ProxySettings: cserial.ToTypedMessage(conf)})
		raw, err := got[0].Account.GetInstance()
		if err != nil {
			t.Fatalf("GetInstance: %v", err)
		}
		u, ok := raw.(*openconnect.User)
		if !ok {
			t.Fatalf("the account is not an OpenConnect one: %T", raw)
		}
		if !proto.Equal(u, conf.Users[0]) {
			t.Fatalf("the account changed on the way:\n got %v\nwant %v", u, conf.Users[0])
		}
	})
}
