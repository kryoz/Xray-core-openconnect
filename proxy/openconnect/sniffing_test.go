package openconnect

import (
	"context"
	"net"
	"slices"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// inboundSniffingCtx rebuilds what proxyman hands an inbound proxy: the
// "sniffing" block of the inbound JSON, turned into a SniffingRequest by the
// very builder the inbound handler uses and put into the session content.
func inboundSniffingCtx(t *testing.T, config *proxyman.SniffingConfig) context.Context {
	t.Helper()
	req, err := proxyman.BuildSniffingRequest(config)
	if err != nil {
		t.Fatalf("build sniffing request: %v", err)
	}
	return session.ContextWithContent(context.Background(), &session.Content{SniffingRequest: req})
}

func sameSniffingRequest(got, want session.SniffingRequest) bool {
	return got.Enabled == want.Enabled &&
		got.MetadataOnly == want.MetadataOnly &&
		got.RouteOnly == want.RouteOnly &&
		slices.Equal(got.OverrideDestinationForProtocol, want.OverrideDestinationForProtocol)
}

func TestSniffingRequestFromInbound(t *testing.T) {
	domainRules, err := geodata.ParseDomainRules([]string{"example.com"}, geodata.Domain_Substr)
	if err != nil {
		t.Fatalf("domain rules: %v", err)
	}
	ipRules, err := geodata.ParseIPRules([]string{"192.168.1.1"})
	if err != nil {
		t.Fatalf("ip rules: %v", err)
	}

	for _, tc := range []struct {
		name           string
		config         *proxyman.SniffingConfig // nil = the inbound has no sniffing block
		want           session.SniffingRequest
		wantExclusions bool
	}{
		{
			name: "no block sniffs on and never overrides",
			want: session.SniffingRequest{Enabled: true},
		},
		{
			name:   "empty block keeps the previous behavior",
			config: &proxyman.SniffingConfig{},
			want:   session.SniffingRequest{Enabled: true},
		},
		{
			name:   "gate config overrides for http and tls, routing only",
			config: &proxyman.SniffingConfig{Enabled: true, DestinationOverride: []string{"http", "tls"}, RouteOnly: true},
			want:   session.SniffingRequest{Enabled: true, OverrideDestinationForProtocol: []string{"http", "tls"}, RouteOnly: true},
		},
		{
			name:   "a block that turns sniffing off is honoured",
			config: &proxyman.SniffingConfig{RouteOnly: true},
			want:   session.SniffingRequest{RouteOnly: true},
		},
		{
			name:           "metadataOnly and the exclusions are passed through",
			config:         &proxyman.SniffingConfig{Enabled: true, DestinationOverride: []string{"tls"}, MetadataOnly: true, DomainsExcluded: domainRules, IpsExcluded: ipRules},
			want:           session.SniffingRequest{Enabled: true, OverrideDestinationForProtocol: []string{"tls"}, MetadataOnly: true},
			wantExclusions: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.config != nil {
				ctx = inboundSniffingCtx(t, tc.config)
			}
			got := sniffingRequestFrom(ctx)
			if !sameSniffingRequest(got, tc.want) {
				t.Fatalf("sniffingRequestFrom() = %+v, want %+v", got, tc.want)
			}
			if hasExclusions := got.ExcludeForDomain != nil && got.ExcludeForIP != nil; hasExclusions != tc.wantExclusions {
				t.Fatalf("sniffingRequestFrom() exclusions present = %v, want %v", hasExclusions, tc.wantExclusions)
			}
		})
	}
}

// sniffCaptureDispatcher records the ctx a flow is dispatched with: that is
// where the dispatcher reads the sniffing settings from.
type sniffCaptureDispatcher struct{ ctx context.Context }

func (d *sniffCaptureDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *sniffCaptureDispatcher) Start() error      { return nil }
func (d *sniffCaptureDispatcher) Close() error      { return nil }

func (d *sniffCaptureDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *sniffCaptureDispatcher) DispatchLink(ctx context.Context, _ xnet.Destination, _ *transport.Link) error {
	d.ctx = ctx
	return nil
}

// TestFlowCarriesInboundSniffing is the regression on the flow path: the
// dispatcher must get the inbound's sniffing settings, not a hardcoded
// "enabled, no override" request.
func TestFlowCarriesInboundSniffing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	pool, err := newIPPool("10.99.0.0/24")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	dest := xnet.TCPDestination(xnet.IPAddress(net.IPv4(93, 184, 216, 34)), 443)

	for _, tc := range []struct {
		name     string
		config   *proxyman.SniffingConfig // nil = the inbound has no sniffing block
		want     session.SniffingRequest
		wantSkip bool // the router must not resolve the sniffed domain
	}{
		{
			name:     "routeOnly config keeps routing on the dialed ip",
			config:   &proxyman.SniffingConfig{Enabled: true, DestinationOverride: []string{"http", "tls"}, RouteOnly: true},
			want:     session.SniffingRequest{Enabled: true, OverrideDestinationForProtocol: []string{"http", "tls"}, RouteOnly: true},
			wantSkip: true,
		},
		{
			name:   "override without routeOnly may still resolve",
			config: &proxyman.SniffingConfig{Enabled: true, DestinationOverride: []string{"tls"}},
			want:   session.SniffingRequest{Enabled: true, OverrideDestinationForProtocol: []string{"tls"}},
		},
		{
			name: "no block keeps the previous behavior",
			want: session.SniffingRequest{Enabled: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })

			ctx := context.Background()
			if tc.config != nil {
				ctx = inboundSniffingCtx(t, tc.config)
			}
			d := &sniffCaptureDispatcher{}
			h := &ocHandler{
				ctx:        context.Background(),
				dispatcher: d,
				tag:        "openconnect",
				registry:   newSessionRegistry(pool),
				sniffing:   sniffingRequestFrom(ctx),
			}
			h.HandleConnection(conn, dest)

			content := session.ContentFromContext(d.ctx)
			if content == nil {
				t.Fatal("flow dispatched without session content")
			}
			if !sameSniffingRequest(content.SniffingRequest, tc.want) {
				t.Fatalf("dispatched sniffing request = %+v, want %+v", content.SniffingRequest, tc.want)
			}
			if content.SkipDNSResolve != tc.wantSkip {
				t.Fatalf("dispatched SkipDNSResolve = %v, want %v", content.SkipDNSResolve, tc.wantSkip)
			}
		})
	}
}
