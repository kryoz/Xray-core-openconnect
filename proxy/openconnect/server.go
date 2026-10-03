package openconnect

import (
	"context"
	"crypto/tls"
	stdnet "net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Server is the OpenConnect inbound. It owns a TCP control-channel listener,
// bound directly (like the wireguard inbound), bypassing the Xray stream-security
// layer.
type Server struct {
	conf          *OpenConnectInboundConfig
	ctx           context.Context
	policyManager policy.Manager
	dispatcher    routing.Dispatcher

	tag     string
	src     net.Destination
	baseMTU uint32

	cert        tls.Certificate
	registry    *sessionRegistry
	users       *userStore
	limiter     *authLimiter
	camoLimiter *authLimiter

	stack  *ocStack
	device *ocDevice

	cancel context.CancelFunc

	mu    sync.Mutex
	tcpLn net.Listener
}

// NewServer builds an OpenConnect inbound from its config.
func NewServer(ctx context.Context, conf *OpenConnectInboundConfig) (*Server, error) {
	if err := conf.validate(); err != nil {
		return nil, err
	}
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)
	d := v.GetFeature(routing.DispatcherType()).(routing.Dispatcher)

	inbound := session.InboundFromContext(ctx)

	pool, err := newIPPool(conf.Subnet)
	if err != nil {
		return nil, err
	}
	for _, u := range conf.Users {
		if u.Ip != "" {
			if ip, err := netip.ParseAddr(u.Ip); err == nil {
				pool.reserve(ip)
			}
		}
	}
	users, err := newUserStore(conf.Users)
	if err != nil {
		return nil, err
	}
	cert, err := loadCert(ctx, conf.CertFile, conf.KeyFile)
	if err != nil {
		return nil, err
	}

	var uplinkCounter, downlinkCounter stats.Counter
	if len(inbound.Tag) > 0 && p.ForSystem().Stats.InboundUplink {
		sm := v.GetFeature(stats.ManagerType()).(stats.Manager)
		c, _ := sm.GetOrRegisterCounter("inbound>>>" + inbound.Tag + ">>>traffic>>>uplink")
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(inbound.Tag) > 0 && p.ForSystem().Stats.InboundDownlink {
		sm := v.GetFeature(stats.ManagerType()).(stats.Manager)
		c, _ := sm.GetOrRegisterCounter("inbound>>>" + inbound.Tag + ">>>traffic>>>downlink")
		if c != nil {
			downlinkCounter = c
		}
	}

	bg := core.ToBackgroundDetachedContext(ctx)
	sCtx, cancel := context.WithCancel(bg)

	// The advertised base MTU must not exceed the link it is sent over:
	// every downlink tunnel packet is base-MTU sized at maximum, so a larger
	// base than the interface MTU fragments every packet (overlay/tunnel
	// hosts). 0 = unresolvable (wildcard listen) → keep the configured value.
	baseMTU := mtuOf(conf)
	if ifm := ifaceMTUOf(inbound.Source.Address.IP()); ifm != 0 && ifm < baseMTU {
		errors.LogInfo(ctx, "openconnect: base MTU ", baseMTU, " exceeds listen interface MTU ", ifm, "; using ", ifm)
		baseMTU = ifm
	}

	registry := newSessionRegistry(pool)
	dpd := conf.Dpd
	if dpd == 0 {
		dpd = DefaultDPD
	}
	// Inner TCP flows share the tunnel's dead-peer window: once DPD would
	// drop the tunnel (2×dpd), also abort a dead peer's retransmission so a
	// killed client cannot leak endpoints/timers that burn CPU afterwards.
	flowTimeout := 2 * time.Duration(dpd) * time.Second
	stack := newOCStack(sCtx, d, inbound.Tag, dataMTUOf(baseMTU), registry, flowTimeout)
	stack.device.uplinkCounter = uplinkCounter
	stack.device.downlinkCounter = downlinkCounter
	// Per-user stats for the L3 relay: same counter names and policy gate as
	// the dispatcher's L4 path (WrapLink), so relayed client↔client bytes are
	// indistinguishable from terminated ones in user>>>name>>>traffic>>>*.
	if lp := p.ForLevel(0); lp.Stats.UserUplink || lp.Stats.UserDownlink {
		sm := v.GetFeature(stats.ManagerType()).(stats.Manager)
		stack.device.userCounter = func(email, dir string) stats.Counter {
			c, _ := sm.GetOrRegisterCounter("user>>>" + email + ">>>traffic>>>" + dir)
			return c
		}
	}
	server := &Server{
		conf:          conf,
		ctx:           sCtx,
		cancel:        cancel,
		policyManager: p,
		dispatcher:    d,
		tag:           inbound.Tag,
		src:           inbound.Source,

		cert:        cert,
		registry:    registry,
		users:       users,
		limiter:     newAuthLimiter(authFailMax),
		camoLimiter: newAuthLimiter(camoFailMax),

		stack:   stack,
		device:  stack.device,
		baseMTU: baseMTU,
	}
	return server, nil
}

// mtuOf resolves the configured MTU, applying the default when unset.
func mtuOf(conf *OpenConnectInboundConfig) uint32 {
	if conf.Mtu == 0 {
		return DefaultMTU
	}
	return conf.Mtu
}

// mtu resolves the effective base MTU: the interface-clamped value set by
// NewServer, or the configured one when the Server was constructed directly
// (tests) and never went through the clamp.
func (s *Server) mtu() uint32 {
	if s.baseMTU != 0 {
		return s.baseMTU
	}
	return mtuOf(s.conf)
}

// dataMTUOf returns the tunnel data-plane MTU: the base MTU minus the CSTP
// tunnel overhead. It is the gVisor NIC MTU, so outgoing IP packets always fit
// the tunnel without exceeding the client's receive window.
func dataMTUOf(base uint32) uint32 {
	if base > cstpOverhead {
		return base - cstpOverhead
	}
	return base
}

// ifaceMTUOf resolves the MTU of the interface holding ip; 0 when unknown.
func ifaceMTUOf(ip net.IP) uint32 {
	if ip == nil || ip.IsUnspecified() {
		return 0
	}
	ifaces, err := stdnet.Interfaces()
	if err != nil {
		return 0
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if an, ok := a.(*stdnet.IPNet); ok && an.IP.Equal(ip) {
				return uint32(ifaces[i].MTU)
			}
		}
	}
	return 0
}

// Network implements proxy.Inbound. The inbound binds its own sockets, so no
// network workers are created by proxyman.
func (*Server) Network() []net.Network {
	return []net.Network{}
}

// Process implements proxy.Inbound. Always a no-op: traffic arrives on the
// server's own listeners, not through proxyman.
func (*Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return nil
}

// Start implements common.Runnable. Binds the TCP control listener.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpLn != nil {
		return nil
	}
	if s.src.Address.Family().IsDomain() {
		return errors.New("listen address must be an IP, not a domain")
	}

	tcpAddr := &net.TCPAddr{IP: s.src.Address.IP(), Port: int(s.src.Port)}
	tcpLn, err := internet.ListenSystem(s.ctx, tcpAddr, nil)
	if err != nil {
		return errors.New("failed to listen on TCP ").Base(err)
	}

	if err := s.stack.Start(); err != nil {
		_ = tcpLn.Close()
		return errors.New("start gVisor stack ").Base(err)
	}

	s.tcpLn = tcpLn
	go s.acceptLoop()
	go s.gcLoop()
	return nil
}

// Close implements common.Closable.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	// The listener fields are deliberately not nil'ed here: acceptLoop reads
	// them without s.mu, and the fields are written exactly once in Start
	// (before those goroutines are spawned). Nil-ing them would introduce a
	// shutdown-time data race and a possible nil.Accept().
	if s.tcpLn != nil {
		err = s.tcpLn.Close()
	}
	if s.stack != nil {
		if e := s.stack.Close(); e != nil && err == nil {
			err = e
		}
		s.stack = nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	return err
}

var _ common.Runnable = (*Server)(nil)
