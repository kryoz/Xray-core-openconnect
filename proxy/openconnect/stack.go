package openconnect

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xtls/xray-core/common/buf"
	ctxpkg "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	tunicmp "github.com/xtls/xray-core/proxy/tun/icmp"
	"github.com/xtls/xray-core/transport"
)

const ocNIC tcpip.NICID = 1

// ocRxPkt is an IP packet pulled from a client's tunnel (client→server).
type ocRxPkt struct {
	from  netip.Addr // sender's virtual IP, set by the read pumps (anti-spoofing, L3 relay)
	frame []byte     // full wire frame [acPKTData]+IP; payload = frame[1:]
}

// ocDevice is a gVisor link device that multiplexes every client's DTLS tunnel
// onto one stack: ReadPacket drains a shared RX queue (client→server), and
// WritePacket routes an outgoing IP packet to the owning client by destination
// virtual IP (server→client).
type ocDevice struct {
	mtu    uint32
	rxCh   chan ocRxPkt
	closed chan struct{}
	once   sync.Once
	// RWMutex: tunnels is read on every downlink/relay packet (WritePacket,
	// relayL3) but written only on session connect/disconnect/teardown, so
	// readers must not serialize each other.
	mu      sync.RWMutex
	tunnels map[netip.Addr]*ocWriter // virtual IP → framed writer token
	// registry enables the L3 client↔client relay (nil = relay disabled);
	// userCounter attributes relayed bytes to user>>>name>>>traffic counters,
	// mirroring the dispatcher's L4 path (nil = per-user stats off).
	registry        *sessionRegistry
	userCounter     func(email, dir string) stats.Counter
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
}

func newOCDevice(mtu uint32) *ocDevice {
	return &ocDevice{
		mtu:     mtu,
		rxCh:    make(chan ocRxPkt, 512),
		closed:  make(chan struct{}),
		tunnels: make(map[netip.Addr]*ocWriter),
	}
}

// ocWriter wraps one framed writer with an identity, so unregisterIf can tell
// a stale session's writer from the live one occupying the same virtual IP.
// batch, when non-nil, receives the frames of one gVisor flush as a single
// call so the writer can pack several records into one datagram (DTLS) or one
// TLS write (CSTP); f remains the single-frame path for relay/WritePacket.
type ocWriter struct {
	f     func([]byte) error
	batch func([][]byte) error
}

func (d *ocDevice) register(virtIP netip.Addr, w func([]byte) error) *ocWriter {
	return d.set(virtIP, &ocWriter{f: w})
}

func (d *ocDevice) registerBatch(virtIP netip.Addr, w func([]byte) error, batch func([][]byte) error) *ocWriter {
	return d.set(virtIP, &ocWriter{f: w, batch: batch})
}

func (d *ocDevice) set(virtIP netip.Addr, t *ocWriter) *ocWriter {
	d.mu.Lock()
	d.tunnels[virtIP] = t
	d.mu.Unlock()
	return t
}

// unregisterIf removes the tunnel writer only when it is still the one being
// unregistered: two sessions of one user may share a static virtual IP, and a
// stale session's teardown must not steal the live session's writer. A nil
// token is a no-op (nothing in the map is ever nil).
func (d *ocDevice) unregisterIf(virtIP netip.Addr, w *ocWriter) {
	d.mu.Lock()
	if d.tunnels[virtIP] == w {
		delete(d.tunnels, virtIP)
	}
	d.mu.Unlock()
}

func (d *ocDevice) close() {
	d.once.Do(func() { close(d.closed) })
}

// ReadPacket implements the device read path (client→server).
func (d *ocDevice) ReadPacket() (byte, *stack.PacketBuffer, error) {
	for {
		select {
		case <-d.closed:
			return 0, nil, io.EOF
		case p := <-d.rxCh:
			if d.relayL3(p) {
				continue
			}
			payload := p.frame[1:]
			if d.uplinkCounter != nil {
				d.uplinkCounter.Add(int64(len(payload)))
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: header.IPv4MinimumSize,
				Payload:            buffer.MakeWithData(payload),
			})
			return payload[0] >> 4, pb, nil
		}
	}
}

// frame builds the [acPKTData]+IP wire frame for one outgoing packet and
// returns its destination virtual IP. AsSlices() yields the complete packet
// including IP/UDP headers; Data() would only cover the payload and lose the
// destination address. One allocation builds the record the tunnel writer
// consumes — the hottest downlink path.
func (d *ocDevice) frame(packet *stack.PacketBuffer) ([]byte, netip.Addr) {
	framed := make([]byte, 1+int(packet.Size()))
	framed[0] = acPKTData
	off := 1
	for _, s := range packet.AsSlices() {
		off += copy(framed[off:], s)
	}
	framed = framed[:off]
	return framed, ocDestIP(framed[1:])
}

// WritePacket implements the device write path (server→client) for a single
// packet.
func (d *ocDevice) WritePacket(packet *stack.PacketBuffer) tcpip.Error {
	framed, destIP := d.frame(packet)
	if !destIP.IsValid() {
		return nil
	}
	d.mu.RLock()
	w, ok := d.tunnels[destIP]
	d.mu.RUnlock()
	if !ok {
		return nil // drop: no tunnel for this destination
	}
	if err := w.f(framed); err != nil {
		return &tcpip.ErrAborted{}
	}
	if d.downlinkCounter != nil {
		d.downlinkCounter.Add(int64(len(framed) - 1))
	}
	return nil
}

// relayL3 relays an IP packet between two l3-marked users straight from the
// sender's tunnel to the destination client's tunnel, bypassing the gVisor
// stack: no L4 demux, no routing.Dispatcher, TCP/UDP/ICMP treated identically.
// TTL is not decremented (single userspace hop, no loop is possible).
// It reports whether the packet was consumed (relayed, or dropped as spoofed);
// false lets it take the regular stack path, byte-identical to a non-l3 pair.
func (d *ocDevice) relayL3(p ocRxPkt) bool {
	// One atomic load fast-path: deployments without L3 users never pay the
	// destination-IP parse or the registry lookups.
	if d.registry == nil || !d.registry.anyL3.Load() {
		return false
	}
	dst := ocDestIP(p.frame[1:])
	if !dst.IsValid() || dst == p.from {
		return false
	}
	dstSess := d.registry.getByVirtIP(dst)
	if dstSess == nil || !dstSess.l3 {
		return false
	}
	srcSess := d.registry.getByVirtIP(p.from)
	if srcSess == nil || !srcSess.l3 {
		return false
	}
	if ocSrcIP(p.frame[1:]) != p.from {
		return true // spoofed source: drop
	}
	d.mu.RLock()
	w := d.tunnels[dst]
	d.mu.RUnlock()
	if w == nil {
		return false // destination session exists but is not connected: regular path
	}
	// p.frame is already [acPKTData]+IP: hand it over as-is, no copy.
	if err := w.f(p.frame); err != nil {
		return true // tunnel writer died with its tunnel; drop
	}
	if d.uplinkCounter != nil {
		d.uplinkCounter.Add(int64(len(p.frame) - 1))
	}
	if d.downlinkCounter != nil {
		d.downlinkCounter.Add(int64(len(p.frame) - 1))
	}
	if d.userCounter != nil {
		if srcSess.user != nil {
			if c := d.userCounter(srcSess.user.Name, "uplink"); c != nil {
				c.Add(int64(len(p.frame) - 1))
			}
		}
		if dstSess.user != nil {
			if c := d.userCounter(dstSess.user.Name, "downlink"); c != nil {
				c.Add(int64(len(p.frame) - 1))
			}
		}
	}
	return true
}

func (d *ocDevice) Wait() {}

// ocDestIP extracts the destination IP from an IP packet. The zero netip.Addr
// (IsValid()==false) means "not parseable" — netip keys avoid the per-packet
// string allocation of net.IP(...).String().
func ocDestIP(payload []byte) netip.Addr {
	if len(payload) >= 20 && payload[0]>>4 == 4 {
		var a [4]byte
		copy(a[:], payload[16:20])
		return netip.AddrFrom4(a)
	}
	if len(payload) >= 40 && payload[0]>>4 == 6 {
		var a [16]byte
		copy(a[:], payload[24:40])
		return netip.AddrFrom16(a)
	}
	return netip.Addr{}
}

// ocLinkEndpoint adapts ocDevice to the gVisor stack.LinkEndpoint interface.
type ocLinkEndpoint struct {
	device *ocDevice

	mu               sync.Mutex
	dispatcherCancel context.CancelFunc
	wg               sync.WaitGroup
}

var _ stack.LinkEndpoint = (*ocLinkEndpoint)(nil)

func (e *ocLinkEndpoint) MTU() uint32                        { return e.device.mtu }
func (e *ocLinkEndpoint) SetMTU(_ uint32)                    {}
func (e *ocLinkEndpoint) MaxHeaderLength() uint16            { return 0 }
func (e *ocLinkEndpoint) LinkAddress() tcpip.LinkAddress     { return "" }
func (e *ocLinkEndpoint) SetLinkAddress(_ tcpip.LinkAddress) {}
func (e *ocLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}
func (e *ocLinkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (e *ocLinkEndpoint) AddHeader(_ *stack.PacketBuffer)         {}
func (e *ocLinkEndpoint) ParseHeader(_ *stack.PacketBuffer) bool  { return true }
func (e *ocLinkEndpoint) SetOnCloseAction(_ func())               {}
func (e *ocLinkEndpoint) Wait() {
	e.wg.Wait()
}

func (e *ocLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dispatcherCancel != nil {
		e.dispatcherCancel()
		e.dispatcherCancel = nil
	}
	if dispatcher != nil {
		ctx, cancel := context.WithCancel(context.Background())
		e.wg.Add(1)
		go e.dispatchLoop(ctx, dispatcher)
		e.dispatcherCancel = cancel
	}
}

func (e *ocLinkEndpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dispatcherCancel != nil
}

func (e *ocLinkEndpoint) Close() {
	e.Attach(nil)
}

// ocSrcIP extracts the source IP from an IP packet.
func ocSrcIP(payload []byte) netip.Addr {
	if len(payload) >= 20 && payload[0]>>4 == 4 {
		var a [4]byte
		copy(a[:], payload[12:16])
		return netip.AddrFrom4(a)
	}
	if len(payload) >= 40 && payload[0]>>4 == 6 {
		var a [16]byte
		copy(a[:], payload[8:24])
		return netip.AddrFrom16(a)
	}
	return netip.Addr{}
}

func (e *ocLinkEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	d := e.device
	var n int
	var downlinkBytes int
	// One gVisor flush can carry frames for several clients (they share the
	// NIC), so group by tunnel writer: a batch-capable DTLS writer sends its
	// frames in one WriteBatch (several records per datagram), CSTP writers
	// and single-frame drops keep the per-frame path.
	batches := make(map[*ocWriter][][]byte)
	for _, pb := range list.AsSlice() {
		framed, dest := d.frame(pb)
		if !dest.IsValid() {
			n++
			continue
		}
		d.mu.RLock()
		w := d.tunnels[dest]
		d.mu.RUnlock()
		if w == nil {
			n++ // drop: no tunnel for this destination
			continue
		}
		if w.batch != nil {
			batches[w] = append(batches[w], framed)
		} else if err := w.f(framed); err != nil {
			return n, &tcpip.ErrAborted{}
		}
		downlinkBytes += len(framed) - 1
		n++
	}
	for w, frames := range batches {
		if err := w.batch(frames); err != nil {
			return n, &tcpip.ErrAborted{}
		}
	}
	if d.downlinkCounter != nil && downlinkBytes > 0 {
		d.downlinkCounter.Add(int64(downlinkBytes))
	}
	return n, nil
}

func (e *ocLinkEndpoint) dispatchLoop(ctx context.Context, dispatcher stack.NetworkDispatcher) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		version, packet, err := e.device.ReadPacket()
		if err != nil {
			e.Attach(nil)
			return
		}
		var proto tcpip.NetworkProtocolNumber
		switch version {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			packet.DecRef()
			continue
		}
		dispatcher.DeliverNetworkPacket(proto, packet)
		packet.DecRef()
	}
}

// ocHandler owns the gVisor stack and dispatches the L4 flows it demuxes into
// the Xray routing.Dispatcher.
type ocHandler struct {
	ctx        context.Context
	dispatcher routing.Dispatcher
	tag        string
	registry   *sessionRegistry
}

// HandleConnection dispatches one gVisor-demuxed TCP/UDP flow.
func (h *ocHandler) HandleConnection(conn net.Conn, destination xnet.Destination) {
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	ctx = ctxpkg.ContextWithID(ctx, session.NewID())

	remote := conn.RemoteAddr()
	if remote == nil {
		return
	}
	source := xnet.DestinationFromAddr(remote)

	inbound := session.Inbound{
		Name:   "openconnect",
		Tag:    h.tag,
		Source: source,
		User:   &protocol.MemoryUser{},
	}
	// Attribute the flow to the authenticated session's user so the
	// dispatcher's standard per-user stats (user>>>email>>>traffic/online)
	// apply, exactly like the regular inbounds.
	if vip, ok := netip.AddrFromSlice(source.Address.IP()); ok {
		if sess := h.registry.getByVirtIP(vip); sess != nil {
			inbound.User = &protocol.MemoryUser{Email: sess.user.Name}
		}
	}
	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{Enabled: true}})

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     destination,
		Status: log.AccessAccepted,
	})

	link := &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
		Writer: buf.NewWriter(conn),
	}
	if err := h.dispatcher.DispatchLink(ctx, destination, link); err != nil {
		errors.LogDebug(ctx, "openconnect: flow closed: ", err)
	}
}

// ocStack bundles the gVisor stack and its link endpoint for the inbound.
type ocStack struct {
	ctx      context.Context
	handler  *ocHandler
	device   *ocDevice
	stack    *stack.Stack
	endpoint *ocLinkEndpoint
	// flowTimeout bounds the unacknowledged-data window of each inner TCP
	// flow. See the TCP_USER_TIMEOUT note in Start.
	flowTimeout time.Duration
}

func newOCStack(ctx context.Context, dispatcher routing.Dispatcher, tag string, mtu uint32, registry *sessionRegistry, flowTimeout time.Duration) *ocStack {
	device := newOCDevice(mtu)
	device.registry = registry // enables the L3 client↔client relay
	return &ocStack{
		ctx:         ctx,
		handler:     &ocHandler{ctx: ctx, dispatcher: dispatcher, tag: tag, registry: registry},
		device:      device,
		endpoint:    &ocLinkEndpoint{device: device},
		flowTimeout: flowTimeout,
	}
}

// Start brings the gVisor stack up and attaches the TCP/UDP/ICMP handlers.
func (s *ocStack) Start() error {
	ipStack, err := createOCStack(s.endpoint)
	if err != nil {
		return err
	}

	tcpForwarder := tcp.NewForwarder(ipStack, 0, 65535, func(r *tcp.ForwarderRequest) {
		go func(r *tcp.ForwarderRequest) {
			var wq waiter.Queue
			id := r.ID()
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				r.Complete(true)
				return
			}
			// Bound the inner TCP flow's unacknowledged-data window. Without
			// TCP_USER_TIMEOUT gVisor retransmits a dead peer's unacked
			// segments forever (RTO capped at maxRTO), so a load-test client
			// killed without FIN/RST leaks the endpoint and its retransmit
			// timer, burning CPU after the tunnel is torn down. Aborting
			// closes the flow and cleans the endpoint up.
			if s.flowTimeout > 0 {
				uto := tcpip.TCPUserTimeoutOption(s.flowTimeout)
				_ = ep.SetSockOpt(&uto)
			}
			s.handler.HandleConnection(
				gonet.NewTCPConn(&wq, ep),
				xnet.TCPDestination(xnet.IPAddress(id.LocalAddress.AsSlice()), xnet.Port(id.LocalPort)),
			)
			ep.Close()
			r.Complete(false)
		}(r)
	})
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpHandler := newOCUdpHandler(s.handler.HandleConnection, s.writeRawUDPPacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		// AsRange().ToSlice() already copies the payload, so no Clone() is
		// needed — a Clone here would leak a PacketBuffer per datagram.
		data := pkt.Data().AsRange().ToSlice()
		srcIP := xnet.IPAddress(id.RemoteAddress.AsSlice())
		dstIP := xnet.IPAddress(id.LocalAddress.AsSlice())
		if srcIP == nil || dstIP == nil {
			return false
		}
		src := xnet.UDPDestination(srcIP, xnet.Port(id.RemotePort))
		dst := xnet.UDPDestination(dstIP, xnet.Port(id.LocalPort))
		udpHandler.HandlePacket(src, dst, data)
		return true
	})

	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, s.handleICMPv4)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, s.handleICMPv6)

	s.stack = ipStack
	return nil
}

// Close tears the stack down.
func (s *ocStack) Close() error {
	if s.stack == nil {
		return nil
	}
	s.device.close()
	s.endpoint.Attach(nil)
	s.stack.Close()
	for _, ep := range s.stack.CleanupEndpoints() {
		ep.Abort()
	}
	return nil
}

func (s *ocStack) handleICMPv4(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return s.handleICMPEchoPacket(header.IPv4ProtocolNumber, id, pkt)
}

func (s *ocStack) handleICMPv6(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return s.handleICMPEchoPacket(header.IPv6ProtocolNumber, id, pkt)
}

// handleICMPEchoPacket answers ping locally, mirroring the TUN inbound: gVisor
// does not forward raw ICMP to the outbound, so an echo request is answered in
// the stack and written back to the client's tunnel.
func (s *ocStack) handleICMPEchoPacket(netProto tcpip.NetworkProtocolNumber, id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	srcIP := id.RemoteAddress
	dstIP := id.LocalAddress
	if srcIP.Len() == 0 || dstIP.Len() == 0 {
		return true
	}

	message := transportPacketBytes(pkt)
	if _, _, ok := tunicmp.ParseEchoRequest(netProto, message); !ok {
		return true
	}

	reply, err := tunicmp.BuildLocalEchoReply(netProto, message, dstIP, srcIP)
	if err != nil {
		errors.LogInfoInner(s.ctx, err, "openconnect: failed to build local icmp echo reply")
		return true
	}
	if err := s.writeRawICMPPacket(netProto, reply, dstIP, srcIP); err != nil {
		errors.LogInfoInner(s.ctx, err, "openconnect: failed to write local icmp echo reply")
	}
	return true
}

func (s *ocStack) writeRawICMPPacket(netProto tcpip.NetworkProtocolNumber, message []byte, srcIP, dstIP tcpip.Address) error {
	ipHeaderSize := header.IPv6MinimumSize
	ipProtocol := header.IPv6ProtocolNumber
	transportProtocol := header.ICMPv6ProtocolNumber
	if netProto == header.IPv4ProtocolNumber {
		ipHeaderSize = header.IPv4MinimumSize
		ipProtocol = header.IPv4ProtocolNumber
		transportProtocol = header.ICMPv4ProtocolNumber
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: ipHeaderSize,
		Payload:            buffer.MakeWithData(message),
	})
	defer pkt.DecRef()

	if netProto == header.IPv4ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + len(message)),
			TTL:         64,
			Protocol:    uint8(transportProtocol),
			SrcAddr:     srcIP,
			DstAddr:     dstIP,
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(message)),
			TransportProtocol: transportProtocol,
			HopLimit:          64,
			SrcAddr:           srcIP,
			DstAddr:           dstIP,
		})
	}

	if err := s.stack.WriteRawPacket(ocNIC, ipProtocol, buffer.MakeWithView(pkt.ToView())); err != nil {
		return errors.New("failed to write raw icmp packet back to stack", err)
	}
	return nil
}

func transportPacketBytes(pkt *stack.PacketBuffer) []byte {
	headerBytes := pkt.TransportHeader().Slice()
	payloadBytes := pkt.Data().AsRange().ToSlice()
	message := make([]byte, len(headerBytes)+len(payloadBytes))
	copy(message, headerBytes)
	copy(message[len(headerBytes):], payloadBytes)
	return message
}

// createOCStack configures a gVisor IP stack over the given link endpoint.
func createOCStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        false,
	}
	gStack := stack.New(opts)

	// Keep the default delegating qdisc (one packet per WritePackets call).
	// CSTP frames MUST NOT be coalesced into one TLS record: the openconnect
	// client (cstp.c cstp_mainloop) reads one record at a time and requires
	// len == 8 + payload_len for the first frame, so a batching qdisc here
	// makes WritePackets emit several frames per tls.Conn.Write and the client
	// errors with "Unexpected packet length" / collapses throughput.
	if err := gStack.CreateNIC(ocNIC, ep); err != nil {
		return nil, errors.New(err.String())
	}
	gStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: ocNIC},
		{Destination: header.IPv6EmptySubnet, NIC: ocNIC},
	})
	if err := gStack.SetSpoofing(ocNIC, true); err != nil {
		return nil, errors.New(err.String())
	}
	if err := gStack.SetPromiscuousMode(ocNIC, true); err != nil {
		return nil, errors.New(err.String())
	}
	return gStack, nil
}
