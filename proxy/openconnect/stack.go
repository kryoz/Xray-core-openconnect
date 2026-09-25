package openconnect

import (
	"context"
	"io"
	"net"
	"sync"

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

// ocRxPkt is an IP packet pulled from a client's DTLS tunnel (client→server).
type ocRxPkt struct {
	version byte // 4 or 6
	payload []byte
}

// ocDevice is a gVisor link device that multiplexes every client's DTLS tunnel
// onto one stack: ReadPacket drains a shared RX queue (client→server), and
// WritePacket routes an outgoing IP packet to the owning client by destination
// virtual IP (server→client).
type ocDevice struct {
	mtu             uint32
	rxCh            chan ocRxPkt
	closed          chan struct{}
	once            sync.Once
	mu              sync.Mutex
	tunnels         map[string]func([]byte) error // virtual IP → framed writer
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
}

func newOCDevice(mtu uint32) *ocDevice {
	return &ocDevice{
		mtu:     mtu,
		rxCh:    make(chan ocRxPkt, 512),
		closed:  make(chan struct{}),
		tunnels: make(map[string]func([]byte) error),
	}
}

func (d *ocDevice) register(virtIP string, w func([]byte) error) {
	d.mu.Lock()
	d.tunnels[virtIP] = w
	d.mu.Unlock()
}

func (d *ocDevice) unregister(virtIP string) {
	d.mu.Lock()
	delete(d.tunnels, virtIP)
	d.mu.Unlock()
}

func (d *ocDevice) close() {
	d.once.Do(func() { close(d.closed) })
}

// ReadPacket implements the device read path (client→server).
func (d *ocDevice) ReadPacket() (byte, *stack.PacketBuffer, error) {
	select {
	case <-d.closed:
		return 0, nil, io.EOF
	case p := <-d.rxCh:
		if d.uplinkCounter != nil {
			d.uplinkCounter.Add(int64(len(p.payload)))
		}
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: header.IPv4MinimumSize,
			Payload:            buffer.MakeWithData(p.payload),
		})
		return p.version, pb, nil
	}
}

// WritePacket implements the device write path (server→client).
func (d *ocDevice) WritePacket(packet *stack.PacketBuffer) tcpip.Error {
	// AsSlices() yields the complete packet including IP/UDP headers; Data()
	// would only cover the payload and lose the destination address.
	payload := make([]byte, 0, int(packet.Size()))
	for _, s := range packet.AsSlices() {
		payload = append(payload, s...)
	}
	destIP := ocDestIP(payload)
	if destIP == "" {
		return nil
	}
	d.mu.Lock()
	w, ok := d.tunnels[destIP]
	d.mu.Unlock()
	if !ok {
		return nil // drop: no tunnel for this destination
	}
	framed := make([]byte, 1+len(payload))
	framed[0] = acPKTData
	copy(framed[1:], payload)
	if err := w(framed); err != nil {
		return &tcpip.ErrAborted{}
	}
	if d.downlinkCounter != nil {
		d.downlinkCounter.Add(int64(len(payload)))
	}
	return nil
}

func (d *ocDevice) Wait() {}

// ocDestIP extracts the destination IP (dotted/hex string) from an IP packet.
func ocDestIP(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	switch payload[0] >> 4 {
	case 4:
		if len(payload) < 20 {
			return ""
		}
		return net.IP(payload[16:20]).String()
	case 6:
		if len(payload) < 40 {
			return ""
		}
		return net.IP(payload[24:40]).String()
	}
	return ""
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

func (e *ocLinkEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, pb := range list.AsSlice() {
		if err := e.device.WritePacket(pb); err != nil {
			return n, &tcpip.ErrAborted{}
		}
		n++
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
}

// HandleConnection dispatches one gVisor-demuxed TCP/UDP flow.
func (h *ocHandler) HandleConnection(conn net.Conn, destination xnet.Destination) {
	defer conn.Close()

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
}

func newOCStack(ctx context.Context, dispatcher routing.Dispatcher, tag string, mtu uint32) *ocStack {
	device := newOCDevice(mtu)
	return &ocStack{
		ctx:      ctx,
		handler:  &ocHandler{ctx: ctx, dispatcher: dispatcher, tag: tag},
		device:   device,
		endpoint: &ocLinkEndpoint{device: device},
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

	if err := gStack.CreateNIC(ocNIC, ep); err != nil {
		return nil, errors.New(err.String()).AtError()
	}
	gStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: ocNIC},
		{Destination: header.IPv6EmptySubnet, NIC: ocNIC},
	})
	if err := gStack.SetSpoofing(ocNIC, true); err != nil {
		return nil, errors.New(err.String()).AtError()
	}
	if err := gStack.SetPromiscuousMode(ocNIC, true); err != nil {
		return nil, errors.New(err.String()).AtError()
	}
	return gStack, nil
}
