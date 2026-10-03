package openconnect

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
)

// ocUdpPacket is a queued UDP datagram for a fullcone flow.
type ocUdpPacket struct {
	data []byte
	dest *xnet.Destination
}

// ocUdpHandler is a fullcone UDP flow table: it binds a flow by source
// addr:port and forwards client datagrams to the dispatcher, writing replies
// back through the gVisor stack. Adapted from the TUN inbound.
type ocUdpHandler struct {
	sync.RWMutex

	udpConns map[xnet.Destination]*ocUdpConn

	handleConnection func(conn net.Conn, dest xnet.Destination)
	writePacket      func(data []byte, src xnet.Destination, dst xnet.Destination) error
}

func newOCUdpHandler(handleConnection func(conn net.Conn, dest xnet.Destination), writePacket func(data []byte, src xnet.Destination, dst xnet.Destination) error) *ocUdpHandler {
	return &ocUdpHandler{
		udpConns:         make(map[xnet.Destination]*ocUdpConn),
		handleConnection: handleConnection,
		writePacket:      writePacket,
	}
}

// HandlePacket forwards a client UDP datagram, creating the flow on first sight.
func (u *ocUdpHandler) HandlePacket(src xnet.Destination, dst xnet.Destination, data []byte) {
	u.RLock()
	conn, found := u.udpConns[src]
	if found {
		select {
		case conn.egress <- &ocUdpPacket{data: data, dest: &dst}:
		default:
		}
		u.RUnlock()
		return
	}
	u.RUnlock()

	u.Lock()
	defer u.Unlock()
	conn, found = u.udpConns[src]
	if !found {
		conn = &ocUdpConn{handler: u, egress: make(chan *ocUdpPacket, 1024), src: src, dst: dst}
		u.udpConns[src] = conn
		go u.handleConnection(conn, dst)
	}
	select {
	case conn.egress <- &ocUdpPacket{data: data, dest: &dst}:
	default:
	}
}

func (u *ocUdpHandler) connectionFinished(conn *ocUdpConn) {
	u.Lock()
	// Close() can fire more than once (teardown + defer). Compare identity so a
	// stale Close of an old flow never tears down the flow that reused its src.
	if cur, found := u.udpConns[conn.src]; found && cur == conn {
		delete(u.udpConns, conn.src)
		close(conn.egress)
	}
	u.Unlock()
}

// ocUdpConn is a synthetic net.Conn over one fullcone UDP flow.
type ocUdpConn struct {
	handler *ocUdpHandler

	egress chan *ocUdpPacket
	src    xnet.Destination
	dst    xnet.Destination
}

// ReadMultiBuffer yields one client datagram per buffer with its UDP
// destination attached, so the dispatcher/outbound sees proper per-packet
// addressing (mirrors the TUN inbound UDP conn).
func (c *ocUdpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		e, ok := <-c.egress
		if !ok {
			return nil, io.EOF
		}
		b := buf.New()
		if _, err := b.Write(e.data); err != nil {
			b.Release()
			continue
		}
		b.UDP = e.dest
		return buf.MultiBuffer{b}, nil
	}
}

func (c *ocUdpConn) Read(p []byte) (int, error) {
	e, ok := <-c.egress
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, e.data)
	if n != len(e.data) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

// WriteMultiBuffer sends one response datagram per buffer; a buffer's UDP
// source overrides the flow's original destination.
func (c *ocUdpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.dst
		if b.UDP != nil && !b.UDP.Address.Family().IsDomain() {
			dst = *b.UDP
		}
		if err := c.handler.writePacket(b.Bytes(), dst, c.src); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

func (c *ocUdpConn) Write(p []byte) (int, error) {
	if err := c.handler.writePacket(p, c.dst, c.src); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ocUdpConn) Close() error {
	c.handler.connectionFinished(c)
	return nil
}

func (c *ocUdpConn) LocalAddr() net.Addr  { return c.dst.RawNetAddr() }
func (c *ocUdpConn) RemoteAddr() net.Addr { return c.src.RawNetAddr() }
func (c *ocUdpConn) SetDeadline(_ time.Time) error {
	return nil
}
func (c *ocUdpConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *ocUdpConn) SetWriteDeadline(_ time.Time) error { return nil }

// writeRawUDPPacket builds a raw UDP/IPv4 packet and injects it into the gVisor
// stack so the reply reaches the client through the device. The tunnel is
// IPv4-only, so both flow addresses are always IPv4.
func (s *ocStack) writeRawUDPPacket(payload []byte, src xnet.Destination, dst xnet.Destination) error {
	if s.stack == nil {
		return nil
	}
	udpLen := header.UDPMinimumSize + len(payload)
	srcIP := tcpip.AddrFromSlice(src.Address.IP())
	dstIP := tcpip.AddrFromSlice(dst.Address.IP())

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.UDPMinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	defer pkt.DecRef()

	udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udpHdr.Encode(&header.UDPFields{
		SrcPort: uint16(src.Port),
		DstPort: uint16(dst.Port),
		Length:  uint16(udpLen),
	})
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, uint16(udpLen))
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(payload, xsum)))

	ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + udpLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     srcIP,
		DstAddr:     dstIP,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	if err := s.stack.WriteRawPacket(ocNIC, header.IPv4ProtocolNumber, buffer.MakeWithView(pkt.ToView())); err != nil {
		return errors.New("write raw udp packet to stack ", err)
	}
	return nil
}
