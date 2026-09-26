package openconnect

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/xtls/xray-core/common/errors"
)

// ocSession is one authenticated OpenConnect client. The PSK is derived from
// the TLS control-channel session and used to key the DTLS data channel.
type ocSession struct {
	sid      [32]byte
	appID    string // hex of the TLS session ID, advertised as X-DTLS-App-ID
	user     *User
	ip       netip.Addr
	psk      []byte
	created  time.Time
	clientIP string // client's real source IP, primary key for UDP demux

	mu        sync.Mutex
	connected bool
	lastDisc  time.Time // last tunnel disconnect; drives cookie/resume TTL
	// activity is the last DTLS data timestamp (UnixNano). Atomic instead of
	// under mu: the DTLS read pump stores it on every packet and must not
	// contend with the control path's dtlsConn/dtlsWriter transactions.
	activity atomic.Int64

	dtlsConn  *dtls.Conn         // established DTLS data channel (nil until handshake)
	pipe      *ocPipe            // UDP demux pipe backing the DTLS conn (for NAT rebinding)
	cstpWrite func([]byte) error // live CSTP/TCP fallback writer; nil once the TCP conn closes
	// dtlsWriter is the device writer token this session's live DTLS
	// generation registered; teardown unregisters it only while it still
	// owns the slot (two sessions of one user may share a static virtual IP).
	// Guarded by mu.
	dtlsWriter *ocWriter
}

// setPSK stores the derived DTLS PSK for this session. Guarded by s.mu: the
// control goroutine writes it on auth/CONNECT while the DTLS handshake
// goroutine reads it via getPSK.
func (s *ocSession) setPSK(psk []byte) {
	s.mu.Lock()
	s.psk = psk
	s.mu.Unlock()
}

// getPSK returns the derived DTLS PSK for this session. Guarded by s.mu.
func (s *ocSession) getPSK() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.psk
}

// markConnected records that the tunnel is (re)established.
func (s *ocSession) markConnected() {
	s.mu.Lock()
	s.connected = true
	s.mu.Unlock()
}

// touchActivity records the last time DTLS data was received from the client.
func (s *ocSession) touchActivity() {
	s.activity.Store(time.Now().UnixNano())
}

// lastActivity returns the last time DTLS data was received from the client.
func (s *ocSession) lastActivity() time.Time {
	return time.Unix(0, s.activity.Load())
}

// expired reports whether the session's cookie/resume window has elapsed.
// A connected session, or one that never disconnected, never expires.
func (s *ocSession) expired(now time.Time, cookieTimeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connected || s.lastDisc.IsZero() {
		return false
	}
	return now.Sub(s.lastDisc) > cookieTimeout
}

// sessionRegistry tracks live sessions by SID (cookie), App-ID, and client IP
// (the primary key for UDP DTLS demux).
type sessionRegistry struct {
	// RWMutex: the index maps are read on the per-packet relay path and per
	// TCP-flow setup, but written only on auth/CONNECT/sweep — readers must
	// not serialize each other.
	mu         sync.RWMutex
	bySID      map[[32]byte]*ocSession
	byAppID    map[string]*ocSession
	byClientIP map[string]*ocSession
	byVirtIP   map[netip.Addr]*ocSession
	pool       *ipPool
	// anyL3 is set once any L3 user registers; relayL3 checks it first so
	// non-L3 deployments pay one atomic load per packet instead of the
	// destination-IP parse plus registry lookup.
	anyL3 atomic.Bool
}

func newSessionRegistry(pool *ipPool) *sessionRegistry {
	return &sessionRegistry{
		bySID:      make(map[[32]byte]*ocSession),
		byAppID:    make(map[string]*ocSession),
		byClientIP: make(map[string]*ocSession),
		byVirtIP:   make(map[netip.Addr]*ocSession),
		pool:       pool,
	}
}

// create allocates a session with a fresh SID and a virtual IP.
func (r *sessionRegistry) create(appID, clientIP string, user *User) (*ocSession, error) {
	sess := &ocSession{appID: appID, clientIP: clientIP, user: user, created: time.Now(), lastDisc: time.Now()}
	sess.activity.Store(time.Now().UnixNano())
	if user != nil && user.L3 {
		r.anyL3.Store(true)
	}
	if _, err := rand.Read(sess.sid[:]); err != nil {
		return nil, errors.New("generate sid").Base(err).AtError()
	}
	if user.Ip != "" {
		ip, err := netip.ParseAddr(user.Ip)
		if err != nil {
			return nil, errors.New("bad static ip for user ").Base(err).AtError()
		}
		sess.ip = ip
	} else {
		ip, err := r.pool.alloc()
		if err != nil {
			return nil, err
		}
		sess.ip = ip
	}
	r.mu.Lock()
	r.bySID[sess.sid] = sess
	if appID != "" {
		r.byAppID[appID] = sess
	}
	if clientIP != "" {
		r.byClientIP[clientIP] = sess
	}
	r.byVirtIP[sess.ip] = sess
	r.mu.Unlock()
	return sess, nil
}

func (r *sessionRegistry) getBySID(sid [32]byte) *ocSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bySID[sid]
}

func (r *sessionRegistry) getByClientIP(ip string) *ocSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byClientIP[ip]
}

// getByVirtIP resolves the session owning a virtual tunnel IP. It attributes
// L4 flows demuxed by the gVisor stack to the authenticated user, enabling
// the dispatcher's standard per-user stats (user>>>email>>>traffic/online).
func (r *sessionRegistry) getByVirtIP(ip netip.Addr) *ocSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byVirtIP[ip]
}

func (r *sessionRegistry) getByAppID(appID string) *ocSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byAppID[appID]
}

func (r *sessionRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.bySID)
}

// remove drops a session and releases its dynamic IP. Secondary indexes are
// conditional: two sessions may share a static virtual IP or a NAT client IP,
// and removing the older one must not clobber the successor's entries.
func (r *sessionRegistry) remove(sess *ocSession) {
	r.mu.Lock()
	delete(r.bySID, sess.sid)
	if r.byAppID[sess.appID] == sess {
		delete(r.byAppID, sess.appID)
	}
	if r.byClientIP[sess.clientIP] == sess {
		delete(r.byClientIP, sess.clientIP)
	}
	if r.byVirtIP[sess.ip] == sess {
		delete(r.byVirtIP, sess.ip)
	}
	r.mu.Unlock()
	if sess.user.Ip == "" {
		r.pool.release(sess.ip)
	}
}

// sweep removes disconnected sessions whose resume window has elapsed, freeing
// their dynamic IPs. Connected sessions are left alone.
func (r *sessionRegistry) sweep(cookieTimeout time.Duration) int {
	now := time.Now()
	r.mu.Lock()
	var dead []*ocSession
	for sid, sess := range r.bySID {
		if sess.expired(now, cookieTimeout) {
			dead = append(dead, sess)
			delete(r.bySID, sid)
			if r.byAppID[sess.appID] == sess {
				delete(r.byAppID, sess.appID)
			}
			if r.byClientIP[sess.clientIP] == sess {
				delete(r.byClientIP, sess.clientIP)
			}
			if r.byVirtIP[sess.ip] == sess {
				delete(r.byVirtIP, sess.ip)
			}
		}
	}
	r.mu.Unlock()
	for _, sess := range dead {
		if sess.user.Ip == "" {
			r.pool.release(sess.ip)
		}
	}
	return len(dead)
}

// ipPool hands out virtual IPv4 addresses from a subnet.
type ipPool struct {
	prefix    netip.Prefix
	ones      int
	mu        sync.Mutex
	next      int
	allocated map[netip.Addr]struct{}
}

func newIPPool(subnet string) (*ipPool, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return nil, errors.New("invalid subnet: ", subnet).Base(err).AtError()
	}
	if !prefix.Addr().Is4() {
		return nil, errors.New("subnet must be IPv4: ", subnet).AtError()
	}
	// Mask the base address: netip.ParsePrefix keeps it as written ("10.0.0.5/24"
	// stays .5), and the pool would then hand out addresses outside the subnet.
	prefix = prefix.Masked()
	ones, err := prefixOnes(subnet)
	if err != nil {
		return nil, err
	}
	// A /30 is the smallest usable pool: one dynamic address left after
	// network, gateway and broadcast are skipped.
	if 32-ones < 2 {
		return nil, errors.New("subnet too small: ", subnet).AtError()
	}
	return &ipPool{prefix: prefix, ones: ones, next: 2, allocated: make(map[netip.Addr]struct{})}, nil
}

// prefixOnes extracts the "/N" length from a CIDR string.
func prefixOnes(cidr string) (int, error) {
	i := strings.LastIndexByte(cidr, '/')
	if i < 0 {
		return 0, errors.New("subnet must be CIDR: ", cidr).AtError()
	}
	n, err := strconv.Atoi(cidr[i+1:])
	if err != nil || n < 0 || n > 32 {
		return 0, errors.New("invalid subnet prefix: ", cidr).AtError()
	}
	return n, nil
}

func (p *ipPool) reserve(ip netip.Addr) {
	p.mu.Lock()
	p.allocated[ip] = struct{}{}
	p.mu.Unlock()
}

func (p *ipPool) alloc() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 1 << (32 - p.ones)
	// Skip network, broadcast and the gateway address (base+1): the
	// gateway/DNS convention (ocserv, vpnc-script) pins base+1 to the
	// server, handing it to a client breaks DNS and the subnet itself.
	usable := total - 3
	base4 := p.prefix.Addr().As4()
	base := binary.BigEndian.Uint32(base4[:])
	for i := 0; i < usable; i++ {
		off := ((p.next-2)+i)%usable + 2
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], base+uint32(off))
		addr := netip.AddrFrom4(a)
		if _, taken := p.allocated[addr]; !taken {
			p.allocated[addr] = struct{}{}
			p.next = off + 1
			if p.next > usable+1 {
				p.next = 2
			}
			return addr, nil
		}
	}
	return netip.Addr{}, errors.New("ip pool exhausted: ", p.prefix.String()).AtError()
}

func (p *ipPool) release(ip netip.Addr) {
	p.mu.Lock()
	delete(p.allocated, ip)
	p.mu.Unlock()
}

// netmask returns the dotted-quad netmask for the pool's prefix length.
func (p *ipPool) netmask() string {
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], ^uint32(0xFFFFFFFF>>uint(p.ones))&0xFFFFFFFF)
	return net.IP(m[:]).String()
}
