package openconnect

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
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
	activity  time.Time // last DTLS data received; drives DPD

	dtlsConn *dtls.Conn // established DTLS data channel (nil until handshake)
	pipe     *ocPipe    // UDP demux pipe backing the DTLS conn (for NAT rebinding)
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

// markDisconnected records a tunnel teardown, starting the resume TTL.
func (s *ocSession) markDisconnected() {
	s.mu.Lock()
	s.connected = false
	s.lastDisc = time.Now()
	s.mu.Unlock()
}

// touchActivity records the last time DTLS data was received from the client.
func (s *ocSession) touchActivity() {
	s.mu.Lock()
	s.activity = time.Now()
	s.mu.Unlock()
}

// lastActivity returns the last time DTLS data was received from the client.
func (s *ocSession) lastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activity
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
	mu         sync.Mutex
	bySID      map[[32]byte]*ocSession
	byAppID    map[string]*ocSession
	byClientIP map[string]*ocSession
	pool       *ipPool
}

func newSessionRegistry(pool *ipPool) *sessionRegistry {
	return &sessionRegistry{
		bySID:      make(map[[32]byte]*ocSession),
		byAppID:    make(map[string]*ocSession),
		byClientIP: make(map[string]*ocSession),
		pool:       pool,
	}
}

// create allocates a session with a fresh SID and a virtual IP.
func (r *sessionRegistry) create(appID, clientIP string, user *User) (*ocSession, error) {
	sess := &ocSession{appID: appID, clientIP: clientIP, user: user, created: time.Now(), lastDisc: time.Now(), activity: time.Now()}
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
	r.mu.Unlock()
	return sess, nil
}

func (r *sessionRegistry) getBySID(sid [32]byte) *ocSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bySID[sid]
}

func (r *sessionRegistry) getByClientIP(ip string) *ocSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byClientIP[ip]
}

func (r *sessionRegistry) getByAppID(appID string) *ocSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byAppID[appID]
}

func (r *sessionRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bySID)
}

// remove drops a session and releases its dynamic IP.
func (r *sessionRegistry) remove(sess *ocSession) {
	r.mu.Lock()
	delete(r.bySID, sess.sid)
	delete(r.byAppID, sess.appID)
	delete(r.byClientIP, sess.clientIP)
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
			delete(r.byAppID, sess.appID)
			delete(r.byClientIP, sess.clientIP)
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
	ones, err := prefixOnes(subnet)
	if err != nil {
		return nil, err
	}
	if 32-ones < 2 {
		return nil, errors.New("subnet too small: ", subnet).AtError()
	}
	return &ipPool{prefix: prefix, ones: ones, next: 1, allocated: make(map[netip.Addr]struct{})}, nil
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
	usable := total - 2 // skip network and broadcast
	base4 := p.prefix.Addr().As4()
	base := binary.BigEndian.Uint32(base4[:])
	for i := 0; i < usable; i++ {
		off := ((p.next-1)+i)%usable + 1
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], base+uint32(off))
		addr := netip.AddrFrom4(a)
		if _, taken := p.allocated[addr]; !taken {
			p.allocated[addr] = struct{}{}
			p.next = off + 1
			if p.next > usable {
				p.next = 1
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
