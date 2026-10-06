package openconnect

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// ocSession is one authenticated OpenConnect client.
type ocSession struct {
	sid      [32]byte
	user     *User
	ip       netip.Addr
	l3       bool // resolved L3 relay flag (user override → group → false); read on the hot relay path
	created  time.Time
	clientIP string // client's real source IP

	// endOnce guards the single "session end" line: both registry.remove and
	// the GC sweep can reap the same session.
	endOnce sync.Once

	mu      sync.Mutex
	tunnels int // live cstpPump instances; the session is connected while > 0
	// tunnelGen counts CONNECTs. A pump whose gen is no longer current was
	// superseded by a newer CONNECT: its TCP connection is already closed and
	// its teardown must not touch the successor's writer or kick. kick closes
	// the current tunnel's connection; openTunnel calls the previous one's.
	tunnelGen uint64
	kick      func()
	lastDisc  time.Time // last tunnel disconnect; drives cookie/resume TTL
	// writer is the device writer token this session's live tunnel registered;
	// teardown unregisters it only while it still owns the slot (two sessions
	// of one user may share a static virtual IP). Guarded by mu.
	writer *ocWriter
}

// userName returns the session's user name, or "-" for an anonymous session.
func (s *ocSession) userName() string {
	if s.user == nil {
		return "-"
	}
	return s.user.Name
}

// sessionStartLine renders the session-start record. Pure so the field set is
// pinned by a test: these lines are grepped during incidents.
func (s *ocSession) sessionStartLine() string {
	static := s.user != nil && s.user.Ip != ""
	group := "-"
	if s.user != nil && s.user.Group != "" {
		group = s.user.Group
	}
	return fmt.Sprintf("openconnect: session start user=%s ip=%s peer=%s group=%s static=%t l3=%t",
		s.userName(), s.ip, s.clientIP, group, static, s.l3)
}

// tunnelClosedLine renders the end of one CSTP/TCP tunnel. now is a parameter
// so tests get deterministic durations.
func (s *ocSession) tunnelClosedLine(reason string, started, now time.Time) string {
	return fmt.Sprintf("openconnect: tunnel closed user=%s ip=%s peer=%s tunnel=%s session=%s reason=%s",
		s.userName(), s.ip, s.clientIP,
		now.Sub(started).Round(time.Second), now.Sub(s.created).Round(time.Second), reason)
}

// sessionEndLine renders the final end of a session.
func (s *ocSession) sessionEndLine(reason string, now time.Time) string {
	static := s.user != nil && s.user.Ip != ""
	return fmt.Sprintf("openconnect: session end user=%s ip=%s peer=%s duration=%s static=%t reason=%s",
		s.userName(), s.ip, s.clientIP, now.Sub(s.created).Round(time.Second), static, reason)
}

// logSessionStart reports the creation of a session (cookie lifetime), for
// every user — static-IP clients included: the address is pinned by config, so
// the old "CONNECT tunnel ip=..." line alone did not tell an operator which
// user it belonged to or from which WAN address the client came.
func (s *ocSession) logSessionStart(ctx context.Context) {
	errors.LogInfo(ctx, s.sessionStartLine())
}

// logTunnelClosed reports the end of one CSTP/TCP tunnel. A session can see
// this several times (a resume re-runs cstpPump), so this — not the session
// end — is what usually says "the client dropped at HH:MM:SS and why".
func (s *ocSession) logTunnelClosed(ctx context.Context, reason string, started time.Time) {
	errors.LogInfo(ctx, s.tunnelClosedLine(reason, started, time.Now()))
}

// markEnded reports whether this call is the one that closes the session
// record: registry.remove and the GC sweep can both reach the same session,
// and a doubled "session end" line would read like two sessions.
func (s *ocSession) markEnded() bool {
	fired := false
	s.endOnce.Do(func() { fired = true })
	return fired
}

// logSessionEnd reports the final end of a session: its cookie/resume window
// elapsed, or it was dropped before the client ever connected. Fires once
// (sync.Once) because both registry.remove and the GC sweep can reach it.
func (s *ocSession) logSessionEnd(ctx context.Context, reason string) {
	if !s.markEnded() {
		return
	}
	errors.LogInfo(ctx, s.sessionEndLine(reason, time.Now()))
}

// openTunnel registers a new tunnel and supersedes the previous one: a CONNECT
// (app restart, VPN toggle, rekey, reconnect after a lost cookie) replaces the
// live tunnel instead of leaving it half-open, as ocserv's worker does. It
// returns the generation the pump must compare against in closeTunnel.
func (s *ocSession) openTunnel(tc io.Closer) uint64 {
	s.mu.Lock()
	s.tunnels++
	s.tunnelGen++
	gen := s.tunnelGen
	prev := s.kick
	s.kick = func() { _ = tc.Close() }
	s.mu.Unlock()
	if prev != nil {
		prev()
	}
	return gen
}

// closeTunnel retires one pump. The session stops being connected, and the
// cookie/resume window starts running, only when its last tunnel is gone; a
// superseded pump never clears its successor's kick.
func (s *ocSession) closeTunnel(gen uint64) {
	s.mu.Lock()
	if s.tunnels > 0 {
		s.tunnels--
	}
	if s.tunnelGen == gen {
		s.kick = nil
	}
	if s.tunnels == 0 {
		s.lastDisc = time.Now()
	}
	s.mu.Unlock()
}

// isSuperseded reports whether a newer CONNECT replaced this pump; the read
// error that follows is then expected, not a client-path failure.
func (s *ocSession) isSuperseded(gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tunnelGen != gen
}

// isConnected reports whether the session has a live tunnel.
func (s *ocSession) isConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tunnels > 0
}

// expired reports whether the session's cookie/resume window has elapsed.
// A session with a live tunnel, or one that never disconnected, never expires.
func (s *ocSession) expired(now time.Time, cookieTimeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnels > 0 || s.lastDisc.IsZero() {
		return false
	}
	return now.Sub(s.lastDisc) > cookieTimeout
}

// sessionRegistry tracks live sessions by SID (cookie) and virtual IP. The
// client's source address is kept on the session for logging only: it is not a
// lookup key, because a mobile or IPv6 client changes it on every reconnect and
// many users share one address behind a NAT.
type sessionRegistry struct {
	// RWMutex: the index maps are read on the per-packet relay path and per
	// TCP-flow setup, but written only on auth/CONNECT/sweep — readers must
	// not serialize each other. Lock order: registry mu before a session's mu
	// (sweep, countConnected and supersedeStale all check session state here).
	mu       sync.RWMutex
	bySID    map[[32]byte]*ocSession
	byVirtIP map[netip.Addr]*ocSession
	pool     *ipPool
	// anyL3 is set once any L3 user registers; relayL3 checks it first so
	// non-L3 deployments pay one atomic load per packet instead of the
	// destination-IP parse plus registry lookup.
	// ponytail: sticky — set on the first L3 session and never cleared when the
	// last one leaves, so a deployment that once had an L3 user keeps paying
	// the destination parse. Upgrade when L3 can be turned off at runtime.
	anyL3 atomic.Bool
}

func newSessionRegistry(pool *ipPool) *sessionRegistry {
	return &sessionRegistry{
		bySID:    make(map[[32]byte]*ocSession),
		byVirtIP: make(map[netip.Addr]*ocSession),
		pool:     pool,
	}
}

// create allocates a session with a fresh SID and a virtual IP. A session
// always belongs to an authenticated user: remove/sweep release the IP lease
// through user.Ip and the L4 attribution reads user.Name, so a nil user is a
// caller bug, not a state to carry through the registry.
func (r *sessionRegistry) create(clientIP string, user *User, l3 bool) (*ocSession, error) {
	if user == nil {
		return nil, errors.New("session without a user")
	}
	sess := &ocSession{clientIP: clientIP, user: user, l3: l3, created: time.Now(), lastDisc: time.Now()}
	if l3 {
		r.anyL3.Store(true)
	}
	if _, err := rand.Read(sess.sid[:]); err != nil {
		return nil, errors.New("generate sid").Base(err)
	}
	if user.Ip != "" {
		ip, err := netip.ParseAddr(user.Ip)
		if err != nil {
			return nil, errors.New("bad static ip for user ").Base(err)
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
	r.byVirtIP[sess.ip] = sess
	r.mu.Unlock()
	return sess, nil
}

func (r *sessionRegistry) getBySID(sid [32]byte) *ocSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bySID[sid]
}

// getByVirtIP resolves the session owning a virtual tunnel IP. It attributes
// L4 flows demuxed by the gVisor stack to the authenticated user, enabling
// the dispatcher's standard per-user stats (user>>>email>>>traffic/online).
func (r *sessionRegistry) getByVirtIP(ip netip.Addr) *ocSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byVirtIP[ip]
}

func (r *sessionRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.bySID)
}

// countConnected returns the number of sessions with a live tunnel. That is
// what max_clients bounds: a session inside its resume window without a tunnel
// holds an IP lease, not a client slot.
func (r *sessionRegistry) countConnected() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, sess := range r.bySID {
		if sess.isConnected() {
			n++
		}
	}
	return n
}

// connectedCount returns how many sessions of user have a live tunnel — what
// max_sessions_per_user bounds (same live-tunnels-not-records accounting as
// countConnected/max_clients). except, when non-nil, is left out of the
// count: a session re-CONNECTing after a dropped path replaces its own
// tunnel, and must not be blocked by the very tunnel it replaces.
// Best-effort snapshot: two CONNECTs of one user racing can both see the
// limit not yet reached and overshoot by one until a tunnel closes.
func (r *sessionRegistry) connectedCount(user string, except *[32]byte) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, sess := range r.bySID {
		if sess.userName() == user && (except == nil || sess.sid != *except) && sess.isConnected() {
			n++
		}
	}
	return n
}

// supersedeStale drops every session of user that has no live tunnel and
// returns how many. A cookie-less reconnect loop (app restart, VPN toggle, lost
// cookie, changed source address) otherwise leaves one zombie per attempt, each
// holding a dynamic IP for the whole cookie window. Keyed by user rather than
// by source address: behind a NAT one address belongs to several users, and a
// mobile client changes it on every attempt. Only sessions whose tunnel is down
// are touched, so a second connected device is never affected; a second idle
// device loses its resume cookie and authenticates again.
func (r *sessionRegistry) supersedeStale(ctx context.Context, user string) int {
	// Scan and unregister under one write lock: with a read lock and a separate
	// remove, a session that got its CONNECT in between was dropped while its
	// tunnel was still live — out of both indexes, invisible to the sweep and
	// the L3 relay, and with its IP back in the pool for another client.
	r.mu.Lock()
	var stale []*ocSession
	for _, sess := range r.bySID {
		if sess.userName() == user && !sess.isConnected() {
			r.retireLocked(sess)
			stale = append(stale, sess)
		}
	}
	r.mu.Unlock()
	for _, sess := range stale {
		r.releaseLease(sess)
		sess.logSessionEnd(ctx, "superseded by re-auth for the same user")
	}
	return len(stale)
}

// retireLocked drops a session from both indexes. The virtual-IP index is
// updated conditionally: two sessions of one user may share a static virtual
// IP, and removing the older one must not clobber the successor's entry.
// Caller holds r.mu for writing.
func (r *sessionRegistry) retireLocked(sess *ocSession) {
	delete(r.bySID, sess.sid)
	if r.byVirtIP[sess.ip] == sess {
		delete(r.byVirtIP, sess.ip)
	}
}

// releaseLease returns a session's dynamic IP to the pool; a static-IP user
// holds no lease. It must run exactly once per session: remove, sweep and
// supersedeStale all reach the same session, and a second release would
// un-allocate an address that a new session has just been handed.
func (r *sessionRegistry) releaseLease(sess *ocSession) {
	if sess.user.Ip == "" {
		r.pool.release(sess.ip)
	}
}

// remove drops a session and releases its dynamic IP. A session already reaped
// by the sweep or by a supersede is not released a second time.
func (r *sessionRegistry) remove(ctx context.Context, sess *ocSession, reason string) {
	r.mu.Lock()
	known := r.bySID[sess.sid] == sess
	if known {
		r.retireLocked(sess)
	}
	r.mu.Unlock()
	if !known {
		return
	}
	r.releaseLease(sess)
	sess.logSessionEnd(ctx, reason)
}

// sweep removes disconnected sessions whose resume window has elapsed, freeing
// their dynamic IPs. Connected sessions are left alone.
func (r *sessionRegistry) sweep(ctx context.Context, cookieTimeout time.Duration) int {
	now := time.Now()
	r.mu.Lock()
	var dead []*ocSession
	for _, sess := range r.bySID {
		if sess.expired(now, cookieTimeout) {
			r.retireLocked(sess)
			dead = append(dead, sess)
		}
	}
	r.mu.Unlock()
	for _, sess := range dead {
		r.releaseLease(sess)
		sess.logSessionEnd(ctx, "cookie/resume window expired")
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
		return nil, errors.New("invalid subnet: ", subnet).Base(err)
	}
	if !prefix.Addr().Is4() {
		return nil, errors.New("subnet must be IPv4: ", subnet)
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
		return nil, errors.New("subnet too small: ", subnet)
	}
	return &ipPool{prefix: prefix, ones: ones, next: 2, allocated: make(map[netip.Addr]struct{})}, nil
}

// prefixOnes extracts the "/N" length from a CIDR string.
func prefixOnes(cidr string) (int, error) {
	i := strings.LastIndexByte(cidr, '/')
	if i < 0 {
		return 0, errors.New("subnet must be CIDR: ", cidr)
	}
	n, err := strconv.Atoi(cidr[i+1:])
	if err != nil || n < 0 || n > 32 {
		return 0, errors.New("invalid subnet prefix: ", cidr)
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
	return netip.Addr{}, errors.New("ip pool exhausted: ", p.prefix.String())
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
