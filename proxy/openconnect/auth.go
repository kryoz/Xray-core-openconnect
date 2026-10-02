package openconnect

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	authFailMax    = 5
	authFailWindow = 5 * time.Minute
	// authFailSweepThreshold triggers a lazy sweep of stale attempts so the
	// limiter map cannot grow without bound from one-shot attacking IPs.
	authFailSweepThreshold = 1024
)

// authUser pairs a parsed credential with its original config user.
type authUser struct {
	cred *credential
	user *User
}

// userStore holds parsed credentials for constant-time verification.
type userStore struct {
	mu    sync.RWMutex
	users map[string]*authUser
}

func newUserStore(users []*User) (*userStore, error) {
	s := &userStore{users: make(map[string]*authUser, len(users))}
	for _, u := range users {
		cred, err := parseCredential(u.Password)
		if err != nil {
			return nil, errors.New("user ", u.Name, ": ").Base(err)
		}
		s.users[u.Name] = &authUser{cred: cred, user: u}
	}
	return s, nil
}

func (s *userStore) check(name, password string) bool {
	s.mu.RLock()
	au, ok := s.users[name]
	s.mu.RUnlock()
	if !ok {
		// Burn comparable time to reduce user-enumeration timing signal.
		dummy := &credential{}
		dummy.check(password)
		return false
	}
	return au.cred.check(password)
}

func (s *userStore) userByName(name string) *User {
	s.mu.RLock()
	au, ok := s.users[name]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return au.user
}

// authLimiter blocks an IP after too many failed authentications in a window.
type authLimiter struct {
	mu       sync.Mutex
	attempts map[string]*failCount
}

type failCount struct {
	count int
	first time.Time
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{attempts: make(map[string]*failCount)}
}

func (l *authLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.attempts[ip]
	if !ok {
		return false
	}
	if time.Since(f.first) > authFailWindow {
		delete(l.attempts, ip)
		return false
	}
	return f.count >= authFailMax
}

// recordFailure records one failed attempt for ip and reports whether the ip
// just crossed into the blocked state.
func (l *authLimiter) recordFailure(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	f, ok := l.attempts[ip]
	if !ok || now.Sub(f.first) > authFailWindow {
		l.attempts[ip] = &failCount{count: 1, first: now}
		l.sweepLocked(now)
		return false
	}
	f.count++
	l.sweepLocked(now)
	return f.count == authFailMax
}

// sweepLocked lazily reaps expired entries once the map grows past the
// threshold, bounding memory under sustained attack. It runs on 1 of 16
// calls: scanning the whole map on every recordFailure would be O(n^2)
// under a mass attack. Caller holds l.mu.
func (l *authLimiter) sweepLocked(now time.Time) {
	if len(l.attempts) < authFailSweepThreshold || rand.IntN(16) != 0 {
		return
	}
	for ip, f := range l.attempts {
		if now.Sub(f.first) > authFailWindow {
			delete(l.attempts, ip)
		}
	}
}

func (l *authLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.attempts, ip)
	l.mu.Unlock()
}

// noteAuthFailure records a failed attempt for peerIP and logs the moment the
// IP crosses into the blocked state.
func (s *Server) noteAuthFailure(peerIP string) {
	if s.limiter.recordFailure(peerIP) {
		errors.LogWarning(s.ctx, fmt.Sprintf("openconnect: auth limiter: %s blocked for %v after %d failed attempts", peerIP, authFailWindow, authFailMax))
	}
}
