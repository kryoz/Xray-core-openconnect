package openconnect

import (
	"context"
	"net/netip"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
	"google.golang.org/protobuf/proto"
)

var (
	_ proxy.UserManager               = (*Server)(nil)
	_ proxy.BlockableUserManager      = (*Server)(nil)
	_ proxy.TunableUserManager        = (*Server)(nil)
	_ proxy.DisconnectableUserManager = (*Server)(nil)
)

// AddUser implements proxy.UserManager: the account becomes usable on the
// running inbound, no restart involved. The stored copy is a clone, so a later
// mutation of the message the caller handed over cannot reach the live store.
func (s *Server) AddUser(ctx context.Context, mu *protocol.MemoryUser) error {
	acc, ok := mu.Account.(*MemoryAccount)
	if !ok {
		return errors.New("not an OpenConnect account: ", mu.Email)
	}
	// Email is the universal key of the user API (GetUser/RemoveUser take it),
	// so for this inbound it has to name the account outright.
	if mu.Email != acc.user.Name {
		return errors.New("email ", mu.Email, " does not match the user name ", acc.user.Name)
	}
	u := proto.Clone(acc.user).(*User)
	// The general contract carries the block on MemoryUser, this protocol
	// carries it on its own User: set both, or an add that arrives blocked
	// would only look blocked through the API.
	if mu.Disabled {
		u.Disabled = proto.Bool(true)
	}
	prefix, err := netip.ParsePrefix(s.conf.Subnet)
	if err != nil {
		return errors.New("invalid subnet: ", s.conf.Subnet).Base(err)
	}
	if err := s.conf.checkUser(u, prefix, s.conf.groupNames()); err != nil {
		return err
	}
	// Claim the static address before touching the store, so a rejected add
	// never leaves an address reserved and an accepted one never races a live
	// session for the same virtual IP.
	var claimed netip.Addr
	if u.Ip != "" {
		// checkUser accepted the address as an in-subnet host address already.
		if ip, err := netip.ParseAddr(u.Ip); err == nil {
			if !s.registry.pool.tryReserve(ip) {
				return errors.New("user ", u.Name, ": static ip ", u.Ip, " is in use by a live session")
			}
			claimed = ip
		}
	}
	// Giving the address back is idempotent: a failed add leaves the claim for
	// the path below, a failed write leaves it to the undo.
	releaseClaim := func() {
		if !claimed.IsValid() {
			return
		}
		s.registry.pool.release(claimed)
		claimed = netip.Addr{}
	}
	// The account is not taken back when the add itself fails: it was never
	// stored, and on a duplicate the name belongs to the account that already
	// has it.
	err = s.mutateUsers(func() error { return s.users.add(u) }, func() error {
		_, err := s.users.remove(u.Name)
		releaseClaim()
		return err
	})
	if err != nil {
		releaseClaim()
		return err
	}
	errors.LogInfo(ctx, "openconnect: user ", u.Name, " added")
	return nil
}

// RemoveUser implements proxy.UserManager. The account is gone from the
// running inbound and its live tunnels are cut with it.
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	var u *User
	// Nothing destructive happens before the write — the address is still
	// reserved and no session was cut — so putting the account back is a
	// complete rollback, and the only one that keeps memory and the file in
	// step: the file still holds the user.
	err := s.mutateUsers(func() error {
		var err error
		u, err = s.users.remove(email)
		return err
	}, func() error {
		return s.users.add(u)
	})
	if err != nil {
		return err
	}
	// The sessions are cut before the static address returns to the pool:
	// released first, a concurrent dynamic alloc could hand the address to
	// another user while the removed user's tunnels were still on it.
	n := s.registry.disconnectUser(ctx, u.Name, "user removed")
	if u.Ip != "" {
		// Undo the config-time reservation. Sessions of this user never
		// released the address themselves: releaseLease skips static users.
		if ip, err := netip.ParseAddr(u.Ip); err == nil {
			s.registry.pool.release(ip)
		}
	}
	errors.LogInfo(ctx, "openconnect: user ", u.Name, " removed, ", n, " session(s) disconnected")
	return nil
}

// SetUserBlocked implements proxy.BlockableUserManager. Blocking keeps the
// account, its credential, its static address and its stats key, but the user
// can no longer authenticate, can no longer resume on a live cookie, and loses
// the tunnels it has up right now.
func (s *Server) SetUserBlocked(ctx context.Context, email string, blocked bool) error {
	var (
		u          *User
		wasBlocked bool
	)
	err := s.mutateUsers(func() error {
		if au, ok := s.users.lookup(email); ok {
			wasBlocked = au.user.GetDisabled()
		}
		var err error
		u, err = s.users.setBlocked(email, blocked)
		return err
	}, func() error {
		// Back to exactly the flag that was there, which is what the file on
		// disk still says.
		_, err := s.users.setBlocked(email, wasBlocked)
		return err
	})
	if err != nil {
		return err
	}
	if !blocked {
		errors.LogInfo(ctx, "openconnect: user ", u.Name, " unblocked")
		return nil
	}
	n := s.registry.disconnectUser(ctx, u.Name, "user blocked")
	errors.LogInfo(ctx, "openconnect: user ", u.Name, " blocked, ", n, " session(s) disconnected")
	return nil
}

// SetUserMaxSessions implements proxy.TunableUserManager. The bound is
// re-resolved from the store on every auth and CONNECT, so the swapped record
// bites from the next limit check on while the sessions up right now keep
// running — nothing is kicked, unlike a block.
// A nil limit removes the override: the account's group bound applies again.
func (s *Server) SetUserMaxSessions(ctx context.Context, email string, limit *uint32) error {
	if au, ok := s.users.lookup(email); !ok {
		return errors.New("user ", email, " not found")
	} else if cur := au.user.MaxSessionsPerUser; cur == limit || (cur != nil && limit != nil && *cur == *limit) {
		return nil // idempotent: nothing to swap, no file rewrite
	}

	var old *User
	err := s.mutateUsers(func() error {
		au, ok := s.users.lookup(email)
		if !ok {
			return errors.New("user ", email, " not found")
		}
		next := proto.Clone(au.user).(*User)
		next.MaxSessionsPerUser = limit
		prev, err := s.users.replace(email, next)
		old = prev
		return err
	}, func() error {
		_, err := s.users.replace(email, old)
		return err
	})
	if err != nil {
		return err
	}
	if limit == nil {
		errors.LogInfo(ctx, "openconnect: max sessions per user of ", email, " reset to the group's limit")
		return nil
	}
	errors.LogInfo(ctx, "openconnect: max sessions per user of ", email, " set to ", *limit)
	return nil
}

// SetUserL3 implements proxy.TunableUserManager. The flag is resolved when a
// session is created, so the swapped record bites from the next session on
// while the sessions up right now keep the flag they started with — nothing
// is kicked, unlike a block.
func (s *Server) SetUserL3(ctx context.Context, email string, l3 *bool) error {
	if au, ok := s.users.lookup(email); !ok {
		return errors.New("user ", email, " not found")
	} else if l3Equal(au.user.L3, l3) {
		return nil // idempotent: nothing to swap, no file rewrite
	}

	var old *User
	err := s.mutateUsers(func() error {
		au, ok := s.users.lookup(email)
		if !ok {
			return errors.New("user ", email, " not found")
		}
		next := proto.Clone(au.user).(*User)
		next.L3 = l3
		prev, err := s.users.replace(email, next)
		old = prev
		return err
	}, func() error {
		_, err := s.users.replace(email, old)
		return err
	})
	if err != nil {
		return err
	}
	errors.LogInfo(ctx, "openconnect: l3 relay of ", email, " set to ", L3Label(l3))
	return nil
}

// DisconnectUser cuts every live session of one account. The account itself
// is untouched — credential, static address, overrides, block flag — so the
// user can authenticate again straight away. It is a no-op when the account
// has no live session.
func (s *Server) DisconnectUser(ctx context.Context, email string) error {
	if _, ok := s.users.lookup(email); !ok {
		return errors.New("user ", email, " not found")
	}
	n := s.registry.disconnectUser(ctx, email, "disconnected by operator")
	errors.LogInfo(ctx, "openconnect: user ", email, " disconnected, ", n, " session(s)")
	return nil
}

// l3Equal compares the tri-state L3 flags: nil, false and true are distinct.
func l3Equal(a, b *bool) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

// L3Label renders a tri-state L3 flag for logs and CLI output.
func L3Label(l3 *bool) string {
	switch {
	case l3 == nil:
		return "inherit"
	case *l3:
		return "on"
	default:
		return "off"
	}
}

// GetUser implements proxy.UserManager. A blocked user is still returned: the
// API has to be able to show an account the operator suspended.
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	au, ok := s.users.lookup(email)
	if !ok {
		return nil
	}
	return memoryUser(au)
}

// GetUsers implements proxy.UserManager.
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	all := s.users.snapshot()
	out := make([]*protocol.MemoryUser, 0, len(all))
	for _, au := range all {
		out = append(out, memoryUser(au))
	}
	return out
}

// GetUsersCount implements proxy.UserManager.
func (s *Server) GetUsersCount(ctx context.Context) int64 {
	return s.users.count()
}

// memoryUser re-wraps a stored account as the form the user API exchanges.
func memoryUser(au *authUser) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Account:  &MemoryAccount{user: au.user, cred: au.cred},
		Email:    au.user.Name,
		Disabled: au.user.GetDisabled(),
	}
}
