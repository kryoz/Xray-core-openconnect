package openconnect

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/protobuf/proto"
)

// memUser builds the MemoryUser the gRPC user API delivers: a protocol.User
// whose account is a TypedMessage of this inbound's User, resolved through the
// global proto registry exactly as AddUserOperation does it.
func memUser(t *testing.T, email string, u *User) *protocol.MemoryUser {
	t.Helper()
	mu, err := (&protocol.User{Email: email, Account: serial.ToTypedMessage(u)}).ToMemoryUser()
	if err != nil {
		t.Fatalf("ToMemoryUser: %v", err)
	}
	return mu
}

// rawMemUser wraps a User without the account parse, for the cases where the
// credential itself is what is under test.
func rawMemUser(email string, u *User) *protocol.MemoryUser {
	return &protocol.MemoryUser{Account: &MemoryAccount{user: u}, Email: email}
}

// foreignAccount stands for an account of another protocol.
type foreignAccount struct{}

func (foreignAccount) Equals(protocol.Account) bool { return false }
func (foreignAccount) ToProto() proto.Message       { return nil }

// closerFunc adapts a closure to the io.Closer a tunnel connection is.
type closerFunc func()

func (f closerFunc) Close() error {
	f()
	return nil
}

// poolHeld reports whether a virtual address is allocated or reserved.
func poolHeld(t *testing.T, p *ipPool, ip string) bool {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.allocated[netip.MustParseAddr(ip)]
	return ok
}

// limiterStrikes reads the failed-authentication count recorded for an IP.
func limiterStrikes(t *testing.T, l *authLimiter, ip string) int {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.attempts[ip]
	if !ok {
		return 0
	}
	return f.count
}

func TestAddUserValidation(t *testing.T) {
	alice := func() []*User { return []*User{{Name: "alice", Password: testPW("pw-a")}} }

	tests := []struct {
		name     string
		existing []*User
		incoming *User
		email    string
		raw      bool // wrap without the account parse: the credential is the case
		wantErr  bool
	}{
		{
			name:     "ok",
			existing: alice(),
			incoming: &User{Name: "bob", Password: testPW("pw-b")},
			email:    "bob",
		},
		{
			name:     "ok with a static ip",
			existing: alice(),
			incoming: &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.50"},
			email:    "bob",
		},
		{
			name:     "ok in a known group",
			existing: alice(),
			incoming: &User{Name: "bob", Password: testPW("pw-b"), Group: "split"},
			email:    "bob",
		},
		{
			name:     "duplicate name",
			existing: alice(),
			incoming: &User{Name: "alice", Password: testPW("pw-b")},
			email:    "alice",
			wantErr:  true,
		},
		{
			name:     "empty name",
			existing: alice(),
			incoming: &User{Name: "", Password: testPW("pw-b")},
			wantErr:  true,
		},
		{
			name:     "malformed credential",
			existing: alice(),
			incoming: &User{Name: "bob", Password: "plaintext"},
			email:    "bob",
			raw:      true,
			wantErr:  true,
		},
		{
			name:     "static ip outside the subnet",
			existing: alice(),
			incoming: &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.77.0.50"},
			email:    "bob",
			wantErr:  true,
		},
		{
			name:     "static ip is the gateway address",
			existing: alice(),
			incoming: &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.1"},
			email:    "bob",
			wantErr:  true,
		},
		{
			name:     "static ip is the broadcast address",
			existing: alice(),
			incoming: &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.255"},
			email:    "bob",
			wantErr:  true,
		},
		{
			name:     "static ip already taken",
			existing: []*User{{Name: "alice", Password: testPW("pw-a"), Ip: "10.99.0.50"}},
			incoming: &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.50"},
			email:    "bob",
			wantErr:  true,
		},
		{
			name:     "unknown route group",
			existing: alice(),
			incoming: &User{Name: "bob", Password: testPW("pw-b"), Group: "nope"},
			email:    "bob",
			wantErr:  true,
		},
		{
			name:     "IPv6 route",
			existing: alice(),
			incoming: &User{Name: "bob", Password: testPW("pw-b"), Routes: []string{"fd00::/8"}},
			email:    "bob",
			wantErr:  true,
		},
		{
			name:     "email does not match the name",
			existing: alice(),
			incoming: &User{Name: "bob", Password: testPW("pw-b")},
			email:    "carol",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerUsers(t, tc.existing)
			s.conf.Groups = []*Group{{Name: "split", Routes: []string{"10.0.0.0/8"}}}
			before := s.users.count()

			var in *protocol.MemoryUser
			if tc.raw {
				in = rawMemUser(tc.email, tc.incoming)
			} else {
				in = memUser(t, tc.email, tc.incoming)
			}
			err := s.AddUser(context.Background(), in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("AddUser error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if s.users.count() != before {
					t.Fatalf("store changed on a rejected add: %d -> %d", before, s.users.count())
				}
				// A rejected add must leave the accounts it collided with
				// exactly as they were.
				for _, want := range tc.existing {
					got := s.users.userByName(want.Name)
					if got == nil || got.Password != want.Password || got.Ip != want.Ip {
						t.Fatalf("existing user %q was changed: %+v", want.Name, got)
					}
				}
				return
			}
			if s.users.count() != before+1 {
				t.Fatalf("store size = %d, want %d", s.users.count(), before+1)
			}
			if tc.incoming.Ip != "" && !poolHeld(t, s.registry.pool, tc.incoming.Ip) {
				t.Fatalf("static ip %s was not reserved in the pool", tc.incoming.Ip)
			}
		})
	}
}

// TestAddUserStaticIpInUseByALiveSession: unlike at start, when the whole
// config is known before the first session exists, a runtime add can name an
// address a live session already holds. Two sessions on one virtual IP would
// clobber the index the L3 relay and the per-user stats are keyed by.
func TestAddUserStaticIpInUseByALiveSession(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	st, cookie := ocAuth(t, s, "alice", "pw-a")
	if st != 200 {
		t.Fatalf("auth: status %d, want 200", st)
	}
	conn, _ := mustTunnel(t, s, cookie)
	defer func() { _ = conn.Close() }()
	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil {
		t.Fatal("no session after CONNECT")
	}
	held := sess.ip.String()

	before := s.users.count()
	err := s.AddUser(context.Background(), memUser(t, "bob", &User{Name: "bob", Password: testPW("pw-b"), Ip: held}))
	if err == nil {
		t.Fatalf("AddUser took the address %s a live session holds", held)
	}
	if s.users.count() != before || s.users.userByName("bob") != nil {
		t.Fatalf("the rejected add changed the store: %d users", s.users.count())
	}
	if !poolHeld(t, s.registry.pool, held) {
		t.Fatalf("the live session lost its address %s", held)
	}
}

// TestAddUserRollsBackTheReservation: an add that fails after claiming its
// static address must give it back, or every rejected request costs an address.
func TestAddUserRollsBackTheReservation(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a"), Ip: "10.99.0.50"}})
	err := s.AddUser(context.Background(), memUser(t, "bob", &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.50"}))
	if err == nil {
		t.Fatal("a duplicate static ip was accepted")
	}
	if poolHeld(t, s.registry.pool, "10.99.0.50") {
		t.Fatal("the rejected add left the address reserved")
	}
}

// TestAddUserDoesNotAliasTheCallersMessage: the store must hold a copy, or a
// caller that reuses its message would mutate a live account.
func TestAddUserDoesNotAliasTheCallersMessage(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	u := &User{Name: "bob", Password: testPW("pw-b")}
	if err := s.AddUser(context.Background(), memUser(t, "bob", u)); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	u.Password = testPW("evil")
	if got := s.users.userByName("bob"); got.Password != testPW("pw-b") {
		t.Fatalf("the stored account followed the caller's message: %q", got.Password)
	}
}

func TestAddUserForeignAccount(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	err := s.AddUser(context.Background(), &protocol.MemoryUser{Account: foreignAccount{}, Email: "bob"})
	if err == nil {
		t.Fatal("an account of another protocol was accepted")
	}
	if s.users.count() != 1 {
		t.Fatalf("store changed: %d users", s.users.count())
	}
}

// TestAddUserRuntimeAuthAndConnect is the point of the whole feature: an
// account created on the running process authenticates and tunnels without a
// restart.
func TestAddUserRuntimeAuthAndConnect(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	ctx := context.Background()
	err := s.AddUser(ctx, memUser(t, "bob", &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.60"}))
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	st, cookie := ocAuth(t, s, "bob", "pw-b")
	if st != 200 {
		t.Fatalf("auth after AddUser: status %d, want 200", st)
	}
	conn, _ := mustTunnel(t, s, cookie)
	defer func() { _ = conn.Close() }()

	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil {
		t.Fatal("no session for the runtime-added user")
	}
	if got := sess.ip.String(); got != "10.99.0.60" {
		t.Fatalf("session ip = %s, want the static ip 10.99.0.60", got)
	}
}

// TestAuthAfterRemoveRejects: the account can disappear between the password
// check and the session create.
func TestAuthAfterRemoveRejects(t *testing.T) {
	s := newTestServerUsers(t, []*User{
		{Name: "alice", Password: testPW("pw-a")},
		{Name: "bob", Password: testPW("pw-b")},
	})
	if err := s.RemoveUser(context.Background(), "bob"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if st, _ := ocAuth(t, s, "bob", "pw-b"); st != 401 {
		t.Fatalf("auth for a removed user: status %d, want 401", st)
	}
}

// TestBlockUserAuthIsIndistinguishableFromAWrongPassword pins the
// enumeration-resistance requirement: a blocked account with the right password
// must give the same answer and the same limiter strike as a wrong password, or
// the endpoint leaks "exists but blocked".
func TestBlockUserAuthIsIndistinguishableFromAWrongPassword(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	ctx := context.Background()

	stWrong, _ := ocAuth(t, s, "alice", "not-the-password")
	strikesWrong := limiterStrikes(t, s.limiter, "127.0.0.1")
	s.limiter.reset("127.0.0.1")

	if err := s.SetUserBlocked(ctx, "alice", true); err != nil {
		t.Fatalf("SetUserBlocked: %v", err)
	}
	stBlocked, _ := ocAuth(t, s, "alice", "pw-a")
	strikesBlocked := limiterStrikes(t, s.limiter, "127.0.0.1")

	if stWrong != 401 || stBlocked != 401 {
		t.Fatalf("statuses: wrong password %d, blocked %d; want 401 and 401", stWrong, stBlocked)
	}
	if strikesWrong != strikesBlocked || strikesBlocked != 1 {
		t.Fatalf("strikes: wrong password %d, blocked %d; want both 1", strikesWrong, strikesBlocked)
	}
	// The account survives a block: the API still shows it, flagged.
	if s.GetUser(ctx, "alice") == nil {
		t.Fatal("a blocked user disappeared from GetUser")
	}
	if u := s.users.userByName("alice"); u == nil || !u.GetDisabled() {
		t.Fatal("the stored user is missing or not marked disabled")
	}
}

// TestBlockUserCutsLiveTunnelAndResume covers G4 (the tunnel up right now) and
// G3 (a cookie holder that must not resume).
func TestBlockUserCutsLiveTunnelAndResume(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	ctx := context.Background()

	st, cookie := ocAuth(t, s, "alice", "pw-a")
	if st != 200 {
		t.Fatalf("auth: status %d, want 200", st)
	}
	conn, _ := mustTunnel(t, s, cookie)
	defer func() { _ = conn.Close() }()

	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil {
		t.Fatal("no session after CONNECT")
	}
	virtualIP := sess.ip.String()

	if err := s.SetUserBlocked(ctx, "alice", true); err != nil {
		t.Fatalf("SetUserBlocked: %v", err)
	}
	// G4: the live tunnel is gone without the client doing anything.
	waitDisconnected(t, sess)
	if n := s.registry.count(); n != 0 {
		t.Fatalf("registry still holds %d session(s) of a blocked user", n)
	}
	if s.registry.getByVirtIP(sess.ip) != nil {
		t.Fatal("the virtual IP index still points at the blocked session")
	}
	// G3: the dynamic address is back in the pool.
	if poolHeld(t, s.registry.pool, virtualIP) {
		t.Fatalf("ip %s was not released back to the pool", virtualIP)
	}
	// G3: the still-valid cookie no longer gets a tunnel.
	resume, rc, _ := ocTunnel(t, s, cookie)
	_ = rc.Close()
	if resume != 401 {
		t.Fatalf("resume after block: status %d, want 401", resume)
	}
}

// TestBlockUserConfigDisabled: the flag is read from the account, so an
// operator can also ship a blocked account in the config.
func TestBlockUserConfigDisabled(t *testing.T) {
	s := newTestServerUsers(t, []*User{
		{Name: "alice", Password: testPW("pw-a")},
		{Name: "bob", Password: testPW("pw-b"), Disabled: boolP(true)},
	})
	if st, _ := ocAuth(t, s, "bob", "pw-b"); st != 401 {
		t.Fatalf("auth for a config-disabled user: status %d, want 401", st)
	}
	if st, _ := ocAuth(t, s, "alice", "pw-a"); st != 200 {
		t.Fatalf("auth for a normal user: status %d, want 200", st)
	}
}

func TestUnblockUserRestoresAccess(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	ctx := context.Background()

	if err := s.SetUserBlocked(ctx, "alice", true); err != nil {
		t.Fatalf("block: %v", err)
	}
	if st, _ := ocAuth(t, s, "alice", "pw-a"); st != 401 {
		t.Fatalf("auth while blocked: status %d, want 401", st)
	}
	// Re-blocking and re-unblocking are no-ops on an account already in that
	// state, and must not drop the stored credential.
	if err := s.SetUserBlocked(ctx, "alice", true); err != nil {
		t.Fatalf("re-block: %v", err)
	}
	if err := s.SetUserBlocked(ctx, "alice", false); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if err := s.SetUserBlocked(ctx, "alice", false); err != nil {
		t.Fatalf("re-unblock: %v", err)
	}
	if u := s.users.userByName("alice"); u == nil || u.Password != testPW("pw-a") {
		t.Fatalf("the account did not survive the block cycle: %+v", u)
	}
	s.limiter.reset("127.0.0.1")

	st, cookie := ocAuth(t, s, "alice", "pw-a")
	if st != 200 {
		t.Fatalf("auth after unblock: status %d, want 200", st)
	}
	conn, _ := mustTunnel(t, s, cookie)
	_ = conn.Close()
}

func TestSetUserBlockedUnknownUser(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	if err := s.SetUserBlocked(context.Background(), "nobody", true); err == nil {
		t.Fatal("blocking an unknown user succeeded")
	}
}

// TestRemoveUserLastUserRefused pins G6: deleting the last account would make
// the next start fail validate(), so the runtime refuses it like the CLI does.
func TestRemoveUserLastUserRefused(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	if err := s.RemoveUser(context.Background(), "alice"); err == nil {
		t.Fatal("removing the last user succeeded")
	}
	if s.users.userByName("alice") == nil {
		t.Fatal("the refused removal changed the store")
	}
}

func TestRemoveUserUnknown(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	if err := s.RemoveUser(context.Background(), "nobody"); err == nil {
		t.Fatal("removing an unknown user succeeded")
	}
}

// TestRemoveUserCutsLiveSessions: removal is not deferred to the client's next
// reconnect, and a static address goes back to the pool with the account.
func TestRemoveUserCutsLiveSessions(t *testing.T) {
	s := newTestServerUsers(t, []*User{
		{Name: "alice", Password: testPW("pw-a")},
		{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.70"},
	})
	// What NewServer does for a static-IP user at start.
	s.registry.pool.reserve(netip.MustParseAddr("10.99.0.70"))
	ctx := context.Background()

	st, cookie := ocAuth(t, s, "bob", "pw-b")
	if st != 200 {
		t.Fatalf("auth: status %d, want 200", st)
	}
	conn, _ := mustTunnel(t, s, cookie)
	defer func() { _ = conn.Close() }()
	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil {
		t.Fatal("no session after CONNECT")
	}

	if err := s.RemoveUser(ctx, "bob"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	waitDisconnected(t, sess)
	if n := s.registry.count(); n != 0 {
		t.Fatalf("registry still holds %d session(s) of a removed user", n)
	}
	if poolHeld(t, s.registry.pool, "10.99.0.70") {
		t.Fatal("the static ip of the removed user is still reserved")
	}
	if s.users.userByName("bob") != nil {
		t.Fatal("the removed user is still in the store")
	}
	if s.users.userByName("alice") == nil {
		t.Fatal("RemoveUser took another account with it")
	}
	resume, rc, _ := ocTunnel(t, s, cookie)
	_ = rc.Close()
	if resume != 401 {
		t.Fatalf("resume after removal: status %d, want 401", resume)
	}
}

// TestUserManagerAPIRoundTrip checks the account survives the API round trip in
// both directions: the credential has to come back for a user read from a
// running inbound to be re-addable, and the block flag has to show up or the
// operator cannot see whom they suspended.
func TestUserManagerAPIRoundTrip(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	ctx := context.Background()
	in := &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.80", L3: boolP(true)}
	if err := s.AddUser(ctx, memUser(t, "bob", in)); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := s.SetUserBlocked(ctx, "bob", true); err != nil {
		t.Fatalf("block: %v", err)
	}

	got := s.GetUser(ctx, "bob")
	if got == nil {
		t.Fatal("GetUser lost a blocked user")
	}
	out, ok := got.Account.(*MemoryAccount)
	if !ok {
		t.Fatalf("account type = %T, want *MemoryAccount", got.Account)
	}
	if out.user.Password != in.Password {
		t.Fatalf("credential changed on the round trip: %q", out.user.Password)
	}
	if !out.user.GetDisabled() {
		t.Fatal("the disabled flag was lost")
	}
	if out.user.Ip != in.Ip || out.user.L3 == nil || !*out.user.L3 {
		t.Fatalf("account fields not preserved: %+v", out.user)
	}
	if got.Email != "bob" {
		t.Fatalf("email = %q, want bob", got.Email)
	}

	back, err := serial.ToTypedMessage(out.ToProto()).GetInstance()
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	if bu, ok := back.(*User); !ok || bu.Name != "bob" || bu.Password != in.Password {
		t.Fatalf("ToProto round trip returned %#v", back)
	}

	if n := s.GetUsersCount(ctx); n != 2 {
		t.Fatalf("GetUsersCount = %d, want 2", n)
	}
	if n := len(s.GetUsers(ctx)); n != 2 {
		t.Fatalf("GetUsers returned %d users, want 2", n)
	}
	if s.GetUser(ctx, "nobody") != nil {
		t.Fatal("GetUser invented an account")
	}
}

func TestMemoryAccountEquals(t *testing.T) {
	account := func(name, pass string) protocol.Account {
		t.Helper()
		a, err := (&User{Name: name, Password: pass}).AsAccount()
		if err != nil {
			t.Fatalf("AsAccount(%s): %v", name, err)
		}
		return a
	}
	a := account("bob", testPW("pw-b"))
	if _, err := (&User{Name: "dave", Password: "not-a-hash"}).AsAccount(); err == nil {
		t.Fatal("AsAccount accepted a malformed credential")
	}

	tests := []struct {
		name  string
		other protocol.Account
		want  bool
	}{
		{name: "same name and credential", other: account("bob", testPW("pw-b")), want: true},
		{name: "other name", other: account("carol", testPW("pw-b")), want: false},
		{name: "other credential", other: account("bob", testPW("other")), want: false},
		{name: "not an openconnect account", other: foreignAccount{}, want: false},
	}
	for _, tc := range tests {
		if got := a.Equals(tc.other); got != tc.want {
			t.Errorf("%s: Equals = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestConcurrentMutationUnderReads runs the mutators against the readers that
// touch the same accounts on the hot path. Meaningful only under -race.
func TestConcurrentMutationUnderReads(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	ctx := context.Background()
	mu := memUser(t, "bob", &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.90"})

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s.users.check("bob", "pw-b")
				if au, ok := s.users.lookup("bob"); ok {
					_ = s.conf.maxSessionsPerUserFor(au.user)
					_ = s.conf.routesFor(au.user)
					_ = au.user.GetDisabled()
				}
				_ = s.GetUsers(ctx)
				_ = s.GetUsersCount(ctx)
			}
		}()
	}

	var writers sync.WaitGroup
	for i := 0; i < 2; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			l3 := true
			for n := 0; n < 200; n++ {
				// Every step may legitimately fail on the other writer's
				// interleaving; what matters is that the store stays
				// consistent and race-free.
				_ = s.AddUser(ctx, mu)
				_ = s.SetUserBlocked(ctx, "bob", true)
				_ = s.SetUserBlocked(ctx, "bob", false)
				_ = s.SetUserMaxSessions(ctx, "bob", proto.Uint32(1))
				_ = s.SetUserL3(ctx, "bob", &l3)
				l3 = !l3
				_ = s.DisconnectUser(ctx, "bob")
				_ = s.RemoveUser(ctx, "bob")
			}
		}()
	}
	writers.Wait()
	close(stop)
	readers.Wait()
	_ = s.RemoveUser(ctx, "bob") // normalize: the last op may have been an add

	if n := s.users.count(); n != 1 {
		t.Fatalf("store holds %d users after the churn, want the 1 original", n)
	}
	if poolHeld(t, s.registry.pool, "10.99.0.90") {
		t.Fatal("the static ip leaked out of the pool after removal")
	}
}

func TestDisconnectUserNoSessions(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	if n := s.registry.disconnectUser(context.Background(), "alice", "nothing to do"); n != 0 {
		t.Fatalf("disconnectUser with no sessions returned %d, want 0", n)
	}
}

// TestDisconnectUserLeavesOtherUsers: a block must not touch anyone else's
// tunnel.
func TestDisconnectUserLeavesOtherUsers(t *testing.T) {
	s := newTestServerUsers(t, []*User{
		{Name: "alice", Password: testPW("pw-a")},
		{Name: "bob", Password: testPW("pw-b")},
	})
	_, cookieA := ocAuth(t, s, "alice", "pw-a")
	connA, _ := mustTunnel(t, s, cookieA)
	defer func() { _ = connA.Close() }()
	sessA := s.registry.getBySID(sidFromCookie(t, s, cookieA))

	if n := s.registry.disconnectUser(context.Background(), "bob", "blocked"); n != 0 {
		t.Fatalf("disconnectUser(bob) dropped %d sessions, want 0", n)
	}
	if !sessA.isConnected() {
		t.Fatal("disconnectUser of another user closed alice's tunnel")
	}
	if s.registry.count() != 1 {
		t.Fatalf("registry holds %d sessions, want alice's only", s.registry.count())
	}
}

// TestConnectRacingBlockRefusesTunnel pins the guard in handleConnect: a block
// or removal that lands between the CONNECT's account check and openTunnel has
// already retired the session, and the kick disconnectUser took found no tunnel
// to close. The ownership check right after openTunnel has to undo the tunnel,
// or it would outlive the operator action on a session the registry no longer
// knows, with its IP lease possibly handed out again already.
func TestConnectRacingBlockRefusesTunnel(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	ctx := context.Background()
	sess, err := s.registry.create("127.0.0.1", s.users.userByName("alice"), false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n := s.registry.disconnectUser(ctx, "alice", "user blocked"); n != 1 {
		t.Fatalf("disconnectUser retired %d session(s), want 1", n)
	}
	gen := sess.openTunnel(closerFunc(func() {}))
	if s.registry.getBySID(sess.sid) != nil {
		t.Fatal("a retired session still owns its SID")
	}
	// What the guard does: close the connection and undo the registration
	// openTunnel just made.
	sess.closeTunnel(gen)
	if sess.isConnected() {
		t.Fatal("the racing tunnel is still connected after the guard")
	}
	if kick := sess.takeKick(); kick != nil {
		t.Fatal("the guard left a kick behind on a retired session")
	}
}

// TestSessionKickedFlagIsPerTunnel: a kick belongs to one tunnel, so a session
// that gets a new tunnel is not reported as closed by the server forever after.
func TestSessionKickedFlagIsPerTunnel(t *testing.T) {
	sess := &ocSession{user: &User{Name: "alice"}}
	closed := false
	sess.openTunnel(closerFunc(func() { closed = true }))

	kick := sess.takeKick()
	if kick == nil {
		t.Fatal("takeKick returned nil for a live tunnel")
	}
	if !sess.kickedByServer() {
		t.Fatal("the kick was not recorded")
	}
	kick()
	if !closed {
		t.Fatal("the kick did not close the tunnel connection")
	}
	if sess.takeKick() != nil {
		t.Fatal("takeKick did not clear the kick")
	}

	sess.openTunnel(closerFunc(func() {}))
	if sess.kickedByServer() {
		t.Fatal("a new tunnel inherited the previous kick's flag")
	}
}
