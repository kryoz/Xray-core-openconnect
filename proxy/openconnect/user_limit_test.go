package openconnect

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestSetUserMaxSessions(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})

	tests := []struct {
		name    string
		email   string
		limit   *uint32
		wantErr bool
		want    uint32
	}{
		{name: "unknown user", email: "ghost", limit: proto.Uint32(2), wantErr: true},
		{name: "set two", email: "alice", limit: proto.Uint32(2), want: 2},
		{name: "tighten to one", email: "alice", limit: proto.Uint32(1), want: 1},
		{name: "zero lifts the bound", email: "alice", limit: proto.Uint32(0), want: 0},
		{name: "setting it again is a no-op", email: "alice", limit: proto.Uint32(0), want: 0},
		{name: "reset to inherit", email: "alice", limit: nil, want: 0},
		{name: "reset again is a no-op", email: "alice", limit: nil, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.SetUserMaxSessions(s.ctx, tt.email, tt.limit)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SetUserMaxSessions(%q, %v): err = %v, wantErr %v", tt.email, tt.limit, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			u := s.users.userByName(tt.email)
			if u.GetMaxSessionsPerUser() != tt.want {
				t.Fatalf("stored override = %d, want %d", u.GetMaxSessionsPerUser(), tt.want)
			}
			if (tt.limit == nil) != (u.MaxSessionsPerUser == nil) {
				t.Fatalf("override present = %v, want %v", u.MaxSessionsPerUser != nil, tt.limit != nil)
			}
			if got := s.conf.maxSessionsPerUserFor(u); got != tt.want {
				t.Fatalf("resolved bound = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestSetUserMaxSessionsLiveEffect: the new bound bites from the next auth on,
// without a restart and without cutting the session that is up right now.
func TestSetUserMaxSessionsLiveEffect(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})

	st, cookie := ocAuth(t, s, "alice", "pw-a")
	if st != 200 {
		t.Fatalf("auth: status %d, want 200", st)
	}
	tun, _ := mustTunnel(t, s, cookie)
	defer func() { _ = tun.Close() }()
	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil {
		t.Fatal("no session for the cookie")
	}

	// Tighten to one while her tunnel is up: the session survives, and a
	// second device of the account is refused at auth.
	if err := s.SetUserMaxSessions(s.ctx, "alice", proto.Uint32(1)); err != nil {
		t.Fatal(err)
	}
	if !sess.isConnected() {
		t.Fatal("tightening the bound cut the live tunnel")
	}
	if st, _ := ocAuth(t, s, "alice", "pw-a"); st != 503 {
		t.Fatalf("second auth under the tightened bound: status %d, want 503", st)
	}

	// Loosen to two: the second device is admitted.
	if err := s.SetUserMaxSessions(s.ctx, "alice", proto.Uint32(2)); err != nil {
		t.Fatal(err)
	}
	if st, _ := ocAuth(t, s, "alice", "pw-a"); st != 200 {
		t.Fatalf("second auth under the loosened bound: status %d, want 200", st)
	}
}

func TestSetUserL3(t *testing.T) {
	on, off := true, false
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a"), Group: "g"}})
	s.conf.Groups = []*Group{{Name: "g", L3: &on}}

	tests := []struct {
		name     string
		email    string
		l3       *bool
		wantErr  bool
		want     *bool
		resolved bool
	}{
		{name: "unknown user", email: "ghost", l3: &on, wantErr: true},
		{name: "force on", email: "alice", l3: &on, want: &on, resolved: true},
		{name: "force off beats the group flag", email: "alice", l3: &off, want: &off, resolved: false},
		{name: "inherit falls back to the group flag", email: "alice", l3: nil, want: nil, resolved: true},
		{name: "again is a no-op", email: "alice", l3: nil, want: nil, resolved: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.SetUserL3(s.ctx, tt.email, tt.l3)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SetUserL3(%q, %v): err = %v, wantErr %v", tt.email, tt.l3, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			u := s.users.userByName(tt.email)
			if !l3Equal(u.L3, tt.want) {
				t.Fatalf("stored override = %v, want %v", u.L3, tt.want)
			}
			if got := s.conf.l3For(u); got != tt.resolved {
				t.Fatalf("resolved flag = %v, want %v", got, tt.resolved)
			}
		})
	}
}

// TestSetUserL3LiveEffect: the flag is captured when a session is created, so
// changing it must not touch the running session, and the next session picks
// the new value up.
func TestSetUserL3LiveEffect(t *testing.T) {
	on, off := true, false
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})

	st, cookie := ocAuth(t, s, "alice", "pw-a")
	if st != 200 {
		t.Fatalf("auth: status %d, want 200", st)
	}
	tun, _ := mustTunnel(t, s, cookie)
	defer func() { _ = tun.Close() }()
	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil || sess.l3 {
		t.Fatalf("first session: %#v, want a live non-l3 session", sess)
	}

	if err := s.SetUserL3(s.ctx, "alice", &on); err != nil {
		t.Fatal(err)
	}
	if !sess.isConnected() || sess.l3 {
		t.Fatal("turning l3 on cut or rewired the running session")
	}

	// The next session of the account starts l3-marked.
	st, cookie2 := ocAuth(t, s, "alice", "pw-a")
	if st != 200 {
		t.Fatalf("second auth: status %d, want 200", st)
	}
	tun2, _ := mustTunnel(t, s, cookie2)
	defer func() { _ = tun2.Close() }()
	sess2 := s.registry.getBySID(sidFromCookie(t, s, cookie2))
	if sess2 == nil || !sess2.l3 {
		t.Fatalf("second session: %#v, want an l3 session", sess2)
	}

	if err := s.SetUserL3(s.ctx, "alice", &off); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserL3(s.ctx, "alice", nil); err != nil {
		t.Fatal(err)
	}
	st, cookie3 := ocAuth(t, s, "alice", "pw-a")
	if st != 200 {
		t.Fatalf("third auth: status %d, want 200", st)
	}
	tun3, _ := mustTunnel(t, s, cookie3)
	defer func() { _ = tun3.Close() }()
	sess3 := s.registry.getBySID(sidFromCookie(t, s, cookie3))
	if sess3 == nil || sess3.l3 {
		t.Fatalf("third session: %#v, want inherit (off) to apply", sess3)
	}
}

func TestDisconnectUser(t *testing.T) {
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})

	if err := s.DisconnectUser(s.ctx, "ghost"); err == nil {
		t.Fatal("unknown user: want error")
	}
	// No live session: a no-op, not an error.
	if err := s.DisconnectUser(s.ctx, "alice"); err != nil {
		t.Fatal(err)
	}

	st, cookie := ocAuth(t, s, "alice", "pw-a")
	if st != 200 {
		t.Fatalf("auth: status %d, want 200", st)
	}
	tun, _ := mustTunnel(t, s, cookie)
	defer func() { _ = tun.Close() }()
	sess := s.registry.getBySID(sidFromCookie(t, s, cookie))
	if sess == nil || !sess.isConnected() {
		t.Fatal("no live session for the cookie")
	}

	if err := s.DisconnectUser(s.ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if sess.isConnected() {
		t.Fatal("the session survived the disconnect")
	}

	// Unlike a block, the account is still usable straight away.
	if st, _ := ocAuth(t, s, "alice", "pw-a"); st != 200 {
		t.Fatalf("re-auth after the disconnect: status %d, want 200", st)
	}
}
