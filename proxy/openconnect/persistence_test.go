package openconnect

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/userstore"
)

func writeUsersFile(t *testing.T, path string, users ...*protocol.User) {
	t.Helper()
	if err := userstore.Save(path, &userstore.UserFile{Users: users}); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

func loadUsersFile(t *testing.T, path string) []*protocol.User {
	t.Helper()
	f, err := userstore.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return f.GetUsers()
}

// fileUser wraps an OpenConnect account as the file stores it.
func fileUser(u *User) *protocol.User {
	return ProtocolUserOf(u)
}

func namesOf(users []*User) []string {
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.Name)
	}
	return names
}

func TestLoadUsersFile(t *testing.T) {
	alice := &User{Name: "alice", Password: testPW("pw-a")}
	bob := &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.50"}
	carol := &User{Name: "carol", Password: testPW("pw-c")}

	tests := []struct {
		name        string
		config      []*User
		noFile      bool // the overlay is configured but does not exist yet
		file        []*protocol.User
		want        []string
		wantErr     bool
		validateErr bool // the config loads but the inbound refuses to start
		wantFile    bool // the overlay must exist afterwards
		check       func(t *testing.T, conf *OpenConnectInboundConfig, path string)
	}{
		{
			name:   "without an overlay the config is the source",
			config: []*User{alice},
			want:   []string{"alice"},
		},
		{
			name:     "a missing overlay is seeded from the config",
			config:   []*User{alice, bob},
			noFile:   true,
			want:     []string{"alice", "bob"},
			wantFile: true,
			check: func(t *testing.T, conf *OpenConnectInboundConfig, path string) {
				if len(loadUsersFile(t, path)) != 2 {
					t.Fatal("the seed did not reach the file")
				}
				// The 0600 mode a seeded overlay needs is userstore.Save's
				// business, and it is asserted there.
			},
		},
		{
			name: "an existing overlay replaces the config",
			config: []*User{
				alice,
				{Name: "deleted-last-week", Password: testPW("pw-d")},
			},
			file: []*protocol.User{fileUser(carol), fileUser(bob)},
			want: []string{"carol", "bob"},
		},
		{
			name: "a blocked account stays blocked across a restart",
			file: []*protocol.User{{
				Email:    "dave",
				Disabled: true,
				Account:  serial.ToTypedMessage(&User{Name: "dave", Password: testPW("pw-d")}),
			}},
			want: []string{"dave"},
			check: func(t *testing.T, conf *OpenConnectInboundConfig, path string) {
				if !conf.Users[0].GetDisabled() {
					t.Fatal("the block did not reach the inbound's own flag")
				}
			},
		},
		{
			name:        "an empty overlay leaves nothing to validate",
			file:        []*protocol.User{},
			validateErr: true, // validate(): at least one user is required
		},
		{
			name: "an account of another protocol is refused",
			file: []*protocol.User{{
				Email:   "mallory",
				Account: serial.ToTypedMessage(&serial.TypedMessage{Type: "xray.proxy.vless.Account"}),
			}},
			wantErr: true,
		},
		{
			name: "an email that contradicts the name is refused",
			file: []*protocol.User{{
				Email:   "carol",
				Account: serial.ToTypedMessage(&User{Name: "dave", Password: testPW("pw-d")}),
			}},
			wantErr: true,
		},
		{
			name:    "a credential that cannot be parsed is refused",
			file:    []*protocol.User{fileUser(&User{Name: "erin", Password: "plaintext"})},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "users.json")
			if tc.file != nil {
				writeUsersFile(t, path, tc.file...)
			} else if !tc.noFile {
				path = ""
			}

			conf := &OpenConnectInboundConfig{
				Users:     tc.config,
				Subnet:    "10.99.0.0/24",
				UsersFile: path,
			}
			if err := conf.loadUsersFile(context.Background()); (err != nil) != tc.wantErr {
				t.Fatalf("loadUsersFile error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if err := conf.validate(); (err != nil) != tc.validateErr {
				t.Fatalf("validate error = %v, want %v", err, tc.validateErr)
			}
			if tc.validateErr {
				return
			}
			if got := namesOf(conf.Users); len(got) != len(tc.want) {
				t.Fatalf("users = %v, want %v", got, tc.want)
			} else {
				for i := range got {
					if got[i] != tc.want[i] {
						t.Fatalf("users = %v, want %v", got, tc.want)
					}
				}
			}
			if _, err := os.Stat(path); os.IsNotExist(err) && tc.wantFile {
				t.Fatal("the overlay was not written")
			}
			if tc.check != nil {
				tc.check(t, conf, path)
			}
		})
	}
}

// TestLoadUsersFileSeedValidation pins the poisoning guard: a config whose users
// would not validate must not seed the overlay, because the file outlives the
// failed start and, once it exists, it — not the config — is what the next
// start reads. Fixing the config would then no longer fix the inbound.
func TestLoadUsersFileSeedValidation(t *testing.T) {
	dir := t.TempDir()

	conf := &OpenConnectInboundConfig{
		Users: []*User{
			{Name: "alice", Password: testPW("pw-a")},
			{Name: "bob", Password: "plaintext"}, // not a credential
		},
		Subnet:    "10.99.0.0/24",
		UsersFile: filepath.Join(dir, "users.json"),
	}
	if err := conf.loadUsersFile(context.Background()); err == nil {
		t.Fatal("seeding from a config with an unparsable credential succeeded")
	}
	if _, err := os.Stat(conf.UsersFile); !os.IsNotExist(err) {
		t.Fatal("a rejected seed still wrote the overlay")
	}

	// A static address outside the subnet is validate()'s complaint rather
	// than the account parse's; the guard has to catch it too, or the next
	// start would refuse the very file this one wrote.
	outside := &OpenConnectInboundConfig{
		Users:     []*User{{Name: "alice", Password: testPW("pw-a"), Ip: "10.7.0.5"}},
		Subnet:    "10.99.0.0/24",
		UsersFile: filepath.Join(dir, "users2.json"),
	}
	if err := outside.loadUsersFile(context.Background()); err == nil {
		t.Fatal("seeding a static ip outside the subnet succeeded")
	}
	if _, err := os.Stat(outside.UsersFile); !os.IsNotExist(err) {
		t.Fatal("a rejected seed still wrote the overlay")
	}
}

func TestUsersFileRecordsRuntimeChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	s.conf.UsersFile = path
	ctx := context.Background()

	bob := &User{Name: "bob", Password: testPW("pw-b"), Ip: "10.99.0.50"}
	if err := s.AddUser(ctx, memUser(t, "bob", bob)); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	users := loadUsersFile(t, path)
	if len(users) != 2 || users[0].Email != "alice" || users[1].Email != "bob" {
		t.Fatalf("the file holds %v, want alice then bob", users)
	}
	// The credential has to survive: an overlay that lost the hashes would
	// lock every account out on the next start.
	stored, err := userFromProtocolUser(users[1])
	if err != nil {
		t.Fatalf("the added account does not read back: %v", err)
	}
	if stored.Password != bob.Password || stored.Ip != bob.Ip {
		t.Fatalf("the added account changed on the way to the file: %+v", stored)
	}

	if err := s.SetUserBlocked(ctx, "bob", true); err != nil {
		t.Fatalf("block: %v", err)
	}
	if users = loadUsersFile(t, path); !users[1].Disabled {
		t.Fatal("the block did not reach the file")
	}

	if err := s.SetUserBlocked(ctx, "bob", false); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if users = loadUsersFile(t, path); users[1].Disabled {
		t.Fatal("the unblock did not reach the file")
	}

	if err := s.RemoveUser(ctx, "bob"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if users = loadUsersFile(t, path); len(users) != 1 || users[0].Email != "alice" {
		t.Fatalf("the removed account is still in the file: %v", users)
	}

	// A restart reads what the running process holds.
	next := &OpenConnectInboundConfig{Subnet: "10.99.0.0/24", UsersFile: path}
	if err := next.loadUsersFile(ctx); err != nil {
		t.Fatalf("restarting on the overlay: %v", err)
	}
	if got := namesOf(next.Users); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("the restart got %v, want alice", got)
	}
}

// TestUsersFileWriteFailureRollsBack covers the order of the two writes: an
// account that works until the next restart is a divergence the operator
// cannot see, so a failed write has to take the memory change back.
func TestUsersFileWriteFailureRollsBack(t *testing.T) {
	s := newTestServerUsers(t, []*User{
		{Name: "alice", Password: testPW("pw-a")},
		{Name: "bob", Password: testPW("pw-b")},
	})
	s.conf.UsersFile = filepath.Join(t.TempDir(), "no-such-dir", "users.json")
	ctx := context.Background()

	const bobIP = "10.99.0.60"
	err := s.AddUser(ctx, memUser(t, "carol", &User{Name: "carol", Password: testPW("pw-c"), Ip: bobIP}))
	if err == nil {
		t.Fatal("an unwritable overlay must fail the add")
	}
	if _, ok := s.users.lookup("carol"); ok {
		t.Fatal("the rolled-back add left carol in the store")
	}
	if poolHeld(t, s.registry.pool, bobIP) {
		t.Fatal("the rolled-back add left the static address claimed")
	}

	if err := s.SetUserBlocked(ctx, "alice", true); err == nil {
		t.Fatal("an unwritable overlay must fail the block")
	}
	if au, ok := s.users.lookup("alice"); !ok || au.user.GetDisabled() {
		t.Fatal("the rolled-back block left alice suspended")
	}

	if err := s.RemoveUser(ctx, "alice"); err == nil {
		t.Fatal("an unwritable overlay must fail the removal")
	}
	if _, ok := s.users.lookup("alice"); !ok {
		t.Fatal("the rolled-back removal left alice gone")
	}
	if got := s.GetUsersCount(ctx); got != 2 {
		t.Fatalf("the store holds %d user(s) after the rollbacks, want 2", got)
	}
}

// TestUsersFileIsTheOnlySource pins the invariant the rollbacks above protect:
// what the file says is what a restart gets, in particular after a change that
// was written successfully.
func TestUsersFileIsTheOnlySource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	writeUsersFile(t, path, fileUser(&User{Name: "from-file", Password: testPW("pw-f")}))

	s := newTestServerUsers(t, []*User{{Name: "alice", Password: testPW("pw-a")}})
	if got := namesOf(s.conf.Users); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("a server without an overlay lost its config users: %v", got)
	}

	conf := &OpenConnectInboundConfig{
		Users:     []*User{{Name: "alice", Password: testPW("pw-a")}},
		Subnet:    "10.99.0.0/24",
		UsersFile: path,
	}
	if err := conf.loadUsersFile(context.Background()); err != nil {
		t.Fatalf("loadUsersFile: %v", err)
	}
	if got := namesOf(conf.Users); len(got) != 1 || got[0] != "from-file" {
		t.Fatalf("the config users overrode the overlay: %v", got)
	}
}
