package inbound

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"

	"github.com/xtls/xray-core/common/userstore"
	"github.com/xtls/xray-core/proxy/vless"
)

func loadOverlay(t *testing.T, path string) *userstore.UserFile {
	t.Helper()
	f, err := userstore.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return f
}

func accountID(t *testing.T, u *vless.MemoryAccount) string {
	t.Helper()
	return u.ID.String()
}

func TestVLessUsersFileRecordsRuntimeChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	validator := new(vless.MemoryValidator)
	h := testVLessHandler(validator)
	h.usersFile = path
	ctx := context.Background()

	alice := testVLessUser("alice@test")
	if err := h.AddUser(ctx, alice); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	f := loadOverlay(t, path)
	if len(f.GetUsers()) != 1 {
		t.Fatalf("the overlay holds %v, want only alice", f.GetUsers())
	}
	stored := f.GetUsers()[0]
	if stored.Email != "alice@test" || stored.Disabled {
		t.Fatalf("the added account is not what was added: %v", stored)
	}
	// The UUID is the credential: an overlay that lost it would lock the
	// account out on the next start.
	rawAccount, err := stored.Account.GetInstance()
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	if got := rawAccount.(*vless.Account).Id; got != accountID(t, alice.Account.(*vless.MemoryAccount)) {
		t.Fatalf("the overlay holds uuid %s, want %s", got, accountID(t, alice.Account.(*vless.MemoryAccount)))
	}
	// The 0600 mode the overlay needs is userstore.Save's business, and it is
	// asserted there.

	if err := h.SetUserBlocked(ctx, "alice@test", true); err != nil {
		t.Fatalf("block: %v", err)
	}
	if !loadOverlay(t, path).GetUsers()[0].Disabled {
		t.Fatal("the block did not reach the overlay")
	}

	if err := h.SetUserBlocked(ctx, "alice@test", false); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if loadOverlay(t, path).GetUsers()[0].Disabled {
		t.Fatal("the unblock did not reach the overlay")
	}

	bob := testVLessUser("bob@test")
	if err := h.AddUser(ctx, bob); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := h.RemoveUser(ctx, "alice@test"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	users := loadOverlay(t, path).GetUsers()
	if len(users) != 1 || users[0].Email != "bob@test" {
		t.Fatalf("the overlay holds %v, want only bob", users)
	}
}

// TestVLessUsersFileWriteFailureRollsBack pins the order of the two writes: an
// account that works until the next restart is a divergence the operator
// cannot see, so a failed write has to take the memory change back.
func TestVLessUsersFileWriteFailureRollsBack(t *testing.T) {
	validator := new(vless.MemoryValidator)
	alice := testVLessUser("alice@test")
	if err := validator.Add(alice); err != nil {
		t.Fatalf("Add: %v", err)
	}
	h := testVLessHandler(validator)
	h.usersFile = filepath.Join(t.TempDir(), "no-such-dir", "users.json")
	ctx := context.Background()

	if err := h.AddUser(ctx, testVLessUser("bob@test")); err == nil {
		t.Fatal("an unwritable overlay must fail the add")
	}
	if h.GetUser(ctx, "bob@test") != nil {
		t.Fatal("the rolled-back add left bob in the validator")
	}

	if err := h.SetUserBlocked(ctx, "alice@test", true); err == nil {
		t.Fatal("an unwritable overlay must fail the block")
	}
	if u := h.GetUser(ctx, "alice@test"); u == nil || u.Disabled {
		t.Fatalf("the rolled-back block left alice suspended: %v", u)
	}

	if err := h.RemoveUser(ctx, "alice@test"); err == nil {
		t.Fatal("an unwritable overlay must fail the removal")
	}
	if h.GetUser(ctx, "alice@test") == nil {
		t.Fatal("the rolled-back removal left alice gone")
	}
	if got := h.GetUsersCount(ctx); got != 1 {
		t.Fatalf("the validator holds %d user(s) after the rollbacks, want 1", got)
	}

	// An account with no email cannot be addressed by the user API, so it could
	// not be taken back out if the write failed: it is refused outright.
	if err := h.AddUser(ctx, testVLessUser("")); err == nil {
		t.Fatal("an unpersistable account must be refused, not added")
	}
}

// TestVLessUsersFileSeedsThenWins covers the start-up side of the overlay: the
// config seeds it once, and from then on the file alone decides which accounts
// the inbound has — an account removed at runtime must not come back from the
// config on the next start.
func TestVLessUsersFileSeedsThenWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")

	alice := testVLessUser("alice@test")
	configUsers := []*protocol.User{{
		Email:   alice.Email,
		Account: serial.ToTypedMessage(alice.Account.(*vless.MemoryAccount).ToProto()),
	}}

	// Seeded from the config, and what was written has to be re-addable: the
	// account is rebuilt through ToMemoryUser when the inbound starts.
	got, err := userstore.LoadOrSeed(path, configUsers, nil)
	if err != nil {
		t.Fatalf("LoadOrSeed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("the seed did not come back: %v", got)
	}
	if _, err := got[0].ToMemoryUser(); err != nil {
		t.Fatalf("the seeded account cannot be re-added: %v", err)
	}

	// The file now exists, so the config no longer has a say.
	again, err := userstore.LoadOrSeed(path, []*protocol.User{{Email: "back-from-the-config"}}, nil)
	if err != nil {
		t.Fatalf("LoadOrSeed after seeding: %v", err)
	}
	if len(again) != 1 || again[0].Email != "alice@test" {
		t.Fatalf("the config overrode the overlay: %v", again)
	}
}
