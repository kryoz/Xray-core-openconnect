package openconnect

import (
	"context"
	"sort"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/userstore"
	"google.golang.org/protobuf/proto"
)

// loadUsersFile resolves the accounts the inbound starts with, before the
// config is validated: with an overlay in place the file, not the config, is
// what the inbound holds, so validating the config's users would check a set
// the inbound is not going to use.
//
// No file configured keeps a config that predates the overlay behaving exactly
// as it did: accounts come from "users" and runtime changes die with the
// process.
func (c *OpenConnectInboundConfig) loadUsersFile(ctx context.Context) error {
	if c.UsersFile == "" {
		return nil
	}
	seed := make([]*protocol.User, 0, len(c.Users))
	for _, u := range c.Users {
		seed = append(seed, ProtocolUserOf(u))
	}
	// The seed is validated before it is written: a config whose users would
	// fail validate() must not poison the overlay, because the file outlives
	// the failed start and, once it exists, fixing the config no longer fixes
	// the inbound. The probe runs the full validate() — names, credentials,
	// static addresses against the subnet, groups, routes — on exactly the
	// users that are about to become the file.
	validateSeed := func(seed []*protocol.User) error {
		staged := make([]*User, 0, len(seed))
		for _, pu := range seed {
			u, err := userFromProtocolUser(pu)
			if err != nil {
				return err
			}
			staged = append(staged, u)
		}
		probe := *c
		probe.Users = staged
		return probe.validate()
	}
	users, err := userstore.LoadOrSeed(c.UsersFile, seed, validateSeed)
	if err != nil {
		return errors.New("openconnect: ").Base(err)
	}
	loaded := make([]*User, 0, len(users))
	for _, pu := range users {
		u, err := userFromProtocolUser(pu)
		if err != nil {
			return errors.New("openconnect: users file ", c.UsersFile, ": ").Base(err)
		}
		loaded = append(loaded, u)
	}
	c.Users = loaded
	errors.LogInfo(ctx, "openconnect: ", len(loaded), " user(s) from ", c.UsersFile)
	return nil
}

// userFromProtocolUser unwraps a stored user back into this protocol's form.
// GetTypedAccount parses the credential on the way, so an overlay corrupted by
// hand fails at start instead of yielding an account nobody can log in to.
func userFromProtocolUser(pu *protocol.User) (*User, error) {
	acc, err := pu.GetTypedAccount()
	if err != nil {
		return nil, err
	}
	ma, ok := acc.(*MemoryAccount)
	if !ok {
		return nil, errors.New("not an OpenConnect account: ", pu.Email)
	}
	if pu.Email != "" && pu.Email != ma.user.Name {
		return nil, errors.New("email ", pu.Email, " does not match the user name ", ma.user.Name)
	}
	// The block lives in both the general contract and this protocol's user;
	// either one set means blocked.
	if pu.Disabled && !ma.user.GetDisabled() {
		// The message is freshly decoded here, so writing it is safe — unlike
		// a user already published to the store.
		ma.user.Disabled = proto.Bool(true)
	}
	return ma.user, nil
}

// persistUsers writes the live store to the overlay. It is called after the
// mutation reached memory, and the caller undoes that mutation when it fails:
// an account that works but does not survive the next restart is a silent
// divergence between what the operator sees and what the process will be.
//
// Call through mutateUsers, which holds Server.mutationMu: the snapshot below
// is the whole store, so it has to belong to the write it is serialized with.
func (s *Server) persistUsers() error {
	if s.conf.UsersFile == "" {
		return nil
	}
	all := s.users.snapshot()
	users := make([]*protocol.User, 0, len(all))
	for _, au := range all {
		users = append(users, protocol.ToProtoUser(memoryUser(au)))
	}
	// The store is a map; without an order every write would rewrite the whole
	// file with the accounts shuffled.
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })

	if err := userstore.Save(s.conf.UsersFile, &userstore.UserFile{Users: users}); err != nil {
		return errors.New("failed to persist users to ", s.conf.UsersFile).Base(err)
	}
	return nil
}

// mutateUsers applies a change to the account store and writes the result to
// the overlay as one step, and puts memory back the way it was when the write
// fails.
//
// The two have to be atomic together. Mutation and write kept separate, a
// second call could mutate the store while the first one was writing, so its
// write would land the second call's change in the file; the second call's own
// write failing would then roll that change out of memory and leave the file
// holding an account the running process has forgotten — the exact divergence
// the write-back exists to prevent, arriving on the next restart.
//
// Sessions are cut outside it: closing a tunnel must not wait on the file.
func (s *Server) mutateUsers(change, undo func() error) error {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()

	if err := change(); err != nil {
		return err
	}
	err := s.persistUsers()
	if err == nil {
		return nil
	}
	if uerr := undo(); uerr != nil {
		errors.LogWarning(s.ctx, "openconnect: the users file write failed and the change could not be rolled back: ", err, " / ", uerr)
	}
	return err
}
