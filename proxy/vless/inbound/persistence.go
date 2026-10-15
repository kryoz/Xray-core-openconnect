package inbound

import (
	"sort"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/userstore"
)

// persistUsers writes the validator's accounts to the overlay of this inbound.
// It runs after the mutation reached memory, and the caller undoes that
// mutation when it fails: an account that works until the next restart leaves
// the operator believing something that the next start will undo.
//
// Call through mutateUsers, which holds Handler.mutationMu: the snapshot below
// is the whole validator, so it has to belong to the write it is serialized
// with.
func (h *Handler) persistUsers() error {
	if h.usersFile == "" {
		return nil
	}

	all := h.validator.GetAll()
	users := make([]*protocol.User, 0, len(all))
	for _, mu := range all {
		users = append(users, protocol.ToProtoUser(mu))
	}
	// The validator stores its accounts in a map; without an order every write
	// would rewrite the file with them shuffled.
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })

	if err := userstore.Save(h.usersFile, &userstore.UserFile{Users: users}); err != nil {
		return errors.New("failed to persist users to ", h.usersFile).Base(err)
	}
	return nil
}

// mutateUsers applies a change to the validator and writes the result to the
// overlay as one step, and puts memory back the way it was when the write
// fails.
//
// The two have to be atomic together. Mutation and write kept separate, a
// second call could mutate the validator while the first one was writing, so its
// write would land the second call's change in the file; the second call's own
// write failing would then roll that change out of memory and leave the file
// holding an account the running process has forgotten — the exact divergence
// the write-back exists to prevent, arriving on the next restart.
//
// Sessions are cut outside it: closing a connection must not wait on the file.
func (h *Handler) mutateUsers(change, undo func() error) error {
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()

	if err := change(); err != nil {
		return err
	}
	err := h.persistUsers()
	if err == nil {
		return nil
	}
	if uerr := undo(); uerr != nil {
		errors.LogWarning(h.ctx, "vless: the users file write failed and the change could not be rolled back: ", err, " / ", uerr)
	}
	return err
}
