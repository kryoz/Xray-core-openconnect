package openconnect

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount is the parsed form of an OpenConnect user: the credential is
// decoded once, and the config message is kept as-is because routes, group
// membership and the per-account session limit are all resolved against it on
// every CONNECT.
//
// As wireguard.PeerConfig does, the config message itself implements
// AsAccount, so a TypedMessage of type xray.proxy.openconnect.User is a valid
// account for AddUserOperation without a separate Account message.
//
// The referenced User is immutable once stored. A state change publishes a
// clone instead of writing into the message, so the tunnel path, which reads
// it through the session without a lock, never observes a half-updated user.
type MemoryAccount struct {
	user *User
	cred *credential
}

// AsAccount implements protocol.AsAccount.
func (u *User) AsAccount() (protocol.Account, error) {
	cred, err := parseCredential(u.Password)
	if err != nil {
		return nil, errors.New("user ", u.Name, ": ").Base(err)
	}
	return &MemoryAccount{user: u, cred: cred}, nil
}

// Equals implements protocol.Account: two accounts are the same account when
// they carry the same name and the same credential.
func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && a.user.Name == b.user.Name && a.user.Password == b.user.Password
}

// ToProto implements protocol.Account. The salted hash is part of the account,
// so it round-trips: a user read back from a running inbound has to be
// re-addable and loadable. Masking it is the job of the API boundary, not of
// the account.
func (a *MemoryAccount) ToProto() proto.Message {
	return a.user
}

// ProtocolUserOf wraps an OpenConnect account as the user the management API
// and the overlay file exchange: the name doubles as the email, because that is
// the key RemoveUser and SetUserBlocked take. The account keeps the salted
// hash — a user read back has to be loadable and re-addable — and masking it is
// the API boundary's job, not this one.
func ProtocolUserOf(u *User) *protocol.User {
	return &protocol.User{
		Email:    u.Name,
		Account:  serial.ToTypedMessage(u),
		Disabled: u.GetDisabled(),
	}
}
