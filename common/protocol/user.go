package protocol

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
)

func (u *User) GetTypedAccount() (Account, error) {
	if u.GetAccount() == nil {
		return nil, errors.New("Account is missing")
	}

	rawAccount, err := u.Account.GetInstance()
	if err != nil {
		return nil, err
	}
	if asAccount, ok := rawAccount.(AsAccount); ok {
		return asAccount.AsAccount()
	}
	if account, ok := rawAccount.(Account); ok {
		return account, nil
	}
	return nil, errors.New("Unknown account type: ", u.Account.Type)
}

func (u *User) ToMemoryUser() (*MemoryUser, error) {
	account, err := u.GetTypedAccount()
	if err != nil {
		return nil, err
	}
	return &MemoryUser{
		Account:  account,
		Email:    u.Email,
		Level:    u.Level,
		Disabled: u.Disabled,
	}, nil
}

func ToProtoUser(mu *MemoryUser) *User {
	if mu == nil {
		return nil
	}
	return &User{
		Account:  serial.ToTypedMessage(mu.Account.ToProto()),
		Email:    mu.Email,
		Level:    mu.Level,
		Disabled: mu.Disabled,
	}
}

// CredentialFingerprint is the comparable stand-in for a stored credential:
// lowercase hex sha256 over its bytes.
//
// It answers one question — does the account an inbound holds still carry the
// credential the licence server exports? — and a digest answers it as well as
// the credential does, while being the only form of it that may leave an
// unauthenticated commander socket. It is taken of the stored form, which is
// salted and is not the password, so recovering that form means guessing the
// salt and the password together: the attack the stored hash already resists.
//
// Both ends of the comparison call this one function — app/proxyman/command on
// the node, cmd/provisioner on the loop that reconciles it — so they cannot
// disagree about it. They are built and deployed separately, and disagreeing
// would read as every account on the node having changed its password at once.
func CredentialFingerprint(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

// MemoryUser is a parsed form of User, to reduce number of parsing of Account proto.
type MemoryUser struct {
	// Account is the parsed account of the protocol.
	Account Account
	Email   string
	Level   uint32
	// Disabled is the soft block of the general user contract: the account
	// definition stays in place, authentication rejects it. Inbound handlers
	// that enforce it also cut the sessions a blocked account has up.
	Disabled bool
}
