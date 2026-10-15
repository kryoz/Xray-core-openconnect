package vless

import (
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

type Validator interface {
	Get(id uuid.UUID) *protocol.MemoryUser
	Add(u *protocol.MemoryUser) error
	Del(email string) error
	SetBlocked(email string, blocked bool) error
	GetByEmail(email string) *protocol.MemoryUser
	GetAll() []*protocol.MemoryUser
	GetCount() int64
}

func ProcessUUID(id [16]byte) [16]byte {
	id[6] = 0
	id[7] = 0
	return id
}

// MemoryValidator stores valid VLESS users.
type MemoryValidator struct {
	// Considering email's usage here, map + sync.Mutex/RWMutex may have better performance.
	email sync.Map
	users sync.Map
}

// Add a VLESS user, Email must be empty or unique.
func (v *MemoryValidator) Add(u *protocol.MemoryUser) error {
	if u.Email != "" {
		_, loaded := v.email.LoadOrStore(strings.ToLower(u.Email), u)
		if loaded {
			return errors.New("User ", u.Email, " already exists.")
		}
	}
	v.users.Store(ProcessUUID(u.Account.(*MemoryAccount).ID.UUID()), u)
	return nil
}

// Del a VLESS user with a non-empty Email.
func (v *MemoryValidator) Del(e string) error {
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := strings.ToLower(e)
	u, _ := v.email.Load(le)
	if u == nil {
		return errors.New("User ", e, " not found.")
	}
	v.email.Delete(le)
	v.users.Delete(ProcessUUID(u.(*protocol.MemoryUser).Account.(*MemoryAccount).ID.UUID()))
	return nil
}

// SetBlocked a VLESS user with a non-empty Email, or restores it when blocked
// is false. The account keeps its UUID, so its stats key and everything keyed
// by the email survive.
//
// The stored record is replaced with a copy rather than written in place: the
// hot path holds the record it authenticated with without a lock, so mutating
// it would be a data race against every flow reading it.
func (v *MemoryValidator) SetBlocked(e string, blocked bool) error {
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := strings.ToLower(e)
	u, _ := v.email.Load(le)
	if u == nil {
		return errors.New("User ", e, " not found.")
	}
	old := u.(*protocol.MemoryUser)
	if old.Disabled == blocked {
		return nil
	}
	updated := *old
	updated.Disabled = blocked
	// The UUID map is where authentication reads, so it goes first: from the
	// moment it answers, no new flow can get in as this account.
	v.users.Store(ProcessUUID(updated.Account.(*MemoryAccount).ID.UUID()), &updated)
	v.email.Store(le, &updated)
	return nil
}

// Get a VLESS user with UUID, nil if user doesn't exist or is blocked. A
// blocked account answers exactly like an unknown UUID, so the refusal gives
// the client no hint that the account exists.
func (v *MemoryValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	u, _ := v.users.Load(ProcessUUID(id))
	if u == nil {
		return nil
	}
	mu := u.(*protocol.MemoryUser)
	if mu.Disabled {
		return nil
	}
	return mu
}

// Get a VLESS user with email, nil if user doesn't exist. A blocked user is
// still returned: the user API has to be able to show an account the operator
// suspended.
func (v *MemoryValidator) GetByEmail(email string) *protocol.MemoryUser {
	email = strings.ToLower(email)
	u, _ := v.email.Load(email)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get all users
func (v *MemoryValidator) GetAll() []*protocol.MemoryUser {
	u := make([]*protocol.MemoryUser, 0, 100)
	v.email.Range(func(key, value interface{}) bool {
		u = append(u, value.(*protocol.MemoryUser))
		return true
	})
	return u
}

// Get users count
func (v *MemoryValidator) GetCount() int64 {
	var c int64 = 0
	v.email.Range(func(key, value interface{}) bool {
		c++
		return true
	})
	return c
}
