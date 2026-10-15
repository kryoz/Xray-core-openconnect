package command

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/openconnect"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// blockableInbound is a minimal inbound that implements
// proxy.BlockableUserManager and records what it was asked to do.
type blockableInbound struct {
	err     error
	added   *protocol.MemoryUser
	email   string
	blocked bool
	calls   int
}

func (*blockableInbound) Network() []cnet.Network { return nil }

func (*blockableInbound) Process(context.Context, cnet.Network, stat.Connection, routing.Dispatcher) error {
	return nil
}

func (m *blockableInbound) AddUser(_ context.Context, u *protocol.MemoryUser) error {
	m.added = u
	return nil
}

func (*blockableInbound) RemoveUser(context.Context, string) error { return nil }

func (*blockableInbound) GetUser(context.Context, string) *protocol.MemoryUser { return nil }

func (*blockableInbound) GetUsers(context.Context) []*protocol.MemoryUser { return nil }

func (*blockableInbound) GetUsersCount(context.Context) int64 { return 0 }

func (m *blockableInbound) SetUserBlocked(_ context.Context, email string, blocked bool) error {
	m.calls++
	m.email = email
	m.blocked = blocked
	return m.err
}

// plainInbound exposes the same inbound without SetUserBlocked, which is what
// an inbound that cannot block users looks like to the operation.
type plainInbound struct {
	proxy.Inbound
	proxy.UserManager
}

// handler is an inbound.Handler handing out a fixed proxy.
type handler struct {
	p proxy.Inbound
}

func (*handler) Start() error { return nil }
func (*handler) Close() error { return nil }
func (*handler) Tag() string  { return "in" }

func (*handler) ReceiverSettings() *serial.TypedMessage { return nil }
func (*handler) ProxySettings() *serial.TypedMessage    { return nil }

func (h *handler) GetInbound() proxy.Inbound { return h.p }

var _ inbound.Handler = (*handler)(nil)

func TestBlockUserOperationApplyInbound(t *testing.T) {
	tests := []struct {
		name        string
		inbound     proxy.Inbound
		op          *BlockUserOperation
		wantErr     bool
		wantEmail   string
		wantBlocked bool
		wantCalls   int
	}{
		{
			name:        "block",
			inbound:     &blockableInbound{},
			op:          &BlockUserOperation{Email: "alice", Blocked: true},
			wantEmail:   "alice",
			wantBlocked: true,
			wantCalls:   1,
		},
		{
			name:        "unblock",
			inbound:     &blockableInbound{},
			op:          &BlockUserOperation{Email: "alice"},
			wantEmail:   "alice",
			wantBlocked: false,
			wantCalls:   1,
		},
		{
			name:        "the inbound refuses",
			inbound:     &blockableInbound{err: errors.New("no such user")},
			op:          &BlockUserOperation{Email: "ghost", Blocked: true},
			wantErr:     true,
			wantEmail:   "ghost",
			wantBlocked: true,
			wantCalls:   1,
		},
		{
			name:    "a user manager that cannot block",
			inbound: &plainInbound{Inbound: &blockableInbound{}, UserManager: &blockableInbound{}},
			op:      &BlockUserOperation{Email: "alice", Blocked: true},
			wantErr: true,
		},
		{
			name:    "not a user manager at all",
			inbound: &blockableOnlyInbound{},
			op:      &BlockUserOperation{Email: "alice", Blocked: true},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.op.ApplyInbound(context.Background(), &handler{p: tc.inbound})
			if (err != nil) != tc.wantErr {
				t.Fatalf("ApplyInbound error = %v, wantErr %v", err, tc.wantErr)
			}
			bm, ok := tc.inbound.(*blockableInbound)
			if !ok {
				return
			}
			if bm.calls != tc.wantCalls || bm.email != tc.wantEmail || bm.blocked != tc.wantBlocked {
				t.Fatalf("SetUserBlocked called %d time(s) with (%q, %t), want (%q, %t) %d time(s)",
					bm.calls, bm.email, bm.blocked, tc.wantEmail, tc.wantBlocked, tc.wantCalls)
			}
		})
	}
}

// blockableOnlyInbound is an inbound that is neither a UserManager nor
// blockable.
type blockableOnlyInbound struct{}

func (*blockableOnlyInbound) Network() []cnet.Network { return nil }

func (*blockableOnlyInbound) Process(context.Context, cnet.Network, stat.Connection, routing.Dispatcher) error {
	return nil
}

// TestBlockUserOperationTravelsAsATypedMessage pins the AlterInbound path: the
// operation reaches the server through common.serial, so its type has to be in
// the global proto registry and it has to satisfy InboundOperation.
func TestBlockUserOperationTravelsAsATypedMessage(t *testing.T) {
	op := &BlockUserOperation{Email: "alice", Blocked: true}
	raw, err := serial.ToTypedMessage(op).GetInstance()
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	got, ok := raw.(InboundOperation)
	if !ok {
		t.Fatalf("the operation is not an InboundOperation: %T", raw)
	}
	blocked, ok := got.(*BlockUserOperation)
	if !ok || blocked.Email != "alice" || !blocked.Blocked {
		t.Fatalf("round trip returned %#v", got)
	}
}

// TestAddUserOperationApplyInbound covers the block flag an add carries: a
// protocol that cannot enforce a block has to refuse the account instead of
// storing one that only looks blocked.
func TestAddUserOperationApplyInbound(t *testing.T) {
	newUser := func(disabled bool) *protocol.User {
		id := uuid.New()
		return &protocol.User{
			Email:    "alice@test",
			Disabled: disabled,
			Account:  serial.ToTypedMessage(&vless.Account{Id: id.String()}),
		}
	}

	tests := []struct {
		name         string
		manager      *blockableInbound
		blockable    bool
		user         *protocol.User
		wantErr      bool
		wantAdded    bool
		wantDisabled bool
	}{
		{
			name:      "an enabled user goes to a manager that cannot enforce a block",
			manager:   &blockableInbound{},
			user:      newUser(false),
			wantAdded: true,
		},
		{
			name:    "a blocked user is refused by a manager that cannot enforce it",
			manager: &blockableInbound{},
			user:    newUser(true),
			wantErr: true,
		},
		{
			name:         "a blocked user goes to a manager that can enforce it",
			manager:      &blockableInbound{},
			blockable:    true,
			user:         newUser(true),
			wantAdded:    true,
			wantDisabled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &handler{p: &plainInbound{Inbound: &blockableOnlyInbound{}, UserManager: tc.manager}}
			if tc.blockable {
				h.p = tc.manager
			}

			op := &AddUserOperation{User: tc.user}
			err := op.ApplyInbound(context.Background(), h)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ApplyInbound error = %v, wantErr %v", err, tc.wantErr)
			}
			if added := tc.manager.added != nil; added != tc.wantAdded {
				t.Fatalf("user stored = %v, want %v", added, tc.wantAdded)
			}
			if tc.wantAdded && tc.manager.added.Disabled != tc.wantDisabled {
				t.Fatalf("stored user Disabled = %v, want %v", tc.manager.added.Disabled, tc.wantDisabled)
			}
		})
	}
}

// TestRedactUserMasksCredentials covers the boundary GetInboundUsers answers
// from: an account keeps everything an operator lists users for and loses the
// secret, because on an unauthenticated commander socket an OpenConnect
// password is a salted hash to attack offline. What takes its place is a
// fingerprint, which is what lets the provisioner notice a changed password
// without the credential ever leaving the node.
func TestRedactUserMasksCredentials(t *testing.T) {
	const secret = "00112233$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name  string
		user  *protocol.User
		check func(t *testing.T, got *protocol.User)
	}{
		{
			name: "nil stays nil",
			user: nil,
			check: func(t *testing.T, got *protocol.User) {
				if got != nil {
					t.Fatalf("redactUser(nil) = %v", got)
				}
			},
		},
		{
			name: "a user without an account is returned as it is",
			user: &protocol.User{Email: "alice", Disabled: true},
			check: func(t *testing.T, got *protocol.User) {
				if got.Email != "alice" || !got.Disabled || got.Account != nil {
					t.Fatalf("the user changed beyond its account: %v", got)
				}
			},
		},
		{
			name: "an OpenConnect credential becomes a fingerprint, the account stays usable",
			user: &protocol.User{
				Email:    "alice",
				Disabled: true,
				Account:  serial.ToTypedMessage(&openconnect.User{Name: "alice", Password: secret, Ip: "10.66.0.5", Group: "split"}),
			},
			check: func(t *testing.T, got *protocol.User) {
				raw, err := got.Account.GetInstance()
				if err != nil {
					t.Fatalf("the account no longer decodes: %v", err)
				}
				u, ok := raw.(*openconnect.User)
				if !ok {
					t.Fatalf("the account is no longer an OpenConnect one: %T", raw)
				}
				// Pinned rather than recomputed from the function the code calls:
				// this is the value a node and a provisioner built at different
				// times have to agree on, and a vector written out is the only
				// thing that notices it ever changed.
				const fingerprint = "5a6a672864d7e46d5f05aca2cbce3a53a990fb1c7c2c3ec988c8b70461d2d799"
				if u.Password != fingerprint {
					t.Fatalf("the credential left the boundary as %q, want its fingerprint %s", u.Password, fingerprint)
				}
				if u.Name != "alice" || u.Ip != "10.66.0.5" || u.Group != "split" {
					t.Fatalf("the account lost more than the credential: %+v", u)
				}
				if got.Email != "alice" || !got.Disabled {
					t.Fatalf("the listing lost the block flag: %v", got)
				}
			},
		},
		{
			name: "an account without a credential of its own is left alone",
			user: &protocol.User{
				Email:   "alice@test",
				Account: serial.ToTypedMessage(&vless.Account{Id: "e3ad5c52-b2ab-4b44-92ad-53dc48a86f54"}),
			},
			check: func(t *testing.T, got *protocol.User) {
				raw, err := got.Account.GetInstance()
				if err != nil {
					t.Fatalf("the account no longer decodes: %v", err)
				}
				// The VLESS uuid is the identity panels list and the operator
				// re-posts; it is not a password field.
				if id := raw.(*vless.Account).Id; id != "e3ad5c52-b2ab-4b44-92ad-53dc48a86f54" {
					t.Fatalf("the uuid was masked: %s", id)
				}
			},
		},
		{
			name: "an account this build cannot decode is not shipped at all",
			user: &protocol.User{
				Email:   "alice",
				Account: &serial.TypedMessage{Type: "xray.unknown.Account", Value: []byte(secret)},
			},
			check: func(t *testing.T, got *protocol.User) {
				if got.Account.GetValue() != nil {
					t.Fatalf("undecodable bytes went out over the socket: %q", got.Account.GetValue())
				}
				if got.Account.GetType() != "xray.unknown.Account" {
					t.Fatalf("the type name was lost: %q", got.Account.GetType())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, redactUser(tc.user))
		})
	}
}
