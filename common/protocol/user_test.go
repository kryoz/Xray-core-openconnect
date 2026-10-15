package protocol

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/serial"
)

// testAccount is the parsed account form the round trip below carries.
type testAccount struct{}

func (a *testAccount) Equals(other Account) bool {
	_, ok := other.(*testAccount)
	return ok
}

func (a *testAccount) ToProto() proto.Message {
	return &SecurityConfig{}
}

// AsAccount makes the typed message come back as an account, the way a real
// account proto does, so ToMemoryUser is exercised without shortcuts.
func (s *SecurityConfig) AsAccount() (Account, error) {
	return &testAccount{}, nil
}

// TestUserDisabledRoundTrip pins the block flag through both directions of the
// general user contract. Dropped on the way in, nothing is blocked at runtime;
// dropped on the way out, the user API hides an account the operator suspended.
func TestUserDisabledRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		disabled bool
	}{
		{name: "enabled", disabled: false},
		{name: "blocked", disabled: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := &User{
				Level:    1,
				Email:    "user@test",
				Account:  serial.ToTypedMessage(&SecurityConfig{Type: SecurityType_AUTO}),
				Disabled: tc.disabled,
			}

			mu, err := u.ToMemoryUser()
			if err != nil {
				t.Fatalf("ToMemoryUser: %v", err)
			}
			if mu.Disabled != tc.disabled {
				t.Fatalf("MemoryUser.Disabled = %v, want %v", mu.Disabled, tc.disabled)
			}
			if mu.Email != u.Email || mu.Level != u.Level {
				t.Fatalf("MemoryUser = %+v, want email %q level %d", mu, u.Email, u.Level)
			}

			back := ToProtoUser(mu)
			if back.Disabled != tc.disabled {
				t.Fatalf("User.Disabled = %v, want %v", back.Disabled, tc.disabled)
			}
			if back.Email != u.Email || back.Level != u.Level {
				t.Fatalf("User = %+v, want email %q level %d", back, u.Email, u.Level)
			}
		})
	}

	if ToProtoUser(nil) != nil {
		t.Fatal("ToProtoUser(nil) must stay nil")
	}
}
