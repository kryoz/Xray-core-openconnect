package command

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/openconnect"
)

// TestRedactionDigestsWhatTheInboundStores covers the link the credential-drift
// check rests on and that neither of its ends can see on its own: the account as
// the inbound holds it has to reach redactUser still carrying the credential it
// authenticates with, so that what leaves the node is a fingerprint of that
// credential rather than of an empty message.
//
// Read the other way round, this is the test that fails if ToProto ever starts
// masking on its own. A caller that reconciles accounts would then compare a
// fingerprint of nothing against a real one, and would conclude every account
// on the node had changed its password at once.
func TestRedactionDigestsWhatTheInboundStores(t *testing.T) {
	cases := []struct {
		name       string
		credential string
	}{
		{
			// Both formats the inbound verifies: the MD5-crypt form an account
			// source mints, and the SHA-256 form xray's own tooling mints.
			name:       "md5-crypt",
			credential: "$1$k7Pq2mXr$Yq8h1H0rJx5Hk1oRlMR1M0",
		},
		{
			name:       "sha-256",
			credential: "00112233$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The account the way the inbound builds one: parsed from the stored
			// message, then wrapped for the user API as GetUsers wraps it.
			account, err := (&openconnect.User{Name: "alice@test", Password: tc.credential}).AsAccount()
			require.NoError(t, err)

			redacted := redactUser(protocol.ToProtoUser(&protocol.MemoryUser{
				Email:   "alice@test",
				Account: account,
			}))
			raw, err := redacted.Account.GetInstance()
			require.NoError(t, err)

			got, ok := raw.(*openconnect.User)
			require.True(t, ok, "the account stopped being an OpenConnect one: %T", raw)
			require.Equal(t, protocol.CredentialFingerprint(tc.credential), got.Password,
				"the fingerprint is not taken of the credential the inbound authenticates with")
			require.Equal(t, "alice@test", got.Name, "the account lost more than its credential")
		})
	}
}
