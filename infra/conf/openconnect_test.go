package conf_test

import (
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/openconnect"
)

func TestOpenConnectNoRoutesJSON(t *testing.T) {
	creator := func() Buildable {
		return new(OpenConnectConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"users": [{"name": "u", "password": "00$00", "group": "split"}],
				"subnet": "10.66.0.0/24",
				"groups": [{"name": "split", "routes": ["10.50.0.0/16"], "noRoutes": ["0.0.0.0/0"]}]
			}`,
			Parser: loadJSON(creator),
			Output: &openconnect.OpenConnectInboundConfig{
				Users:  []*openconnect.User{{Name: "u", Password: "00$00", Group: "split"}},
				Subnet: "10.66.0.0/24",
				Groups: []*openconnect.Group{{Name: "split", Routes: []string{"10.50.0.0/16"}, NoRoutes: []string{"0.0.0.0/0"}}},
			},
		},
	})
}

func TestOpenConnectGroupDTLSJSON(t *testing.T) {
	no, yes := false, true
	creator := func() Buildable {
		return new(OpenConnectConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"users": [{"name": "u", "password": "00$00"}],
				"subnet": "10.66.0.0/24",
				"groups": [{"name": "mobile", "dtls": false}]
			}`,
			Parser: loadJSON(creator),
			Output: &openconnect.OpenConnectInboundConfig{
				Users:  []*openconnect.User{{Name: "u", Password: "00$00"}},
				Subnet: "10.66.0.0/24",
				Groups: []*openconnect.Group{{Name: "mobile", Dtls: &no}},
			},
		},
		{
			Input: `{
				"users": [{"name": "u", "password": "00$00"}],
				"subnet": "10.66.0.0/24",
				"groups": [{"name": "corp", "dtls": true}]
			}`,
			Parser: loadJSON(creator),
			Output: &openconnect.OpenConnectInboundConfig{
				Users:  []*openconnect.User{{Name: "u", Password: "00$00"}},
				Subnet: "10.66.0.0/24",
				Groups: []*openconnect.Group{{Name: "corp", Dtls: &yes}},
			},
		},
		{
			Input: `{
				"users": [{"name": "u", "password": "00$00"}],
				"subnet": "10.66.0.0/24",
				"groups": [{"name": "legacy"}]
			}`,
			Parser: loadJSON(creator),
			Output: &openconnect.OpenConnectInboundConfig{
				Users:  []*openconnect.User{{Name: "u", Password: "00$00"}},
				Subnet: "10.66.0.0/24",
				Groups: []*openconnect.Group{{Name: "legacy"}},
			},
		},
	})
}

// TestOpenConnectUserDTLSJSON verifies the per-user dtls override survives
// the JSON layer: without the mapping a user-level "dtls": true is silently
// dropped and the group's dtls:false wins (the 2026-10-03 gate incident).
func TestOpenConnectUserDTLSJSON(t *testing.T) {
	no, yes := false, true
	creator := func() Buildable {
		return new(OpenConnectConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"users": [{"name": "alex", "password": "00$00", "group": "mobile", "dtls": true}],
				"subnet": "10.66.0.0/24",
				"groups": [{"name": "mobile", "dtls": false}]
			}`,
			Parser: loadJSON(creator),
			Output: &openconnect.OpenConnectInboundConfig{
				Users:  []*openconnect.User{{Name: "alex", Password: "00$00", Group: "mobile", Dtls: &yes}},
				Subnet: "10.66.0.0/24",
				Groups: []*openconnect.Group{{Name: "mobile", Dtls: &no}},
			},
		},
		{
			Input: `{
				"users": [{"name": "u", "password": "00$00", "dtls": false}],
				"subnet": "10.66.0.0/24"
			}`,
			Parser: loadJSON(creator),
			Output: &openconnect.OpenConnectInboundConfig{
				Users:  []*openconnect.User{{Name: "u", Password: "00$00", Dtls: &no}},
				Subnet: "10.66.0.0/24",
			},
		},
	})
}
