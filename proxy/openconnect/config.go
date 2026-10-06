package openconnect

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

const (
	MinMTU = 576
	MaxMTU = 1500

	// DefaultMTU matches a standard 1500-byte link so both tunnel MSS values
	// reach ~1394; NewServer clamps it down to the listen interface's MTU.
	DefaultMTU           = 1500
	DefaultDPD           = 90
	DefaultCookieTimeout = 300
)

// credential is a parsed user password: salted SHA-256.
type credential struct {
	salt []byte
	hash [sha256.Size]byte
}

// check verifies the stored hash against a candidate password in constant time.
func (c *credential) check(password string) bool {
	sum := sha256.Sum256(append(append([]byte{}, c.salt...), password...))
	return subtle.ConstantTimeCompare(c.hash[:], sum[:]) == 1
}

// parseCredential decodes a "salt_hex$hash_hex" password field.
func parseCredential(field string) (*credential, error) {
	saltHex, hashHex, ok := strings.Cut(field, "$")
	if !ok {
		return nil, errors.New("password must be formatted as salt_hex$hash_hex")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) == 0 {
		return nil, errors.New("invalid password salt").Base(err)
	}
	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != sha256.Size {
		return nil, errors.New("invalid password hash").Base(err)
	}
	c := &credential{salt: salt}
	copy(c.hash[:], hash)
	return c, nil
}

// GenerateCredential produces the "salt_hex$hash_hex" password field for a
// plaintext password, with a fresh random 16-byte salt.
func GenerateCredential(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("failed to generate salt").Base(err)
	}
	sum := sha256.Sum256(append(salt, password...))
	return hex.EncodeToString(salt) + "$" + hex.EncodeToString(sum[:]), nil
}

// validate checks the inbound configuration for internal consistency.
func (c *OpenConnectInboundConfig) validate() error {
	if len(c.Users) == 0 {
		return errors.New("at least one user is required")
	}
	prefix, err := netip.ParsePrefix(c.Subnet)
	if err != nil {
		return errors.New("invalid subnet: ", c.Subnet).Base(err)
	}
	if !prefix.Addr().Is4() {
		return errors.New("subnet must be IPv4: ", c.Subnet)
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("certFile and keyFile must both be set or both empty")
	}
	for _, ns := range c.Dns {
		if _, err := netip.ParseAddr(ns); err != nil {
			return errors.New("invalid dns server: ", ns).Base(err)
		}
	}
	groupNames := make(map[string]struct{}, len(c.Groups))
	for _, g := range c.Groups {
		if g.Name == "" {
			return errors.New("route group name must not be empty")
		}
		if _, dup := groupNames[g.Name]; dup {
			return errors.New("duplicate route group: ", g.Name)
		}
		for _, r := range g.Routes {
			if err := validateRoute(r); err != nil {
				return errors.New("route group ", g.Name, ": ").Base(err)
			}
		}
		for _, r := range g.NoRoutes {
			if err := validateRoute(r); err != nil {
				return errors.New("route group ", g.Name, ": ").Base(err)
			}
		}
		groupNames[g.Name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(c.Users))
	staticIPs := make(map[netip.Addr]string, len(c.Users))
	for _, u := range c.Users {
		if u.Name == "" {
			return errors.New("user name must not be empty")
		}
		if _, dup := seen[u.Name]; dup {
			return errors.New("duplicate user: ", u.Name)
		}
		seen[u.Name] = struct{}{}
		if _, err := parseCredential(u.Password); err != nil {
			return errors.New("user ", u.Name, ": ").Base(err)
		}
		if u.Ip != "" {
			ip, err := netip.ParseAddr(u.Ip)
			if err != nil {
				return errors.New("user ", u.Name, ": invalid static ip: ", u.Ip).Base(err)
			}
			if !prefix.Contains(ip) {
				return errors.New("user ", u.Name, ": static ip ", u.Ip, " outside subnet ", c.Subnet)
			}
			if ip == prefix.Addr() || ip == ipv4Broadcast(prefix) {
				return errors.New("user ", u.Name, ": static ip ", u.Ip, " is a network/broadcast address")
			}
			if ip == firstHost(prefix) {
				return errors.New("user ", u.Name, ": static ip ", u.Ip, " is the gateway/DNS address of the subnet")
			}
			if other, dup := staticIPs[ip]; dup {
				return errors.New("duplicate static ip ", u.Ip, " for users ", other, " and ", u.Name)
			}
			staticIPs[ip] = u.Name
		}
		for _, r := range u.Routes {
			if err := validateRoute(r); err != nil {
				return errors.New("user ", u.Name, ": ").Base(err)
			}
		}
		if u.Group != "" {
			if _, ok := groupNames[u.Group]; !ok {
				return errors.New("user ", u.Name, ": unknown route group: ", u.Group)
			}
		}
	}
	for _, r := range c.Routes {
		if err := validateRoute(r); err != nil {
			return err
		}
	}
	// The camouflage secret is matched against the raw query string, so it
	// must be a single unencoded token; the realm lands in a response header.
	if strings.ContainsAny(c.CamouflageSecret, "?& \t\r\n") {
		return errors.New("camouflageSecret must not contain '?', '&', whitespace or CR/LF")
	}
	if strings.ContainsAny(c.CamouflageRealm, "\"\r\n") {
		return errors.New("camouflageRealm must not contain quotes or CR/LF")
	}
	if c.Mtu != 0 && (c.Mtu < MinMTU || c.Mtu > MaxMTU) {
		return errors.New("mtu out of range [", MinMTU, ",", MaxMTU, "]: ", c.Mtu)
	}
	return nil
}

// routesFor resolves the split-routing networks for a user's session:
// group routes first, then the user's own routes, each network advertised
// as its own X-CSTP-Split-Include line. A user with neither falls back to
// the inbound-level routes; still none means a full tunnel (no headers).
// Duplicate CIDRs across group and user are left as-is: a repeated route
// line is harmless to the client.
func (c *OpenConnectInboundConfig) routesFor(u *User) []string {
	if u == nil {
		return c.Routes
	}
	var out []string
	if u.Group != "" {
		for _, g := range c.Groups {
			if g.Name == u.Group {
				out = append(out, g.Routes...)
				break
			}
		}
	}
	if len(u.Routes) > 0 {
		out = append(out, u.Routes...)
	}
	if len(out) == 0 {
		return c.Routes
	}
	return out
}

// noRoutesFor resolves the split-routing exclusions for a user's session:
// the no-route networks of the user's group, if any. Exclusions live on the
// group (not the inbound), so a user without a group has none.
func (c *OpenConnectInboundConfig) noRoutesFor(u *User) []string {
	if u == nil || u.Group == "" {
		return nil
	}
	for _, g := range c.Groups {
		if g.Name == u.Group {
			return g.NoRoutes
		}
	}
	return nil
}

// l3For reports whether a user's sessions participate in the L3
// client↔client relay: the user's own l3 flag when set, otherwise the
// group's l3 flag, otherwise false. L3 is opt-in: an unset flag anywhere
// means off.
func (c *OpenConnectInboundConfig) l3For(u *User) bool {
	if u == nil {
		return false
	}
	// Per-user override wins over the group flag; nil means "not set".
	if u.L3 != nil {
		return *u.L3
	}
	if u.Group == "" {
		return false
	}
	for _, g := range c.Groups {
		if g.Name == u.Group {
			return g.L3 != nil && *g.L3
		}
	}
	return false
}

// maxSessionsPerUserFor returns the live-tunnel bound that applies to u's
// account: the user's own max_sessions_per_user when set, otherwise the
// group's, otherwise the inbound-level one. 0 = unlimited.
func (c *OpenConnectInboundConfig) maxSessionsPerUserFor(u *User) uint32 {
	if u != nil && u.MaxSessionsPerUser != nil {
		return *u.MaxSessionsPerUser
	}
	if u != nil && u.Group != "" {
		for _, g := range c.Groups {
			if g.Name == u.Group {
				if g.MaxSessionsPerUser != nil {
					return *g.MaxSessionsPerUser
				}
				break
			}
		}
	}
	return c.MaxSessionsPerUser
}

// validateRoute checks one split-routing network: IPv4 CIDR.
func validateRoute(r string) error {
	p, err := netip.ParsePrefix(r)
	if err != nil {
		return errors.New("invalid route (want IPv4 CIDR): ", r).Base(err)
	}
	if !p.Addr().Is4() {
		return errors.New("route must be IPv4: ", r)
	}
	return nil
}

// firstHost returns the first host address of an IPv4 prefix (base+1),
// reserved for the gateway/DNS. The caller must ensure the prefix is IPv4.
func firstHost(p netip.Prefix) netip.Addr {
	a4 := p.Masked().Addr().As4()
	a4[3]++
	return netip.AddrFrom4(a4)
}

// ipv4Broadcast returns the broadcast address of an IPv4 prefix. The caller
// must ensure the prefix is IPv4.
func ipv4Broadcast(p netip.Prefix) netip.Addr {
	a4 := p.Masked().Addr().As4()
	base := binary.BigEndian.Uint32(a4[:])
	mask := ^uint32(0) << (32 - p.Bits())
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], base|^mask)
	return netip.AddrFrom4(out)
}
