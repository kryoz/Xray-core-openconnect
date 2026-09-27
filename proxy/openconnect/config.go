package openconnect

import (
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
		return nil, errors.New("password must be formatted as salt_hex$hash_hex").AtError()
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) == 0 {
		return nil, errors.New("invalid password salt").Base(err).AtError()
	}
	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != sha256.Size {
		return nil, errors.New("invalid password hash").Base(err).AtError()
	}
	c := &credential{salt: salt}
	copy(c.hash[:], hash)
	return c, nil
}

// validate checks the inbound configuration for internal consistency.
func (c *OpenConnectInboundConfig) validate() error {
	if len(c.Users) == 0 {
		return errors.New("at least one user is required").AtError()
	}
	prefix, err := netip.ParsePrefix(c.Subnet)
	if err != nil {
		return errors.New("invalid subnet: ", c.Subnet).Base(err).AtError()
	}
	if !prefix.Addr().Is4() {
		return errors.New("subnet must be IPv4: ", c.Subnet).AtError()
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("certFile and keyFile must both be set or both empty").AtError()
	}
	for _, ns := range c.Dns {
		if _, err := netip.ParseAddr(ns); err != nil {
			return errors.New("invalid dns server: ", ns).Base(err).AtError()
		}
	}
	groupNames := make(map[string]struct{}, len(c.Groups))
	for _, g := range c.Groups {
		if g.Name == "" {
			return errors.New("route group name must not be empty").AtError()
		}
		if _, dup := groupNames[g.Name]; dup {
			return errors.New("duplicate route group: ", g.Name).AtError()
		}
		for _, r := range g.Routes {
			if err := validateRoute(r); err != nil {
				return errors.New("route group ", g.Name, ": ").Base(err).AtError()
			}
		}
		groupNames[g.Name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(c.Users))
	staticIPs := make(map[netip.Addr]string, len(c.Users))
	for _, u := range c.Users {
		if u.Name == "" {
			return errors.New("user name must not be empty").AtError()
		}
		if _, dup := seen[u.Name]; dup {
			return errors.New("duplicate user: ", u.Name).AtError()
		}
		seen[u.Name] = struct{}{}
		if _, err := parseCredential(u.Password); err != nil {
			return errors.New("user ", u.Name, ": ").Base(err).AtError()
		}
		if u.Ip != "" {
			ip, err := netip.ParseAddr(u.Ip)
			if err != nil {
				return errors.New("user ", u.Name, ": invalid static ip: ", u.Ip).Base(err).AtError()
			}
			if !prefix.Contains(ip) {
				return errors.New("user ", u.Name, ": static ip ", u.Ip, " outside subnet ", c.Subnet).AtError()
			}
			if ip == prefix.Addr() || ip == ipv4Broadcast(prefix) {
				return errors.New("user ", u.Name, ": static ip ", u.Ip, " is a network/broadcast address").AtError()
			}
			if ip == firstHost(prefix) {
				return errors.New("user ", u.Name, ": static ip ", u.Ip, " is the gateway/DNS address of the subnet").AtError()
			}
			if other, dup := staticIPs[ip]; dup {
				return errors.New("duplicate static ip ", u.Ip, " for users ", other, " and ", u.Name).AtError()
			}
			staticIPs[ip] = u.Name
		}
		for _, r := range u.Routes {
			if err := validateRoute(r); err != nil {
				return errors.New("user ", u.Name, ": ").Base(err).AtError()
			}
		}
		if u.Group != "" {
			if _, ok := groupNames[u.Group]; !ok {
				return errors.New("user ", u.Name, ": unknown route group: ", u.Group).AtError()
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
		return errors.New("camouflageSecret must not contain '?', '&', whitespace or CR/LF").AtError()
	}
	if strings.ContainsAny(c.CamouflageRealm, "\"\r\n") {
		return errors.New("camouflageRealm must not contain quotes or CR/LF").AtError()
	}
	if c.Mtu != 0 && (c.Mtu < MinMTU || c.Mtu > MaxMTU) {
		return errors.New("mtu out of range [", MinMTU, ",", MaxMTU, "]: ", c.Mtu).AtError()
	}
	switch c.Cipher {
	case "", "auto", "aes128gcm", "chacha20poly1305":
	default:
		return errors.New("cipher must be one of auto, aes128gcm, chacha20poly1305: ", c.Cipher).AtError()
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

// validateRoute checks one split-routing network: IPv4 CIDR.
func validateRoute(r string) error {
	p, err := netip.ParsePrefix(r)
	if err != nil {
		return errors.New("invalid route (want IPv4 CIDR): ", r).Base(err).AtError()
	}
	if !p.Addr().Is4() {
		return errors.New("route must be IPv4: ", r).AtError()
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
