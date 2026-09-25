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

	DefaultMTU           = 1400
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
			if other, dup := staticIPs[ip]; dup {
				return errors.New("duplicate static ip ", u.Ip, " for users ", other, " and ", u.Name).AtError()
			}
			staticIPs[ip] = u.Name
		}
	}
	if c.Mtu != 0 && (c.Mtu < MinMTU || c.Mtu > MaxMTU) {
		return errors.New("mtu out of range [", MinMTU, ",", MaxMTU, "]: ", c.Mtu).AtError()
	}
	return nil
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
