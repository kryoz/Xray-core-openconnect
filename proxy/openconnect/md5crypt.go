package openconnect

import (
	"crypto/md5"
	"crypto/subtle"
	"strings"
)

// MD5-crypt: the "$1$" scheme glibc, ocpasswd and htpasswd -m use.
//
// It exists here because an OpenConnect deployment usually arrives with an
// ocpasswd file already in place, and the stored value is a one-way hash:
// without verifying this format, moving to this inbound means asking every
// user for a new password. Both formats are accepted side by side, so a
// migration is per-account rather than all-at-once.
//
// ponytail: MD5-crypt is weak — 1000 unsalted-by-design rounds, no memory
// hardness. Ceiling: it is only ever verified here, never minted
// (GenerateCredential still mints salted SHA-256); drop this file once no
// store holds a $1$ value.
const (
	md5CryptPrefix    = "$1$"
	md5CryptRounds    = 1000
	md5CryptSaltMin   = 1
	md5CryptSaltMax   = 8
	md5CryptDigestLen = 22
)

// cryptAlphabet is the scheme's own base64 variant, not RFC 4648's.
const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// splitMD5Crypt splits a "$1$salt$digest" field into its parts, rejecting
// anything the scheme cannot have produced.
func splitMD5Crypt(field string) (salt, digest string, ok bool) {
	rest, isMD5 := strings.CutPrefix(field, md5CryptPrefix)
	if !isMD5 {
		return "", "", false
	}
	salt, digest, found := strings.Cut(rest, "$")
	if !found || len(salt) < md5CryptSaltMin || len(salt) > md5CryptSaltMax || len(digest) != md5CryptDigestLen {
		return "", "", false
	}
	// A digest character outside the alphabet can never match, so a field
	// holding one is a broken import rather than a wrong password.
	if strings.TrimLeft(digest, cryptAlphabet) != "" {
		return "", "", false
	}
	return salt, digest, true
}

// verifyMD5Crypt reports whether password hashes to the stored digest, in
// constant time with respect to the digest.
func verifyMD5Crypt(password, salt, digest string) bool {
	return subtle.ConstantTimeCompare([]byte(md5CryptDigest(password, salt)), []byte(digest)) == 1
}

// md5CryptDigest runs the MD5-CRYPT algorithm and encodes the result the way
// the scheme does: five 24-bit groups plus a 2-character tail, LSB-first.
func md5CryptDigest(password, salt string) string {
	p := []byte(password)

	// A second digest of password+salt+password, used as a repeating key.
	sum := md5.Sum(append(append(append([]byte{}, p...), []byte(salt)...), p...))

	a := md5.New()
	a.Write(p)
	a.Write([]byte(md5CryptPrefix))
	a.Write([]byte(salt))
	for i := range len(p) {
		a.Write(sum[i%16 : i%16+1])
	}
	// Per bit of the password length: a NUL for a set bit, the first character
	// for a clear one. The scheme zeroes the accumulator before this step, so
	// the "digest byte" it would write is always NUL.
	for i := len(p); i > 0; i >>= 1 {
		if i&1 == 1 {
			a.Write([]byte{0})
		} else {
			a.Write(p[:1])
		}
	}
	dc := a.Sum(nil)

	for i := range md5CryptRounds {
		h := md5.New()
		if i&1 == 1 {
			h.Write(p)
		} else {
			h.Write(dc)
		}
		if i%3 != 0 {
			h.Write([]byte(salt))
		}
		if i%7 != 0 {
			h.Write(p)
		}
		if i&1 == 1 {
			h.Write(dc)
		} else {
			h.Write(p)
		}
		dc = h.Sum(nil)
	}

	add := func(out []byte, c0, c1, c2 byte, n int) []byte {
		v := int(c0)<<16 | int(c1)<<8 | int(c2)
		for range n {
			out = append(out, cryptAlphabet[v&0x3F])
			v >>= 6
		}
		return out
	}
	var out []byte
	out = add(out, dc[0], dc[6], dc[12], 4)
	out = add(out, dc[1], dc[7], dc[13], 4)
	out = add(out, dc[2], dc[8], dc[14], 4)
	out = add(out, dc[3], dc[9], dc[15], 4)
	out = add(out, dc[4], dc[10], dc[5], 4)
	out = add(out, 0, 0, dc[11], 2)
	return string(out)
}
