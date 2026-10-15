package openconnect

import (
	"strings"
	"testing"
)

// The vectors come from `openssl passwd -1 -salt <salt> <password>`, an
// independent implementation of the scheme: agreeing with them is
// interoperability with ocpasswd, not a snapshot of this code.
func TestMD5CryptVectors(t *testing.T) {
	cases := []struct {
		name     string
		password string
		field    string
	}{
		{"typical", "password", "$1$EsKzB9Hg$QJ1F2fv/XVov/2paCLZDV/"},
		{"short salt", "secret123", "$1$abcde$iVqra0zQw0iSIPRo1SOsP1"},
		{"salt with . and /", "short", "$1$0yexv6.m$Y9tiE8uc1ZZNq2jj9xKdR."},
		{"16-char password", "16chars16chars1", "$1$ELIztMnb$aJ.jwI5.MLP4dQeGe.WSO0"},
		{"long password", "a-very-long-password-that-exceeds-sixteen-chars", "$1$NZEHPeuc$NU7fcAr3z8zhgd.ePJ6zJ/"},
		{"empty password", "", "$1$./y/uSJ1$i5OdwKmHcIqAYN6mGsARx1"},
		{"1-char salt", "p1", "$1$s$x9seNJhajEBUoLN2ioyIf."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			salt, digest, ok := splitMD5Crypt(tc.field)
			if !ok {
				t.Fatalf("splitMD5Crypt(%q) rejected a valid field", tc.field)
			}
			if got := md5CryptDigest(tc.password, salt); got != digest {
				t.Errorf("md5CryptDigest(%q, %q) = %q, want %q", tc.password, salt, got, digest)
			}
			if !verifyMD5Crypt(tc.password, salt, digest) {
				t.Error("the right password was rejected")
			}
			if verifyMD5Crypt(tc.password+"x", salt, digest) {
				t.Error("a wrong password was accepted")
			}
		})
	}
}

func TestParseCredentialFormats(t *testing.T) {
	generated, err := GenerateCredential("hunter2")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		field    string
		password string
		wantErr  string
		accepts  bool
	}{
		{"md5crypt", "$1$EsKzB9Hg$QJ1F2fv/XVov/2paCLZDV/", "password", "", true},
		{"md5crypt wrong password", "$1$EsKzB9Hg$QJ1F2fv/XVov/2paCLZDV/", "Password", "", false},
		{"sha256", generated, "hunter2", "", true},
		{"sha256 wrong password", generated, "hunter3", "", false},
		{"md5crypt salt too long", "$1$abcdefghi$QJ1F2fv/XVov/2paCLZDV/", "password", "malformed MD5-crypt", false},
		{"md5crypt digest too short", "$1$EsKzB9Hg$QJ1F2fv", "password", "malformed MD5-crypt", false},
		{"md5crypt digest too long", "$1$EsKzB9Hg$QJ1F2fv/XVov/2paCLZDV/X", "password", "malformed MD5-crypt", false},
		{"md5crypt digest off alphabet", "$1$EsKzB9Hg$QJ1F2fv/XVov/2paCLZDV!", "password", "malformed MD5-crypt", false},
		{"md5crypt no digest", "$1$EsKzB9Hg$", "password", "malformed MD5-crypt", false},
		{"md5crypt prefix alone", "$1$", "password", "malformed MD5-crypt", false},
		{"no separator", "deadbeef", "password", "salt_hex$hash_hex", false},
		{"empty salt", "$" + strings.Repeat("0", 64), "password", "invalid password salt", false},
		{"salt not hex", "zz$" + strings.Repeat("0", 64), "password", "invalid password salt", false},
		{"hash wrong length", "00ff$" + strings.Repeat("0", 62), "password", "invalid password hash", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := parseCredential(tc.field)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseCredential(%q) err = %v, want one containing %q", tc.field, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCredential(%q): %v", tc.field, err)
			}
			if got := cred.check(tc.password); got != tc.accepts {
				t.Errorf("check(%q) = %v, want %v", tc.password, got, tc.accepts)
			}
		})
	}
}

// The two formats have to coexist in one store: a migration is per account, so
// a file holding both is the normal state, not an edge case.
func TestUserStoreMixedFormats(t *testing.T) {
	native, err := GenerateCredential("native-pass")
	if err != nil {
		t.Fatal(err)
	}
	store, err := newUserStore([]*User{
		{Name: "md5@example.com", Password: "$1$EsKzB9Hg$QJ1F2fv/XVov/2paCLZDV/"},
		{Name: "sha@example.com", Password: native},
		{Name: "off@example.com", Password: "$1$EsKzB9Hg$QJ1F2fv/XVov/2paCLZDV/", Disabled: boolP(true)},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, password string
		want           bool
	}{
		{"md5@example.com", "password", true},
		{"md5@example.com", "wrong", false},
		{"sha@example.com", "native-pass", true},
		{"sha@example.com", "wrong", false},
		{"off@example.com", "password", false},
		{"unknown@example.com", "password", false},
	}
	for _, tc := range cases {
		if got := store.check(tc.name, tc.password); got != tc.want {
			t.Errorf("check(%q, %q) = %v, want %v", tc.name, tc.password, got, tc.want)
		}
	}
}
