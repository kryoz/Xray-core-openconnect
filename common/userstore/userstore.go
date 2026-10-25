// Package userstore keeps the accounts of an inbound in a file next to the
// config, so that what the management API changes on a running process —
// add, block, remove — survives a restart without rewriting the config file.
//
// The file holds xray.common.protocol.User entries, the very message the API
// exchanges, in the JSON form xray configs use. It is written atomically and
// 0600: an account carries a credential, and a half-written file would either
// lock every account out or resurrect one the operator deleted.
package userstore

import (
	"os"
	"path/filepath"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/encoding/protojson"
)

// marshalOptions writes the file the way xray configs read: camelCase field
// names, one field per line.
var marshalOptions = protojson.MarshalOptions{Multiline: true, Indent: "  "}

// unmarshalOptions tolerates fields this build does not know, so that a
// rollback to an older binary does not turn the overlay into a start-up
// failure.
var unmarshalOptions = protojson.UnmarshalOptions{DiscardUnknown: true}

// Load reads the overlay at path.
func Load(path string) (*UserFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("failed to read users file ", path).Base(err)
	}
	f := new(UserFile)
	if err := unmarshalOptions.Unmarshal(data, f); err != nil {
		return nil, errors.New("invalid users file ", path).Base(err)
	}
	return f, nil
}

// Exists reports whether the overlay is there. A path that is present but
// unreadable is reported as an error rather than as absent: seeding over an
// existing file would discard the accounts in it.
func Exists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.New("failed to stat users file ", path).Base(err)
	}
	return true, nil
}

// Save writes the overlay atomically: a temporary file in the same directory,
// 0600, flushed, then renamed over the target, then the directory flushed so
// the rename itself survives a crash. A reader therefore sees either the whole
// previous state or the whole new one, never a truncated file.
//
// The directory has to exist — creating it here would hide a typo in usersFile
// behind a silently empty overlay.
func Save(path string, f *UserFile) error {
	if path == "" {
		return errors.New("users file path is empty")
	}
	data, err := marshalOptions.Marshal(f)
	if err != nil {
		return errors.New("failed to serialize users file").Base(err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return errors.New("failed to create a temporary users file in ", dir).Base(err)
	}
	tmpName := tmp.Name()
	defer func() {
		// A no-op once the rename below has moved the file away.
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return errors.New("failed to protect users file ", path).Base(err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return errors.New("failed to write users file ", path).Base(err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return errors.New("failed to flush users file ", path).Base(err)
	}
	if err := tmp.Close(); err != nil {
		return errors.New("failed to close users file ", path).Base(err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return errors.New("failed to replace users file ", path).Base(err)
	}
	fsyncDir(dir)
	return nil
}

// fsyncDir makes the rename that replaced the overlay durable. Not every
// platform lets a directory be synced; the file itself already is, so a failure
// here costs durability of the rename, not the data.
func fsyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// LoadOrSeed resolves the accounts an inbound with a users file has to start
// with. Without a file the seed — the users the config declares — is returned
// unchanged and nothing is written, which keeps a config that predates the
// overlay behaving exactly as before. With a file that does not exist yet the
// seed is written out, so the first restart already has something to read.
// With a file that exists, the file is the only source of users: an account
// removed at runtime must not come back from the config on the next start.
// The bool says which of the two it was: the caller needs it to tell the
// operator that the config's own users went unread.
//
// validateSeed, when set, runs against the seed before it is written. The file
// outlives a failed start, and once it exists it — not the config — is what
// the next start reads: seeding from a config whose users do not validate
// would turn one bad start into a permanently broken inbound.
func LoadOrSeed(path string, seed []*protocol.User, validateSeed func([]*protocol.User) error) ([]*protocol.User, bool, error) {
	if path == "" {
		return seed, false, nil
	}
	ok, err := Exists(path)
	if err != nil {
		return nil, false, err
	}
	if ok {
		f, err := Load(path)
		if err != nil {
			return nil, false, err
		}
		return f.GetUsers(), true, nil
	}
	if validateSeed != nil {
		if err := validateSeed(seed); err != nil {
			return nil, false, err
		}
	}
	f := &UserFile{Users: seed}
	if err := Save(path, f); err != nil {
		return nil, false, err
	}
	return f.GetUsers(), false, nil
}
