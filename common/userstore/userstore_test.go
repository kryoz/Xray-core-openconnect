package userstore

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/protobuf/proto"
)

// accountOf wraps an arbitrary payload as the account of a user. TypedMessage
// is itself a registered message, which keeps the codec under test free of any
// protocol's account type — and its bytes field exercises the base64 form the
// file uses.
func accountOf(payload string) *serial.TypedMessage {
	return serial.ToTypedMessage(&serial.TypedMessage{
		Type:  "xray.test.Account",
		Value: []byte(payload),
	})
}

func sampleFile() *UserFile {
	return &UserFile{Users: []*protocol.User{
		{Email: "alice@test", Level: 1, Account: accountOf("salt$hash")},
		{Email: "bob@test", Disabled: true, Account: accountOf("other$hash")},
	}}
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	want := sampleFile()

	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !proto.Equal(got, want) {
		t.Fatalf("round trip changed the file:\n got %v\nwant %v", got, want)
	}

	// The file holds credentials: it must not be readable by anyone else, and
	// the write must not leave its temporary behind.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// Windows has no Unix permission bits — a file reports 0666 whatever was
	// asked for — so only the platforms that have them can be checked.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("file mode = %#o, want 0600", perm)
		}
	}
	if entries := dirEntries(t, dir); len(entries) != 1 {
		t.Fatalf("the directory holds %v, want only the overlay", entries)
	}

	// Written the way xray configs read: camelCase, one field per line.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(raw)
	// protojson deliberately varies the whitespace after ':' from build to
	// build (google.golang.org/protobuf/internal/detrand) — a -race build, or
	// simply a different compile, emits two spaces instead of one — so the
	// assertion cannot depend on it. What matters is the camelCase names and
	// the values.
	compact := regexp.MustCompile(`:[ \t]+`).ReplaceAllString(text, ":")
	if !strings.Contains(compact, "\"email\":\"alice@test\"") || !strings.Contains(compact, "\"disabled\":true") {
		t.Fatalf("the file is not the xray JSON form:\n%s", text)
	}
}

func TestSaveReplacesTheWholeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	if err := Save(path, sampleFile()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	replacement := &UserFile{Users: []*protocol.User{{Email: "carol@test", Account: accountOf("c")}}}
	if err := Save(path, replacement); err != nil {
		t.Fatalf("Save over an existing file: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !proto.Equal(got, replacement) {
		t.Fatalf("the second write did not replace the file: %v", got)
	}
	if entries := dirEntries(t, dir); len(entries) != 1 {
		t.Fatalf("the directory holds %v, want only the overlay", entries)
	}
}

func TestSaveFailureLeavesTheOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	if err := Save(path, sampleFile()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// A directory that does not exist cannot hold the temporary file, so the
	// write fails before anything of the existing overlay is touched.
	missing := filepath.Join(dir, "no-such-dir", "users.json")
	if err := Save(missing, &UserFile{}); err == nil {
		t.Fatal("writing into a missing directory must fail")
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !proto.Equal(got, sampleFile()) {
		t.Fatalf("a failed write disturbed the overlay: %v", got)
	}
}

func TestLoadOrSeed(t *testing.T) {
	seed := sampleFile().Users

	tests := []struct {
		name    string
		path    bool // the overlay exists before the call
		content string
		want    []*protocol.User
		wantErr bool
	}{
		{name: "no path keeps the config users", want: seed},
		{name: "an existing overlay wins over the config", path: true, want: []*protocol.User{{Email: "from-file"}}},
		{name: "an empty overlay is the operator's decision", path: true, content: "{\"users\":[]}"},
		{name: "a corrupt overlay is an error", path: true, content: "not json", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := ""
			if tc.path {
				path = filepath.Join(dir, "users.json")
				content := tc.content
				if content == "" {
					f := &UserFile{Users: []*protocol.User{{Email: "from-file"}}}
					raw, err := marshalOptions.Marshal(f)
					if err != nil {
						t.Fatalf("Marshal: %v", err)
					}
					content = string(raw)
				}
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}

			got, fromFile, err := LoadOrSeed(path, seed, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadOrSeed error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if fromFile != tc.path {
				t.Fatalf("the accounts came from an existing overlay = %v, want %v", fromFile, tc.path)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d user(s) %v, want %d", len(got), got, len(tc.want))
			}
			for i := range got {
				if !proto.Equal(got[i], tc.want[i]) {
					t.Fatalf("user %d = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestLoadOrSeedWritesTheSeedOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")

	got, fromFile, err := LoadOrSeed(path, sampleFile().Users, nil)
	if err != nil {
		t.Fatalf("LoadOrSeed: %v", err)
	}
	if fromFile {
		t.Fatal("the first start read an overlay that did not exist")
	}
	if len(got) != 2 {
		t.Fatalf("the seed did not come back: %v", got)
	}
	// Seeded, so the next start has something to read — and it is readable.
	again, fromFile, err := LoadOrSeed(path, []*protocol.User{{Email: "config-only"}}, nil)
	if err != nil {
		t.Fatalf("LoadOrSeed after seeding: %v", err)
	}
	if !fromFile {
		t.Fatal("the second start did not read the overlay the first one seeded")
	}
	if len(again) != 2 || again[0].Email != "alice@test" {
		t.Fatalf("the second start did not read the seeded file: %v", again)
	}
	if entries := dirEntries(t, dir); len(entries) != 1 {
		t.Fatalf("the directory holds %v, want only the overlay", entries)
	}
}

// TestLoadOrSeedValidatesBeforeWriting pins the poisoning guard: a seed that
// fails validation must not become a file, because the file outlives the failed
// start and, once it exists, it is what the next start reads.
func TestLoadOrSeedValidatesBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")

	reject := func([]*protocol.User) error { return errors.New("bad seed") }
	if _, _, err := LoadOrSeed(path, sampleFile().Users, reject); err == nil {
		t.Fatal("a rejected seed passed LoadOrSeed")
	}
	if entries := dirEntries(t, dir); len(entries) != 0 {
		t.Fatalf("a rejected seed still wrote %v", entries)
	}

	accept := func(seed []*protocol.User) error {
		if len(seed) != 2 {
			t.Fatalf("validateSeed saw %d user(s), want the whole seed", len(seed))
		}
		return nil
	}
	if _, _, err := LoadOrSeed(path, sampleFile().Users, accept); err != nil {
		t.Fatalf("LoadOrSeed with an accepting validator: %v", err)
	}
	if entries := dirEntries(t, dir); len(entries) != 1 {
		t.Fatalf("the directory holds %v, want only the overlay", entries)
	}
	// An existing file is the source and is never run past the validator.
	if _, _, err := LoadOrSeed(path, sampleFile().Users, reject); err != nil {
		t.Fatalf("validateSeed must not run for an existing overlay: %v", err)
	}
}
