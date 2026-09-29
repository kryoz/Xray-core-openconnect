package openconnect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	jsoncomment "github.com/xtls/xray-core/infra/conf/json"
	"github.com/xtls/xray-core/main/commands/base"
	oc "github.com/xtls/xray-core/proxy/openconnect"
)

var cmdAdd = &base.Command{
	UsageLine: "{{.Exec}} openconnect add [-c config.json] [-in tag] [-ip ip] [<name> <password>]",
	Short:     "Add a user to an OpenConnect inbound",
	Long: `
{{.Exec}} {{.LongName}} [-c config.json] [-in tag] [-ip ip] <name> <password>
Adds a user with a freshly generated salted credential to the
"users" array of an OpenConnect inbound in the given JSON config.
Use "-" as the password to read it from stdin.
`,
}

var cmdList = &base.Command{
	UsageLine: "{{.Exec}} openconnect list [-c config.json] [-in tag]",
	Short:     "List users of OpenConnect inbounds",
}

var cmdPasswd = &base.Command{
	UsageLine: "{{.Exec}} openconnect passwd [-c config.json] [-in tag] [<name> <password>]",
	Short:     "Rotate the password of an OpenConnect user",
	Long: `
{{.Exec}} {{.LongName}} [-c config.json] [-in tag] <name> <password>
Replaces the user's credential with a new salted hash. Use "-" as the
password to read it from stdin.
`,
}

var cmdRm = &base.Command{
	UsageLine: "{{.Exec}} openconnect rm [-c config.json] [-in tag] [<name>]",
	Short:     "Remove a user from an OpenConnect inbound",
}

func init() {
	cmdAdd.Run = executeAdd // break init loop
	cmdList.Run = executeList
	cmdPasswd.Run = executePasswd
	cmdRm.Run = executeRm
}

var (
	addConfig  = cmdAdd.Flag.String("c", "", "path to the xray JSON config file")
	addInbound = cmdAdd.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
	addIP      = cmdAdd.Flag.String("ip", "", "static IP for the user, within the inbound subnet")

	listConfig  = cmdList.Flag.String("c", "", "path to the xray JSON config file")
	listInbound = cmdList.Flag.String("in", "", "inbound tag (lists only that inbound)")

	passwdConfig  = cmdPasswd.Flag.String("c", "", "path to the xray JSON config file")
	passwdInbound = cmdPasswd.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")

	rmConfig  = cmdRm.Flag.String("c", "", "path to the xray JSON config file")
	rmInbound = cmdRm.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
)

func executeAdd(cmd *base.Command, args []string) {
	if len(args) != 2 {
		cmd.Usage()
	}
	name, passwordArg := args[0], args[1]
	if name == "" {
		base.Fatalf("user name must not be empty")
	}
	password, err := readPassword(passwordArg)
	if err != nil {
		base.Fatalf("reading password: %v", err)
	}
	cred, err := oc.GenerateCredential(password)
	if err != nil {
		base.Fatalf("%v", err)
	}

	doc, err := loadConfig(*addConfig)
	must(err)
	ib, err := findInbound(doc, *addInbound)
	must(err)
	users, err := usersOf(ib)
	must(err)
	for _, u := range users {
		if userName(u) == name {
			base.Fatalf("user %q already exists", name)
		}
	}
	user := map[string]any{"name": name, "password": cred}
	if *addIP != "" {
		user["ip"] = *addIP
	}
	setUsers(ib, append(users, user))
	must(saveConfig(*addConfig, doc))
	fmt.Printf("added user %q to %s\n", name, inboundLabel(ib))
}

func executeList(cmd *base.Command, args []string) {
	doc, err := loadConfig(*listConfig)
	must(err)
	inbounds, err := findInbounds(doc, *listInbound)
	must(err)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, ib := range inbounds {
		users, err := usersOf(ib)
		must(err)
		for _, u := range users {
			m, _ := u.(map[string]any)
			ip, _ := m["ip"].(string)
			group, _ := m["group"].(string)
			l3, _ := m["l3"].(bool)
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\n", inboundLabel(ib), userName(u), ip, group, l3); err != nil {
				base.Fatalf("%v", err)
			}
		}
	}
	if err := w.Flush(); err != nil {
		base.Fatalf("%v", err)
	}
}

func executePasswd(cmd *base.Command, args []string) {
	if len(args) != 2 {
		cmd.Usage()
	}
	name, passwordArg := args[0], args[1]
	password, err := readPassword(passwordArg)
	if err != nil {
		base.Fatalf("reading password: %v", err)
	}
	cred, err := oc.GenerateCredential(password)
	if err != nil {
		base.Fatalf("%v", err)
	}

	doc, err := loadConfig(*passwdConfig)
	must(err)
	ib, err := findInbound(doc, *passwdInbound)
	must(err)
	users, err := usersOf(ib)
	must(err)
	for _, u := range users {
		if userName(u) != name {
			continue
		}
		m, _ := u.(map[string]any)
		m["password"] = cred
		must(saveConfig(*passwdConfig, doc))
		fmt.Printf("rotated password of %q in %s\n", name, inboundLabel(ib))
		return
	}
	base.Fatalf("user %q not found", name)
}

func executeRm(cmd *base.Command, args []string) {
	if len(args) != 1 {
		cmd.Usage()
	}
	name := args[0]

	doc, err := loadConfig(*rmConfig)
	must(err)
	ib, err := findInbound(doc, *rmInbound)
	must(err)
	users, err := usersOf(ib)
	must(err)
	rest := make([]any, 0, len(users))
	removed := false
	for _, u := range users {
		if userName(u) == name {
			removed = true
			continue
		}
		rest = append(rest, u)
	}
	if !removed {
		base.Fatalf("user %q not found", name)
	}
	if len(rest) == 0 {
		base.Fatalf("refusing to remove the last user; the inbound requires at least one")
	}
	setUsers(ib, rest)
	must(saveConfig(*rmConfig, doc))
	fmt.Printf("removed user %q from %s\n", name, inboundLabel(ib))
}

// must prints the error and exits with status 1.
func must(err error) {
	if err != nil {
		base.Fatalf("%v", err)
	}
}

// loadConfig reads an xray JSON config, tolerating the comment styles the
// xray JSON loader accepts.
func loadConfig(path string) (map[string]any, error) {
	if path == "" {
		return nil, errors.New("config file is required (-c)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	dec := json.NewDecoder(&jsoncomment.Reader{Reader: bytes.NewReader(data)})
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return doc, nil
}

// saveConfig writes the doc back as indented JSON, keeping the file's
// permission bits.
func saveConfig(path string, doc map[string]any) error {
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, fi.Mode().Perm())
}

// findInbounds returns all OpenConnect inbounds, or only the one with the
// given tag.
func findInbounds(doc map[string]any, tag string) ([]map[string]any, error) {
	raw, ok := doc["inbounds"].([]any)
	if !ok {
		return nil, errors.New("config has no inbounds array")
	}
	var found []map[string]any
	for _, item := range raw {
		ib, ok := item.(map[string]any)
		if !ok || ib["protocol"] != "openconnect" {
			continue
		}
		if tag == "" || ib["tag"] == tag {
			found = append(found, ib)
		}
	}
	if len(found) == 0 {
		if tag != "" {
			return nil, fmt.Errorf("no OpenConnect inbound with tag %q", tag)
		}
		return nil, errors.New("no OpenConnect inbound found in config")
	}
	return found, nil
}

// findInbound returns the single OpenConnect inbound to modify: the only
// one present, or the one selected by tag.
func findInbound(doc map[string]any, tag string) (map[string]any, error) {
	found, err := findInbounds(doc, tag)
	if err != nil {
		return nil, err
	}
	if len(found) > 1 {
		names := make([]string, len(found))
		for i, ib := range found {
			t, _ := ib["tag"].(string)
			names[i] = t
		}
		return nil, fmt.Errorf("several OpenConnect inbounds (%s); select one with -in", strings.Join(names, ", "))
	}
	return found[0], nil
}

func usersOf(ib map[string]any) ([]any, error) {
	settings, ok := ib["settings"].(map[string]any)
	if !ok {
		return nil, errors.New("inbound has no settings object")
	}
	users, ok := settings["users"].([]any)
	if !ok {
		return nil, errors.New("inbound settings has no users array")
	}
	return users, nil
}

func setUsers(ib map[string]any, users []any) {
	ib["settings"].(map[string]any)["users"] = users
}

func userName(u any) string {
	m, _ := u.(map[string]any)
	name, _ := m["name"].(string)
	return name
}

func inboundLabel(ib map[string]any) string {
	if tag, ok := ib["tag"].(string); ok && tag != "" {
		return "inbound " + tag
	}
	return "the OpenConnect inbound"
}
