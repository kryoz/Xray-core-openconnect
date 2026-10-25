package openconnect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	jsoncomment "github.com/xtls/xray-core/infra/conf/json"
	"github.com/xtls/xray-core/main/commands/base"
	oc "github.com/xtls/xray-core/proxy/openconnect"
)

var cmdAdd = &base.Command{
	UsageLine: "{{.Exec}} openconnect add [-c config.json | -s 127.0.0.1:8080 -in tag] [-ip ip] [<name> <password>]",
	Short:     "Add a user to an OpenConnect inbound",
	Long: `
{{.Exec}} {{.LongName}} [-c config.json] [-in tag] [-ip ip] <name> <password>
{{.Exec}} {{.LongName}} -s 127.0.0.1:8080 -in tag [-ip ip] <name> <password>
Adds a user with a freshly generated salted credential to the
"users" array of an OpenConnect inbound in the given JSON config.
Use "-" as the password to read it from stdin.
With -s the user is added to a running process instead, and the inbound
validates it against the subnet, the route groups and the accounts it already
holds. Add "usersFile" to the inbound for the change to survive a restart.
`,
}

var cmdList = &base.Command{
	UsageLine: "{{.Exec}} openconnect list [-c config.json | -s 127.0.0.1:8080 -in tag]",
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
	UsageLine: "{{.Exec}} openconnect rm [-c config.json | -s 127.0.0.1:8080 -in tag] [<name>]",
	Short:     "Remove a user from an OpenConnect inbound",
}

var cmdBlock = &base.Command{
	UsageLine: "{{.Exec}} openconnect block [-c config.json | -s 127.0.0.1:8080 -in tag] <name>",
	Short:     "Suspend an OpenConnect user without deleting it",
	Long: `
{{.Exec}} {{.LongName}} [-c config.json] [-in tag] <name>
{{.Exec}} {{.LongName}} -s 127.0.0.1:8080 -in tag <name>
Suspends a user: it stops authenticating, its live tunnels are cut and it can no
longer resume on a session cookie it holds, while its credential, its static
address and its stats key stay in place. Unblock it to restore exactly the same
account.

With -s the change is applied to a running process; without it the config file
is edited and takes effect on the next start.
`,
}

var cmdUnblock = &base.Command{
	UsageLine: "{{.Exec}} openconnect unblock [-c config.json | -s 127.0.0.1:8080 -in tag] <name>",
	Short:     "Restore a suspended OpenConnect user",
	Long: `
{{.Exec}} {{.LongName}} [-c config.json] [-in tag] <name>
{{.Exec}} {{.LongName}} -s 127.0.0.1:8080 -in tag <name>
Reverses a block: the account authenticates again with the credential it kept.
`,
}

var cmdLimit = &base.Command{
	UsageLine: "{{.Exec}} openconnect limit [-c config.json | -s 127.0.0.1:8080 -in tag] [<name> <maxSessions|inherit>]",
	Short:     "Change the per-account live-session limit of an OpenConnect user",
	Long: `
{{.Exec}} {{.LongName}} [-c config.json] [-in tag] <name> <maxSessions>
{{.Exec}} {{.LongName}} -s 127.0.0.1:8080 -in tag <name> <maxSessions>
Sets the live-tunnel bound of one account; 0 lifts the bound. While set, it
overrides the account's group bound and the inbound default. inherit removes
the override: the group's bound applies again.
With -s the change lands on a running process at once: the new bound is
checked from the next auth or CONNECT on, the sessions up right now keep
running, and the change is persisted with the account. Without -s the config
file is edited and the change takes effect on the next start.
`,
}

var cmdL3 = &base.Command{
	UsageLine: "{{.Exec}} openconnect l3 [-c config.json | -s 127.0.0.1:8080 -in tag] [<name> <on|off|inherit>]",
	Short:     "Set the per-user L3 client-to-client relay override of an OpenConnect user",
	Long: `
{{.Exec}} {{.LongName}} [-c config.json] [-in tag] <name> <on|off|inherit>
{{.Exec}} {{.LongName}} -s 127.0.0.1:8080 -in tag <name> <on|off|inherit>
Sets the per-user L3 relay override; while set it wins over the group's l3
flag. on forces the relay on, off forces it off, inherit drops the override
and the group flag applies again.
With -s the change lands on a running process at once, from the next session
on; the change is persisted with the account. Without -s the config file is
edited and the change takes effect on the next start.
`,
}

var cmdDisconnect = &base.Command{
	UsageLine: "{{.Exec}} openconnect disconnect [-s 127.0.0.1:8080 -in tag] [<name>]",
	Short:     "Cut the live sessions of an OpenConnect user without blocking the account",
	Long: `
{{.Exec}} {{.LongName}} -s 127.0.0.1:8080 -in tag <name>
Cuts every live tunnel of the account. The account itself is untouched —
credential, static address, overrides, block flag — so the user can
authenticate again straight away. Unlike block, nothing is persisted and the
change exists only in the running process.
`,
}

func init() {
	cmdAdd.Run = executeAdd // break init loop
	cmdList.Run = executeList
	cmdPasswd.Run = executePasswd
	cmdRm.Run = executeRm
	cmdBlock.Run = executeBlock
	cmdUnblock.Run = executeUnblock
	cmdLimit.Run = executeLimit
	cmdL3.Run = executeL3
	cmdDisconnect.Run = executeDisconnect
}

// serverUsage is the -s flag every user command carries: set, it talks to a
// running process; empty, it edits the config file, which is how the tool
// behaved before the API existed for it.
const serverUsage = "API address of a running xray (e.g. 127.0.0.1:8080); without it the config file is edited"

var (
	addConfig  = cmdAdd.Flag.String("c", "", "path to the xray JSON config file")
	addInbound = cmdAdd.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
	addIP      = cmdAdd.Flag.String("ip", "", "static IP for the user, within the inbound subnet")
	addServer  = cmdAdd.Flag.String("s", "", serverUsage)

	listConfig  = cmdList.Flag.String("c", "", "path to the xray JSON config file")
	listInbound = cmdList.Flag.String("in", "", "inbound tag (lists only that inbound)")
	listServer  = cmdList.Flag.String("s", "", serverUsage)

	passwdConfig  = cmdPasswd.Flag.String("c", "", "path to the xray JSON config file")
	passwdInbound = cmdPasswd.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
	passwdServer  = cmdPasswd.Flag.String("s", "", serverUsage)

	rmConfig  = cmdRm.Flag.String("c", "", "path to the xray JSON config file")
	rmInbound = cmdRm.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
	rmServer  = cmdRm.Flag.String("s", "", serverUsage)

	blockConfig  = cmdBlock.Flag.String("c", "", "path to the xray JSON config file")
	blockInbound = cmdBlock.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
	blockServer  = cmdBlock.Flag.String("s", "", serverUsage)

	unblockConfig  = cmdUnblock.Flag.String("c", "", "path to the xray JSON config file")
	unblockInbound = cmdUnblock.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
	unblockServer  = cmdUnblock.Flag.String("s", "", serverUsage)

	limitConfig  = cmdLimit.Flag.String("c", "", "path to the xray JSON config file")
	limitInbound = cmdLimit.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
	limitServer  = cmdLimit.Flag.String("s", "", serverUsage)

	l3Config  = cmdL3.Flag.String("c", "", "path to the xray JSON config file")
	l3Inbound = cmdL3.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
	l3Server  = cmdL3.Flag.String("s", "", serverUsage)

	disconnectInbound = cmdDisconnect.Flag.String("in", "", "inbound tag (needed when several OpenConnect inbounds exist)")
	disconnectServer  = cmdDisconnect.Flag.String("s", "", serverUsage)
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

	if *addServer != "" {
		onlineAdd(*addServer, *addInbound, &oc.User{Name: name, Password: cred, Ip: *addIP})
		return
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
	if *listServer != "" {
		onlineList(*listServer, *listInbound)
		return
	}

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
			blocked, _ := m["disabled"].(bool)
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%t\n", inboundLabel(ib), userName(u), ip, group, l3, blocked); err != nil {
				base.Fatalf("%v", err)
			}
		}
	}
	if err := w.Flush(); err != nil {
		base.Fatalf("%v", err)
	}
}

func executePasswd(cmd *base.Command, args []string) {
	if *passwdServer != "" {
		// Rotating a password on a live process would mean removing the account
		// and adding it back with the new credential. That cannot be undone
		// half-way — the old credential is not readable back over an API that
		// masks it — so it is not offered rather than offered and risky.
		base.Fatalf("password rotation over the API is not supported: edit the config (-c) or the users file and restart")
	}

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

	if *rmServer != "" {
		onlineRemove(*rmServer, *rmInbound, name)
		return
	}

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

func executeBlock(cmd *base.Command, args []string) {
	runBlock(cmd, args, true, *blockConfig, *blockInbound, *blockServer)
}

func executeUnblock(cmd *base.Command, args []string) {
	runBlock(cmd, args, false, *unblockConfig, *unblockInbound, *unblockServer)
}

// runBlock suspends a user, or restores it when blocked is false: over the API
// when -s names a running process, in the config file otherwise.
func runBlock(cmd *base.Command, args []string, blocked bool, config, inbound, server string) {
	if len(args) != 1 {
		cmd.Usage()
	}
	name := args[0]
	if server != "" {
		onlineBlock(server, inbound, name, blocked)
		return
	}

	doc, err := loadConfig(config)
	must(err)
	ib, err := findInbound(doc, inbound)
	must(err)
	if file := usersFileOf(ib); file != "" {
		base.Fatalf("%s keeps its accounts in %q; that file, not the config, is what the inbound loads. Use -s, or edit the file and restart", inboundLabel(ib), file)
	}
	users, err := usersOf(ib)
	must(err)
	for _, u := range users {
		if userName(u) != name {
			continue
		}
		m, _ := u.(map[string]any)
		if blocked {
			m["disabled"] = true
		} else {
			delete(m, "disabled")
		}
		must(saveConfig(config, doc))
		verb := "blocked"
		if !blocked {
			verb = "unblocked"
		}
		fmt.Printf("%s user %q in %s; takes effect on the next start\n", verb, name, inboundLabel(ib))
		return
	}
	base.Fatalf("user %q not found", name)
}

func executeLimit(cmd *base.Command, args []string) {
	if len(args) != 2 {
		cmd.Usage()
	}
	name, limitArg := args[0], args[1]
	if name == "" {
		base.Fatalf("user name must not be empty")
	}
	limit, err := parseLimit(limitArg)
	if err != nil {
		base.Fatalf("maxSessions must be an unsigned integer (0 lifts the bound) or inherit: %v", err)
	}

	if *limitServer != "" {
		onlineLimit(*limitServer, *limitInbound, name, limit)
		return
	}

	doc, err := loadConfig(*limitConfig)
	must(err)
	ib, err := findInbound(doc, *limitInbound)
	must(err)
	if file := usersFileOf(ib); file != "" {
		base.Fatalf("%s keeps its accounts in %q; that file, not the config, is what the inbound loads. Use -s, or edit the file and restart", inboundLabel(ib), file)
	}
	users, err := usersOf(ib)
	must(err)
	for _, u := range users {
		if userName(u) != name {
			continue
		}
		m, _ := u.(map[string]any)
		if limit == nil {
			delete(m, "maxSessionsPerUser")
			must(saveConfig(*limitConfig, doc))
			fmt.Printf("removed the max-sessions override of %q in %s; the group's limit applies again; takes effect on the next start\n", name, inboundLabel(ib))
		} else {
			m["maxSessionsPerUser"] = *limit
			must(saveConfig(*limitConfig, doc))
			fmt.Printf("set max sessions per user of %q in %s to %d; takes effect on the next start\n", name, inboundLabel(ib), *limit)
		}
		return
	}
	base.Fatalf("user %q not found", name)
}

// parseLimit maps the CLI word to the bound: a number forces the account's
// own bound (0 lifts it, unlimited), inherit leaves it to the group's bound.
func parseLimit(arg string) (*uint32, error) {
	switch strings.ToLower(arg) {
	case "inherit", "unset", "group":
		return nil, nil
	}
	v, err := strconv.ParseUint(arg, 10, 32)
	if err != nil {
		return nil, err
	}
	limit := uint32(v)
	return &limit, nil
}

// parseL3 maps the CLI word to the tri-state flag: on and off force the
// relay, inherit leaves it to the group's l3 flag.
func parseL3(arg string) (*bool, error) {
	switch strings.ToLower(arg) {
	case "on", "true", "1":
		v := true
		return &v, nil
	case "off", "false", "0":
		v := false
		return &v, nil
	case "inherit", "unset", "group":
		return nil, nil
	}
	return nil, errors.New("expected on, off or inherit")
}

func executeL3(cmd *base.Command, args []string) {
	if len(args) != 2 {
		cmd.Usage()
	}
	name, arg := args[0], args[1]
	if name == "" {
		base.Fatalf("user name must not be empty")
	}
	l3, err := parseL3(arg)
	if err != nil {
		base.Fatalf("l3 must be on, off or inherit: %v", err)
	}

	if *l3Server != "" {
		onlineL3(*l3Server, *l3Inbound, name, l3)
		return
	}

	doc, err := loadConfig(*l3Config)
	must(err)
	ib, err := findInbound(doc, *l3Inbound)
	must(err)
	if file := usersFileOf(ib); file != "" {
		base.Fatalf("%s keeps its accounts in %q; that file, not the config, is what the inbound loads. Use -s, or edit the file and restart", inboundLabel(ib), file)
	}
	users, err := usersOf(ib)
	must(err)
	for _, u := range users {
		if userName(u) != name {
			continue
		}
		m, _ := u.(map[string]any)
		if l3 == nil {
			delete(m, "l3")
		} else {
			m["l3"] = *l3
		}
		must(saveConfig(*l3Config, doc))
		fmt.Printf("set l3 of %q in %s to %s; takes effect on the next start\n", name, inboundLabel(ib), oc.L3Label(l3))
		return
	}
	base.Fatalf("user %q not found", name)
}

func executeDisconnect(cmd *base.Command, args []string) {
	if len(args) != 1 {
		cmd.Usage()
	}
	name := args[0]
	if name == "" {
		base.Fatalf("user name must not be empty")
	}
	// Live sessions only exist in a running process; there is no config file
	// to edit for this one.
	if *disconnectServer == "" {
		base.Fatalf("-s is required: disconnecting only makes sense against a running process")
	}
	onlineDisconnect(*disconnectServer, *disconnectInbound, name)
}

// usersFileOf returns the overlay file an inbound keeps its accounts in, if it
// names one.
func usersFileOf(ib map[string]any) string {
	settings, ok := ib["settings"].(map[string]any)
	if !ok {
		return ""
	}
	file, _ := settings["usersFile"].(string)
	return file
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
