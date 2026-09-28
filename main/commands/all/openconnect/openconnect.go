package openconnect

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xtls/xray-core/main/commands/base"
	oc "github.com/xtls/xray-core/proxy/openconnect"
)

// CmdOpenConnect holds all openconnect sub commands
var CmdOpenConnect = &base.Command{
	UsageLine: "{{.Exec}} openconnect",
	Short:     "OpenConnect user management",
	Long: `
{{.Exec}} {{.LongName}} manages users of OpenConnect inbounds.

Passwords are stored salted (SHA-256), so the tool generates the
"salt_hex$hash_hex" credential for you. The config file is edited in
place; note that rewriting removes any comments it contained.
`,
	Commands: []*base.Command{
		cmdHash,
		cmdAdd,
		cmdList,
		cmdPasswd,
		cmdRm,
	},
}

var cmdHash = &base.Command{
	UsageLine: "{{.Exec}} openconnect hash [<password>]",
	Short:     "Generate a salted SHA-256 credential for an OpenConnect password",
	Long: `
{{.Exec}} {{.LongName}} <password>
Prints a "salt_hex$hash_hex" credential for the given password, ready to
paste into the inbound's "users[].password" field. Use "-" to read the
password from stdin.
`,
}

func init() {
	cmdHash.Run = executeHash // break init loop
}

func executeHash(cmd *base.Command, args []string) {
	if len(args) != 1 {
		cmd.Usage()
	}
	password, err := readPassword(args[0])
	if err != nil {
		base.Fatalf("reading password: %v", err)
	}
	cred, err := oc.GenerateCredential(password)
	if err != nil {
		base.Fatalf("%v", err)
	}
	fmt.Println(cred)
}

// readPassword returns the argument as-is, or reads one line from stdin
// when the argument is "-", so passwords can stay out of shell history.
func readPassword(arg string) (string, error) {
	if arg != "-" {
		return arg, nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
