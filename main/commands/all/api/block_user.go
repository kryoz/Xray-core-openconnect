package api

import (
	"fmt"

	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	cserial "github.com/xtls/xray-core/common/serial"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdBlockUser = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api bu [--server=127.0.0.1:8080] -tag=tag [-unblock] <email1> [email2]...",
	Short:       "Block or unblock users of inbounds",
	Long: `
Block or unblock users of an inbound.

A blocked account is kept, not deleted: it stops authenticating, loses the
sessions it has up right now, and cannot resume on a session cookie it holds.
Its credential and its stats key stay in place, so unblocking restores exactly
the account that was suspended.

Arguments:
	-s, -server
		The API server address. Default 127.0.0.1:8080
	-t, -timeout
		Timeout seconds to call API. Default 3
	-tag
		Inbound tag
	-unblock
		Restore a blocked user instead of blocking it
Example:
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -tag="vless-in" "xray@love.com"
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -tag="vless-in" -unblock "xray@love.com"
`,
	Run: executeBlockUser,
}

func executeBlockUser(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	var tag string
	var unblock bool
	cmd.Flag.StringVar(&tag, "tag", "", "")
	cmd.Flag.BoolVar(&unblock, "unblock", false, "")
	cmd.Flag.Parse(args)
	emails := cmd.Flag.Args()
	if len(tag) < 1 {
		base.Fatalf("inbound tag not specified")
	}
	if len(emails) < 1 {
		base.Fatalf("no user specified")
	}

	conn, ctx, close := dialAPIServer()
	defer close()
	client := handlerService.NewHandlerServiceClient(conn)

	action, done := "block", "Blocked"
	if unblock {
		action, done = "unblock", "Unblocked"
	}

	success := 0
	for _, email := range emails {
		fmt.Println(action+" user:", email)
		_, err := client.AlterInbound(ctx, &handlerService.AlterInboundRequest{
			Tag: tag,
			Operation: cserial.ToTypedMessage(
				&handlerService.BlockUserOperation{
					Email:   email,
					Blocked: !unblock,
				},
			),
		})
		if err == nil {
			success += 1
		} else {
			fmt.Println(err)
		}
	}
	fmt.Println(done, success, "user(s) in total.")
}
