package openconnect

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/main/commands/base"
	oc "github.com/xtls/xray-core/proxy/openconnect"
)

// Online mode: the operations above applied to a running process over the
// commander's gRPC socket, so an account starts or stops working without a
// restart. The socket is not authenticated — reaching it is reaching every
// account of every inbound — so it belongs on loopback or a unix socket.

// apiTimeout bounds one management call, the same budget xray api gives one.
const apiTimeout = 3 * time.Second

// dialAPI connects to the API of a running xray.
func dialAPI(addr string) (*grpc.ClientConn, context.Context, func()) {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		base.Fatalf("failed to dial %s: %v", addr, err)
	}
	return conn, ctx, func() {
		cancel()
		_ = conn.Close()
	}
}

// requireTag: the online commands address one inbound by tag. Offline the tag
// is optional because a config usually holds a single OpenConnect inbound; the
// running process can hold any number of them.
func requireTag(tag, mode string) string {
	if tag == "" {
		base.Fatalf("-in is required with -s (%s)", mode)
	}
	return tag
}

// alter applies one operation to the inbound tag and reports the outcome of
// the named action.
func alter(ctx context.Context, conn *grpc.ClientConn, tag, action, target string, op proto.Message) {
	_, err := handlerService.NewHandlerServiceClient(conn).AlterInbound(ctx, &handlerService.AlterInboundRequest{
		Tag:       tag,
		Operation: cserial.ToTypedMessage(op),
	})
	must(err)
	fmt.Printf("%s user %q in the running inbound %s\n", action, target, tag)
}

func onlineAdd(addr, tag string, u *oc.User) {
	conn, ctx, close := dialAPI(addr)
	defer close()
	// The running inbound validates what the file editor cannot know: the
	// subnet, the route groups, the names and addresses its other accounts
	// already hold.
	alter(ctx, conn, requireTag(tag, "add"), "added", u.Name, &handlerService.AddUserOperation{
		User: oc.ProtocolUserOf(u),
	})
}

func onlineRemove(addr, tag, name string) {
	conn, ctx, close := dialAPI(addr)
	defer close()
	alter(ctx, conn, requireTag(tag, "rm"), "removed", name, &handlerService.RemoveUserOperation{
		Email: name,
	})
}

func onlineBlock(addr, tag, name string, blocked bool) {
	conn, ctx, close := dialAPI(addr)
	defer close()
	action := "blocked"
	if !blocked {
		action = "unblocked"
	}
	alter(ctx, conn, requireTag(tag, "block"), action, name, &handlerService.BlockUserOperation{
		Email:   name,
		Blocked: blocked,
	})
}

func onlineList(addr, tag string) {
	conn, ctx, close := dialAPI(addr)
	defer close()
	resp, err := handlerService.NewHandlerServiceClient(conn).GetInboundUsers(ctx,
		&handlerService.GetInboundUserRequest{Tag: requireTag(tag, "list")})
	must(err)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, pu := range resp.GetUsers() {
		raw, err := pu.GetAccount().GetInstance()
		if err != nil {
			base.Fatalf("inbound %q is not an OpenConnect inbound: %v", tag, err)
		}
		u, ok := raw.(*oc.User)
		if !ok {
			base.Fatalf("inbound %q is not an OpenConnect inbound", tag)
		}
		// The password never arrives: the API masks credentials.
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%t\n",
			tag, pu.GetEmail(), u.GetIp(), u.GetGroup(), u.GetL3(), pu.GetDisabled()); err != nil {
			base.Fatalf("%v", err)
		}
	}
	must(w.Flush())
}
