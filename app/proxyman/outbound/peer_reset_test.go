package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	xerrors "github.com/xtls/xray-core/common/errors"
)

func TestPeerReset(t *testing.T) {
	// The chain freedom builds for a peer RST mid-stream: buf.Copy fails with a
	// *net.OpError, each layer wraps it with errors.New(...).Base(err).
	rstChain := xerrors.New("connection ends").Base(
		xerrors.New("failed to process request").Base(
			&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}))

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil cause", nil, false},
		{"freedom RST chain", xerrors.Cause(rstChain), true},
		{"bare ECONNABORTED", syscall.ECONNABORTED, true},
		{"EOF is filtered before this point", io.EOF, false},
		{"canceled", context.Canceled, false},
		{"dial failure stays reportable", errors.New("connection refused"), false},
	}
	for _, c := range cases {
		if got := peerReset(c.err); got != c.want {
			t.Errorf("%s: peerReset(%v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}
