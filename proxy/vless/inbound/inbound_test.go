package inbound

import (
	"context"
	stdnet "net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
)

type testPolicyManager struct{}

func (testPolicyManager) Type() interface{}              { return policy.ManagerType() }
func (testPolicyManager) Start() error                   { return nil }
func (testPolicyManager) Close() error                   { return nil }
func (testPolicyManager) ForLevel(uint32) policy.Session { return policy.SessionDefault() }
func (testPolicyManager) ForSystem() policy.System       { return policy.System{} }

// testDispatcher blocks in DispatchLink while block is open, so a dispatched
// flow stays "live" (holding its session slot) until the test closes it.
type testDispatcher struct {
	mu     sync.Mutex
	active int
	block  chan struct{}
}

func (d *testDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *testDispatcher) Start() error      { return nil }
func (d *testDispatcher) Close() error      { return nil }

func (d *testDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	return nil, errors.New("not implemented in test")
}

func (d *testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	d.mu.Lock()
	d.active++
	block := d.block
	d.mu.Unlock()
	if block != nil {
		<-block
	}
	d.mu.Lock()
	d.active--
	d.mu.Unlock()
	return nil
}

func (d *testDispatcher) activeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active
}

func waitActive(t *testing.T, d *testDispatcher, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := d.activeCount(); got == want {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("dispatcher active flows = %d, want %d", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testVLessUser(email string) *protocol.MemoryUser {
	user := &protocol.MemoryUser{Level: 0, Email: email}
	user.Account = &vless.MemoryAccount{ID: protocol.NewID(uuid.New())}
	return user
}

// startVLessFlow runs h.Process for one fresh pipe endpoint carrying a valid
// VLESS request header of user, and returns a channel closed with Process's
// error. The client end writes the header, then drains the server's replies
// for as long as the pipe is open.
func startVLessFlow(t *testing.T, h *Handler, disp routing.Dispatcher, user *protocol.MemoryUser) <-chan error {
	t.Helper()
	client, server := stdnet.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })

	header := buf.StackNew()
	req := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    user,
		Command: protocol.RequestCommandTCP,
		Address: xnet.IPAddress(stdnet.ParseIP("1.2.3.4").To4()),
		Port:    xnet.Port(80),
	}
	if err := encoding.EncodeRequestHeader(&header, req, &encoding.Addons{}); err != nil {
		t.Fatalf("encode header: %v", err)
	}
	go func() {
		_, _ = client.Write(header.Bytes())
		b := make([]byte, 4096)
		for {
			if _, err := client.Read(b); err != nil {
				return
			}
		}
	}()

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.TCPDestination(xnet.IPAddress(stdnet.ParseIP("127.0.0.1").To4()), 12345),
		Tag:    "vless-test",
	})
	done := make(chan error, 1)
	go func() { done <- h.Process(ctx, xnet.Network_TCP, server, disp) }()
	return done
}

func TestUserSessionLimiter(t *testing.T) {
	t.Run("respects limit and frees slots", func(t *testing.T) {
		l := newUserSessionLimiter(2)
		if !l.tryAcquire("a@test") {
			t.Fatal("first acquire must succeed")
		}
		if !l.tryAcquire("a@test") {
			t.Fatal("second acquire must succeed")
		}
		if l.tryAcquire("a@test") {
			t.Fatal("third acquire of the same account must fail")
		}
		if !l.tryAcquire("b@test") {
			t.Fatal("other accounts must not share the limit")
		}
		l.release("a@test")
		if !l.tryAcquire("a@test") {
			t.Fatal("released slot must be reacquirable")
		}
		if len(l.live) != 2 {
			t.Fatalf("live entries = %d, want 2", len(l.live))
		}
	})
	t.Run("unlimited when max is zero", func(t *testing.T) {
		l := newUserSessionLimiter(0)
		for i := 0; i < 100; i++ {
			if !l.tryAcquire("a@test") {
				t.Fatalf("acquire %d must succeed with no limit", i)
			}
		}
	})
	t.Run("release without acquire is a no-op", func(t *testing.T) {
		l := newUserSessionLimiter(1)
		l.release("ghost@test")
		if len(l.live) != 0 {
			t.Fatalf("live entries = %d, want 0", len(l.live))
		}
	})
	t.Run("concurrent acquire/release leaks nothing", func(t *testing.T) {
		l := newUserSessionLimiter(4)
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					if l.tryAcquire("u@test") {
						l.release("u@test")
					}
				}
			}()
		}
		wg.Wait()
		if len(l.live) != 0 {
			t.Fatalf("leftover slots: %v", l.live)
		}
	})
}

// TestProcessMaxSessionsPerUser exercises the limit through Handler.Process:
// a second live flow of the same account is rejected before dispatch, other
// accounts keep getting in, and a freed slot admits the same account again.
func TestProcessMaxSessionsPerUser(t *testing.T) {
	alice := testVLessUser("alice@test")
	bob := testVLessUser("bob@test")
	validator := new(vless.MemoryValidator)
	common.Must(validator.Add(alice))
	common.Must(validator.Add(bob))

	h := &Handler{
		policyManager: testPolicyManager{},
		validator:     validator,
		sessions:      newUserSessionLimiter(1),
	}
	disp := &testDispatcher{block: make(chan struct{})}

	// Flow 1 (alice) acquires the only slot and stays live in the dispatcher.
	flow1 := startVLessFlow(t, h, disp, alice)
	waitActive(t, disp, 1)

	// Flow 2 (same account) is rejected before dispatch: the connection is
	// closed, which is the only refusal a VLESS client can see.
	flow2 := startVLessFlow(t, h, disp, alice)
	err2 := <-flow2
	if err2 == nil || !strings.Contains(err2.Error(), "max sessions per user reached") {
		t.Fatalf("rejected flow error = %v, want the max-sessions error", err2)
	}

	// Flow 3 (another account) is unaffected by alice's limit.
	flow3 := startVLessFlow(t, h, disp, bob)
	waitActive(t, disp, 2)

	// Flow 1 ends: alice's slot frees and the next flow of hers passes.
	close(disp.block)
	if err1 := <-flow1; err1 != nil {
		t.Fatalf("flow 1: %v", err1)
	}
	if err4 := <-startVLessFlow(t, h, disp, alice); err4 != nil {
		t.Fatalf("alice after her slot freed: %v", err4)
	}
	<-flow3
}
