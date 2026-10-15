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

// testDispatcher keeps a dispatched flow alive instead of serving it: it
// blocks while block is open, or drains the link until the connection breaks
// when drain is set. Either way the flow stays "live" — holding its session
// slot and its entry in the flow registry — until the connection ends.
type testDispatcher struct {
	mu     sync.Mutex
	active int
	block  chan struct{}
	// drain holds the link until its connection breaks, which is how a test
	// sees a flow that an operator block or removal has cut.
	drain bool
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
	if d.drain {
		_ = buf.Copy(link.Reader, buf.Discard)
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

// testCloser stands in for a connection the flow registry is asked to cut.
type testCloser struct {
	mu sync.Mutex
	n  int
}

func (c *testCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil
}

func (c *testCloser) closed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func TestFlowRegistry(t *testing.T) {
	up := func() bool { return true }
	down := func() bool { return false }

	t.Run("closeAll cuts the account and nothing else", func(t *testing.T) {
		var r flowRegistry
		alice := []*testCloser{{}, {}, {}}
		for _, conn := range alice {
			if _, ok := r.add("alice@test", conn, up); !ok {
				t.Fatal("an enabled account must be admitted")
			}
		}
		bob := &testCloser{}
		r.add("bob@test", bob, up)

		if n := r.closeAll("alice@test"); n != 3 {
			t.Fatalf("closeAll closed %d, want 3", n)
		}
		for i, conn := range alice {
			if got := conn.closed(); got != 1 {
				t.Fatalf("flow %d closed %d times, want 1", i+1, got)
			}
		}
		if bob.closed() != 0 {
			t.Fatal("another account must not be touched")
		}
		if n := r.closeAll("alice@test"); n != 0 {
			t.Fatalf("a second closeAll closed %d, want 0", n)
		}
	})

	t.Run("remove unregisters exactly one flow", func(t *testing.T) {
		var r flowRegistry
		first, second := &testCloser{}, &testCloser{}
		removeFirst, _ := r.add("a@test", first, up)
		removeSecond, _ := r.add("a@test", second, up)

		removeFirst()
		if n := r.closeAll("a@test"); n != 1 {
			t.Fatalf("closeAll closed %d, want 1", n)
		}
		if first.closed() != 0 {
			t.Fatal("the flow that unregistered itself must not be closed")
		}
		if second.closed() != 1 {
			t.Fatal("the live flow must be closed")
		}
		// The flow ends on its own after closeAll already dropped it.
		removeSecond()
	})

	t.Run("a flow ending late keeps a newer one registered", func(t *testing.T) {
		var r flowRegistry
		stale, fresh := &testCloser{}, &testCloser{}
		removeStale, _ := r.add("a@test", stale, up)
		r.closeAll("a@test")
		removeFresh, _ := r.add("a@test", fresh, up)

		removeStale()
		if n := r.closeAll("a@test"); n != 1 {
			t.Fatalf("closeAll closed %d, want 1: the newer flow must still be tracked", n)
		}
		if fresh.closed() != 1 {
			t.Fatal("the newer flow must be closed")
		}
		removeFresh()
	})

	t.Run("another case of the email still reaches the flows", func(t *testing.T) {
		var r flowRegistry
		conn := &testCloser{}
		if _, ok := r.add("Alice@Test", conn, up); !ok {
			t.Fatal("an enabled account must be admitted")
		}
		if n := r.closeAll("alice@test"); n != 1 {
			t.Fatalf("closeAll closed %d, want 1", n)
		}
		if conn.closed() != 1 {
			t.Fatal("the flow of the differently typed email must be closed")
		}
	})

	t.Run("an account that went away is not admitted", func(t *testing.T) {
		var r flowRegistry
		conn := &testCloser{}
		remove, ok := r.add("alice@test", conn, down)
		if ok {
			t.Fatal("a blocked account must not be admitted")
		}
		if remove != nil {
			t.Fatal("a refused flow gets nothing to unregister")
		}
		if n := r.closeAll("alice@test"); n != 0 {
			t.Fatalf("closeAll closed %d, want 0", n)
		}
	})

	t.Run("a user without an email is not tracked", func(t *testing.T) {
		var r flowRegistry
		conn := &testCloser{}
		remove, ok := r.add("", conn, down)
		if !ok {
			t.Fatal("a user without an email has no operator action to wait for")
		}
		remove()
		if conn.closed() != 0 {
			t.Fatal("nothing may be closed here")
		}
	})

	t.Run("closeAll racing with flows that end", func(t *testing.T) {
		var r flowRegistry
		done := make(chan struct{})
		go func() {
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < 50; j++ {
						remove, ok := r.add("a@test", &testCloser{}, up)
						if !ok {
							continue
						}
						if j%2 == 0 {
							remove()
						} else {
							r.closeAll("a@test")
						}
					}
				}()
			}
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("closeAll deadlocked against a flow unregistering itself")
		}
	})
}

// TestMemoryValidatorUserAPI walks the validator through the operations the
// user API performs on it, in the order an operator would do them.
func TestMemoryValidatorUserAPI(t *testing.T) {
	alice := testVLessUser("alice@test")
	aliceAgain := testVLessUser("alice@test")
	aliceID := alice.Account.(*vless.MemoryAccount).ID.UUID()

	steps := []struct {
		name    string
		op      func(v *vless.MemoryValidator) error
		wantErr string
		canAuth bool
	}{
		{name: "add", op: func(v *vless.MemoryValidator) error { return v.Add(alice) }, canAuth: true},
		{name: "duplicate email is refused", op: func(v *vless.MemoryValidator) error { return v.Add(aliceAgain) }, wantErr: "already exists", canAuth: true},
		{name: "block", op: func(v *vless.MemoryValidator) error { return v.SetBlocked("alice@test", true) }, canAuth: false},
		{name: "block again", op: func(v *vless.MemoryValidator) error { return v.SetBlocked("ALICE@test", true) }, canAuth: false},
		{name: "empty email", op: func(v *vless.MemoryValidator) error { return v.SetBlocked("", true) }, wantErr: "Email must not be empty", canAuth: false},
		{name: "unknown email", op: func(v *vless.MemoryValidator) error { return v.SetBlocked("ghost@test", true) }, wantErr: "not found", canAuth: false},
		{name: "unblock", op: func(v *vless.MemoryValidator) error { return v.SetBlocked("alice@test", false) }, canAuth: true},
		{name: "remove", op: func(v *vless.MemoryValidator) error { return v.Del("alice@test") }, canAuth: false},
		{name: "remove again", op: func(v *vless.MemoryValidator) error { return v.Del("alice@test") }, wantErr: "not found", canAuth: false},
	}

	validator := new(vless.MemoryValidator)
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			err := step.op(validator)
			switch {
			case step.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case step.wantErr != "" && (err == nil || !strings.Contains(err.Error(), step.wantErr)):
				t.Fatalf("err = %v, want %q", err, step.wantErr)
			}
			if got := validator.Get(aliceID) != nil; got != step.canAuth {
				t.Fatalf("account authenticates = %v, want %v", got, step.canAuth)
			}
		})
	}

	t.Run("a blocked account stays visible to the user API", func(t *testing.T) {
		validator := new(vless.MemoryValidator)
		common.Must(validator.Add(testVLessUser("bob@test")))
		common.Must(validator.SetBlocked("bob@test", true))

		u := validator.GetByEmail("bob@test")
		if u == nil || !u.Disabled {
			t.Fatal("GetByEmail must return the suspended account as blocked")
		}
		if len(validator.GetAll()) != 1 || validator.GetCount() != 1 {
			t.Fatal("the suspended account must still be listed and counted")
		}
	})
}

// waitDone fails unless the flow ends, which is what cutting it has to cause.
func waitDone(t *testing.T, name string, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s is still live, want it cut", name)
	}
}

func testVLessHandler(validator vless.Validator) *Handler {
	return &Handler{
		policyManager: testPolicyManager{},
		validator:     validator,
		sessions:      newUserSessionLimiter(0),
	}
}

// TestProcessSetUserBlocked blocks an account that has live flows: they are
// cut, its next connection is refused the way an unknown UUID is, another
// account is left alone, and restoring it lets the account in again.
func TestProcessSetUserBlocked(t *testing.T) {
	ctx := context.Background()
	// The account is spelled differently from the operator's email on purpose:
	// both sides have to meet in the middle.
	alice := testVLessUser("Alice@Test")
	bob := testVLessUser("bob@test")
	validator := new(vless.MemoryValidator)
	common.Must(validator.Add(alice))
	common.Must(validator.Add(bob))

	h := testVLessHandler(validator)
	disp := &testDispatcher{drain: true}

	alice1 := startVLessFlow(t, h, disp, alice)
	alice2 := startVLessFlow(t, h, disp, alice)
	alice3 := startVLessFlow(t, h, disp, alice)
	startVLessFlow(t, h, disp, bob) // another account must stay up
	waitActive(t, disp, 4)

	if err := h.SetUserBlocked(ctx, "alice@test", true); err != nil {
		t.Fatalf("block: %v", err)
	}
	waitDone(t, "alice flow 1", alice1)
	waitDone(t, "alice flow 2", alice2)
	waitDone(t, "alice flow 3", alice3)
	waitActive(t, disp, 1)

	if validator.Get(alice.Account.(*vless.MemoryAccount).ID.UUID()) != nil {
		t.Fatal("a blocked account must not authenticate")
	}
	if u := h.GetUser(ctx, "alice@test"); u == nil || !u.Disabled {
		t.Fatal("the user API must still show the suspended account as blocked")
	}

	// A new flow of a blocked account is refused the way an unknown UUID is.
	if err := <-startVLessFlow(t, h, disp, alice); err == nil || !strings.Contains(err.Error(), "invalid request user id") {
		t.Fatalf("a blocked account got in: %v", err)
	}

	if err := h.SetUserBlocked(ctx, "ALICE@test", false); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	restored := startVLessFlow(t, h, disp, alice)
	waitActive(t, disp, 2)
	select {
	case err := <-restored:
		t.Fatalf("the restored account was refused: %v", err)
	default:
	}
	if u := h.GetUser(ctx, "alice@test"); u == nil || u.Disabled {
		t.Fatal("the restored account must read as enabled")
	}
}

// TestProcessRemoveUserCutsLiveFlows removes an account that has live flows.
func TestProcessRemoveUserCutsLiveFlows(t *testing.T) {
	ctx := context.Background()
	alice := testVLessUser("alice@test")
	validator := new(vless.MemoryValidator)
	common.Must(validator.Add(alice))

	h := testVLessHandler(validator)
	disp := &testDispatcher{drain: true}

	first := startVLessFlow(t, h, disp, alice)
	second := startVLessFlow(t, h, disp, alice)
	waitActive(t, disp, 2)

	if err := h.RemoveUser(ctx, "ghost@test"); err == nil {
		t.Fatal("removing an unknown account must fail")
	}
	if err := h.RemoveUser(ctx, "alice@test"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	waitDone(t, "first flow", first)
	waitDone(t, "second flow", second)
	waitActive(t, disp, 0)

	if h.GetUser(ctx, "alice@test") != nil {
		t.Fatal("the removed account must be gone from the user API")
	}
}
