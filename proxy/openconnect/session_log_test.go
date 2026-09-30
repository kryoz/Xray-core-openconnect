package openconnect

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// sessionLogLine pins the field set of the session-lifecycle records. During the
// 2026-09-30 networp incident the fork logged session starts only for clients
// whose address was allocated dynamically, and nothing at all for the end of a
// session — an operator could not tell when (or whether) a client had a session
// at all. These lines are now the answer to "was that user connected at 15:31?",
// so their fields are contract, not cosmetics.
func TestSessionLogLines(t *testing.T) {
	created := time.Date(2026, 9, 30, 15, 27, 40, 0, time.UTC)
	sess := &ocSession{
		user:     &User{Name: "vovan-router", Ip: "172.16.10.198", Group: "splitroute"},
		ip:       netip.MustParseAddr("172.16.10.198"),
		clientIP: "203.0.113.7",
		appID:    "deadbeef",
		created:  created,
	}

	start := sess.sessionStartLine(false)
	for _, want := range []string{
		"session start",
		"user=vovan-router",
		"ip=172.16.10.198",
		"peer=203.0.113.7",
		"group=splitroute",
		"static=true",
		"l3=false",
		"dtls=false",
		"appID=deadbeef",
	} {
		if !strings.Contains(start, want) {
			t.Errorf("session start line %q missing %q", start, want)
		}
	}

	closed := sess.tunnelClosedLine("client closed TCP (EOF)", created.Add(time.Minute), created.Add(6*time.Minute+5*time.Second))
	for _, want := range []string{
		"tunnel closed",
		"user=vovan-router",
		"peer=203.0.113.7",
		"tunnel=5m5s",
		"session=6m5s",
		"reason=client closed TCP (EOF)",
	} {
		if !strings.Contains(closed, want) {
			t.Errorf("tunnel closed line %q missing %q", closed, want)
		}
	}

	end := sess.sessionEndLine("cookie/resume window expired", created.Add(7*time.Minute))
	for _, want := range []string{
		"session end",
		"user=vovan-router",
		"duration=7m0s",
		"static=true",
		"reason=cookie/resume window expired",
	} {
		if !strings.Contains(end, want) {
			t.Errorf("session end line %q missing %q", end, want)
		}
	}
}

// TestSessionLogLinesAnonymous covers a session without a user object (or with
// an empty group): the line must stay parseable instead of dropping fields.
func TestSessionLogLinesAnonymous(t *testing.T) {
	sess := &ocSession{ip: netip.MustParseAddr("172.16.10.10"), created: time.Now()}

	start := sess.sessionStartLine(true)
	for _, want := range []string{"user=-", "group=-", "static=false", "dtls=true"} {
		if !strings.Contains(start, want) {
			t.Errorf("anonymous session start line %q missing %q", start, want)
		}
	}
}

// TestMarkEndedOnce checks the reaping paths cannot double-log: both
// registry.remove and the GC sweep can reach the same session.
func TestMarkEndedOnce(t *testing.T) {
	sess := &ocSession{ip: netip.MustParseAddr("172.16.10.10"), created: time.Now()}

	if !sess.markEnded() {
		t.Fatal("first markEnded must report the session as closed")
	}
	for i := 0; i < 3; i++ {
		if sess.markEnded() {
			t.Fatal("markEnded reported a second close of the same session")
		}
	}
}
