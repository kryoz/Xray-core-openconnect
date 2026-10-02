package openconnect

import (
	"fmt"
	"testing"
	"time"
)

func TestAuthLimiterBlocksAfterMaxFailures(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < authFailMax-1; i++ {
		if l.recordFailure("1.2.3.4") {
			t.Fatalf("attempt %d reported block before threshold", i+1)
		}
	}
	if !l.recordFailure("1.2.3.4") {
		t.Fatal("attempt at threshold did not report block")
	}
	if !l.blocked("1.2.3.4") {
		t.Fatal("ip not blocked after max failures")
	}
	l.reset("1.2.3.4")
	if l.blocked("1.2.3.4") {
		t.Fatal("ip still blocked after reset")
	}
}

func TestAuthLimiterWindowExpiry(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < authFailMax; i++ {
		l.recordFailure("1.2.3.4")
	}
	l.mu.Lock()
	l.attempts["1.2.3.4"].first = time.Now().Add(-authFailWindow - time.Second)
	l.mu.Unlock()
	if l.blocked("1.2.3.4") {
		t.Fatal("ip still blocked after window expiry")
	}
}

func TestAuthLimiterSweepReapsStaleEntries(t *testing.T) {
	l := newAuthLimiter()
	stale := time.Now().Add(-authFailWindow - time.Second)
	l.mu.Lock()
	for i := 0; i < authFailSweepThreshold+10; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		l.attempts[ip] = &failCount{count: 1, first: stale}
	}
	l.mu.Unlock()
	// 512 calls give ~32 expected sweeps; P(zero) ≈ (15/16)^512 ≈ 1e-14.
	for i := 0; i < 512; i++ {
		l.recordFailure("10.99.99.99")
	}
	l.mu.Lock()
	n := len(l.attempts)
	l.mu.Unlock()
	if n > authFailSweepThreshold {
		t.Fatalf("sweep did not reap stale entries: %d remain", n)
	}
}
