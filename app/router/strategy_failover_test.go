package router

import (
	"context"
	"sync"
	"testing"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/features/extension"
	"google.golang.org/protobuf/proto"
)

type fakeObservatory struct {
	mu     sync.Mutex
	status []*observatory.OutboundStatus
}

func (f *fakeObservatory) GetObservation(ctx context.Context) (proto.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]*observatory.OutboundStatus, len(f.status))
	for i, s := range f.status {
		cp[i] = &observatory.OutboundStatus{
			OutboundTag: s.OutboundTag,
			Alive:       s.Alive,
			FailStreak:  s.FailStreak,
		}
	}
	return &observatory.ObservationResult{Status: cp}, nil
}

func (f *fakeObservatory) Type() interface{} {
	return extension.ObservatoryType()
}

func (f *fakeObservatory) Start() error { return nil }

func (f *fakeObservatory) Close() error { return nil }

func (f *fakeObservatory) set(tag string, alive bool, failStreak int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.status {
		if s.OutboundTag == tag {
			s.Alive = alive
			s.FailStreak = failStreak
			return
		}
	}
	f.status = append(f.status, &observatory.OutboundStatus{OutboundTag: tag, Alive: alive, FailStreak: failStreak})
}

// candidatesAlphabetical mimics outbound.Manager.Select output, which is
// sorted alphabetically regardless of selector order.
var candidatesAlphabetical = []string{"backup", "primary"}

func TestFailoverOrdering(t *testing.T) {
	fake := &fakeObservatory{}
	s := NewFailoverStrategy([]string{"primary", "backup"}, nil)
	s.observatory = fake
	fake.set("primary", true, 0)
	fake.set("backup", true, 0)
	if got := s.PickOutbound(candidatesAlphabetical); got != "primary" {
		t.Fatalf("want primary (selector order), got %q", got)
	}
}

func TestFailoverStickyFailoverFailback(t *testing.T) {
	fake := &fakeObservatory{}
	s := NewFailoverStrategy([]string{"primary", "backup"}, nil) // threshold = 2
	s.observatory = fake

	fake.set("primary", true, 0)
	fake.set("backup", true, 0)
	if got := s.PickOutbound(candidatesAlphabetical); got != "primary" {
		t.Fatalf("sticky: want primary, got %q", got)
	}

	// one failed probe: below threshold, still primary
	fake.set("primary", false, 1)
	if got := s.PickOutbound(candidatesAlphabetical); got != "primary" {
		t.Fatalf("hysteresis: want primary after 1 failed probe, got %q", got)
	}

	// second consecutive failed probe: fail over
	fake.set("primary", false, 2)
	if got := s.PickOutbound(candidatesAlphabetical); got != "backup" {
		t.Fatalf("failover: want backup after 2 failed probes, got %q", got)
	}

	// a successful probe resets the streak: fail back
	fake.set("primary", true, 0)
	if got := s.PickOutbound(candidatesAlphabetical); got != "primary" {
		t.Fatalf("failback: want primary after successful probe, got %q", got)
	}

	// one failed probe after success: still primary
	fake.set("primary", false, 1)
	if got := s.PickOutbound(candidatesAlphabetical); got != "primary" {
		t.Fatalf("streak reset: want primary after 1 failed probe following success, got %q", got)
	}
}

func TestFailoverThresholdSetting(t *testing.T) {
	fake := &fakeObservatory{}
	s := NewFailoverStrategy([]string{"primary", "backup"}, &StrategyFailoverConfig{FailThreshold: 3})
	s.observatory = fake

	fake.set("primary", true, 0)
	fake.set("backup", true, 0)

	fake.set("primary", false, 2)
	if got := s.PickOutbound(candidatesAlphabetical); got != "primary" {
		t.Fatalf("threshold 3: want primary after 2 failed probes, got %q", got)
	}
	fake.set("primary", false, 3)
	if got := s.PickOutbound(candidatesAlphabetical); got != "backup" {
		t.Fatalf("threshold 3: want backup after 3 failed probes, got %q", got)
	}
}

func TestFailoverAllDown(t *testing.T) {
	fake := &fakeObservatory{}
	s := NewFailoverStrategy([]string{"primary", "backup"}, nil)
	s.observatory = fake

	fake.set("primary", false, 2)
	fake.set("backup", false, 2)
	if got := s.PickOutbound(candidatesAlphabetical); got != "" {
		t.Fatalf("want empty tag (routes to fallbackTag), got %q", got)
	}
}

func TestFailoverUnobservedTagIsUp(t *testing.T) {
	fake := &fakeObservatory{}
	s := NewFailoverStrategy([]string{"primary", "backup"}, nil)
	s.observatory = fake
	// no observation data at all
	if got := s.PickOutbound(candidatesAlphabetical); got != "primary" {
		t.Fatalf("want first selector when unobserved, got %q", got)
	}
}

func TestFailoverNoObservatory(t *testing.T) {
	s := NewFailoverStrategy([]string{"primary", "backup"}, nil)
	if got := s.PickOutbound(candidatesAlphabetical); got != "primary" {
		t.Fatalf("without observatory want first selector, got %q", got)
	}
}

func TestFailoverConcurrent(t *testing.T) {
	fake := &fakeObservatory{}
	s := NewFailoverStrategy([]string{"primary", "backup"}, nil)
	s.observatory = fake
	fake.set("primary", true, 0)
	fake.set("backup", true, 0)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = s.PickOutbound(candidatesAlphabetical)
				fake.set("primary", j%2 == 0, int64(j%3))
			}
		}()
	}
	wg.Wait()
}
