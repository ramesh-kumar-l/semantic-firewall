package ratelimit_test

import (
	"testing"
	"time"

	"github.com/ramesh152/semantic-firewall/internal/ratelimit"
)

func TestLimiter_AllowWithinBurst(t *testing.T) {
	l := ratelimit.New(1000.0, 5, 0) // high rate, burst 5
	defer l.Stop()
	for i := 0; i < 5; i++ {
		if !l.Allow("key") {
			t.Errorf("request %d should be allowed (within burst)", i+1)
		}
	}
}

func TestLimiter_DenyOverBurst(t *testing.T) {
	l := ratelimit.New(0.001, 1, 0) // near-zero rate, burst 1
	defer l.Stop()
	l.Allow("key") // consume the burst
	if l.Allow("key") {
		t.Error("second request should be denied (burst exhausted)")
	}
}

func TestLimiter_DifferentKeysAreIndependent(t *testing.T) {
	l := ratelimit.New(0.001, 1, 0) // near-zero rate, burst 1 each
	defer l.Stop()
	if !l.Allow("key1") {
		t.Error("key1 first request should be allowed")
	}
	if !l.Allow("key2") {
		t.Error("key2 should have its own burst (independent of key1)")
	}
}

func TestLimiter_StopIdempotent(t *testing.T) {
	l := ratelimit.New(10.0, 10, time.Second)
	l.Stop()
	l.Stop() // must not panic
}

func TestLimiter_StopSafeWithNoTTL(t *testing.T) {
	l := ratelimit.New(10.0, 10, 0) // no TTL — no cleanup goroutine
	l.Stop()                         // must not panic
	l.Stop()
}

func TestLimiter_AllowAfterStop(t *testing.T) {
	l := ratelimit.New(1000.0, 10, time.Second)
	l.Stop()
	// Allow should still work after Stop (Stop only halts cleanup goroutine).
	if !l.Allow("key") {
		t.Error("Allow should still work after Stop")
	}
}
