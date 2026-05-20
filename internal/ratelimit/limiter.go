package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type entry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// Limiter is a per-key token-bucket rate limiter with optional TTL eviction.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	rps     float64
	burst   int
	ttl     time.Duration
	done    chan struct{}
}

// New creates a Limiter. ttl > 0 starts a background cleanup goroutine that
// evicts entries idle for longer than ttl; call Stop() on shutdown.
func New(rps float64, burst int, ttl time.Duration) *Limiter {
	l := &Limiter{
		entries: make(map[string]*entry),
		rps:     rps,
		burst:   burst,
		ttl:     ttl,
		done:    make(chan struct{}),
	}
	if ttl > 0 {
		go l.cleanup()
	}
	return l
}

// Allow reports whether the given key is within its rate limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	e, ok := l.entries[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(rate.Limit(l.rps), l.burst)}
		l.entries[key] = e
	}
	e.lastSeen = time.Now()
	lim := e.lim
	l.mu.Unlock()
	return lim.Allow()
}

// Stop halts the background cleanup goroutine. Safe to call when TTL == 0.
func (l *Limiter) Stop() {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(l.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-l.ttl)
			l.mu.Lock()
			for key, e := range l.entries {
				if e.lastSeen.Before(cutoff) {
					delete(l.entries, key)
				}
			}
			l.mu.Unlock()
		case <-l.done:
			return
		}
	}
}
