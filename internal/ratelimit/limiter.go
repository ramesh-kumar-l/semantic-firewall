package ratelimit

import (
	"sync"

	"golang.org/x/time/rate"
)

// Limiter is a per-key token-bucket rate limiter.
// Keys are typically caller_id values or IP addresses.
type Limiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	rps      float64
	burst    int
}

func New(rps float64, burst int) *Limiter {
	return &Limiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rps,
		burst:    burst,
	}
}

// Allow reports whether the given key is within its rate limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.RLock()
	lim, ok := l.limiters[key]
	l.mu.RUnlock()
	if !ok {
		l.mu.Lock()
		lim, ok = l.limiters[key]
		if !ok {
			lim = rate.NewLimiter(rate.Limit(l.rps), l.burst)
			l.limiters[key] = lim
		}
		l.mu.Unlock()
	}
	return lim.Allow()
}
