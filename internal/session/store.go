package session

import (
	"sync"
	"time"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

// Record holds aggregated session state across turns.
type Record struct {
	TurnCount int
	MaxRisk   types.RiskScore
	FirstSeen time.Time
	LastSeen  time.Time
}

// Store is a thread-safe in-memory session registry with optional TTL eviction.
type Store struct {
	mu      sync.Mutex
	entries map[string]*Record
	ttl     time.Duration
	done    chan struct{}
}

// New creates a session store. If ttl > 0, a background goroutine evicts idle sessions.
func New(ttl time.Duration) *Store {
	s := &Store{
		entries: make(map[string]*Record),
		ttl:     ttl,
		done:    make(chan struct{}),
	}
	if ttl > 0 {
		go s.cleanup()
	}
	return s
}

// Get returns a copy of the session record for sessionID, or nil if not found.
func (s *Store) Get(sessionID string) *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.entries[sessionID]
	if !ok {
		return nil
	}
	cp := *rec
	return &cp
}

// Update upserts a session record with the outcome of the latest turn.
func (s *Store) Update(sessionID string, risk types.RiskScore, _ []types.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.entries[sessionID]
	if !ok {
		rec = &Record{FirstSeen: time.Now()}
		s.entries[sessionID] = rec
	}
	rec.TurnCount++
	rec.LastSeen = time.Now()
	if risk > rec.MaxRisk {
		rec.MaxRisk = risk
	}
}

// Stop shuts down the background cleanup goroutine. Safe to call multiple times.
func (s *Store) Stop() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func (s *Store) cleanup() {
	ticker := time.NewTicker(s.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-s.ttl)
			s.mu.Lock()
			for id, rec := range s.entries {
				if rec.LastSeen.Before(cutoff) {
					delete(s.entries, id)
				}
			}
			s.mu.Unlock()
		case <-s.done:
			return
		}
	}
}
