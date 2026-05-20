package session_test

import (
	"testing"
	"time"

	"github.com/ramesh152/semantic-firewall/internal/session"
	"github.com/ramesh152/semantic-firewall/pkg/types"
)

func TestStore_GetUnknown(t *testing.T) {
	s := session.New(0)
	defer s.Stop()
	if s.Get("nonexistent") != nil {
		t.Error("want nil for unknown session ID")
	}
}

func TestStore_UpdateAndGet(t *testing.T) {
	s := session.New(0)
	defer s.Stop()
	s.Update("sess1", 0.7, nil)
	rec := s.Get("sess1")
	if rec == nil {
		t.Fatal("want record after Update, got nil")
	}
	if rec.TurnCount != 1 {
		t.Errorf("want TurnCount=1, got %d", rec.TurnCount)
	}
	if rec.MaxRisk != 0.7 {
		t.Errorf("want MaxRisk=0.7, got %f", rec.MaxRisk)
	}
}

func TestStore_TurnCountIncrements(t *testing.T) {
	s := session.New(0)
	defer s.Stop()
	s.Update("sess2", 0.1, nil)
	s.Update("sess2", 0.2, nil)
	s.Update("sess2", 0.3, nil)
	rec := s.Get("sess2")
	if rec.TurnCount != 3 {
		t.Errorf("want TurnCount=3, got %d", rec.TurnCount)
	}
}

func TestStore_MaxRiskOnlyIncreases(t *testing.T) {
	s := session.New(0)
	defer s.Stop()
	s.Update("sess3", 0.8, nil)
	s.Update("sess3", 0.3, nil) // lower risk — should not overwrite
	rec := s.Get("sess3")
	if rec.MaxRisk != 0.8 {
		t.Errorf("want MaxRisk=0.8 (max), got %f", rec.MaxRisk)
	}
}

func TestStore_GetReturnsIndependentCopy(t *testing.T) {
	s := session.New(0)
	defer s.Stop()
	s.Update("sess4", 0.5, nil)
	rec1 := s.Get("sess4")
	s.Update("sess4", 0.9, nil)
	rec2 := s.Get("sess4")
	// rec1 should not be mutated by the second update
	if rec1.MaxRisk != 0.5 {
		t.Errorf("Get must return a copy; rec1.MaxRisk should still be 0.5, got %f", rec1.MaxRisk)
	}
	if rec2.MaxRisk != 0.9 {
		t.Errorf("want rec2.MaxRisk=0.9, got %f", rec2.MaxRisk)
	}
}

func TestStore_TTLEviction(t *testing.T) {
	ttl := 50 * time.Millisecond
	s := session.New(ttl)
	defer s.Stop()
	s.Update("evict-me", 0.5, nil)
	// Wait for longer than TTL + one cleanup sweep (ttl/2 interval)
	time.Sleep(ttl * 3)
	if rec := s.Get("evict-me"); rec != nil {
		t.Errorf("session should have been evicted after TTL, got %+v", rec)
	}
}

func TestStore_StopIdempotent(t *testing.T) {
	s := session.New(time.Second)
	s.Stop()
	s.Stop() // must not panic
}

func TestStore_FindingsParamIgnored(t *testing.T) {
	// Update accepts findings but doesn't crash when nil or non-nil
	s := session.New(0)
	defer s.Stop()
	findings := []types.Finding{{Type: types.FindingRoleOverride, Severity: types.SeverityHigh}}
	s.Update("sess5", 0.7, findings)
	s.Update("sess5", 0.8, nil)
	rec := s.Get("sess5")
	if rec.TurnCount != 2 {
		t.Errorf("want TurnCount=2, got %d", rec.TurnCount)
	}
}
