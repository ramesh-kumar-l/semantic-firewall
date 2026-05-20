package scoring_test

import (
	"context"
	"testing"

	"github.com/ramesh152/semantic-firewall/internal/scoring"
	"github.com/ramesh152/semantic-firewall/pkg/types"
)

func TestRuleBasedScorer_NoFindings(t *testing.T) {
	s := scoring.NewRuleBasedScorer()
	score, err := s.Score(context.Background(), "hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	if score != 0.0 {
		t.Errorf("want 0.0 for no findings, got %f", score)
	}
}

func TestRuleBasedScorer_EmptyFindings(t *testing.T) {
	s := scoring.NewRuleBasedScorer()
	score, err := s.Score(context.Background(), "hello", []types.Finding{})
	if err != nil {
		t.Fatal(err)
	}
	if score != 0.0 {
		t.Errorf("want 0.0 for empty findings, got %f", score)
	}
}

func TestRuleBasedScorer_CriticalFinding(t *testing.T) {
	s := scoring.NewRuleBasedScorer()
	findings := []types.Finding{{Severity: types.SeverityCritical}}
	score, err := s.Score(context.Background(), "x", findings)
	if err != nil {
		t.Fatal(err)
	}
	// Critical weight = 0.9 → score = 1 - (1-0.9) = 0.9
	if score < 0.85 {
		t.Errorf("want score >= 0.85 for critical finding, got %f", score)
	}
}

func TestRuleBasedScorer_HighFinding(t *testing.T) {
	s := scoring.NewRuleBasedScorer()
	findings := []types.Finding{{Severity: types.SeverityHigh}}
	score, err := s.Score(context.Background(), "x", findings)
	if err != nil {
		t.Fatal(err)
	}
	// High weight = 0.7 → score = 0.7
	if score < 0.65 {
		t.Errorf("want score >= 0.65 for high finding, got %f", score)
	}
}

func TestRuleBasedScorer_DiminishingReturns(t *testing.T) {
	s := scoring.NewRuleBasedScorer()
	one := []types.Finding{{Severity: types.SeverityHigh}}
	two := []types.Finding{{Severity: types.SeverityHigh}, {Severity: types.SeverityHigh}}
	s1, _ := s.Score(context.Background(), "x", one)
	s2, _ := s.Score(context.Background(), "x", two)
	if s2 <= s1 {
		t.Errorf("two findings should score higher than one: s1=%f s2=%f", s1, s2)
	}
}

func TestRuleBasedScorer_ScoreInBounds(t *testing.T) {
	s := scoring.NewRuleBasedScorer()
	// Ten critical findings — score must still be in [0, 1].
	findings := make([]types.Finding, 10)
	for i := range findings {
		findings[i] = types.Finding{Severity: types.SeverityCritical}
	}
	score, err := s.Score(context.Background(), "x", findings)
	if err != nil {
		t.Fatal(err)
	}
	if score < 0.0 || score > 1.0 {
		t.Errorf("score must be in [0, 1], got %f", score)
	}
}

func TestRuleBasedScorer_SeverityOrdering(t *testing.T) {
	s := scoring.NewRuleBasedScorer()
	tests := []struct {
		sev types.Severity
	}{
		{types.SeverityInfo},
		{types.SeverityLow},
		{types.SeverityMedium},
		{types.SeverityHigh},
		{types.SeverityCritical},
	}
	prev := types.RiskScore(-1)
	for _, tt := range tests {
		score, err := s.Score(context.Background(), "x", []types.Finding{{Severity: tt.sev}})
		if err != nil {
			t.Fatal(err)
		}
		if score < prev {
			t.Errorf("severity %s should score >= %s: got %f < %f", tt.sev, "previous", score, prev)
		}
		prev = score
	}
}
