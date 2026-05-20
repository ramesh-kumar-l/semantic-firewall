package scoring

import (
	"context"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

// Scorer computes a normalized risk score [0.0, 1.0] for a prompt.
type Scorer interface {
	Score(ctx context.Context, prompt string, findings []types.Finding) (types.RiskScore, error)
}

// RuleBasedScorer derives a score from detected findings using severity weights.
// It is deterministic: same findings → same score.
type RuleBasedScorer struct {
	rules []scoringRule
}

func NewRuleBasedScorer() *RuleBasedScorer {
	return &RuleBasedScorer{rules: defaultRules}
}

// Score returns a risk score derived purely from findings severity.
func (s *RuleBasedScorer) Score(_ context.Context, _ string, findings []types.Finding) (types.RiskScore, error) {
	if len(findings) == 0 {
		return types.RiskScoreMin, nil
	}

	var total float64
	for _, f := range findings {
		total += severityWeight(f.Severity)
	}

	// Apply diminishing returns: each additional finding adds less.
	// score = 1 - (1 - w1) * (1 - w2) * ... capped at 1.0
	score := 1.0
	for _, f := range findings {
		w := severityWeight(f.Severity)
		score *= (1.0 - w)
	}
	score = 1.0 - score

	if score > 1.0 {
		score = 1.0
	}
	return types.RiskScore(score), nil
}

func severityWeight(s types.Severity) float64 {
	switch s {
	case types.SeverityCritical:
		return 0.9
	case types.SeverityHigh:
		return 0.7
	case types.SeverityMedium:
		return 0.4
	case types.SeverityLow:
		return 0.2
	default:
		return 0.0
	}
}
