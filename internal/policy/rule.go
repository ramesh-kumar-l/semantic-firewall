package policy

import "github.com/ramesh152/semantic-firewall/pkg/types"

// Condition describes when a rule triggers.
type Condition string

const (
	// ConditionScoreAbove triggers when risk_score >= threshold.
	ConditionScoreAbove Condition = "score_above"
	// ConditionHasFinding triggers when any finding matches the given severity.
	ConditionHasFinding Condition = "has_finding"
	// ConditionAlways always triggers (catch-all default rule).
	ConditionAlways Condition = "always"
)

// Rule maps a condition to a policy action.
type Rule struct {
	Name      string
	Condition Condition
	Threshold float64          // used by ConditionScoreAbove
	Severity  types.Severity   // used by ConditionHasFinding
	Action    types.Decision
}

// matches returns true if this rule's condition is satisfied.
func (r Rule) matches(score types.RiskScore, findings []types.Finding) bool {
	switch r.Condition {
	case ConditionAlways:
		return true

	case ConditionScoreAbove:
		return float64(score) >= r.Threshold

	case ConditionHasFinding:
		for _, f := range findings {
			if f.Severity == r.Severity || severityGTE(f.Severity, r.Severity) {
				return true
			}
		}
		return false
	}
	return false
}

// severityGTE returns true if a >= b in severity ordering.
func severityGTE(a, b types.Severity) bool {
	return severityRank(a) >= severityRank(b)
}

func severityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 5
	case types.SeverityHigh:
		return 4
	case types.SeverityMedium:
		return 3
	case types.SeverityLow:
		return 2
	case types.SeverityInfo:
		return 1
	}
	return 0
}
