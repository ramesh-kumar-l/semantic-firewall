package policy

import (
	"context"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

// Engine evaluates policy rules to produce a Decision.
type Engine interface {
	Evaluate(ctx context.Context, score types.RiskScore, findings []types.Finding) (types.Decision, string, error)
}

// RuleEngine evaluates an ordered list of rules; first match wins.
type RuleEngine struct {
	rules         []Rule
	defaultAction types.Decision
}

// NewRuleEngine builds an engine with the given deny threshold and default action.
// Rules are evaluated in order; the first matching rule determines the decision.
func NewRuleEngine(denyThreshold float64, defaultAction types.Decision) *RuleEngine {
	rules := []Rule{
		// Deny on any critical finding.
		{
			Name:      "deny_on_critical_finding",
			Condition: ConditionHasFinding,
			Severity:  types.SeverityCritical,
			Action:    types.DecisionDeny,
		},
		// Deny on any high finding.
		{
			Name:      "deny_on_high_finding",
			Condition: ConditionHasFinding,
			Severity:  types.SeverityHigh,
			Action:    types.DecisionDeny,
		},
		// Deny when risk score exceeds threshold.
		{
			Name:      "deny_on_score_threshold",
			Condition: ConditionScoreAbove,
			Threshold: denyThreshold,
			Action:    types.DecisionDeny,
		},
		// Default rule — falls through to configured default action.
		{
			Name:      "default",
			Condition: ConditionAlways,
			Action:    defaultAction,
		},
	}
	return &RuleEngine{rules: rules, defaultAction: defaultAction}
}

// Evaluate returns the first matching rule's action, plus the rule name.
// Returns (defaultAction, "default", nil) if no non-default rule matches.
func (e *RuleEngine) Evaluate(_ context.Context, score types.RiskScore, findings []types.Finding) (types.Decision, string, error) {
	for _, r := range e.rules {
		if r.matches(score, findings) {
			return r.Action, r.Name, nil
		}
	}
	return e.defaultAction, "default", nil
}
