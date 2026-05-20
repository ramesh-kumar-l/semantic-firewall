package policy

import (
	"context"
	"sync"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

// Engine evaluates policy rules to produce a Decision.
type Engine interface {
	Evaluate(ctx context.Context, score types.RiskScore, findings []types.Finding) (types.Decision, string, error)
}

// RuleEngine evaluates an ordered list of rules; first match wins.
type RuleEngine struct {
	mu            sync.RWMutex
	rules         []Rule
	defaultAction types.Decision
}

// NewRuleEngine builds an engine with the given deny threshold and default action.
func NewRuleEngine(denyThreshold float64, defaultAction types.Decision) *RuleEngine {
	rules := []Rule{
		{
			Name:      "deny_on_critical_finding",
			Condition: ConditionHasFinding,
			Severity:  types.SeverityCritical,
			Action:    types.DecisionDeny,
		},
		{
			Name:      "deny_on_high_finding",
			Condition: ConditionHasFinding,
			Severity:  types.SeverityHigh,
			Action:    types.DecisionDeny,
		},
		{
			Name:      "deny_on_score_threshold",
			Condition: ConditionScoreAbove,
			Threshold: denyThreshold,
			Action:    types.DecisionDeny,
		},
		{
			Name:      "default",
			Condition: ConditionAlways,
			Action:    defaultAction,
		},
	}
	return &RuleEngine{rules: rules, defaultAction: defaultAction}
}

// UpdateRules atomically replaces the active rule set.
func (e *RuleEngine) UpdateRules(rules []Rule) {
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
}

// Evaluate returns the first matching rule's action, plus the rule name.
func (e *RuleEngine) Evaluate(_ context.Context, score types.RiskScore, findings []types.Finding) (types.Decision, string, error) {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()
	for _, r := range rules {
		if r.matches(score, findings) {
			return r.Action, r.Name, nil
		}
	}
	return e.defaultAction, "default", nil
}
