package policy_test

import (
	"context"
	"testing"

	"github.com/ramesh152/semantic-firewall/internal/policy"
	"github.com/ramesh152/semantic-firewall/pkg/types"
)

func TestRuleEngine_CriticalFindingDeny(t *testing.T) {
	e := policy.NewRuleEngine(0.8, types.DecisionAllow)
	findings := []types.Finding{{Severity: types.SeverityCritical}}
	dec, _, err := e.Evaluate(context.Background(), 0.0, findings)
	if err != nil {
		t.Fatal(err)
	}
	if dec != types.DecisionDeny {
		t.Errorf("want deny for critical finding, got %s", dec)
	}
}

func TestRuleEngine_HighFindingDeny(t *testing.T) {
	e := policy.NewRuleEngine(0.8, types.DecisionAllow)
	findings := []types.Finding{{Severity: types.SeverityHigh}}
	dec, _, err := e.Evaluate(context.Background(), 0.0, findings)
	if err != nil {
		t.Fatal(err)
	}
	if dec != types.DecisionDeny {
		t.Errorf("want deny for high finding, got %s", dec)
	}
}

func TestRuleEngine_ScoreAboveThresholdDeny(t *testing.T) {
	e := policy.NewRuleEngine(0.8, types.DecisionAllow)
	dec, _, err := e.Evaluate(context.Background(), 0.9, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec != types.DecisionDeny {
		t.Errorf("want deny for score 0.9 > threshold 0.8, got %s", dec)
	}
}

func TestRuleEngine_ScoreAtThresholdDeny(t *testing.T) {
	e := policy.NewRuleEngine(0.8, types.DecisionAllow)
	dec, _, err := e.Evaluate(context.Background(), 0.8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec != types.DecisionDeny {
		t.Errorf("want deny at threshold, got %s", dec)
	}
}

func TestRuleEngine_LowScoreNoFindingsAllow(t *testing.T) {
	e := policy.NewRuleEngine(0.8, types.DecisionAllow)
	dec, _, err := e.Evaluate(context.Background(), 0.1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec != types.DecisionAllow {
		t.Errorf("want allow for clean request, got %s", dec)
	}
}

func TestRuleEngine_DefaultAction(t *testing.T) {
	// Default action is DecisionDeny
	e := policy.NewRuleEngine(0.8, types.DecisionDeny)
	dec, _, err := e.Evaluate(context.Background(), 0.0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec != types.DecisionDeny {
		t.Errorf("want deny as default action, got %s", dec)
	}
}

func TestRuleEngine_UpdateRules(t *testing.T) {
	e := policy.NewRuleEngine(0.8, types.DecisionAllow)
	// Replace with a single "always transform" rule.
	newRules := []policy.Rule{
		{Name: "custom_transform", Condition: policy.ConditionAlways, Action: types.DecisionTransform},
	}
	e.UpdateRules(newRules)
	dec, rule, err := e.Evaluate(context.Background(), 0.0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec != types.DecisionTransform {
		t.Errorf("want transform from custom rule, got %s", dec)
	}
	if rule != "custom_transform" {
		t.Errorf("want rule name 'custom_transform', got %q", rule)
	}
}

func TestRuleEngine_RuleNameReturned(t *testing.T) {
	e := policy.NewRuleEngine(0.8, types.DecisionAllow)
	findings := []types.Finding{{Severity: types.SeverityCritical}}
	_, rule, err := e.Evaluate(context.Background(), 0.0, findings)
	if err != nil {
		t.Fatal(err)
	}
	if rule == "" {
		t.Error("want non-empty rule name, got empty string")
	}
}
