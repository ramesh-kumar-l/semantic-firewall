package policy

import (
	"fmt"
	"os"

	"github.com/ramesh152/semantic-firewall/pkg/types"
	"gopkg.in/yaml.v3"
)

type ruleYAML struct {
	Name      string  `yaml:"name"`
	Condition string  `yaml:"condition"`
	Threshold float64 `yaml:"threshold"`
	Severity  string  `yaml:"severity"`
	Action    string  `yaml:"action"`
}

type policyFileYAML struct {
	Rules []ruleYAML `yaml:"rules"`
}

// LoadRulesFromFile parses a YAML policy file and returns the ordered rule list.
func LoadRulesFromFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var pf policyFileYAML
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}
	rules := make([]Rule, 0, len(pf.Rules))
	for _, r := range pf.Rules {
		rule, err := parseRuleYAML(r)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseRuleYAML(r ruleYAML) (Rule, error) {
	cond := Condition(r.Condition)
	switch cond {
	case ConditionScoreAbove, ConditionHasFinding, ConditionAlways:
	default:
		return Rule{}, fmt.Errorf("unknown condition %q", r.Condition)
	}
	action := types.Decision(r.Action)
	switch action {
	case types.DecisionAllow, types.DecisionDeny, types.DecisionTransform, types.DecisionAlert:
	default:
		return Rule{}, fmt.Errorf("unknown action %q", r.Action)
	}
	return Rule{
		Name:      r.Name,
		Condition: cond,
		Threshold: r.Threshold,
		Severity:  types.Severity(r.Severity),
		Action:    action,
	}, nil
}
