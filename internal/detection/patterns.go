package detection

import (
	"regexp"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

type pattern struct {
	re       *regexp.Regexp
	findType types.FindingType
	severity types.Severity
	label    string
}

// injectionPatterns covers well-known prompt injection phrases.
// Patterns are compiled once at package init.
var injectionPatterns = []pattern{
	// Role override — critical
	{
		re:       regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions?`),
		findType: types.FindingRoleOverride,
		severity: types.SeverityCritical,
		label:    "ignore_previous_instructions",
	},
	{
		re:       regexp.MustCompile(`(?i)forget\s+(everything|all|your\s+instructions?)`),
		findType: types.FindingRoleOverride,
		severity: types.SeverityCritical,
		label:    "forget_instructions",
	},
	{
		re:       regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|context|training)`),
		findType: types.FindingRoleOverride,
		severity: types.SeverityCritical,
		label:    "disregard_instructions",
	},
	{
		re:       regexp.MustCompile(`(?i)you\s+are\s+now\s+[a-z]`),
		findType: types.FindingRoleOverride,
		severity: types.SeverityCritical,
		label:    "you_are_now",
	},
	{
		re:       regexp.MustCompile(`(?i)act\s+as\s+(if\s+you\s+are|a|an)\s+[a-z]`),
		findType: types.FindingRoleOverride,
		severity: types.SeverityHigh,
		label:    "act_as",
	},
	{
		re:       regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+[a-z]`),
		findType: types.FindingRoleOverride,
		severity: types.SeverityHigh,
		label:    "pretend_to_be",
	},
	{
		re:       regexp.MustCompile(`(?i)your\s+(new\s+)?(role|persona|identity|name)\s+is`),
		findType: types.FindingRoleOverride,
		severity: types.SeverityHigh,
		label:    "new_role_identity",
	},

	// Jailbreak — high
	{
		re:       regexp.MustCompile(`(?i)\bDAN\b`),
		findType: types.FindingJailbreak,
		severity: types.SeverityHigh,
		label:    "dan_jailbreak",
	},
	{
		re:       regexp.MustCompile(`(?i)do\s+anything\s+now`),
		findType: types.FindingJailbreak,
		severity: types.SeverityHigh,
		label:    "do_anything_now",
	},
	{
		re:       regexp.MustCompile(`(?i)jailbreak`),
		findType: types.FindingJailbreak,
		severity: types.SeverityHigh,
		label:    "jailbreak_keyword",
	},
	{
		re:       regexp.MustCompile(`(?i)bypass\s+(your\s+)?(safety|filter|restriction|guardrail|limit)`),
		findType: types.FindingJailbreak,
		severity: types.SeverityHigh,
		label:    "bypass_safety",
	},
	{
		re:       regexp.MustCompile(`(?i)ignore\s+(your\s+)?(safety|ethical|moral)\s+(guidelines?|rules?|training)`),
		findType: types.FindingJailbreak,
		severity: types.SeverityHigh,
		label:    "ignore_safety_guidelines",
	},

	// Prompt injection — medium to high
	{
		re:       regexp.MustCompile(`(?i)system\s*prompt`),
		findType: types.FindingPromptInjection,
		severity: types.SeverityMedium,
		label:    "system_prompt_reference",
	},
	{
		re:       regexp.MustCompile(`(?i)reveal\s+(your\s+)?(system\s+prompt|instructions?|context)`),
		findType: types.FindingPromptInjection,
		severity: types.SeverityHigh,
		label:    "reveal_system_prompt",
	},
	{
		re:       regexp.MustCompile(`(?i)what\s+(are|were)\s+your\s+instructions?`),
		findType: types.FindingPromptInjection,
		severity: types.SeverityMedium,
		label:    "ask_for_instructions",
	},
	{
		re:       regexp.MustCompile(`(?i)new\s+instructions?:`),
		findType: types.FindingPromptInjection,
		severity: types.SeverityHigh,
		label:    "new_instructions_colon",
	},
	{
		re:       regexp.MustCompile(`(?i)\[\s*system\s*\]`),
		findType: types.FindingPromptInjection,
		severity: types.SeverityHigh,
		label:    "fake_system_tag",
	},
	{
		re:       regexp.MustCompile(`(?i)<\s*system\s*>`),
		findType: types.FindingPromptInjection,
		severity: types.SeverityHigh,
		label:    "fake_system_xml_tag",
	},
}
