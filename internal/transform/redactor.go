package transform

import (
	"strings"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

const redactedPlaceholder = "[REDACTED]"

// Redact replaces each finding's evidence string in prompt with [REDACTED].
// Findings with no evidence are skipped.
func Redact(prompt string, findings []types.Finding) string {
	result := prompt
	for _, f := range findings {
		if f.Evidence != "" {
			result = strings.ReplaceAll(result, f.Evidence, redactedPlaceholder)
		}
	}
	return result
}
