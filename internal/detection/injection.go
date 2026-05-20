package detection

import (
	"context"
	"fmt"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

const detectorName = "injection_detector_v1"

// InjectionDetector detects prompt injection, role override, and jailbreak attempts.
type InjectionDetector struct{}

func NewInjectionDetector() *InjectionDetector {
	return &InjectionDetector{}
}

func (d *InjectionDetector) Name() string {
	return detectorName
}

// Detect runs all injection patterns against the prompt and returns findings.
// It is deterministic: same prompt → same findings.
func (d *InjectionDetector) Detect(_ context.Context, prompt string) ([]types.Finding, error) {
	var findings []types.Finding
	seen := make(map[string]bool)

	for _, p := range injectionPatterns {
		match := p.re.FindString(prompt)
		if match == "" {
			continue
		}
		// Deduplicate by label — one finding per pattern type.
		if seen[p.label] {
			continue
		}
		seen[p.label] = true

		findings = append(findings, types.Finding{
			Type:     p.findType,
			Severity: p.severity,
			Evidence: fmt.Sprintf("matched pattern %q: %q", p.label, truncate(match, 100)),
			Detector: detectorName,
		})
	}

	return findings, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
