package transform_test

import (
	"strings"
	"testing"

	"github.com/ramesh152/semantic-firewall/internal/transform"
	"github.com/ramesh152/semantic-firewall/pkg/types"
)

func TestRedact_NoFindings(t *testing.T) {
	result := transform.Redact("hello world", nil)
	if result != "hello world" {
		t.Errorf("want unchanged prompt, got %q", result)
	}
}

func TestRedact_EmptyFindings(t *testing.T) {
	result := transform.Redact("hello world", []types.Finding{})
	if result != "hello world" {
		t.Errorf("want unchanged prompt, got %q", result)
	}
}

func TestRedact_SingleFinding(t *testing.T) {
	findings := []types.Finding{
		{Evidence: "bad phrase"},
	}
	prompt := "please bad phrase do something"
	result := transform.Redact(prompt, findings)
	if strings.Contains(result, "bad phrase") {
		t.Errorf("want evidence redacted, got %q", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Errorf("want [REDACTED] in output, got %q", result)
	}
}

func TestRedact_EmptyEvidence_Skipped(t *testing.T) {
	findings := []types.Finding{
		{Evidence: ""},
	}
	prompt := "original unchanged"
	result := transform.Redact(prompt, findings)
	if result != prompt {
		t.Errorf("empty evidence should be skipped, got %q", result)
	}
}

func TestRedact_MultipleOccurrences(t *testing.T) {
	findings := []types.Finding{
		{Evidence: "bad"},
	}
	result := transform.Redact("bad actors do bad things", findings)
	if strings.Contains(result, "bad") {
		t.Errorf("all occurrences should be redacted, got %q", result)
	}
	count := strings.Count(result, "[REDACTED]")
	if count != 2 {
		t.Errorf("want 2 redactions, got %d in %q", count, result)
	}
}

func TestRedact_MultipleFindings(t *testing.T) {
	findings := []types.Finding{
		{Evidence: "alpha"},
		{Evidence: "beta"},
	}
	result := transform.Redact("alpha and beta are here", findings)
	if strings.Contains(result, "alpha") || strings.Contains(result, "beta") {
		t.Errorf("want both findings redacted, got %q", result)
	}
}

func TestRedact_PromptUnchangedForNonMatchingEvidence(t *testing.T) {
	findings := []types.Finding{
		{Evidence: "not-in-prompt"},
	}
	result := transform.Redact("safe prompt", findings)
	if result != "safe prompt" {
		t.Errorf("non-matching evidence should leave prompt unchanged, got %q", result)
	}
}
