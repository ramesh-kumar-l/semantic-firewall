package types

import (
	"encoding/json"
	"time"
)

type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionDeny      Decision = "deny"
	DecisionTransform Decision = "transform"
	DecisionAlert     Decision = "alert"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type FindingType string

const (
	FindingPromptInjection  FindingType = "prompt_injection"
	FindingRoleOverride     FindingType = "role_override"
	FindingJailbreak        FindingType = "jailbreak"
	FindingEncodingTrick    FindingType = "encoding_trick"
	FindingMemoryPoisoning  FindingType = "memory_poisoning"
	FindingToolCallInjection FindingType = "tool_call_injection"
)

// RiskScore is a normalized risk value in [0.0, 1.0].
type RiskScore float64

const (
	RiskScoreMin RiskScore = 0.0
	RiskScoreMax RiskScore = 1.0
)

type Finding struct {
	Type     FindingType `json:"type"`
	Severity Severity    `json:"severity"`
	Evidence string      `json:"evidence"`
	Detector string      `json:"detector"`
}

type PromptContext struct {
	CallerID  string            `json:"caller_id,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type InspectRequest struct {
	RequestID string             `json:"request_id,omitempty"`
	Model     string             `json:"model,omitempty"`
	Prompt    string             `json:"prompt"`
	Context   *PromptContext     `json:"context,omitempty"`
	ToolCalls []json.RawMessage  `json:"tool_calls,omitempty"` // optional: structured tool call objects to inspect
}

type InspectResponse struct {
	TraceID         string    `json:"trace_id"`
	RequestID       string    `json:"request_id"`
	Decision        Decision  `json:"decision"`
	RiskScore       RiskScore `json:"risk_score"`
	Findings        []Finding `json:"findings"`
	LatencyMs       int64     `json:"latency_ms"`
	Timestamp       time.Time `json:"timestamp"`
	SanitizedPrompt string    `json:"sanitized_prompt,omitempty"` // set when decision == transform
	Message         string    `json:"message,omitempty"`          // set when decision == deny
}

type AuditRecord struct {
	TraceID           string    `json:"trace_id"`
	RequestID         string    `json:"request_id"`
	Timestamp         time.Time `json:"timestamp"`
	PromptHash        string    `json:"prompt_hash"`
	PromptLength      int       `json:"prompt_length"`
	Model             string    `json:"model,omitempty"`
	CallerID          string    `json:"caller_id,omitempty"`
	SessionID         string    `json:"session_id,omitempty"`
	RiskScore         RiskScore `json:"risk_score"`
	Findings          []Finding `json:"findings"`
	Decision          Decision  `json:"decision"`
	PolicyRuleMatched string    `json:"policy_rule_matched,omitempty"`
	LatencyMs         int64     `json:"latency_ms"`
	FirewallVersion   string    `json:"firewall_version"`
	Cancelled         bool      `json:"cancelled,omitempty"`
	Timeout           bool      `json:"timeout,omitempty"`
}
