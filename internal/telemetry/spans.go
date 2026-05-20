package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	SpanInspect        = "firewall.inspect"
	SpanNormalize      = "firewall.normalize"
	SpanScore          = "firewall.score"
	SpanDetect         = "firewall.detect"
	SpanPolicyEvaluate = "firewall.policy.evaluate"
	SpanAuditWrite     = "firewall.audit.write"
)

// AttrSet is a helper for recording common span attributes.
func AttrSet(span trace.Span, attrs ...attribute.KeyValue) {
	span.SetAttributes(attrs...)
}

func AttrDecision(decision string) attribute.KeyValue {
	return attribute.String("firewall.decision", decision)
}

func AttrRiskScore(score float64) attribute.KeyValue {
	return attribute.Float64("firewall.risk_score", score)
}

func AttrFindingsCount(n int) attribute.KeyValue {
	return attribute.Int("firewall.findings_count", n)
}

func AttrPromptHash(hash string) attribute.KeyValue {
	return attribute.String("firewall.prompt_hash", hash)
}

func AttrTraceID(id string) attribute.KeyValue {
	return attribute.String("firewall.trace_id", id)
}

func AttrLatencyMs(ms int64) attribute.KeyValue {
	return attribute.Int64("firewall.latency_ms", ms)
}

// RecordError records an error on a span and sets its status to error.
func RecordError(span trace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// StartSpan starts a child span using the provider's tracer.
func (p *Provider) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return p.Tracer.Start(ctx, name, opts...)
}
