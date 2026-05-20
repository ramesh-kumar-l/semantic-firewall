package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Instruments holds all metric instruments for the firewall.
type Instruments struct {
	RequestsTotal  metric.Int64Counter
	RequestsDenied metric.Int64Counter
	RequestsAllowed metric.Int64Counter
	RiskScore      metric.Float64Histogram
	LatencyMs      metric.Int64Histogram
	FindingsTotal  metric.Int64Counter
}

// NewInstruments creates and registers all metric instruments.
func NewInstruments(meter metric.Meter) (*Instruments, error) {
	requestsTotal, err := meter.Int64Counter(
		"firewall.requests.total",
		metric.WithDescription("Total number of inspection requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("create requests_total counter: %w", err)
	}

	requestsDenied, err := meter.Int64Counter(
		"firewall.requests.denied",
		metric.WithDescription("Total requests denied by policy"),
	)
	if err != nil {
		return nil, fmt.Errorf("create requests_denied counter: %w", err)
	}

	requestsAllowed, err := meter.Int64Counter(
		"firewall.requests.allowed",
		metric.WithDescription("Total requests allowed by policy"),
	)
	if err != nil {
		return nil, fmt.Errorf("create requests_allowed counter: %w", err)
	}

	riskScore, err := meter.Float64Histogram(
		"firewall.risk_score",
		metric.WithDescription("Distribution of risk scores (0.0–1.0)"),
	)
	if err != nil {
		return nil, fmt.Errorf("create risk_score histogram: %w", err)
	}

	latencyMs, err := meter.Int64Histogram(
		"firewall.latency_ms",
		metric.WithDescription("Per-request inspection latency in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("create latency_ms histogram: %w", err)
	}

	findingsTotal, err := meter.Int64Counter(
		"firewall.findings.total",
		metric.WithDescription("Total findings detected (by type and severity)"),
	)
	if err != nil {
		return nil, fmt.Errorf("create findings_total counter: %w", err)
	}

	return &Instruments{
		RequestsTotal:   requestsTotal,
		RequestsDenied:  requestsDenied,
		RequestsAllowed: requestsAllowed,
		RiskScore:       riskScore,
		LatencyMs:       latencyMs,
		FindingsTotal:   findingsTotal,
	}, nil
}

func (i *Instruments) RecordRequest(ctx context.Context, decision string, riskScore float64, latencyMs int64) {
	attrs := metric.WithAttributes(attribute.String("decision", decision))
	i.RequestsTotal.Add(ctx, 1, attrs)
	i.RiskScore.Record(ctx, riskScore)
	i.LatencyMs.Record(ctx, latencyMs)

	switch decision {
	case "deny":
		i.RequestsDenied.Add(ctx, 1)
	case "allow":
		i.RequestsAllowed.Add(ctx, 1)
	}
}

func (i *Instruments) RecordFinding(ctx context.Context, findingType, severity string) {
	i.FindingsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("finding_type", findingType),
		attribute.String("severity", severity),
	))
}
