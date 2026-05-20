# Observability Model

## Principle

If a system cannot be observed, it cannot be trusted.

Every critical operation in Semantic Firewall emits structured telemetry so that:
- every decision is explainable
- every anomaly is detectable
- every incident is replayable

## Tracing Strategy

**Technology:** OpenTelemetry Go SDK

### Trace Structure

Each `/v1/inspect` request creates one root span:

```
[firewall.inspect]
  └─ [firewall.normalize]
  └─ [firewall.score]
  └─ [firewall.detect]
  └─ [firewall.policy.evaluate]
  └─ [firewall.audit.write]
```

### Span Attributes (on root span)

| Attribute | Type | Description |
|-----------|------|-------------|
| `firewall.trace_id` | string | Internal trace UUID |
| `firewall.request_id` | string | Caller-supplied or generated |
| `firewall.decision` | string | allow/deny/transform/alert |
| `firewall.risk_score` | float | 0.0–1.0 |
| `firewall.findings_count` | int | Number of findings |
| `firewall.prompt_hash` | string | SHA-256 of normalized prompt |
| `firewall.latency_ms` | int | Total processing time |

### V1 Export

stdout exporter (`stdouttrace`) — structured JSON to stdout.

Upgrade path: swap for OTLP exporter (Jaeger, Tempo, Honeycomb) without code changes.

## Metrics Strategy

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `firewall.requests.total` | Counter | Total inspected requests |
| `firewall.requests.denied` | Counter | Requests denied |
| `firewall.requests.allowed` | Counter | Requests allowed |
| `firewall.risk_score` | Histogram | Distribution of risk scores |
| `firewall.latency_ms` | Histogram | Per-request latency |
| `firewall.findings.total` | Counter | Total findings (by type + severity) |

### Labels / Dimensions

- `decision` — allow/deny
- `finding_type` — prompt_injection / role_override / etc.
- `severity` — info/low/medium/high/critical

### V1 Export

stdout exporter (`stdoutmetric`) — structured JSON to stdout.

## Logging Standards

**Technology:** Go `log/slog` (structured JSON)

### Log Levels

- `INFO` — request processed, normal flow
- `WARN` — unexpected but handled (e.g., unknown content type)
- `ERROR` — internal failure (always with error detail + trace ID)
- `DEBUG` — detailed per-finding info (disabled in production by default)

### Required Fields in Every Log Line

```json
{
  "time": "RFC3339",
  "level": "INFO|WARN|ERROR|DEBUG",
  "trace_id": "uuid",
  "msg": "human readable",
  "component": "middleware|scorer|detector|policy|audit",
  ...context fields
}
```

### Log Events (Mandatory)

| Event | Level | Trigger |
|-------|-------|---------|
| `request.received` | INFO | Inspection request arrives |
| `request.processed` | INFO | Inspection complete |
| `request.denied` | WARN | Policy decision = deny |
| `finding.detected` | WARN | Any non-info finding |
| `audit.write.error` | ERROR | Audit log write fails |
| `internal.error` | ERROR | Any unexpected error |

## Audit Architecture

### Purpose

Provide an immutable, replayable record of every inspection decision.

### Format

JSON-L (one JSON object per line), append-only.

### Audit Record Schema

```json
{
  "trace_id": "uuid",
  "request_id": "uuid",
  "timestamp": "RFC3339",
  "prompt_hash": "sha256:...",
  "prompt_length": 512,
  "model": "string",
  "caller_id": "string",
  "session_id": "string",
  "risk_score": 0.85,
  "findings": [...],
  "decision": "deny",
  "policy_rule_matched": "string",
  "latency_ms": 4,
  "firewall_version": "0.1.0"
}
```

### Integrity Properties (V1)

- Append-only: no update or delete operations
- Includes prompt hash (not raw prompt — privacy-preserving by default)
- Deterministic: same input → same hash → same audit entry shape

### V1 Storage

Local file (`audit.jsonl`) — configurable path.

Upgrade path: swap writer for Kafka, S3, PostgreSQL without audit record schema changes.

## Replayability

Every audit record contains sufficient information to:
1. Identify the request (trace_id, request_id, timestamp)
2. Reproduce the analysis (prompt_hash + risk_score + findings)
3. Verify the decision (policy_rule_matched)
4. Correlate with OTel trace (trace_id shared across audit + OTel)
