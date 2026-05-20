# Tech Stack

## Language

**Go 1.22+**

Rationale:
- Strong runtime guarantees (no GC pauses at this scale, fast startup)
- Excellent for security middleware (low-level control, strong typing)
- First-class HTTP server support
- Small binary, easy deployment
- No runtime surprises (unlike Python/JS async edge cases)
- Strong standard library (crypto, net/http, sync, context)

## HTTP Framework

**Standard `net/http` + `chi` router (github.com/go-chi/chi/v5)**

Rationale:
- `chi` is lightweight, idiomatic Go, supports middleware chaining cleanly
- No heavy frameworks — avoids hidden magic
- Chi middleware pattern maps perfectly to the inspection pipeline

## Observability

**OpenTelemetry Go SDK**
- `go.opentelemetry.io/otel`
- `go.opentelemetry.io/otel/trace`
- `go.opentelemetry.io/otel/metric`
- `go.opentelemetry.io/otel/exporters/stdout/stdouttrace` (V1 — stdout export)
- `go.opentelemetry.io/otel/exporters/stdout/stdoutmetric` (V1)
- `go.opentelemetry.io/otel/sdk/trace`
- `go.opentelemetry.io/otel/sdk/metric`

Rationale:
- Vendor-neutral — can swap exporter to Jaeger, Prometheus, OTLP later
- Industry standard for AI observability
- Zero-dependency on specific backends in V1

## Logging

**`log/slog` (Go 1.21+ structured logging)**

Rationale:
- Built into standard library since Go 1.21
- Structured JSON output natively
- No external dependency
- Integrates with OTel via log bridge in future phases

## Configuration

**`github.com/spf13/viper`** for config loading (YAML/JSON/env)

Rationale:
- Supports file + env + flags
- Industry standard in Go ecosystem
- Avoids home-grown config parsing

## Testing

**Standard `testing` package + `github.com/stretchr/testify`**

Rationale:
- `testify` for assertions without boilerplate
- No test framework magic — plain Go tests
- Deterministic, parallel-safe tests

## Audit Storage (V1)

**JSON-L file (append-only)**

Rationale:
- Simplest reliable implementation
- Easy to parse, replay, and stream
- No database dependency in V1
- Upgrade path: swap writer for Kafka/S3/PG in later phases

## Dependency Management

**Go modules (`go.mod` / `go.sum`)**

## Build

**Standard `go build`**

## Module Path

`github.com/ramesh152/semantic-firewall`

## Version Decisions

| Component          | Version   | Decision Date |
|--------------------|-----------|---------------|
| Go                 | 1.22+     | 2026-05-20    |
| chi                | v5        | 2026-05-20    |
| OTel Go SDK        | latest    | 2026-05-20    |
| testify            | v1        | 2026-05-20    |
| viper              | v1        | 2026-05-20    |
