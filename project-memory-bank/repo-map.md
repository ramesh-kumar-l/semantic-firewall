# Repository Map

## Root Structure

```
semantic-firewall/
├── cmd/
│   └── server/
│       └── main.go              # Entry point, server startup, config loading
├── internal/
│   ├── middleware/
│   │   ├── inspect.go           # HTTP inspection middleware (orchestrates pipeline)
│   │   └── inspect_test.go
│   ├── scoring/
│   │   ├── scorer.go            # Risk scorer interface + rule-based implementation
│   │   ├── rules.go             # Built-in scoring rules
│   │   └── scorer_test.go
│   ├── detection/
│   │   ├── detector.go          # Detector interface
│   │   ├── injection.go         # Prompt injection detector
│   │   ├── patterns.go          # Detection pattern sets
│   │   └── detector_test.go
│   ├── policy/
│   │   ├── engine.go            # Policy engine
│   │   ├── rule.go              # Rule types + evaluation
│   │   └── engine_test.go
│   ├── audit/
│   │   ├── logger.go            # Audit logger (append-only JSON-L)
│   │   └── logger_test.go
│   └── telemetry/
│       ├── otel.go              # OTel setup (tracer + meter)
│       ├── spans.go             # Span helpers
│       └── metrics.go           # Metric definitions
├── pkg/
│   ├── types/
│   │   └── types.go             # Shared types (InspectRequest, InspectResponse, Finding, Decision, etc.)
│   └── errors/
│       └── errors.go            # Error types (FirewallError, codes)
├── config/
│   └── config.go                # Config struct + loader (viper)
├── project-memory-bank/
│   ├── project-overview.md
│   ├── current-phase.md
│   ├── architecture-summary.md
│   ├── tech-stack.md
│   ├── api-contracts.md
│   ├── security-model.md
│   ├── observability-model.md
│   ├── reliability-model.md
│   ├── repo-map.md
│   ├── engineering-decisions.md
│   ├── task-history.md
│   └── future-roadmap.md
├── go.mod
├── go.sum
├── README.md
└── LICENSE
```

## Module Boundaries

### `cmd/server`
**Owns:** application wiring, startup, shutdown  
**Depends on:** internal/*, config, pkg/*  
**Must NOT:** contain business logic

### `internal/middleware`
**Owns:** HTTP request/response lifecycle, pipeline orchestration  
**Depends on:** scoring, detection, policy, audit, telemetry, pkg/types  
**Must NOT:** implement detection or scoring logic directly

### `internal/scoring`
**Owns:** risk score computation  
**Depends on:** pkg/types  
**Must NOT:** make HTTP calls, write audit records

### `internal/detection`
**Owns:** finding generation from prompts  
**Depends on:** pkg/types  
**Must NOT:** make policy decisions, write audit records

### `internal/policy`
**Owns:** decision from findings + score  
**Depends on:** pkg/types  
**Must NOT:** inspect prompts directly, write audit records

### `internal/audit`
**Owns:** writing immutable audit records  
**Depends on:** pkg/types  
**Must NOT:** make policy decisions, inspect prompts

### `internal/telemetry`
**Owns:** OTel initialization and span/metric helpers  
**Depends on:** OTel SDK  
**Must NOT:** contain business logic

### `pkg/types`
**Owns:** shared data types  
**Depends on:** nothing internal  
**Must NOT:** contain logic

### `pkg/errors`
**Owns:** error types and codes  
**Depends on:** nothing internal  
**Must NOT:** contain business logic

### `config`
**Owns:** configuration schema and loading  
**Depends on:** viper  
**Must NOT:** contain business logic

## Key Interfaces (V1)

```go
// Scorer computes a risk score for a normalized prompt
type Scorer interface {
    Score(ctx context.Context, prompt string) (RiskScore, error)
}

// Detector produces findings from a normalized prompt
type Detector interface {
    Detect(ctx context.Context, prompt string) ([]Finding, error)
}

// PolicyEngine evaluates findings and score to produce a decision
type PolicyEngine interface {
    Evaluate(ctx context.Context, score RiskScore, findings []Finding) (Decision, string, error)
}

// AuditLogger writes an immutable audit record
type AuditLogger interface {
    Write(ctx context.Context, record AuditRecord) error
}
```
