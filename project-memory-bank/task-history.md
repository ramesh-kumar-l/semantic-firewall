# Task History

## Phase 0 — Foundation & Scaffolding

### TASK-001: Project Memory Bank Initialization

**Date:** 2026-05-20  
**Status:** Complete  
**Phase:** 0

**Summary:**  
Created all 12 project-memory-bank files from scratch. Project was previously a blank slate with only a README.

**Files Created:**
- `project-memory-bank/project-overview.md`
- `project-memory-bank/current-phase.md`
- `project-memory-bank/architecture-summary.md`
- `project-memory-bank/tech-stack.md`
- `project-memory-bank/api-contracts.md`
- `project-memory-bank/security-model.md`
- `project-memory-bank/observability-model.md`
- `project-memory-bank/reliability-model.md`
- `project-memory-bank/repo-map.md`
- `project-memory-bank/engineering-decisions.md`
- `project-memory-bank/task-history.md` (this file)
- `project-memory-bank/future-roadmap.md`

**Key Decisions Made:**
- Language: Go (ADR-001)
- Router: chi v5 (ADR-002)
- Audit: JSON-L append-only (ADR-003)
- Telemetry: OTel stdout export (ADR-004)
- Logging: log/slog (ADR-005)
- Scoring: Rule-based v1 (ADR-006)
- Error behavior: Fail-closed (ADR-007)

**Architecture Defined:**
- V1 scope bounded to 7 subsystems
- Module boundaries established
- Core interfaces defined
- API contract specified

---

### TASK-002: Go Module Scaffold

**Date:** 2026-05-20  
**Status:** Complete  
**Phase:** 0

**Summary:**  
Initialized Go module and scaffolded all package directories and stub files.

**Files Created:**
- `go.mod`
- `cmd/server/main.go`
- `pkg/types/types.go`
- `pkg/errors/errors.go`
- `config/config.go`
- `internal/middleware/inspect.go`
- `internal/scoring/scorer.go`
- `internal/scoring/rules.go`
- `internal/detection/detector.go`
- `internal/detection/injection.go`
- `internal/detection/patterns.go`
- `internal/policy/engine.go`
- `internal/policy/rule.go`
- `internal/audit/logger.go`
- `internal/telemetry/otel.go`
- `internal/telemetry/spans.go`
- `internal/telemetry/metrics.go`

---

## Phase 2 — Policy Engine & Observability

### TASK-003: Phase 2 Implementation

**Date:** 2026-05-20  
**Status:** Complete  
**Phase:** 2

**Summary:**  
Implemented YAML-driven policy rules with hot-reload, Prometheus /metrics endpoint, OTLP trace exporter support, and per-caller rate limiting.

**Files Created:**
- `internal/policy/loader.go` — YAML policy rule parser
- `internal/ratelimit/limiter.go` — per-caller token-bucket rate limiter
- `config/policy_rules.yaml` — example YAML rules file
- `config/config.example.yaml` — example full config

**Files Modified:**
- `go.mod` — added fsnotify, prometheus exporter, otlp trace exporter, x/time, yaml.v3
- `config/config.go` — added RateLimitConfig, policy.rules_file, telemetry OTLP fields
- `internal/policy/engine.go` — added sync.RWMutex + UpdateRules() for hot-reload
- `internal/telemetry/otel.go` — pluggable trace/metrics exporters; Config struct; MetricsHandler field
- `internal/middleware/inspect.go` — added *ratelimit.Limiter parameter; version bumped to 0.2.0
- `pkg/errors/errors.go` — added CodeRateLimited
- `cmd/server/main.go` — wired Prometheus /metrics, YAML policy load, fsnotify watcher, rate limiter

**Key Decisions:**
- Prometheus is default metrics exporter (pull-based, production-ready)
- OTLP is opt-in trace exporter (set `telemetry.exporter_type: otlp`)
- Hot-reload is file-watch only (not full config reload — port/host changes still require restart)
- Rate limiter map has no TTL eviction (acceptable for bounded caller populations in V2)
- YAML rules fully replace hardcoded defaults when `policy.rules_file` is set
