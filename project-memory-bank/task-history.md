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

---

## Phase 3 — Transform & Alert Actions

### TASK-004: Phase 3 Implementation

**Date:** 2026-05-20  
**Status:** Complete  
**Phase:** 3

**Summary:**  
Implemented `transform` prompt redaction, async webhook alerting, API key authentication middleware, configurable deny message, and rate limiter TTL eviction.

**Files Created:**
- `internal/transform/redactor.go` — replaces finding evidence with `[REDACTED]`
- `internal/alert/webhook.go` — async HTTP POST alerter
- `internal/middleware/apikey.go` — API key auth middleware (Bearer / X-API-Key, subtle compare)

**Files Modified:**
- `pkg/errors/errors.go` — added CodeUnauthorized
- `pkg/types/types.go` — added SanitizedPrompt, Message to InspectResponse
- `config/config.go` — added AuthConfig, AlertConfig, DenyMessage, TTLSeconds
- `internal/ratelimit/limiter.go` — added TTL eviction with background cleanup goroutine + Stop()
- `internal/middleware/inspect.go` — Options struct; transform/alert/deny handling; version 0.3.0
- `cmd/server/main.go` — wired alerter, API key middleware, TTL rate limiter
- `config/config.example.yaml` — added auth, alert, deny_message, ttl_seconds sections

**Key Decisions:**
- `transform` redacts finding evidence strings in-place; `sanitized_prompt` returned in response body
- `alert` fires async goroutine webhook POST with full AuditRecord; caller receives `decision: alert` at HTTP 200
- All decisions return HTTP 200 — inspection API, not proxy
- API key auth applied per-route only to `/v1/inspect`; `/health` + `/metrics` unauthenticated
- Rate limiter simplified to single write-lock (safe `lastSeen` update); TTL sweep every ttl/2
- `inspectmw.Handler()` now takes `Options` struct (breaking change from Phase 2)

---

## Phase 4 — Advanced Detection

### TASK-005: Phase 4 Implementation

**Date:** 2026-05-20  
**Status:** Complete  
**Phase:** 4

**Summary:**  
Implemented encoding-aware normalization (base64/ROT13/unicode/URL), memory poisoning detection patterns, tool call inspection, and multi-turn session context awareness.

**Files Created:**
- `internal/normalize/normalizer.go` — encoding detection + prompt normalization
- `internal/detection/toolcall.go` — `ExtractToolCallText()` for tool call inspection
- `internal/session/store.go` — in-memory session state store with TTL eviction

**Files Modified:**
- `pkg/types/types.go` — added `FindingMemoryPoisoning`, `FindingToolCallInjection`; `ToolCalls []json.RawMessage` to `InspectRequest`
- `internal/detection/patterns.go` — 6 new memory poisoning patterns
- `internal/middleware/inspect.go` — wired normalizer, tool call detection, session escalation; `SessionStore` in `Options`; version 0.4.0
- `cmd/server/main.go` — wired session store, version 0.4.0
- `config/config.go` — added `SessionConfig` with `TTLSeconds`
- `config/config.example.yaml` — added `session` section
- `go.mod` — added `golang.org/x/text v0.16.0`

**Key Decisions:**
- Normalizer runs before all detection; encoding findings prepended to findings list
- Tool call inspection reuses `InjectionDetector` — no new interface; extracted text passed as plain string
- Session escalation: ×1.2 multiplier on risk when prior `MaxRisk > 0.5` (capped at 1.0)
- Session store disabled when `ttl_seconds = 0` (no goroutine, nil pointer)
- `normalize()` stub in `inspect.go` replaced with real `normalize.Normalize()` call

---

## Phase 5 — Testing & Hardening

### TASK-006: Phase 5 Implementation

**Date:** 2026-05-20  
**Status:** Complete  
**Phase:** 5

**Summary:**  
Wrote unit tests for all packages and an integration test for the full `/v1/inspect` pipeline, plus a fuzz target for the encoding normalizer.

**Files Created:**
- `internal/normalize/normalizer_test.go` — 6 unit tests + `FuzzNormalize` fuzz target
- `internal/detection/injection_test.go` — 7 unit tests
- `internal/detection/toolcall_test.go` — 6 unit tests
- `internal/session/store_test.go` — 7 unit tests (incl. real TTL eviction)
- `internal/scoring/scorer_test.go` — 6 unit tests
- `internal/policy/engine_test.go` — 7 unit tests
- `internal/transform/redactor_test.go` — 7 unit tests
- `internal/ratelimit/limiter_test.go` — 6 unit tests
- `internal/middleware/apikey_test.go` — 7 middleware tests
- `internal/middleware/inspect_test.go` — 11 integration tests (full pipeline)

**Key Decisions:**
- Standard library testing only (no stretchr/testify)
- All tests use black-box `package xxx_test` pattern
- `TestMain` in middleware package creates shared OTel provider with stdout exporters
- `noopLogger` implements `audit.Logger` in test code (no disk I/O during tests)
- Fuzz seeds cover all 5 normalization paths (base64, ROT13, URL, ZWS, clean)
