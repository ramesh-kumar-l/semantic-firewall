# Current Phase

## Phase: 2 — Policy Engine & Observability

**Status:** Complete  
**Started:** 2026-05-20  
**Completed:** 2026-05-20

---

## Phase 2 Goals

- [x] YAML-driven policy rules (`internal/policy/loader.go`)
- [x] Policy hot-reload via fsnotify (watches `policy.rules_file` on disk)
- [x] Prometheus `/metrics` endpoint (OTel Prometheus exporter)
- [x] OTLP trace exporter support (`telemetry.exporter_type: otlp`)
- [x] Pluggable telemetry config (`telemetry.Config` struct in telemetry package)
- [x] Per-caller rate limiting (`internal/ratelimit`, token bucket via `golang.org/x/time/rate`)
- [x] `CodeRateLimited` error code added to `pkg/errors`
- [x] `RateLimitConfig` and extended policy/telemetry config fields in `config/config.go`
- [x] `config/policy_rules.yaml` and `config/config.example.yaml` example files

## Phase 2 Key Decisions

- Prometheus is the default metrics exporter (replaces stdout metrics); stdout traces remain default
- Metrics → Prometheus pull-based; Traces → stdout (default) or OTLP push-based
- Rate limiting is per caller_id (from request body), falls back to RemoteAddr
- No in-memory rate limiter cleanup in V2 (unbounded map); acceptable for bounded caller populations
- Hot-reload is file-based (fsnotify Write/Create events), atomic rule swap under sync.RWMutex
- YAML policy rules fully replace hardcoded defaults when `policy.rules_file` is set

## Next Phase: Phase 3 — Transform & Alert Actions

### Phase 3 Goals
1. `transform` action: prompt sanitization / redaction
2. `alert` action: webhook or structured alert emission  
3. Configurable response templates for denied requests
4. API key authentication middleware
5. Rate limiting cleanup (TTL-based limiter map eviction)

## Blockers

- Go 1.22+ must be installed before building (`go mod tidy && go build ./...`)
- `go.sum` not yet generated (requires `go mod tidy` with network access)

## Notes

- `telemetry.New()` signature changed: now takes `telemetry.Config` struct instead of `(serviceName, serviceVersion string)`
- `inspectmw.Handler()` signature extended: last parameter is `*ratelimit.Limiter` (nil = disabled)
