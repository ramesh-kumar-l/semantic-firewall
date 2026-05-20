# Current Phase

## Phase: 3 — Transform & Alert Actions

**Status:** Complete  
**Started:** 2026-05-20  
**Completed:** 2026-05-20

---

## Phase 3 Goals

- [x] `transform` action: prompt sanitization / redaction (`internal/transform/redactor.go`)
- [x] `alert` action: async webhook POST (`internal/alert/webhook.go`)
- [x] Configurable deny message: `policy.deny_message` in config → `message` field in response
- [x] API key authentication middleware (`internal/middleware/apikey.go`)
  - Accepts `Authorization: Bearer <key>` or `X-API-Key: <key>`
  - Constant-time comparison (`crypto/subtle`)
  - Applied per-route (protects `/v1/inspect` only)
- [x] Rate limiter TTL eviction: background cleanup goroutine, `Stop()` method
- [x] `Options` struct in `internal/middleware` (replaces long param list)
- [x] `CodeUnauthorized` error code added to `pkg/errors`
- [x] `SanitizedPrompt` and `Message` fields added to `types.InspectResponse`
- [x] `AuthConfig`, `AlertConfig`, `DenyMessage`, `TTLSeconds` added to `config/config.go`
- [x] `config/config.example.yaml` updated with new sections

## Phase 3 Key Decisions

- `transform` decision: redacts finding evidence strings with `[REDACTED]`; returns `sanitized_prompt` in response
- `alert` decision: fires async webhook POST (goroutine) with `AuditRecord` as payload; caller receives `decision: alert`
- All decisions return HTTP 200 — this is an inspection API, not a proxy; caller checks `decision` field
- API key auth is a chi middleware applied per-route (not global); `/health` and `/metrics` remain unauthenticated
- Rate limiter uses single write-lock (simplified from Phase 2 double-checked locking) to safely track `lastSeen`
- TTL eviction sweeps every `ttl/2` interval; 0 TTL = no eviction, no goroutine started
- `inspectmw.Handler()` now takes `Options` struct instead of individual params (breaking change from Phase 2)
- Version bumped to `0.3.0`

## Breaking Changes from Phase 2

- `inspectmw.Handler()` signature: now takes `Options` struct as last param (was: 3 individual params)
- `ratelimit.New()` signature: now takes `ttl time.Duration` as third param
- `firewallVersion` constant in middleware: `"0.3.0"`

## Next Phase: Phase 4 — Advanced Detection

### Phase 4 Goals
1. Encoding-aware normalization (base64, rot13, unicode tricks)
2. Semantic similarity detection (embedding-based, optional)
3. Memory poisoning detection patterns
4. Tool call inspection (structured JSON tool calls)
5. Multi-turn context awareness

## Blockers

- Go 1.22+ must be installed before building (`go mod tidy && go build ./...`)
- `go.sum` not yet generated (requires `go mod tidy` with network access)

## Notes

- `telemetry.New()` still takes `telemetry.Config` struct (unchanged from Phase 2)
- `inspectmw.APIKeyAuth()` is in the `middleware` package alongside `Handler()`
