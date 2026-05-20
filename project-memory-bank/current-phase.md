# Current Phase

## Phase: 4 — Advanced Detection

**Status:** Complete  
**Started:** 2026-05-20  
**Completed:** 2026-05-20

---

## Phase 4 Goals

- [x] Encoding-aware normalization (`internal/normalize/normalizer.go`)
  - Zero-width / invisible Unicode character stripping
  - NFKC Unicode normalization (collapses homoglyphs via `golang.org/x/text`)
  - URL percent-encoding detection and decode
  - Base64 segment detection and decode (printable ASCII check)
  - ROT13 canary detection and full-string decode
- [x] Memory poisoning detection patterns (added to `internal/detection/patterns.go`)
  - `from_now_on`, `remember_you_must`, `new_default_behavior`, `store_in_memory`, `always_respond_with`, `whenever_user_asks`
  - New `FindingMemoryPoisoning` finding type
- [x] Tool call inspection (`internal/detection/toolcall.go`)
  - `ExtractToolCallText()` recursively extracts string values from `[]json.RawMessage`
  - Result passed to existing `InjectionDetector.Detect()` — no new interface needed
  - `ToolCalls []json.RawMessage` added to `types.InspectRequest`
- [x] Multi-turn context awareness (`internal/session/store.go`)
  - In-memory session registry with TTL eviction (same pattern as rate limiter)
  - `Get()` / `Update()` per session_id in request context
  - If `MaxRisk > 0.5` in prior turns: current risk escalated ×1.2 (capped at 1.0)
  - `SessionStore *session.Store` added to `Options` struct
  - `session.ttl_seconds` config key (default 3600, 0 = disabled)
- [x] New finding types: `FindingMemoryPoisoning`, `FindingToolCallInjection`
- [x] `golang.org/x/text v0.16.0` added to `go.mod`
- [x] Version bumped to `0.4.0`

## Phase 4 Key Decisions

- Normalizer runs before all detection; encoding findings prepended to findings list
- Tool call injection findings reuse `InjectionDetector` — no separate interface; any matched finding is labelled with detector name `injection_detector_v1`
- Session escalation: simple ×1.2 multiplier when prior MaxRisk > 0.5 (conservative; callers can tune via YAML rules threshold)
- Session store disabled when `ttl_seconds = 0` (no goroutine started, nil pointer passed)
- `normalize.Normalize()` replaces the stub `normalize()` function in `inspect.go`

## Breaking Changes from Phase 3

- `golang.org/x/text` added to `go.mod` — `go mod tidy` required before build
- `firewallVersion` constant in middleware: `"0.4.0"`
- `Options.SessionStore *session.Store` added (nil-safe; no callers break)
- `types.InspectRequest.ToolCalls []json.RawMessage` added (nil-safe; no callers break)

## Next Phase: Phase 5 — Testing & Hardening (proposed)

### Phase 5 Goals
1. Unit tests for all packages (normalize, detection, session, scoring, policy, transform, alert)
2. Integration test for the full `/v1/inspect` pipeline
3. Fuzz target for normalize.Normalize()
4. Benchmark for hot path (detection + scoring)

## Blockers

- Go 1.22+ must be installed before building
- `go mod tidy` required after Phase 4 (new `golang.org/x/text` dependency)
- `go.sum` not yet generated

## Notes

- `golang.org/x/text v0.16.0` needed for `golang.org/x/text/unicode/norm` NFKC normalization
- Session store pattern mirrors `ratelimit.Limiter` (same TTL eviction logic)
