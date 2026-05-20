# Current Phase

## Phase: 5 — Testing & Hardening

**Status:** Complete  
**Started:** 2026-05-20  
**Completed:** 2026-05-20

---

## Phase 5 Goals

- [x] Unit tests for all packages
  - `internal/normalize/normalizer_test.go` — 6 tests + fuzz target
  - `internal/detection/injection_test.go` — 7 tests (clean, role_override, jailbreak, prompt_injection, memory_poisoning, dedup, field validation)
  - `internal/detection/toolcall_test.go` — 6 tests (nil, simple, nested, multiple, invalid JSON, type filtering)
  - `internal/session/store_test.go` — 7 tests (unknown, update+get, turn count, max risk, copy, TTL eviction, stop idempotent)
  - `internal/scoring/scorer_test.go` — 6 tests (no findings, empty, critical, high, diminishing returns, bounds, severity ordering)
  - `internal/policy/engine_test.go` — 7 tests (critical/high deny, score threshold, at-threshold, default action, update rules, rule name)
  - `internal/transform/redactor_test.go` — 7 tests (no findings, empty, single, empty evidence, multiple occurrences, multiple findings, non-matching)
  - `internal/ratelimit/limiter_test.go` — 6 tests (within burst, deny over burst, independent keys, stop idempotent, no-TTL stop, allow after stop)
- [x] API key middleware tests: `internal/middleware/apikey_test.go` — 7 tests (bearer, X-API-Key, multiple keys, invalid, missing, no prefix, empty list)
- [x] Integration test: `internal/middleware/inspect_test.go` — 11 tests covering full `/v1/inspect` pipeline
  - Clean prompt → allow; injection → deny; tool call injection → deny
  - Missing prompt → 400; too large → 422; invalid body → 400; rate limited → 429
  - Custom deny message; findings not null; response content-type
- [x] Fuzz target: `FuzzNormalize` in `normalizer_test.go` (runs with `go test -fuzz=FuzzNormalize`)
- [x] `TestMain` in middleware package sets up shared telemetry provider (stdout exporter, initialized once per test binary)

## Phase 5 Key Decisions

- No `stretchr/testify` dependency — tests use standard `testing` package only
- Black-box tests (`package xxx_test`) throughout — no access to unexported symbols needed
- Session store TTL eviction tested with 50ms TTL to keep wall-clock time under ~200ms
- Integration test uses a `noopLogger` (in-memory discard) to avoid file system state
- `TestMain` in `middleware_test` package initializes OTel provider once; avoids global provider races across tests
- Fuzz seeds: clean prompt, base64 attack, ROT13, URL-encoded, zero-width, empty

## Test Coverage Summary

| Package | Tests | Notes |
|---------|-------|-------|
| normalize | 6 + fuzz | covers all 5 normalization paths |
| detection/injection | 7 | all finding types incl. memory_poisoning |
| detection/toolcall | 6 | incl. nested JSON, invalid input |
| session | 7 | incl. TTL eviction (real 50ms sleep) |
| scoring | 6 | severity ordering, bounds check |
| policy | 7 | incl. UpdateRules hot-swap |
| transform | 7 | incl. edge cases |
| ratelimit | 6 | incl. post-Stop behavior |
| middleware/apikey | 7 | both header formats |
| middleware/inspect | 11 | full pipeline integration |

## Next Phase: Phase 6 — Production Readiness (proposed)

### Phase 6 Goals (pending approval)
1. Dockerfile + multi-stage build
2. `config/config.example.yaml` → documented reference config
3. `docker-compose.yml` for local dev (firewall + Prometheus + Grafana)
4. Makefile with `build`, `test`, `fuzz`, `lint`, `docker` targets
5. Health check endpoint improvements (dependency status)
6. Graceful shutdown improvements (drain in-flight requests)

## Blockers

- Go 1.22+ must be installed to run tests
- `go mod tidy` required (resolve `golang.org/x/text` + any new test dependencies)
- `go test ./...` to verify all tests pass
- `go test -fuzz=FuzzNormalize ./internal/normalize/` to run fuzzer

## Notes

- Trace output from `stdouttrace` exporter appears in test output; this is acceptable
- The TTL eviction test in `session` uses `time.Sleep(ttl*3)` — will add ~150ms to test run time
