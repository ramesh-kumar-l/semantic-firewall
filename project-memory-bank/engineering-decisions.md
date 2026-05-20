# Engineering Decisions

## ADR-001: Go as Primary Language

**Date:** 2026-05-20  
**Status:** Accepted

**Context:**  
Need to choose between TypeScript and Go for the core platform.

**Decision:**  
Go.

**Rationale:**
- Strong runtime guarantees (no async edge cases, predictable GC at this scale)
- Security middleware is a natural fit (low-level control, strong typing)
- Fast binary startup — suitable for sidecar/proxy deployment
- Standard library is sufficient for most V1 needs
- Easier to reason about concurrency safety

**Rejected:** TypeScript — excellent for API velocity but Node.js event loop edge cases and weaker typing make it riskier for a security-critical path.

**Tradeoffs:**
- Slower initial development vs TypeScript
- Less LLM ecosystem tooling in Go vs Python/TS (acceptable — we're building infra, not calling LLMs directly)

---

## ADR-002: `net/http` + `chi` over Gin/Echo

**Date:** 2026-05-20  
**Status:** Accepted

**Context:**  
Need an HTTP routing/middleware solution.

**Decision:**  
`chi` v5 with standard `net/http`.

**Rationale:**
- Chi is idiomatic, lightweight, no magic
- Middleware chaining maps cleanly to the inspection pipeline
- Standard `net/http` compatibility — no framework lock-in
- Easy to test (standard http.Handler interface)

**Rejected:**
- Gin — more magic, slightly less idiomatic, larger surface area
- Echo — similar concerns, less community longevity guarantee

---

## ADR-003: JSON-L Append-Only File for Audit Log (V1)

**Date:** 2026-05-20  
**Status:** Accepted

**Context:**  
Need an audit log that is immutable and replayable.

**Decision:**  
Local append-only JSON-L file in V1.

**Rationale:**
- Simplest implementation that meets the immutability requirement
- Zero database dependencies in V1
- Easy to parse, stream, replay
- Clear upgrade path (swap writer interface → Kafka/S3/PG in V2)

**Rejected:**
- SQLite — adds query complexity, overkill for V1
- PostgreSQL — external dependency, premature in V1
- Embedded Kafka — massive complexity for V1 scope

**Known Limitation:** Not horizontally scalable (single file, single process). Acceptable in V1; addressed by async distributed writer in V2.

---

## ADR-004: Stdout OTel Export in V1

**Date:** 2026-05-20  
**Status:** Accepted

**Context:**  
Need to emit traces and metrics without mandating infrastructure.

**Decision:**  
`stdouttrace` + `stdoutmetric` exporters in V1.

**Rationale:**
- Zero infrastructure dependency
- Vendor-neutral (OTel SDK is the abstraction)
- OTLP exporter can be added in V2 with no code changes beyond exporter swap
- Works in any environment (CI, local dev, container)

---

## ADR-005: `log/slog` over `zap`/`zerolog`

**Date:** 2026-05-20  
**Status:** Accepted

**Context:**  
Need structured logging.

**Decision:**  
Standard library `log/slog` (Go 1.21+).

**Rationale:**
- Zero external dependency
- Structured JSON natively
- Adequate performance for V1 (not on the hot path in tight loops)
- Upgrade path to `zap` handler if performance becomes a concern

**Rejected:** `zap` — excellent library, but adding a dependency for functionality the stdlib now provides is not justified in V1.

---

## ADR-006: Rule-Based Scoring (No ML) in V1

**Date:** 2026-05-20  
**Status:** Accepted

**Context:**  
Need risk scoring that is reliable and deterministic.

**Decision:**  
Pure rule-based scoring with deterministic output.

**Rationale:**
- Deterministic: same input → same score (testable, auditable, replayable)
- No model dependency — no inference latency, no version drift
- Explainable: score factors can be enumerated
- ML-based scoring is a V3+ concern

**Tradeoff:** Less nuanced than ML — will miss sophisticated low-pattern attacks. Acceptable for V1 baseline.

---

## ADR-007: Fail-Closed on Any Internal Error

**Date:** 2026-05-20  
**Status:** Accepted

**Context:**  
Need to define error behavior for all internal failure modes.

**Decision:**  
Any unhandled error in the inspection pipeline → deny + 500 + audit.

**Rationale:**
- A security system that fails open on error is worse than no system
- Predictable failure mode is better than undefined behavior
- 500 is a valid signal for callers to handle (treat as deny)

**Only exception:** OTel export failure is non-fatal (telemetry loss is acceptable; blocking a valid request due to export failure is not).
