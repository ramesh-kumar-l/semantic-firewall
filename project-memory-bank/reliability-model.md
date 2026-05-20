# Reliability Model

## Core Principle

**Fail closed. Fail explicitly. Fail observably.**

A security system that fails open is worse than no system. Every failure mode in Semantic Firewall must result in a predictable, audited, explicit outcome.

## Fault Tolerance

### Error Taxonomy

| Error Type | Behavior | Response |
|------------|----------|---------|
| Invalid input | Reject immediately | 400 + structured error |
| Prompt too large | Reject with limit info | 422 + max size |
| Scorer error | Fail closed → deny | 500 (internal), deny decision |
| Detector panic | Recover + fail closed | 500 (internal), deny decision |
| Policy engine error | Fail closed → deny | 500 (internal), deny decision |
| Audit write failure | Log to stderr + fail closed | 500 (internal), deny decision |
| OTel export failure | Non-fatal, continue | Log to stderr, request completes |

**OTel export failures are the ONLY non-fatal errors** — telemetry loss is acceptable; silently allowing a malicious prompt is not.

## Panic Recovery

Every HTTP handler wraps in a recover middleware.
Panics from any subsystem are caught, logged with stack trace, and result in a closed-fail 500 response.

```
[panic in any subsystem]
    → recover() in HTTP middleware
    → log ERROR with stack + trace_id
    → return 500 to caller
    → emit fail_closed metric
```

## Deterministic Behavior

### Risk Scoring
- Must be deterministic: same prompt → same score, every time
- No randomness in V1 scoring
- Score is a pure function of normalized prompt + rule set

### Detection
- Pattern matching is deterministic
- No probabilistic detection in V1
- Results reproducible from audit log

### Policy Evaluation
- Rules evaluated in declared order
- First-match wins (unless cascade configured)
- Policy evaluation is a pure function of findings + score + rules

## Retry Strategy (V1)

No retries in V1 — inspection is synchronous and single-attempt.
Rationale: retrying a failed security check on the same input is not meaningful. If the system fails, it fails closed and the caller can retry the original operation.

## Context Cancellation

All internal operations respect `context.Context`.
If the caller disconnects or times out:
- In-progress inspection is cancelled
- Partial audit record is written with `cancelled: true`
- No denial penalty applied (caller is responsible for retry behavior)

## Request Timeout

Configurable inspection timeout (default: 500ms).
If exceeded:
- Fail closed → deny
- Audit record written with `timeout: true`
- OTel span marked with timeout attribute

## Resiliency Principles

1. **Stateless inspection** — each request is independent; no shared mutable state between requests (except append-only audit log)
2. **No blocking I/O in hot path** — audit writes are synchronous but fast (local file in V1)
3. **Bounded memory** — prompt size limits prevent memory exhaustion
4. **Graceful shutdown** — server drains in-flight requests before exit (configurable drain timeout, default: 10s)

## Known Reliability Gaps (V1)

- Audit log write is synchronous — high throughput may create I/O bottleneck (acceptable in V1; async writer in V2)
- No circuit breaker on audit writer (added in V2 if needed)
- No request queue — direct HTTP, no backpressure (acceptable in V1)
- Single-process — no HA in V1 (stateless design enables horizontal scaling in V2)
