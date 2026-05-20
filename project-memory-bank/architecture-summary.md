# Architecture Summary

## High-Level Architecture (V1)

```
[AI Client / Agent]
        |
        | HTTP (proxy or inline middleware)
        v
+-------------------------+
|   Semantic Firewall     |
|   HTTP Gateway          |
|                         |
|  +-----------------+    |
|  | Inspection      |    |   <- inspects every request
|  | Middleware      |    |
|  +-----------------+    |
|          |              |
|  +-----------------+    |
|  | Risk Scorer     |    |   <- deterministic risk score (0.0–1.0)
|  +-----------------+    |
|          |              |
|  +-----------------+    |
|  | Injection       |    |   <- pattern + heuristic detection
|  | Detector        |    |
|  +-----------------+    |
|          |              |
|  +-----------------+    |
|  | Policy Engine   |    |   <- allow / deny / transform / alert
|  +-----------------+    |
|          |              |
|  +-----------------+    |
|  | Audit Logger    |    |   <- immutable append-only JSON-L
|  +-----------------+    |
|          |              |
|  +-----------------+    |
|  | OTel Emitter    |    |   <- traces, metrics, structured logs
|  +-----------------+    |
+-------------------------+
        |
        | (if allowed)
        v
[AI Backend / LLM API]
```

## Major Subsystems

### 1. HTTP Gateway (`cmd/server`)
- Entry point
- Routes: `/v1/inspect`, `/health`, `/metrics`
- Handles request lifecycle

### 2. Inspection Middleware (`internal/middleware`)
- Extracts prompt payload from request
- Orchestrates the inspection pipeline
- Returns allow/deny/transform decision + trace ID

### 3. Risk Scorer (`internal/scoring`)
- Deterministic rule-based scoring in V1
- Input: normalized prompt
- Output: RiskScore (0.0–1.0) + contributing factors

### 4. Injection Detector (`internal/detection`)
- Pattern-based detection (regex + rule sets)
- Heuristic scoring (entropy, override attempts, role injection)
- Returns: []Finding with severity + evidence

### 5. Policy Engine (`internal/policy`)
- Evaluates findings + risk score against policy rules
- Actions: Allow / Deny / Transform / Alert
- Rules are loaded from config (YAML/JSON)

### 6. Audit Logger (`internal/audit`)
- Append-only JSON-L writer
- Every request gets a complete audit record
- Includes: trace ID, timestamp, prompt hash, findings, decision, latency

### 7. Telemetry (`internal/telemetry`)
- OpenTelemetry SDK setup
- Span creation helpers
- Metrics: request count, risk score histogram, latency, deny rate

## Communication Patterns

- All internal calls are synchronous in V1 (single-process, no queues)
- Middleware chain: request → scorer → detector → policy → audit → response
- Telemetry is emitted at each stage via span attributes and metrics

## Runtime Flow

```
1. Request arrives at HTTP gateway
2. Inspection middleware extracts + normalizes prompt
3. Risk scorer assigns score (0.0–1.0)
4. Injection detector produces findings
5. Policy engine evaluates → decision
6. Audit logger writes immutable record
7. OTel emits span + metrics
8. Response returned (allow → proxy; deny → 403 + reason)
```

## Security Boundaries

- All external input treated as hostile
- Prompt normalization before analysis (prevent encoding tricks)
- Audit log is append-only (no delete/update operations)
- Deny is the default on error (fail-closed)

## Trust Model (V1)

- Firewall itself is the trust root
- AI backend is trusted (post-firewall)
- AI client is untrusted (pre-firewall)
- All policy decisions are logged with full context

## Deployment Model (V1)

Single Go binary, HTTP server, file-based audit log, stdout OTel export.
Can run as a sidecar, a standalone proxy, or embedded library.
