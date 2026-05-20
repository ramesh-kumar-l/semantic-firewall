# API Contracts

## V1 API — HTTP

### Base URL
`http://localhost:8080` (default, configurable)

---

### `POST /v1/inspect`

Inspects a prompt and returns a policy decision.

**Request:**
```json
{
  "request_id": "string (optional, UUID — generated if absent)",
  "model": "string (optional, e.g. 'gpt-4', 'claude-3')",
  "prompt": "string (required, the prompt text to inspect)",
  "context": {
    "caller_id": "string (optional)",
    "session_id": "string (optional)",
    "metadata": {}
  }
}
```

**Response (200 OK — allowed):**
```json
{
  "trace_id": "string (UUID)",
  "request_id": "string",
  "decision": "allow",
  "risk_score": 0.12,
  "findings": [],
  "latency_ms": 3,
  "timestamp": "2026-05-20T10:00:00Z"
}
```

**Response (200 OK — denied):**
```json
{
  "trace_id": "string (UUID)",
  "request_id": "string",
  "decision": "deny",
  "risk_score": 0.87,
  "findings": [
    {
      "type": "prompt_injection",
      "severity": "critical",
      "evidence": "Detected role override: 'ignore previous instructions'",
      "detector": "injection_detector_v1"
    }
  ],
  "latency_ms": 4,
  "timestamp": "2026-05-20T10:00:00Z"
}
```

**HTTP Status Codes:**
- `200` — inspection complete (check `decision` field for allow/deny)
- `400` — malformed request (missing required fields)
- `422` — prompt exceeds size limits
- `500` — internal error (firewall fails closed — treat as deny)

**Notes:**
- `500` MUST be treated as deny by callers
- `decision` field is the authoritative result — not HTTP status
- `trace_id` links to audit log and OTel trace

---

### `GET /health`

Liveness check.

**Response (200 OK):**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "uptime_seconds": 1234
}
```

---

### `GET /metrics`

Prometheus-compatible metrics (text format).
(Phase 1: stdout OTel export only; `/metrics` endpoint added in Phase 2)

---

## Shared Types

### `Decision`
```
"allow" | "deny" | "transform" | "alert"
```
- V1 implements: `allow`, `deny`
- V2 adds: `transform`, `alert`

### `Severity`
```
"info" | "low" | "medium" | "high" | "critical"
```

### `Finding`
```json
{
  "type": "string",
  "severity": "Severity",
  "evidence": "string",
  "detector": "string"
}
```

---

## Compatibility Guarantees

- V1 API is versioned under `/v1/` — breaking changes require new version prefix
- `decision`, `trace_id`, `risk_score`, `findings` are stable fields
- Additional fields may be added without version bump (additive only)
- Fields will never be removed from a versioned endpoint without a new version
