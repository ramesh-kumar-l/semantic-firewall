# Future Roadmap

## Phase 0 — Foundation (Current)
- Project memory bank
- Go module scaffold
- Core type definitions

## Phase 1 — Prompt Inspection Core
- HTTP server (chi)
- Prompt inspection middleware
- Rule-based semantic risk scorer
- Prompt injection + role override detector
- Basic policy engine (allow/deny)
- Append-only audit logger (JSON-L)
- OTel setup (stdout traces + metrics)

## Phase 2 — Policy Engine & Observability
- Full policy rule language (allow/deny/transform/alert)
- Policy rules loaded from YAML config
- Prometheus `/metrics` endpoint
- OTLP exporter support (pluggable)
- Log/slog → OTel log bridge
- Policy hot-reload

## Phase 3 — Transform & Alert Actions
- `transform` action: prompt sanitization / redaction
- `alert` action: webhook or structured alert emission
- Configurable response templates for denied requests
- Rate limiting (per caller_id / session_id)
- API authentication (API key middleware)

## Phase 4 — Advanced Detection
- Encoding-aware normalization (base64, rot13, unicode tricks)
- Semantic similarity detection (embedding-based, optional)
- Memory poisoning detection patterns
- Tool call inspection (structured JSON tool calls)
- Multi-turn context awareness

## Phase 5 — Multi-Agent Governance (Future)
- Agent identity and trust levels
- Inter-agent communication inspection
- Privilege escalation detection
- Agent behavior policy enforcement
- Trust score per agent over time

## Phase 6 — Enterprise & Scale
- Multi-tenant isolation
- Remote policy management API
- Distributed audit log (Kafka/S3)
- Horizontal scaling support
- RBAC for policy administration
- Compliance reporting (SOC2, ISO 27001 alignment)

## Phase 7 — AI Compliance Platform
- Runtime AI compliance framework
- Regulatory policy packs (GDPR, HIPAA, EU AI Act)
- Evidence collection for audits
- Integration with GRC platforms
- AI risk register

---

## Deferred Capabilities

The following are explicitly deferred and NOT in scope until later phases:

- Enterprise dashboards (Phase 6)
- ML-based risk scoring (Phase 4)
- Distributed policy orchestration (Phase 6)
- Billing / entitlements (Phase 6)
- RBAC platform (Phase 6)
- Complex control planes (Phase 6)
- Agent-to-agent governance (Phase 5)
- Real-time streaming inspection (Phase 4+)
