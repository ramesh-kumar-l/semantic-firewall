# Security Model

## Core Assumption

**All inputs are hostile until proven safe.**

The firewall sits at the trust boundary. Nothing arriving from the AI client side is trusted. Every prompt, parameter, and header is treated as potentially adversarial.

## Threat Model (V1)

### Primary Threats

| Threat | Description | Detection | Mitigation |
|--------|-------------|-----------|------------|
| Prompt Injection | Attacker embeds instructions to override system behavior | Pattern matching + heuristics | Deny on detection, audit |
| Role Override | "Ignore previous instructions", "You are now..." | Keyword + semantic patterns | Deny + critical finding |
| Jailbreak Attempt | Bypass safety via roleplay, hypotheticals, encoding tricks | Pattern rules + entropy | Score + policy decision |
| Semantic Exfiltration | Prompts designed to extract system prompt or data | N/A in V1 | Defer to V2 |
| Tool Abuse | Malformed tool calls designed to escape sandbox | N/A in V1 | Defer to V2 |
| Memory Poisoning | Injecting false context into long-term memory | N/A in V1 | Defer to V2 |
| Encoding Tricks | Unicode, base64, rot13 to bypass keyword detection | Normalization pre-analysis | Normalize + detect |

### Attack Surfaces

1. **Prompt payload** — primary attack surface in V1
2. **Request headers** — potential metadata injection (mitigated by strict parsing)
3. **Config file** — policy rules (trusted; file integrity not enforced in V1)
4. **Audit log** — append-only (no deletion API in V1)

## Trust Boundaries

```
[UNTRUSTED]                    [TRUSTED]
AI Client / User Prompt  -->   Semantic Firewall  -->  AI Backend
                               (trust root, V1)
```

- AI client: untrusted
- Firewall internals: trusted
- AI backend: trusted (post-firewall)
- Config/policy files: trusted (no remote policy in V1)

## Fail-Safe Principle

**Default action on any internal error: DENY**

- If risk scorer panics/errors → deny
- If policy engine fails → deny
- If audit logger fails → deny + log to stderr
- Never silently allow on error

## Enforcement Layers

### Layer 1: Input Validation
- Prompt size limits (configurable max bytes)
- Required field validation
- Content-type enforcement

### Layer 2: Normalization
- Unicode normalization (NFC)
- Whitespace collapsing
- Encoding detection (base64 hints, etc.)
- Applied BEFORE detection to prevent bypass

### Layer 3: Detection
- Injection patterns (curated rule set)
- Role override patterns
- Heuristic scoring (keyword density, override phrasing)

### Layer 4: Policy Enforcement
- Rules evaluated in order
- First matching rule wins (unless configured for cascade)
- Default rule: allow (configurable to deny)

### Layer 5: Audit
- Every request logged regardless of decision
- Audit record is immutable (append-only file in V1)
- Includes: full prompt hash (SHA-256), findings, decision, trace ID

## Security Assumptions (V1)

- Firewall process runs in a trusted environment
- Policy file is not remotely controlled (no SSRF surface)
- Audit log file is on trusted storage
- No authentication on the firewall API in V1 (network-level isolation assumed)
- Single-tenant in V1

## Known Limitations (V1)

- No semantic understanding (rule-based only, no ML)
- No authentication/authorization on the API
- No rate limiting
- No multi-tenant isolation
- Encoding-based bypasses may exist if normalization rules are incomplete

## Security Review Checklist

For every execution path:
- [ ] Does it handle hostile input without panicking?
- [ ] Does it fail closed on error?
- [ ] Is the decision audited?
- [ ] Is telemetry emitted?
- [ ] Are there injection vectors in the path?
