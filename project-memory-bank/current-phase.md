# Current Phase

## Phase: 0 — Foundation & Scaffolding

**Status:** In Progress  
**Started:** 2026-05-20

---

## Active Milestone

Set up project-memory-bank, establish Go module structure, scaffold core packages for Phase 1 implementation.

## Phase Goals

- [x] Create all 12 project-memory-bank files
- [ ] Initialize Go module (`go mod init`)
- [ ] Scaffold directory structure
- [ ] Define core shared types (`pkg/types`)
- [ ] Define error types (`pkg/errors`)
- [ ] Create `cmd/server/main.go` stub
- [ ] Set up `go.sum` with initial dependencies

## In-Progress Tasks

- Scaffolding memory bank (in progress)

## Next Phase: Phase 1 — Prompt Inspection Core

### Phase 1 Goals
1. HTTP server with health endpoint
2. Prompt inspection middleware (inline intercept)
3. Semantic risk scorer (deterministic, rule-based v1)
4. Prompt injection detector (pattern + heuristic)
5. Basic policy engine (allow / deny / transform / alert actions)
6. Structured audit logger (append-only, JSON-L)
7. OpenTelemetry setup (traces + metrics)

### Phase 1 Entry Criteria
- Phase 0 scaffold complete and committed
- Go module initialized
- Core types defined

## Blockers

None.

## Notes

Language decision: **Go** (chosen for runtime guarantees, performance, security middleware fit).
