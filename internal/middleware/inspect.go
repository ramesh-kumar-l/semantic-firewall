package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	fwerrors "github.com/ramesh152/semantic-firewall/pkg/errors"
	"github.com/ramesh152/semantic-firewall/pkg/types"

	"github.com/ramesh152/semantic-firewall/internal/audit"
	"github.com/ramesh152/semantic-firewall/internal/detection"
	"github.com/ramesh152/semantic-firewall/internal/policy"
	"github.com/ramesh152/semantic-firewall/internal/scoring"
	"github.com/ramesh152/semantic-firewall/internal/telemetry"
)

const (
	firewallVersion = "0.1.0"
	maxPromptBytes  = 65536
)

// Handler returns an http.HandlerFunc that inspects prompts.
func Handler(
	scorer scoring.Scorer,
	detector detection.Detector,
	engine policy.Engine,
	logger audit.Logger,
	tel *telemetry.Provider,
	instruments *telemetry.Instruments,
	inspectTimeout time.Duration,
	maxBytes int,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		ctx, cancel := context.WithTimeout(r.Context(), inspectTimeout)
		defer cancel()

		ctx, rootSpan := tel.StartSpan(ctx, telemetry.SpanInspect)
		defer rootSpan.End()

		req, httpCode, fwErr := parseRequest(r, maxBytes)
		if fwErr != nil {
			writeError(w, httpCode, fwErr)
			return
		}

		if req.RequestID == "" {
			req.RequestID = uuid.New().String()
		}
		traceID := uuid.New().String()

		telemetry.AttrSet(rootSpan,
			telemetry.AttrTraceID(traceID),
		)

		slog.InfoContext(ctx, "request.received",
			"trace_id", traceID,
			"request_id", req.RequestID,
			"prompt_length", len(req.Prompt),
		)

		// Normalize: trim excess whitespace; no encoding changes in V1.
		normalized := normalize(req.Prompt)

		// Score (findings-driven in V1; pass nil findings initially, then refine)
		// Detection must run before scoring so scorer can use findings.
		_, detectSpan := tel.StartSpan(ctx, telemetry.SpanDetect)
		findings, err := detector.Detect(ctx, normalized)
		detectSpan.End()
		if err != nil {
			handleInternalError(ctx, w, traceID, req.RequestID, err, logger, instruments, start)
			return
		}

		_, scoreSpan := tel.StartSpan(ctx, telemetry.SpanScore)
		riskScore, err := scorer.Score(ctx, normalized, findings)
		scoreSpan.End()
		if err != nil {
			handleInternalError(ctx, w, traceID, req.RequestID, err, logger, instruments, start)
			return
		}

		_, policySpan := tel.StartSpan(ctx, telemetry.SpanPolicyEvaluate)
		decision, ruleMatched, err := engine.Evaluate(ctx, riskScore, findings)
		policySpan.End()
		if err != nil {
			handleInternalError(ctx, w, traceID, req.RequestID, err, logger, instruments, start)
			return
		}

		latencyMs := time.Since(start).Milliseconds()

		telemetry.AttrSet(rootSpan,
			telemetry.AttrDecision(string(decision)),
			telemetry.AttrRiskScore(float64(riskScore)),
			telemetry.AttrFindingsCount(len(findings)),
			telemetry.AttrPromptHash(promptHash(normalized)),
			telemetry.AttrLatencyMs(latencyMs),
		)

		// Emit metrics.
		instruments.RecordRequest(ctx, string(decision), float64(riskScore), latencyMs)
		for _, f := range findings {
			instruments.RecordFinding(ctx, string(f.Type), string(f.Severity))
		}

		// Audit — written regardless of decision; fail closed if write fails.
		auditRec := types.AuditRecord{
			TraceID:           traceID,
			RequestID:         req.RequestID,
			Timestamp:         time.Now().UTC(),
			PromptHash:        promptHash(normalized),
			PromptLength:      utf8.RuneCountInString(normalized),
			Model:             req.Model,
			RiskScore:         riskScore,
			Findings:          safeFindings(findings),
			Decision:          decision,
			PolicyRuleMatched: ruleMatched,
			LatencyMs:         latencyMs,
			FirewallVersion:   firewallVersion,
		}
		if req.Context != nil {
			auditRec.CallerID = req.Context.CallerID
			auditRec.SessionID = req.Context.SessionID
		}

		_, auditSpan := tel.StartSpan(ctx, telemetry.SpanAuditWrite)
		writeErr := logger.Write(ctx, auditRec)
		auditSpan.End()
		if writeErr != nil {
			slog.ErrorContext(ctx, "audit.write.error",
				"trace_id", traceID,
				"error", writeErr.Error(),
			)
			writeError(w, http.StatusInternalServerError,
				fwerrors.Wrap(fwerrors.CodeInternalError, "audit write failed", writeErr))
			return
		}

		if decision == types.DecisionDeny {
			slog.WarnContext(ctx, "request.denied",
				"trace_id", traceID,
				"risk_score", riskScore,
				"rule", ruleMatched,
				"findings", len(findings),
			)
		} else {
			slog.InfoContext(ctx, "request.processed",
				"trace_id", traceID,
				"decision", decision,
			)
		}

		resp := types.InspectResponse{
			TraceID:   traceID,
			RequestID: req.RequestID,
			Decision:  decision,
			RiskScore: riskScore,
			Findings:  safeFindings(findings),
			LatencyMs: latencyMs,
			Timestamp: time.Now().UTC(),
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func parseRequest(r *http.Request, maxBytes int) (*types.InspectRequest, int, *fwerrors.FirewallError) {
	if r.Method != http.MethodPost {
		return nil, http.StatusMethodNotAllowed,
			fwerrors.New(fwerrors.CodeInvalidInput, "method not allowed")
	}

	r.Body = http.MaxBytesReader(nil, r.Body, int64(maxBytes)+256)

	var req types.InspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, http.StatusBadRequest,
			fwerrors.Wrap(fwerrors.CodeInvalidInput, "invalid request body", err)
	}

	if req.Prompt == "" {
		return nil, http.StatusBadRequest,
			fwerrors.New(fwerrors.CodeInvalidInput, "prompt is required")
	}

	if len(req.Prompt) > maxBytes {
		return nil, http.StatusUnprocessableEntity,
			fwerrors.New(fwerrors.CodePromptTooLarge, fmt.Sprintf("prompt exceeds %d bytes", maxBytes))
	}

	return &req, 0, nil
}

func handleInternalError(
	ctx context.Context,
	w http.ResponseWriter,
	traceID, _ string,
	err error,
	logger audit.Logger,
	instruments *telemetry.Instruments,
	start time.Time,
) {
	slog.ErrorContext(ctx, "internal.error",
		"trace_id", traceID,
		"error", err.Error(),
	)
	instruments.RecordRequest(ctx, "deny", 1.0, time.Since(start).Milliseconds())
	writeError(w, http.StatusInternalServerError,
		fwerrors.Wrap(fwerrors.CodeInternalError, "inspection failed", err))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err *fwerrors.FirewallError) {
	writeJSON(w, code, err)
}

func normalize(s string) string {
	// V1: return as-is; normalization (unicode NFC, whitespace collapsing)
	// added in Phase 2 when encoding-trick detection is implemented.
	return s
}

func promptHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("sha256:%x", h)
}

func safeFindings(findings []types.Finding) []types.Finding {
	if findings == nil {
		return []types.Finding{}
	}
	return findings
}
