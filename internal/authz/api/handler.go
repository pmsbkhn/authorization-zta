// Package api is the AuthZEN 1.0 facade: the HTTP surface that PEPs call. It
// hides the PDP/OPA internals behind the standard Access Evaluation endpoint and
// is the only component that speaks HTTP, keeping transport concerns out of the
// decision core.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/pmsbkhn/authorization-zta/internal/authz/authzen"
)

// Evaluator is the decision dependency the facade calls (pdp.Service satisfies it).
type Evaluator interface {
	Evaluate(ctx context.Context, req authzen.Request) (authzen.Response, error)
}

// Handler is the HTTP facade.
type Handler struct {
	eval Evaluator
	log  *slog.Logger
}

// NewHandler builds the facade over an Evaluator.
func NewHandler(eval Evaluator, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{eval: eval, log: log}
}

// Routes returns the configured mux. The Access Evaluation path follows the
// AuthZEN 1.0 API ("/access/v1/evaluation"); design-v3 sketches it as "/eval".
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /access/v1/evaluation", h.handleEvaluation)
	mux.HandleFunc("GET /healthz", h.handleHealth)
	return mux
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) handleEvaluation(w http.ResponseWriter, r *http.Request) {
	var req authzen.Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	resp, err := h.eval.Evaluate(r.Context(), req)
	if err != nil {
		var ve *authzen.ValidationError
		if errors.As(err, &ve) {
			// Contract violation: tell the caller exactly what was wrong.
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":  "contract_violation",
				"issues": ve.Issues,
			})
			return
		}
		// Anything else is an internal failure; never leak details to the PEP.
		h.log.Error("evaluation failed", "correlation_id", req.CorrelationID(), "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "evaluation failed")
		return
	}

	h.log.Info("decision",
		"correlation_id", req.CorrelationID(),
		"profile", string(req.AuthZProfile()),
		"action", req.Action.Name,
		"resource", req.Resource.Type,
		"pep", req.PEPID(),
		"allow", resp.Decision,
	)
	writeJSON(w, http.StatusOK, resp)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
