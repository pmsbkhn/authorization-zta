package pep

import (
	"encoding/json"
	"net/http"

	"github.com/pmsbkhn/authorization-zta/internal/authz/authzen"
)

// Middleware wraps a protected handler with this PEP's enforcement. The mapping
// from Outcome to HTTP status is profile-specific — this is where the cross-PEP
// "bubble-up" pattern (design-v3 §4) lives:
//
//   - East-West / Partner PEP on step-up → 403 + X-Step-Up-Required. The deep
//     service has no user session, so it refuses and signals upstream instead of
//     trying to challenge.
//   - Edge PEP on step-up → 401 challenge. The gateway is the only place with a
//     user session, so it (and only it) turns the requirement into an MFA prompt.
func (p *PEP) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := p.Check(r)
		w.Header().Set(HeaderCorrelationID, out.CorrelationID)

		switch out.Kind {
		case Allow:
			// Propagate identity context + decision token to the workload, and
			// echo the token back to the caller so it can replay it (within the
			// TTL) to take the PEP's fast-path on an identical follow-up request.
			r.Header.Set(HeaderCorrelationID, out.CorrelationID)
			if out.DecisionToken != "" {
				r.Header.Set(HeaderDecisionToken, out.DecisionToken)
				w.Header().Set(HeaderDecisionToken, out.DecisionToken)
			}
			p.log.Info("pep allow",
				"profile", string(p.cfg.Profile), "pep", p.cfg.PEPID,
				"correlation_id", out.CorrelationID, "path", r.URL.Path, "reason", out.ReasonCode)
			next.ServeHTTP(w, r)

		case DenyStepUp:
			// Always advertise the requirement so it can bubble up the chain.
			w.Header().Set(HeaderStepUpRequired, out.RequiredACR)
			if p.cfg.Profile == authzen.ProfileEdge {
				p.log.Info("pep step-up challenge", "correlation_id", out.CorrelationID, "required_acr", out.RequiredACR)
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error":        "step_up_required",
					"required_acr": out.RequiredACR,
					"method":       "mfa",
				})
				return
			}
			p.log.Info("pep step-up bubble-up", "profile", string(p.cfg.Profile),
				"correlation_id", out.CorrelationID, "required_acr", out.RequiredACR)
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":        "step_up_required",
				"required_acr": out.RequiredACR,
			})

		case DropL0:
			p.log.Warn("pep L0 drop", "correlation_id", out.CorrelationID, "reason", out.ReasonCode)
			writeJSON(w, http.StatusForbidden, map[string]any{"error": out.ReasonCode})

		default: // DenyRoute, DenyForbidden
			p.log.Info("pep deny", "profile", string(p.cfg.Profile),
				"correlation_id", out.CorrelationID, "reason", out.ReasonCode)
			writeJSON(w, http.StatusForbidden, map[string]any{"error": out.ReasonCode})
		}
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
