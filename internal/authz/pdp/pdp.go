// Package pdp is the Policy Decision Point: the orchestration layer behind the
// AuthZEN facade. It validates the VSP Standard Contract, evaluates the request
// against a policy engine, mints a decision token on allow, and assembles the
// AuthZEN response (decision + obligations + token).
//
// It depends on the engine through an interface so the decision backend (OPA
// today, a Zanzibar-style ReBAC engine tomorrow — design-v3 §6.3) can be swapped
// without touching the facade or the contract.
package pdp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pmsbkhn/authorization-zta/internal/authz/authzen"
	"github.com/pmsbkhn/authorization-zta/internal/authz/engine"
	"github.com/pmsbkhn/authorization-zta/internal/authz/token"
)

// Engine is the decision backend the PDP routes to. engine.Engine satisfies it.
type Engine interface {
	Eval(ctx context.Context, input any) (engine.Decision, error)
}

// Service is the unified router / PDP. Safe for concurrent use.
type Service struct {
	engine Engine
	issuer *token.Issuer
}

// New wires a PDP from a decision engine and a decision-token issuer.
func New(e Engine, issuer *token.Issuer) *Service {
	return &Service{engine: e, issuer: issuer}
}

// Evaluate runs the full AuthZEN access-evaluation pipeline for one request.
//
// Validation failures are returned as an error (the facade maps them to HTTP
// 400). A well-formed request that policy denies is NOT an error — it returns a
// Response with Decision == false, which is the normal Zero Trust outcome.
func (s *Service) Evaluate(ctx context.Context, req authzen.Request) (authzen.Response, error) {
	if err := req.Validate(); err != nil {
		return authzen.Response{}, err
	}

	// Convert to a plain map so the policy engine sees exactly the JSON shape the
	// contract specifies, regardless of Go struct details.
	input, err := toInput(req)
	if err != nil {
		return authzen.Response{}, err
	}

	dec, err := s.engine.Eval(ctx, input)
	if err != nil {
		return authzen.Response{}, fmt.Errorf("pdp: engine eval: %w", err)
	}

	return s.assemble(req, dec)
}

// assemble turns an engine Decision into the AuthZEN response, attaching a
// decision token on allow and mapping obligations onto the contract.
func (s *Service) assemble(req authzen.Request, dec engine.Decision) (authzen.Response, error) {
	rc := &authzen.ResponseContext{
		ReasonCode:  dec.ReasonCode,
		Obligations: toObligations(dec.Obligations),
	}

	if dec.Allow {
		tok, err := s.issuer.Issue(token.Claims{
			Subject:       req.Subject.ID,
			Action:        req.Action.Name,
			Resource:      req.Resource.Type + "/" + req.Resource.ID,
			AAL:           req.Subject.AuthAssuranceLevel(),
			ResDigest:     token.ResourceDigest(req.Resource.Properties),
			CorrelationID: req.CorrelationID(),
		})
		if err != nil {
			return authzen.Response{}, fmt.Errorf("pdp: issuing decision token: %w", err)
		}
		rc.DecisionToken = &authzen.DecisionToken{
			Value:      tok,
			TTLSeconds: s.issuer.TTLSeconds(),
		}
	}

	return authzen.Response{Decision: dec.Allow, Context: rc}, nil
}

// toObligations maps the engine's raw obligation maps onto the typed contract.
func toObligations(raw []map[string]any) []authzen.Obligation {
	if len(raw) == 0 {
		return nil
	}
	out := make([]authzen.Obligation, 0, len(raw))
	for _, m := range raw {
		ob := authzen.Obligation{}
		if t, ok := m["type"].(string); ok {
			ob.Type = t
		}
		if d, ok := m["details"].(map[string]any); ok {
			ob.Details = d
		}
		out = append(out, ob)
	}
	return out
}

// toInput round-trips the request through JSON into a map[string]any, the shape
// OPA evaluates against.
func toInput(req authzen.Request) (map[string]any, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("pdp: marshal request: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("pdp: unmarshal request to map: %w", err)
	}
	return m, nil
}
