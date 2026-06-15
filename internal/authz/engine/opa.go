// Package engine embeds the Open Policy Agent (OPA) as a library. It compiles
// the hierarchical Rego bundle once at startup, then evaluates each AuthZEN
// request against a single decision entrypoint. Embedding (rather than calling a
// sidecar over HTTP) keeps L2 evaluation in-process and removes a network hop
// from the hot path.
package engine

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// DefaultDecisionQuery is the single Rego entrypoint the PDP evaluates. The
// hierarchical policies (global → profiles → domain) all compose into this one
// document so the Go side never needs to know the policy layout.
const DefaultDecisionQuery = "data.vsp.authz.decision"

// Decision is the engine's normalized view of a policy result. It is policy-
// engine agnostic on purpose: swapping OPA for another PDP backend later only
// requires producing this struct.
type Decision struct {
	// Allow is the final boolean authorization decision.
	Allow bool
	// Obligations are side-effects the PEP must fulfil (step_up, log, ...),
	// returned verbatim from policy as ordered maps.
	Obligations []map[string]any
	// ReasonCode is a machine-readable explanation (esp. on deny).
	ReasonCode string
}

// Engine holds a prepared, reusable Rego query. It is safe for concurrent use:
// PreparedEvalQuery.Eval may be called from many goroutines.
type Engine struct {
	query rego.PreparedEvalQuery
}

// New compiles the given modules (keyed by module name) and base data document
// into a prepared query for `queryPath`. Compilation errors (syntax, unsafe
// vars, type errors) surface here, at startup, rather than per-request.
func New(ctx context.Context, modules map[string]string, data map[string]any, queryPath string) (*Engine, error) {
	if queryPath == "" {
		queryPath = DefaultDecisionQuery
	}

	opts := []func(*rego.Rego){
		rego.Query(queryPath),
		rego.Store(inmem.NewFromObject(data)),
	}
	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}

	r := rego.New(opts...)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("engine: preparing query %q: %w", queryPath, err)
	}
	return &Engine{query: pq}, nil
}

// Eval runs the prepared query with `input` (the AuthZEN request) bound as
// `input` inside Rego, and normalizes the result into a Decision.
//
// A missing/undefined decision document is treated as a hard deny: in Zero Trust
// the absence of an explicit allow is a denial, never an allow.
func (e *Engine) Eval(ctx context.Context, input any) (Decision, error) {
	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Decision{}, fmt.Errorf("engine: eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		// Undefined decision → deny (fail-closed).
		return Decision{Allow: false, ReasonCode: "policy_undefined"}, nil
	}

	val, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{}, fmt.Errorf("engine: decision document has unexpected type %T", rs[0].Expressions[0].Value)
	}
	return parseDecision(val), nil
}

// parseDecision converts the raw Rego decision object into a typed Decision,
// defaulting every field to its fail-closed zero value.
func parseDecision(val map[string]any) Decision {
	d := Decision{}
	if allow, ok := val["allow"].(bool); ok {
		d.Allow = allow
	}
	if rc, ok := val["reason_code"].(string); ok {
		d.ReasonCode = rc
	}
	if raw, ok := val["obligations"].([]any); ok {
		for _, item := range raw {
			if m, ok := item.(map[string]any); ok {
				d.Obligations = append(d.Obligations, m)
			}
		}
	}
	return d
}
