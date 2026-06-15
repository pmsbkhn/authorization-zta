package engine_test

import (
	"context"
	"testing"

	"github.com/pmsbkhn/authorization-zta/internal/authz/engine"
	"github.com/pmsbkhn/authorization-zta/internal/testsupport/policyfixture"
)

// newEngine builds an engine from the real embedded bundle so the test exercises
// the same compilation path as production.
func newEngine(t *testing.T) *engine.Engine {
	t.Helper()
	mods, err := policyfixture.Modules()
	if err != nil {
		t.Fatalf("load modules: %v", err)
	}
	data, err := policyfixture.Data()
	if err != nil {
		t.Fatalf("load data: %v", err)
	}
	eng, err := engine.New(context.Background(), mods, data, engine.DefaultDecisionQuery)
	if err != nil {
		t.Fatalf("compile engine: %v", err)
	}
	return eng
}

func edgeSettle(aal string, amount int) map[string]any {
	return map[string]any{
		"subject":  map[string]any{"type": "user", "id": "u-1", "properties": map[string]any{"auth_assurance_level": aal}},
		"action":   map[string]any{"name": "acct:settle", "properties": map[string]any{"method": "POST"}},
		"resource": map[string]any{"type": "acct:wallet", "id": "acc-1", "properties": map[string]any{"amount": amount, "currency": "VND"}},
		"context":  map[string]any{"authz_profile": "edge", "source_ip": "10.0.0.1"},
	}
}

func TestEngine_HighValueRequiresAAL3(t *testing.T) {
	eng := newEngine(t)
	ctx := context.Background()

	d, err := eng.Eval(ctx, edgeSettle("AAL3", 9_000_000))
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !d.Allow {
		t.Fatalf("AAL3 high-value should allow, got deny (%s)", d.ReasonCode)
	}

	d, err = eng.Eval(ctx, edgeSettle("AAL2", 9_000_000))
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if d.Allow {
		t.Fatal("AAL2 high-value should deny")
	}
	if d.ReasonCode != "step_up_required" {
		t.Fatalf("reason = %q, want step_up_required", d.ReasonCode)
	}
	if !hasObligation(d.Obligations, "step_up") {
		t.Fatalf("expected step_up obligation, got %v", d.Obligations)
	}
}

func TestEngine_MissingRequiredAttributeDenies(t *testing.T) {
	eng := newEngine(t)
	input := edgeSettle("AAL3", 9_000_000)
	// Drop the required "currency" attribute.
	delete(input["resource"].(map[string]any)["properties"].(map[string]any), "currency")

	d, err := eng.Eval(context.Background(), input)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if d.Allow || d.ReasonCode != "request_invalid" {
		t.Fatalf("missing currency should be request_invalid deny, got allow=%v reason=%q", d.Allow, d.ReasonCode)
	}
}

func TestEngine_UnknownDomainDenies(t *testing.T) {
	eng := newEngine(t)
	input := map[string]any{
		"subject":  map[string]any{"type": "user", "id": "u-1", "properties": map[string]any{"auth_assurance_level": "AAL3"}},
		"action":   map[string]any{"name": "ghost:do"},
		"resource": map[string]any{"type": "ghost:thing", "id": "g-1", "properties": map[string]any{}},
		"context":  map[string]any{"authz_profile": "edge", "source_ip": "10.0.0.1"},
	}
	d, err := eng.Eval(context.Background(), input)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if d.Allow || d.ReasonCode != "unknown_domain" {
		t.Fatalf("unknown domain should deny with unknown_domain, got allow=%v reason=%q", d.Allow, d.ReasonCode)
	}
}

func hasObligation(obs []map[string]any, typ string) bool {
	for _, o := range obs {
		if o["type"] == typ {
			return true
		}
	}
	return false
}
