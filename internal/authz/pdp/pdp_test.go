package pdp_test

import (
	"context"
	"testing"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/authz/authzen"
	"github.com/pmsbkhn/authorization-zta/internal/authz/engine"
	"github.com/pmsbkhn/authorization-zta/internal/authz/pdp"
	"github.com/pmsbkhn/authorization-zta/internal/authz/token"
	"github.com/pmsbkhn/authorization-zta/internal/testsupport/policyfixture"
)

func newService(t *testing.T) (*pdp.Service, *token.Issuer) {
	t.Helper()
	mods, err := policyfixture.Modules()
	if err != nil {
		t.Fatalf("modules: %v", err)
	}
	data, err := policyfixture.Data()
	if err != nil {
		t.Fatalf("data: %v", err)
	}
	eng, err := engine.New(context.Background(), mods, data, engine.DefaultDecisionQuery)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	iss := token.NewIssuer([]byte("test-secret"), 5*time.Minute)
	return pdp.New(eng, iss), iss
}

func edgeSettleReq(aal string, amount int) authzen.Request {
	return authzen.Request{
		Subject:  authzen.Subject{Type: "user", ID: "u-1", Properties: map[string]any{"auth_assurance_level": aal}},
		Action:   authzen.Action{Name: "acct:settle", Properties: map[string]any{"method": "POST"}},
		Resource: authzen.Resource{Type: "acct:wallet", ID: "acc-1", Properties: map[string]any{"amount": amount, "currency": "VND"}},
		Context:  map[string]any{"authz_profile": "edge", "source_ip": "10.0.0.1", "correlation_id": "t-42"},
	}
}

func TestEvaluate_AllowMintsVerifiableToken(t *testing.T) {
	svc, iss := newService(t)

	resp, err := svc.Evaluate(context.Background(), edgeSettleReq("AAL3", 9_000_000))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected allow, got deny")
	}
	if resp.Context == nil || resp.Context.DecisionToken == nil {
		t.Fatal("allow must carry a decision_token")
	}
	if resp.Context.DecisionToken.TTLSeconds != 300 {
		t.Errorf("ttl = %d, want 300", resp.Context.DecisionToken.TTLSeconds)
	}
	claims, err := iss.Verify(resp.Context.DecisionToken.Value)
	if err != nil {
		t.Fatalf("decision token must verify: %v", err)
	}
	if claims.Subject != "u-1" || claims.Action != "acct:settle" || claims.AAL != "AAL3" {
		t.Fatalf("token claims mismatch: %+v", claims)
	}
}

func TestEvaluate_DenyCarriesStepUpNoToken(t *testing.T) {
	svc, _ := newService(t)

	resp, err := svc.Evaluate(context.Background(), edgeSettleReq("AAL2", 9_000_000))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision {
		t.Fatal("expected deny for AAL2 high-value")
	}
	if resp.Context.DecisionToken != nil {
		t.Fatal("deny must not carry a decision_token")
	}
	if resp.Context.ReasonCode != "step_up_required" {
		t.Errorf("reason = %q, want step_up_required", resp.Context.ReasonCode)
	}
	found := false
	for _, ob := range resp.Context.Obligations {
		if ob.Type == authzen.ObligationStepUp && ob.Details["required_acr"] == "AAL3" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected step_up→AAL3 obligation, got %+v", resp.Context.Obligations)
	}
}

func TestEvaluate_InvalidContractIsError(t *testing.T) {
	svc, _ := newService(t)
	bad := edgeSettleReq("AAL3", 9_000_000)
	bad.Action.Name = "settle" // breaks <domain>:<action>

	_, err := svc.Evaluate(context.Background(), bad)
	if err == nil {
		t.Fatal("expected validation error for malformed action name")
	}
	var ve *authzen.ValidationError
	if !asValidationError(err, &ve) {
		t.Fatalf("expected *authzen.ValidationError, got %T", err)
	}
}

func asValidationError(err error, target **authzen.ValidationError) bool {
	for err != nil {
		if ve, ok := err.(*authzen.ValidationError); ok {
			*target = ve
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
