package pep

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/authzen"
	"github.com/pmsbkhn/authorization-zta/internal/token"
)

// countingPDP records how many times it was consulted and always allows.
type countingPDP struct{ calls atomic.Int32 }

func (c *countingPDP) Evaluate(context.Context, authzen.Request) (authzen.Response, error) {
	c.calls.Add(1)
	return authzen.Response{Decision: true, Context: &authzen.ResponseContext{ReasonCode: "ok"}}, nil
}

func newReusePEP(pdp PDP, iss *token.Issuer) *PEP {
	return New(Config{
		Profile:       authzen.ProfileEdge,
		PEPID:         "test-edge",
		PDP:           pdp,
		TokenVerifier: iss,
		Routes: []Route{{
			Method: "POST", Path: "/pay",
			Action: "bill:pay", ResourceType: "bill:invoice",
			ResourceProps: []string{"amount", "currency"},
		}},
	})
}

// mintFor builds a token whose claims match the request the PEP will construct
// for the given amount.
func mintFor(t *testing.T, iss *token.Issuer, amount int) string {
	t.Helper()
	props := map[string]any{}
	body, _ := json.Marshal(map[string]any{"amount": amount, "currency": "VND"})
	_ = json.Unmarshal(body, &props)
	tok, err := iss.Issue(token.Claims{
		Subject:   "u-1",
		Action:    "bill:pay",
		Resource:  "bill:invoice/inv-1",
		AAL:       "AAL2",
		ResDigest: token.ResourceDigest(props),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

func doCheck(p *PEP, tok string, amount int) Outcome {
	body, _ := json.Marshal(map[string]any{"amount": amount, "currency": "VND"})
	r := httptest.NewRequest("POST", "/pay", bytes.NewReader(body))
	r.Header.Set("X-Vsp-Subject-Id", "u-1")
	r.Header.Set("X-Vsp-Aal", "AAL2")
	r.Header.Set("X-Vsp-Resource-Id", "inv-1")
	if tok != "" {
		r.Header.Set(HeaderDecisionToken, tok)
	}
	return p.Check(r)
}

func TestDecisionToken_SkipsPDPOnReuse(t *testing.T) {
	iss := token.NewIssuer([]byte("s"), 5*time.Minute)
	pdp := &countingPDP{}
	p := newReusePEP(pdp, iss)

	// No token → PDP consulted.
	if out := doCheck(p, "", 1_000_000); out.Kind != Allow {
		t.Fatalf("expected allow, got %v", out.Kind)
	}
	if pdp.calls.Load() != 1 {
		t.Fatalf("expected 1 PDP call, got %d", pdp.calls.Load())
	}

	// Valid matching token → PDP NOT consulted (fast-path).
	tok := mintFor(t, iss, 1_000_000)
	out := doCheck(p, tok, 1_000_000)
	if out.Kind != Allow || out.ReasonCode != "decision_token_reuse" {
		t.Fatalf("expected fast-path allow, got kind=%v reason=%q", out.Kind, out.ReasonCode)
	}
	if pdp.calls.Load() != 1 {
		t.Fatalf("fast-path must not call PDP; calls=%d", pdp.calls.Load())
	}
}

func TestDecisionToken_RejectedWhenAttributesChange(t *testing.T) {
	iss := token.NewIssuer([]byte("s"), 5*time.Minute)
	pdp := &countingPDP{}
	p := newReusePEP(pdp, iss)

	// Token minted for amount=1,000,000 but presented on a 9,000,000 request:
	// the resource digest differs, so the token is NOT honored and the PDP is
	// consulted (preventing low-value tokens from authorizing high-value calls).
	tok := mintFor(t, iss, 1_000_000)
	out := doCheck(p, tok, 9_000_000)
	if out.Kind != Allow {
		t.Fatalf("expected allow via PDP, got %v", out.Kind)
	}
	if out.ReasonCode == "decision_token_reuse" {
		t.Fatal("token must not be reused when resource attributes change")
	}
	if pdp.calls.Load() != 1 {
		t.Fatalf("expected PDP consulted on digest mismatch; calls=%d", pdp.calls.Load())
	}
}
