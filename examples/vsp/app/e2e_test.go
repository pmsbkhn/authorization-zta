package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pmsbkhn/authorization-zta/examples/vsp/app"
	"github.com/pmsbkhn/zta-core/authz/pep"
	"github.com/pmsbkhn/zta-core/services"
	"github.com/pmsbkhn/zta-core/signals/caep"
	"github.com/pmsbkhn/zta-core/testsupport/mock"
)

// chain wires the whole data path in-process: client → gateway → multibill →
// wallet → pdp. It returns the gateway base URL and a cleanup func.
func chain(t *testing.T, walletCfg app.WalletConfig) string {
	t.Helper()

	pdpH, err := services.PDPHandler(context.Background(), app.DemoPDPConfig([]byte("test")))
	if err != nil {
		t.Fatalf("pdp: %v", err)
	}
	pdp := httptest.NewServer(pdpH.Routes())
	t.Cleanup(pdp.Close)

	walletCfg.PDPURL = pdp.URL
	wallet := httptest.NewServer(app.WalletHandler(walletCfg))
	t.Cleanup(wallet.Close)

	multibill := httptest.NewServer(app.MultibillHandler(app.MultibillConfig{
		WalletURL:  wallet.URL,
		SelfSpiffe: "spiffe://vsp.local/ns/billing/sa/multi-bill-svc",
	}))
	t.Cleanup(multibill.Close)

	gwH, err := app.GatewayHandler(app.GatewayConfig{PDPURL: pdp.URL, UpstreamURL: multibill.URL})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gw := httptest.NewServer(gwH)
	t.Cleanup(gw.Close)

	return gw.URL
}

// pay sends a user payment through the gateway at the given assurance level.
func pay(t *testing.T, gwURL, aal string, amount int) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"amount": amount, "currency": "VND"})
	req, _ := http.NewRequest(http.MethodPost, gwURL+"/pay", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(pep.HeaderSubjectID, "u-1")
	req.Header.Set(pep.HeaderAAL, aal)
	req.Header.Set(pep.HeaderResourceID, "inv-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pay: %v", err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &m)
	return m
}

// The headline scenario (design-v3 §4): a high-value payment at AAL2 is denied
// deep in the wallet, the step-up bubbles up to a 401 at the edge, and the same
// payment retried at AAL3 succeeds.
func TestE2E_BubbleUpStepUpThenRetrySucceeds(t *testing.T) {
	gw := chain(t, app.WalletConfig{})

	// AAL2, 9M VND → wallet demands AAL3; edge surfaces a 401 challenge.
	resp := pay(t, gw, "AAL2", 9_000_000)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 step-up challenge, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get(pep.HeaderStepUpRequired); got != "AAL3" {
		t.Errorf("X-Step-Up-Required = %q, want AAL3", got)
	}
	body := decode(t, resp)
	if body["error"] != "step_up_required" || body["required_acr"] != "AAL3" {
		t.Errorf("unexpected challenge body: %v", body)
	}

	// Retry the same payment at AAL3 → settles end to end.
	resp = pay(t, gw, "AAL3", 9_000_000)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on AAL3 retry, got %d", resp.StatusCode)
	}
	body = decode(t, resp)
	if body["settled"] != true {
		t.Errorf("expected settled=true, got %v", body)
	}
}

// Decision-token re-use: after the wallet allows a settlement once, multibill
// caches the decision token and replays it on an identical follow-up. We prove
// the PDP is genuinely bypassed by taking the PDP offline between calls: the
// repeat still settles (fast-path), while a *different* amount fails (it must
// consult the now-dead PDP). Direct multibill→wallet path isolates the hop.
func TestE2E_DecisionTokenReuseSurvivesPDPOutage(t *testing.T) {
	secret := []byte("test")
	pdpH, err := services.PDPHandler(context.Background(), app.DemoPDPConfig(secret))
	if err != nil {
		t.Fatalf("pdp: %v", err)
	}
	pdp := httptest.NewServer(pdpH.Routes())

	wallet := httptest.NewServer(app.WalletHandler(app.WalletConfig{
		PDPURL:      pdp.URL,
		TokenSecret: secret, // same secret as PDP → PEP can verify decision tokens
	}))
	t.Cleanup(wallet.Close)

	mb := httptest.NewServer(app.MultibillHandler(app.MultibillConfig{
		WalletURL:           wallet.URL,
		SelfSpiffe:          "spiffe://vsp.local/ns/billing/sa/multi-bill-svc", // dev header L0
		CacheDecisionTokens: true,
	}))
	t.Cleanup(mb.Close)

	// 1) PDP up: settles and caches the decision token.
	if resp := pay(t, mb.URL, "AAL3", 9_000_000); resp.StatusCode != http.StatusOK {
		t.Fatalf("first settle: expected 200, got %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// PDP outage.
	pdp.Close()

	// 2) Identical settle survives via the cached token (no PDP needed).
	if resp := pay(t, mb.URL, "AAL3", 9_000_000); resp.StatusCode != http.StatusOK {
		t.Fatalf("repeat settle should survive PDP outage via token re-use, got %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// 3) A different amount has no cached token, must consult the dead PDP → fails.
	if resp := pay(t, mb.URL, "AAL3", 1_000_000); resp.StatusCode == http.StatusOK {
		t.Fatal("a non-cached settlement must not succeed while the PDP is down")
	} else {
		resp.Body.Close()
	}
}

// CAEP continuous evaluation: after a session-revoked SET is pushed to the
// wallet's PEP, settlements for that subject are denied — even though the
// payment previously succeeded and a decision token would otherwise let it
// through (design-v3 §6.2).
func TestE2E_CAEPRevocationDeniesThroughChain(t *testing.T) {
	secret := []byte("test")
	caepSecret := []byte("caep-test")

	pdpH, err := services.PDPHandler(context.Background(), app.DemoPDPConfig(secret))
	if err != nil {
		t.Fatalf("pdp: %v", err)
	}
	pdp := httptest.NewServer(pdpH.Routes())
	t.Cleanup(pdp.Close)

	wallet := httptest.NewServer(app.WalletHandler(app.WalletConfig{
		PDPURL:      pdp.URL,
		TokenSecret: secret,
		CAEPSecret:  caepSecret,
	}))
	t.Cleanup(wallet.Close)

	mb := httptest.NewServer(app.MultibillHandler(app.MultibillConfig{
		WalletURL:  wallet.URL,
		SelfSpiffe: "spiffe://vsp.local/ns/billing/sa/multi-bill-svc",
	}))
	t.Cleanup(mb.Close)

	gwH, _ := app.GatewayHandler(app.GatewayConfig{PDPURL: pdp.URL, UpstreamURL: mb.URL})
	gw := httptest.NewServer(gwH)
	t.Cleanup(gw.Close)

	// Before revocation: settles fine.
	if resp := pay(t, gw.URL, "AAL3", 9_000_000); resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revocation settle: expected 200, got %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// Push a session-revoked SET to the wallet PEP.
	tx := caep.NewTransmitter(caep.NewSigner(caepSecret), []string{wallet.URL + "/events"})
	if err := tx.Emit(context.Background(), caep.Event{Type: caep.EventSessionRevoked, Subject: "u-1"}); err != nil {
		t.Fatalf("emit revocation: %v", err)
	}

	// After revocation: denied deep in the wallet, surfaced as 403.
	resp := pay(t, gw.URL, "AAL3", 9_000_000)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("post-revocation settle: expected 403, got %d", resp.StatusCode)
	}
}

// A low-value payment needs no step-up: AAL2 settles directly.
func TestE2E_LowValueDirectAllow(t *testing.T) {
	gw := chain(t, app.WalletConfig{})

	resp := pay(t, gw, "AAL2", 1_000_000)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if decode(t, resp)["settled"] != true {
		t.Error("expected settled=true for low-value AAL2 payment")
	}
}

// L0: the wallet's East-West PEP drops a call whose delegation actor (SVID) is
// not attested, before any policy evaluation.
func TestE2E_WalletL0RejectsRevokedCaller(t *testing.T) {
	revoked := "spiffe://vsp.local/ns/billing/sa/multi-bill-svc"
	gw := chain(t, app.WalletConfig{
		Attestor: &mock.WorkloadAttestor{Revoked: map[string]bool{revoked: true}},
	})

	// Even at AAL3 the wallet refuses: the caller's SVID is revoked at L0, so the
	// step-up bubbles up to a 401 is NOT what happens — it's a hard L0 deny (403)
	// that surfaces at the edge as a plain forbidden, not a challenge.
	resp := pay(t, gw, "AAL3", 1_000_000)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from L0 drop, got %d", resp.StatusCode)
	}
	if resp.Header.Get(pep.HeaderStepUpRequired) != "" {
		t.Error("L0 drop must not advertise a step-up")
	}
}
