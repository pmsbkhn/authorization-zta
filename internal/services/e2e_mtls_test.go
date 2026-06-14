package services_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/services"
	"github.com/pmsbkhn/authorization-zta/internal/spiffe"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	walletID    = "spiffe://vsp.local/ns/wallet/sa/vsp-wallet-svc"
	multibillID = "spiffe://vsp.local/ns/billing/sa/multi-bill-svc"
)

// mtlsChain wires the chain with the wallet served over real mTLS. The caller
// supplies the HTTP client multibill uses to reach the wallet, which is how each
// test varies the client-side certificate behaviour.
func mtlsChain(t *testing.T, ca *spiffe.CA, walletSVID *x509svid.SVID, multibillClient *http.Client) string {
	t.Helper()

	pdpH, err := services.PDPHandler(context.Background(), services.PDPConfig{TokenSecret: []byte("test")})
	if err != nil {
		t.Fatalf("pdp: %v", err)
	}
	pdp := httptest.NewServer(pdpH.Routes())
	t.Cleanup(pdp.Close)

	// Start the wallet over real mTLS. We build the listener manually rather than
	// httptest.StartTLS, which would inject its own self-signed cert and shadow
	// the SVID's GetCertificate when the client sends no SNI (IP dialling).
	walletSrv := &http.Server{
		Handler:   services.WalletHandler(services.WalletConfig{PDPURL: pdp.URL, RequirePeerSVID: true}),
		TLSConfig: spiffe.MTLSServerConfig(walletSVID, ca.Bundle()),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = walletSrv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = walletSrv.Close() })
	walletURL := "https://" + ln.Addr().String()

	multibill := httptest.NewServer(services.MultibillHandler(services.MultibillConfig{
		WalletURL:  walletURL, // https
		SelfSpiffe: "",        // identity travels in the client certificate
		HTTPClient: multibillClient,
	}))
	t.Cleanup(multibill.Close)

	gwH, err := services.GatewayHandler(services.GatewayConfig{PDPURL: pdp.URL, UpstreamURL: multibill.URL})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	gw := httptest.NewServer(gwH)
	t.Cleanup(gw.Close)
	return gw.URL
}

func mtlsClient(cfg *tls.Config) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// Happy path over mTLS: the delegation actor reaches the PDP via the verified
// client certificate (no X-Vsp-Caller-Spiffe header). A high-value payment at
// AAL2 still bubbles up a step-up; retried at AAL3 it settles. That the AAL2 call
// yields step_up (not request_invalid) proves the East-West "act" was populated
// from the peer SVID.
func TestE2E_MTLS_BubbleUpThenRetry(t *testing.T) {
	ca, err := spiffe.NewCA("vsp.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	walletSVID, _ := ca.Mint(walletID)
	mbSVID, _ := ca.Mint(multibillID)

	gw := mtlsChain(t, ca, walletSVID, mtlsClient(spiffe.MTLSClientConfig(mbSVID, ca.Bundle())))

	resp := pay(t, gw, "AAL2", 9_000_000)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 step-up over mTLS, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = pay(t, gw, "AAL3", 9_000_000)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on AAL3 retry over mTLS, got %d", resp.StatusCode)
	}
	if decode(t, resp)["settled"] != true {
		t.Error("expected settled=true")
	}
}

// L0 drop-connection: a caller with no client SVID never completes the TLS
// handshake (the server requires a client certificate), so it never reaches the
// PEP or PDP. multibill surfaces the dropped connection as 502 — the channel-
// level enforcement of design-v3 §2 ("sai → Drop connection ngay lập tức").
func TestE2E_MTLS_NoClientCertDroppedAtHandshake(t *testing.T) {
	ca, _ := spiffe.NewCA("vsp.local")
	walletSVID, _ := ca.Mint(walletID)

	// Client trusts the server CA but presents NO certificate of its own.
	noCert := mtlsClient(tlsconfig.TLSClientConfig(ca.Bundle(), tlsconfig.AuthorizeMemberOf(ca.TrustDomain())))
	gw := mtlsChain(t, ca, walletSVID, noCert)

	resp := pay(t, gw, "AAL3", 1_000_000)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 (TLS drop) for missing client SVID, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Step-Up-Required") != "" {
		t.Error("a dropped connection must not advertise a step-up")
	}
}

// A certificate minted by a foreign CA is rejected at the TLS handshake: it never
// reaches the PEP. multibill surfaces the failure as 502.
func TestE2E_MTLS_ForeignCARejectedAtHandshake(t *testing.T) {
	ca, _ := spiffe.NewCA("vsp.local")
	walletSVID, _ := ca.Mint(walletID)

	foreignCA, _ := spiffe.NewCA("vsp.local")
	foreignSVID, _ := foreignCA.Mint(multibillID) // same id, wrong issuer

	// Present the foreign cert but trust the real server CA, so only the client
	// cert is the problem.
	foreign := mtlsClient(spiffe.MTLSClientConfig(foreignSVID, ca.Bundle()))
	gw := mtlsChain(t, ca, walletSVID, foreign)

	resp := pay(t, gw, "AAL3", 1_000_000)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 (handshake rejected) for foreign-CA cert, got %d", resp.StatusCode)
	}
}
