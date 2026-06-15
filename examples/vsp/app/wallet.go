package app

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/pmsbkhn/zta-core/authz/authzen"
	"github.com/pmsbkhn/zta-core/authz/pdpclient"
	"github.com/pmsbkhn/zta-core/authz/pep"
	"github.com/pmsbkhn/zta-core/authz/token"
	"github.com/pmsbkhn/zta-core/signals/caep"
	"github.com/pmsbkhn/zta-core/testsupport/mock"
)

// WalletConfig configures the VSP Wallet workload + its East-West PEP.
type WalletConfig struct {
	PDPURL   string
	PDP      pep.PDP                // optional transport override (e.g. gRPC-over-mTLS); default HTTP
	Attestor *mock.WorkloadAttestor // nil → default (any spiffe:// attested)
	Logger   *slog.Logger
	// RequirePeerSVID makes the East-West PEP demand a verified mTLS peer
	// certificate (set when the wallet is served over mTLS). When false, the
	// X-Vsp-Caller-Spiffe header stands in (dev mode).
	RequirePeerSVID bool
	// TokenSecret, when set, enables decision-token re-use: the PEP verifies a
	// presented X-Decision-Token (HS256 with this secret, matching the PDP) and
	// skips the PDP for identical requests within the token TTL.
	TokenSecret []byte
	// CAEPSecret, when set, enables a CAEP receiver at POST /events: pushed
	// session-revoked SETs make the PEP deny the subject immediately, overriding
	// any still-valid decision token.
	CAEPSecret []byte
}

// WalletHandler builds the wallet service: POST /settle guarded by an East-West
// PEP. On step-up the PEP bubbles up (403 + X-Step-Up-Required) rather than
// challenging, because this deep service has no user session.
func WalletHandler(cfg WalletConfig) http.Handler {
	attestor := cfg.Attestor
	if attestor == nil {
		attestor = &mock.WorkloadAttestor{Revoked: map[string]bool{}}
	}
	var verifier pep.TokenVerifier
	if len(cfg.TokenSecret) > 0 {
		// TTL here is unused for verification (Verify reads exp from the token).
		verifier = token.NewIssuer(cfg.TokenSecret, time.Minute)
	}
	pdpClient := cfg.PDP
	if pdpClient == nil {
		pdpClient = pdpclient.New(cfg.PDPURL)
	}

	mux := http.NewServeMux()
	var revocations pep.RevocationChecker
	if len(cfg.CAEPSecret) > 0 {
		cache := caep.NewRevocationCache()
		mux.HandleFunc("POST /events", caep.NewReceiver(caep.NewSigner(cfg.CAEPSecret), cache).Handler())
		revocations = cache
	}

	guard := pep.New(pep.Config{
		Profile:         authzen.ProfileEastWest,
		PEPID:           "vsp-wallet-sidecar",
		PDP:             pdpClient,
		Attestor:        attestor,
		Logger:          cfg.Logger,
		RequirePeerSVID: cfg.RequirePeerSVID,
		TokenVerifier:   verifier,
		Revocations:     revocations,
		Routes: []pep.Route{{
			Method:        http.MethodPost,
			Path:          "/settle",
			Action:        "wallet:settle",
			ResourceType:  "wallet:account",
			ResourceProps: []string{"amount", "currency"},
		}},
	})

	mux.Handle("POST /settle", guard.Middleware(http.HandlerFunc(settle)))
	mux.HandleFunc("GET /healthz", okHandler)
	return mux
}

// settle is the protected workload; it runs only after the PEP allowed the call.
func settle(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"settled":  true,
		"amount":   body["amount"],
		"currency": body["currency"],
	})
}

func okHandler(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
