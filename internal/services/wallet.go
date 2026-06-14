package services

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/pmsbkhn/authorization-zta/internal/authzen"
	"github.com/pmsbkhn/authorization-zta/internal/mock"
	"github.com/pmsbkhn/authorization-zta/internal/pdpclient"
	"github.com/pmsbkhn/authorization-zta/internal/pep"
)

// WalletConfig configures the VSP Wallet workload + its East-West PEP.
type WalletConfig struct {
	PDPURL   string
	Attestor *mock.WorkloadAttestor // nil → default (any spiffe:// attested)
	Logger   *slog.Logger
	// RequirePeerSVID makes the East-West PEP demand a verified mTLS peer
	// certificate (set when the wallet is served over mTLS). When false, the
	// X-Vsp-Caller-Spiffe header stands in (dev mode).
	RequirePeerSVID bool
}

// WalletHandler builds the wallet service: POST /settle guarded by an East-West
// PEP. On step-up the PEP bubbles up (403 + X-Step-Up-Required) rather than
// challenging, because this deep service has no user session.
func WalletHandler(cfg WalletConfig) http.Handler {
	attestor := cfg.Attestor
	if attestor == nil {
		attestor = &mock.WorkloadAttestor{Revoked: map[string]bool{}}
	}
	guard := pep.New(pep.Config{
		Profile:         authzen.ProfileEastWest,
		PEPID:           "vsp-wallet-sidecar",
		PDP:             pdpclient.New(cfg.PDPURL),
		Attestor:        attestor,
		Logger:          cfg.Logger,
		RequirePeerSVID: cfg.RequirePeerSVID,
		Routes: []pep.Route{{
			Method:        http.MethodPost,
			Path:          "/settle",
			Action:        "wallet:settle",
			ResourceType:  "wallet:account",
			ResourceProps: []string{"amount", "currency"},
		}},
	})

	mux := http.NewServeMux()
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
