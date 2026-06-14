package services

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/pep"
)

// MultibillConfig configures the Multi-Bill workload.
type MultibillConfig struct {
	WalletURL  string
	SelfSpiffe string // delegation actor stamped on the East-West call
	Logger     *slog.Logger
	HTTPClient *http.Client
}

// MultibillHandler builds the Multi-Bill service: POST /pay settles via the
// wallet, propagating user identity and stamping its own SPIFFE id as the
// delegation actor. A step-up signalled by the wallet is bubbled up unchanged.
func MultibillHandler(cfg MultibillConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}

	pay := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		out, err := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.WalletURL+"/settle", bytes.NewReader(body))
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		out.Header.Set("Content-Type", "application/json")
		copyHeader(out, r, pep.HeaderSubjectID)
		copyHeader(out, r, pep.HeaderAAL)
		copyHeader(out, r, pep.HeaderResourceID)
		copyHeader(out, r, pep.HeaderCorrelationID)
		out.Header.Set(pep.HeaderCallerSpiffe, cfg.SelfSpiffe) // assert delegation actor

		resp, err := cfg.HTTPClient.Do(out)
		if err != nil {
			cfg.Logger.Error("wallet call failed", "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Bubble-up: relay a step-up requirement upstream verbatim.
		if su := resp.Header.Get(pep.HeaderStepUpRequired); su != "" {
			cfg.Logger.Info("bubbling up step-up from wallet", "required_acr", su,
				"correlation_id", r.Header.Get(pep.HeaderCorrelationID))
			w.Header().Set(pep.HeaderStepUpRequired, su)
		}
		if cid := resp.Header.Get(pep.HeaderCorrelationID); cid != "" {
			w.Header().Set(pep.HeaderCorrelationID, cid)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /pay", pay)
	mux.HandleFunc("GET /healthz", okHandler)
	return mux
}

func copyHeader(dst, src *http.Request, key string) {
	if v := src.Header.Get(key); v != "" {
		dst.Header.Set(key, v)
	}
}
