// Command wallet is the VSP Core Wallet workload, fronted by an East-West PEP.
// At the deep end of the call chain it has no user session: on a PDP step-up its
// PEP returns 403 + X-Step-Up-Required and lets the requirement bubble up.
//
// When SVID_* env is present it serves over mTLS and derives the caller's
// delegation identity from the verified peer certificate (L0). Otherwise it runs
// plain HTTP in dev mode, trusting the X-Vsp-Caller-Spiffe header.
package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/services"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("svc", "wallet")

	pdpURL := envOr("PDP_URL", "http://localhost:8080")
	addr := envOr("WALLET_ADDR", ":8082")

	tlsCfg, mtls, err := services.LoadServerTLS()
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}

	handler := services.WalletHandler(services.WalletConfig{
		PDPURL:          pdpURL,
		Logger:          log,
		RequirePeerSVID: mtls,
	})

	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}

	if mtls {
		srv.TLSConfig = tlsCfg
		log.Info("wallet listening (mTLS)", "addr", addr, "pdp", pdpURL)
		// Certs come from TLSConfig (SPIFFE SVID), so the file args are empty.
		err = srv.ListenAndServeTLS("", "")
	} else {
		log.Warn("wallet listening (PLAIN HTTP, dev mode — L0 trusts X-Vsp-Caller-Spiffe header)", "addr", addr, "pdp", pdpURL)
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
