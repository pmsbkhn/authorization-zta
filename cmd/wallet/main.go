// Command wallet is the VSP Core Wallet workload, fronted by an East-West PEP.
// At the deep end of the call chain it has no user session: on a PDP step-up its
// PEP returns 403 + X-Step-Up-Required and lets the requirement bubble up.
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

	handler := services.WalletHandler(services.WalletConfig{PDPURL: pdpURL, Logger: log})

	log.Info("wallet listening", "addr", addr, "pdp", pdpURL)
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
