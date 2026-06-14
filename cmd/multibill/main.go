// Command multibill is the Multi-Bill workload. POST /pay settles via the VSP
// Wallet over the East-West hop: it stamps its own SPIFFE id as the delegation
// actor and bubbles up any X-Step-Up-Required the wallet returns.
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
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("svc", "multibill")

	walletURL := envOr("WALLET_URL", "http://localhost:8082")
	selfSpiffe := envOr("MULTIBILL_SPIFFE", "spiffe://vsp.local/ns/billing/sa/multi-bill-svc")
	addr := envOr("MULTIBILL_ADDR", ":8081")

	handler := services.MultibillHandler(services.MultibillConfig{
		WalletURL:  walletURL,
		SelfSpiffe: selfSpiffe,
		Logger:     log,
	})

	log.Info("multibill listening", "addr", addr, "wallet", walletURL, "spiffe", selfSpiffe)
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
