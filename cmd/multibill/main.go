// Command multibill is the Multi-Bill workload. POST /pay settles via the VSP
// Wallet over the East-West hop. When SVID_* env is present it calls the wallet
// over mTLS, presenting its own X509-SVID — the wallet derives the delegation
// actor from that verified certificate. Otherwise it falls back to stamping the
// X-Vsp-Caller-Spiffe header (dev mode).
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

	tlsCfg, mtls, err := services.LoadClientTLS()
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	cfg := services.MultibillConfig{WalletURL: walletURL, SelfSpiffe: selfSpiffe, Logger: log, HTTPClient: client}
	if mtls {
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		// Workload identity now travels in the client certificate, not a header.
		cfg.SelfSpiffe = ""
		log.Info("multibill calling wallet over mTLS", "wallet", walletURL)
	} else {
		log.Warn("multibill calling wallet over PLAIN HTTP (dev mode)", "wallet", walletURL, "spiffe", selfSpiffe)
	}

	handler := services.MultibillHandler(cfg)

	log.Info("multibill listening", "addr", addr)
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
