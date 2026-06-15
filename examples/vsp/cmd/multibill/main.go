// Command multibill is the Multi-Bill workload. It is both an mTLS server (the
// gateway authenticates to it) and an mTLS client (it authenticates to the
// wallet). POST /pay settles via the VSP Wallet over the East-West hop; the
// wallet derives the delegation actor from multibill's verified client cert.
// Without SVID_* / SPIFFE_ENDPOINT_SOCKET it runs plain HTTP in dev mode.
package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/pmsbkhn/authorization-zta/examples/vsp/app"
	"github.com/pmsbkhn/authorization-zta/internal/services"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("svc", "multibill")

	walletURL := envOr("WALLET_URL", "http://localhost:8082")
	selfSpiffe := envOr("MULTIBILL_SPIFFE", "spiffe://vsp.local/ns/billing/sa/multi-bill-svc")
	addr := envOr("MULTIBILL_ADDR", ":8081")

	serverTLS, serverMTLS, err := services.LoadServerTLS()
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
	clientTLS, clientMTLS, err := services.LoadClientTLS()
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	cfg := app.MultibillConfig{WalletURL: walletURL, SelfSpiffe: selfSpiffe, Logger: log, HTTPClient: client}
	if clientMTLS {
		client.Transport = &http.Transport{TLSClientConfig: clientTLS}
		cfg.SelfSpiffe = "" // identity travels in the client certificate, not a header
		log.Info("multibill → wallet over mTLS", "wallet", walletURL)
	} else {
		log.Warn("multibill → wallet over PLAIN HTTP (dev mode)", "wallet", walletURL, "spiffe", selfSpiffe)
	}

	srv := &http.Server{Addr: addr, Handler: app.MultibillHandler(cfg), ReadHeaderTimeout: 5 * time.Second}
	if serverMTLS {
		srv.TLSConfig = serverTLS
		log.Info("multibill listening (mTLS)", "addr", addr)
		err = srv.ListenAndServeTLS("", "")
	} else {
		log.Info("multibill listening (plain)", "addr", addr)
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
