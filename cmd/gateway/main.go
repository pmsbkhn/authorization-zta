// Command gateway is the Edge PEP / API Gateway: the only PEP with a user
// session. It authorizes inbound user traffic (profile=edge), reverse-proxies to
// Multi-Bill, and converts a bubbled-up X-Step-Up-Required into a 401 MFA
// challenge so the client can re-authenticate and retry (design-v3 §4).
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
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("svc", "gateway")

	pdpURL := envOr("PDP_URL", "http://localhost:8080")
	upstreamURL := envOr("MULTIBILL_URL", "http://localhost:8081")
	addr := envOr("GATEWAY_ADDR", ":8088")

	handler, err := services.GatewayHandler(services.GatewayConfig{
		PDPURL:      pdpURL,
		UpstreamURL: upstreamURL,
		Logger:      log,
	})
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}

	log.Info("gateway listening", "addr", addr, "pdp", pdpURL, "upstream", upstreamURL)
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
