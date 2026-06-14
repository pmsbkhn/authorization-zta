// Command pdp runs the VSP Control Plane: the AuthZEN 1.0 facade in front of an
// embedded OPA decision engine.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/services"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With("svc", "pdp")

	handler, err := services.PDPHandler(context.Background(), services.PDPConfig{
		TokenSecret: tokenSecret(),
		TokenTTL:    tokenTTL(),
		Logger:      log,
	})
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}

	addr := envOr("PDP_ADDR", ":8080")
	log.Info("PDP listening", "addr", addr)
	srv := &http.Server{Addr: addr, Handler: handler.Routes(), ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func tokenSecret() []byte {
	if s := os.Getenv("PDP_TOKEN_SECRET"); s != "" {
		return []byte(s)
	}
	return []byte("dev-insecure-secret-change-me") // production MUST set PDP_TOKEN_SECRET
}

func tokenTTL() time.Duration {
	if s := os.Getenv("PDP_TOKEN_TTL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return 300 * time.Second
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
