// Command pdp runs the VSP Control Plane: the AuthZEN 1.0 facade in front of an
// embedded OPA decision engine. It loads the hierarchical Rego bundle, wires the
// PDP and the (mocked) policy-information seams, and serves the Access
// Evaluation API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/api"
	"github.com/pmsbkhn/authorization-zta/internal/engine"
	"github.com/pmsbkhn/authorization-zta/internal/mock"
	"github.com/pmsbkhn/authorization-zta/internal/pdp"
	"github.com/pmsbkhn/authorization-zta/internal/token"
	"github.com/pmsbkhn/authorization-zta/policies"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx := context.Background()

	// 1. Load the embedded policy bundle and compile the OPA engine once.
	mods, err := policies.Modules()
	if err != nil {
		return err
	}
	data, err := policies.Data()
	if err != nil {
		return err
	}
	eng, err := engine.New(ctx, mods, data, engine.DefaultDecisionQuery)
	if err != nil {
		return err
	}
	log.Info("policy engine ready", "modules", len(mods), "query", engine.DefaultDecisionQuery)

	// 2. Document the (mocked) PIP seams. Not yet on the hot path in M1, but
	//    instantiated so the wiring points are explicit.
	store := &mock.PolicyStore{Bundle: nil, Version: "embedded"}
	if _, ver, err := store.LatestBundle(ctx); err == nil {
		log.Info("policy store seam ready (mock)", "bundle_version", ver)
	}
	_ = &mock.IdentityProvider{Subjects: map[string]map[string]any{}}
	_ = &mock.WorkloadAttestor{Revoked: map[string]bool{}}

	// 3. Decision token issuer.
	issuer := token.NewIssuer(tokenSecret(), tokenTTL())

	// 4. PDP + AuthZEN facade.
	service := pdp.New(eng, issuer)
	handler := api.NewHandler(service, log)

	addr := envOr("PDP_ADDR", ":8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Info("PDP listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func tokenSecret() []byte {
	if s := os.Getenv("PDP_TOKEN_SECRET"); s != "" {
		return []byte(s)
	}
	// Dev-only fallback; production MUST set PDP_TOKEN_SECRET.
	return []byte("dev-insecure-secret-change-me")
}

func tokenTTL() time.Duration {
	if s := os.Getenv("PDP_TOKEN_TTL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return 300 * time.Second // matches the design's 300s example
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
