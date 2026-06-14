// Package services holds the wiring for each VSP process (PDP, wallet, multibill,
// gateway) as constructor functions returning http.Handler. Keeping the wiring
// here — out of package main — lets the cmd/* binaries stay thin and lets the
// end-to-end test assemble the whole call chain in-process with httptest.
package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/api"
	"github.com/pmsbkhn/authorization-zta/internal/engine"
	"github.com/pmsbkhn/authorization-zta/internal/pdp"
	"github.com/pmsbkhn/authorization-zta/internal/token"
	"github.com/pmsbkhn/authorization-zta/policies"
)

// PDPConfig configures the Control Plane PDP.
type PDPConfig struct {
	TokenSecret []byte
	TokenTTL    time.Duration
	Logger      *slog.Logger
	// Bundle, when non-empty, is a compiled OPA bundle the PDP loads from the
	// policy store (S3) instead of the embedded policies — the GitOps pull path.
	Bundle []byte
}

// PDPService builds the decision core (embedded OPA engine + token issuer).
// Policy compilation happens here, so a bad bundle fails at construction. The
// returned service backs both the HTTP facade and the gRPC server.
func PDPService(ctx context.Context, cfg PDPConfig) (*pdp.Service, error) {
	var eng *engine.Engine
	var err error
	if len(cfg.Bundle) > 0 {
		// Pull-from-store path: run exactly the bundle CI published.
		eng, err = engine.NewFromBundle(ctx, cfg.Bundle, engine.DefaultDecisionQuery)
	} else {
		// Embedded path: policies baked into the binary.
		mods, derr := policies.Modules()
		if derr != nil {
			return nil, derr
		}
		data, derr := policies.Data()
		if derr != nil {
			return nil, derr
		}
		eng, err = engine.New(ctx, mods, data, engine.DefaultDecisionQuery)
	}
	if err != nil {
		return nil, err
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 300 * time.Second
	}
	return pdp.New(eng, token.NewIssuer(cfg.TokenSecret, cfg.TokenTTL)), nil
}

// PDPHandler builds the AuthZEN HTTP facade over the decision core.
func PDPHandler(ctx context.Context, cfg PDPConfig) (*api.Handler, error) {
	svc, err := PDPService(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return api.NewHandler(svc, cfg.Logger), nil
}
