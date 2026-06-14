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
}

// PDPHandler builds the AuthZEN facade over an embedded OPA engine. Policy
// compilation happens here, so a bad bundle fails at construction.
func PDPHandler(ctx context.Context, cfg PDPConfig) (*api.Handler, error) {
	mods, err := policies.Modules()
	if err != nil {
		return nil, err
	}
	data, err := policies.Data()
	if err != nil {
		return nil, err
	}
	eng, err := engine.New(ctx, mods, data, engine.DefaultDecisionQuery)
	if err != nil {
		return nil, err
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 300 * time.Second
	}
	issuer := token.NewIssuer(cfg.TokenSecret, cfg.TokenTTL)
	return api.NewHandler(pdp.New(eng, issuer), cfg.Logger), nil
}
