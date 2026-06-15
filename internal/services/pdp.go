// Package services holds the reusable platform wiring an adopter composes a
// Control Plane / PEP from: building the PDP decision core (PDPService /
// PDPHandler), mTLS material from the SVID source (mtls.go) and the gRPC PDP
// transport (grpc.go). It is deliberately free of any business workload; the
// reference VSP workloads (gateway / multibill / wallet) live under
// examples/vsp/app and consume this package.
package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/authz/api"
	"github.com/pmsbkhn/authorization-zta/internal/authz/engine"
	"github.com/pmsbkhn/authorization-zta/internal/authz/pdp"
	"github.com/pmsbkhn/authorization-zta/internal/authz/token"
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
	// ExtraModules / ExtraData let an adopter layer its own domain policy (Rego
	// modules keyed by path + base data) on top of the embedded framework policies
	// (vsp.global / vsp.lib / vsp.profiles / vsp.authz). This is the in-process
	// extension point a system uses to supply its `vsp.domain.<x>` rules without
	// forking the core; production typically pulls a full compiled Bundle instead.
	// Ignored when Bundle is set.
	ExtraModules map[string]string
	ExtraData    map[string]any
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
		// Layer the adopter's domain policy + data over the framework.
		for k, v := range cfg.ExtraModules {
			mods[k] = v
		}
		for k, v := range cfg.ExtraData {
			data[k] = v
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
