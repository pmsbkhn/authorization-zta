// Command pdp runs the VSP *reference* Control Plane PDP: the platform decision
// core (internal/services) with the VSP domain policy (examples/vsp/policies)
// layered onto the embedded framework via PDPConfig.ExtraModules. It mirrors the
// generic platform PDP (cmd/pdp) but ships the demo's wallet/bill rules so the
// example stack authorizes end to end without an external bundle store.
//
// A real adopter would instead run the generic cmd/pdp and supply its own domain
// policy (its own ExtraModules, or a compiled bundle pulled from S3).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pmsbkhn/authorization-zta/examples/vsp/app"
	"github.com/pmsbkhn/authorization-zta/internal/authz/api"
	"github.com/pmsbkhn/authorization-zta/internal/authz/grpcpdp"
	"github.com/pmsbkhn/authorization-zta/internal/services"
	authzenv1 "github.com/pmsbkhn/authorization-zta/proto/authzen/v1"
	"google.golang.org/grpc"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With("svc", "pdp")
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg := app.DemoPDPConfig(tokenSecret())
	cfg.TokenTTL = tokenTTL()
	cfg.Logger = log

	svc, err := services.PDPService(context.Background(), cfg)
	if err != nil {
		return err
	}

	// Optional gRPC endpoint (design-v3 §6.1), over mTLS when an SVID is available.
	if grpcAddr := os.Getenv("PDP_GRPC_ADDR"); grpcAddr != "" {
		ln, err := net.Listen("tcp", grpcAddr)
		if err != nil {
			return err
		}
		var opts []grpc.ServerOption
		if creds, mtls, err := services.PDPGRPCServerCreds(); err != nil {
			return err
		} else if mtls {
			opts = append(opts, creds)
			log.Info("PDP gRPC listening (mTLS)", "addr", grpcAddr)
		} else {
			log.Warn("PDP gRPC listening (PLAIN, dev mode)", "addr", grpcAddr)
		}
		gs := grpc.NewServer(opts...)
		authzenv1.RegisterAccessEvaluationServer(gs, grpcpdp.NewServer(svc))
		go func() {
			if err := gs.Serve(ln); err != nil {
				log.Error("grpc serve", "err", err)
			}
		}()
	}

	addr := envOr("PDP_ADDR", ":8080")
	log.Info("PDP HTTP listening", "addr", addr)
	srv := &http.Server{Addr: addr, Handler: api.NewHandler(svc, log).Routes(), ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
