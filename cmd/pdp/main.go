// Command pdp runs the VSP Control Plane: the decision core (embedded OPA)
// exposed over the AuthZEN HTTP facade and, optionally, a gRPC endpoint for the
// efficient internal data path (design-v3 §6.1).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/api"
	"github.com/pmsbkhn/authorization-zta/internal/bundlestore"
	"github.com/pmsbkhn/authorization-zta/internal/grpcpdp"
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
	cfg := services.PDPConfig{
		TokenSecret: tokenSecret(),
		TokenTTL:    tokenTTL(),
		Logger:      log,
	}
	// GitOps pull path: load the compiled bundle from the immutable S3 store.
	if ep := os.Getenv("S3_ENDPOINT"); ep != "" {
		store, err := bundlestore.New(bundlestore.Config{
			Endpoint:  ep,
			AccessKey: envOr("S3_ACCESS_KEY", "minioadmin"),
			SecretKey: envOr("S3_SECRET_KEY", "minioadmin"),
			Bucket:    envOr("S3_BUCKET", "vsp-policy-bundles"),
			Object:    envOr("S3_OBJECT", "bundle.tar.gz"),
		})
		if err != nil {
			return err
		}
		data, version, err := store.LatestBundle(context.Background())
		if err != nil {
			return err
		}
		cfg.Bundle = data
		log.Info("loaded policy bundle from S3", "bytes", len(data), "version", version)
	}

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
