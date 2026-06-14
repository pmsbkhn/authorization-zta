// Command wallet is the VSP Core Wallet workload, fronted by an East-West PEP.
// At the deep end of the call chain it has no user session: on a PDP step-up its
// PEP returns 403 + X-Step-Up-Required and lets the requirement bubble up.
//
// When SVID_* env is present it serves over mTLS and derives the caller's
// delegation identity from the verified peer certificate (L0). Otherwise it runs
// plain HTTP in dev mode, trusting the X-Vsp-Caller-Spiffe header.
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
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("svc", "wallet")

	pdpURL := envOr("PDP_URL", "http://localhost:8080")
	addr := envOr("WALLET_ADDR", ":8082")

	tlsCfg, mtls, err := services.LoadServerTLS()
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}

	wcfg := services.WalletConfig{
		PDPURL:          pdpURL,
		Logger:          log,
		RequirePeerSVID: mtls,
		TokenSecret:     []byte(envOr("PDP_TOKEN_SECRET", "dev-insecure-secret-change-me")),
	}
	if s := os.Getenv("CAEP_SECRET"); s != "" {
		wcfg.CAEPSecret = []byte(s)
		log.Info("CAEP receiver enabled at POST /events")
	}
	// Prefer gRPC-over-mTLS to the PDP when configured.
	if grpcAddr := os.Getenv("PDP_GRPC_ADDR"); grpcAddr != "" {
		c, err := services.PDPGRPCClient(grpcAddr)
		if err != nil {
			log.Error("fatal", "err", err)
			os.Exit(1)
		}
		wcfg.PDP = c
		log.Info("wallet → PDP over gRPC/mTLS", "addr", grpcAddr)
	}
	handler := services.WalletHandler(wcfg)

	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}

	if mtls {
		srv.TLSConfig = tlsCfg
		log.Info("wallet listening (mTLS)", "addr", addr, "pdp", pdpURL)
		// Certs come from TLSConfig (SPIFFE SVID), so the file args are empty.
		err = srv.ListenAndServeTLS("", "")
	} else {
		log.Warn("wallet listening (PLAIN HTTP, dev mode — L0 trusts X-Vsp-Caller-Spiffe header)", "addr", addr, "pdp", pdpURL)
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
