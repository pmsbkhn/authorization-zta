package grpcpdp_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/authz/engine"
	"github.com/pmsbkhn/authorization-zta/internal/authz/grpcpdp"
	"github.com/pmsbkhn/authorization-zta/internal/authz/pdp"
	"github.com/pmsbkhn/authorization-zta/internal/authz/token"
	"github.com/pmsbkhn/authorization-zta/internal/identity/spiffe"
	"github.com/pmsbkhn/authorization-zta/internal/testsupport/policyfixture"
	authzenv1 "github.com/pmsbkhn/authorization-zta/proto/authzen/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// startMTLSGRPCPDP runs the gRPC PDP behind mTLS using the server SVID and
// returns the listen address.
func startMTLSGRPCPDP(t *testing.T, ca *spiffe.CA) string {
	t.Helper()
	mods, _ := policyfixture.Modules()
	data, _ := policyfixture.Data()
	eng, err := engine.New(context.Background(), mods, data, engine.DefaultDecisionQuery)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	svc := pdp.New(eng, token.NewIssuer([]byte("t"), 5*time.Minute))

	serverSVID, _ := ca.Mint("spiffe://vsp.local/ns/pdp/sa/pdp-svc")
	creds := credentials.NewTLS(spiffe.MTLSServerConfig(serverSVID, ca.Bundle()))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	authzenv1.RegisterAccessEvaluationServer(srv, grpcpdp.NewServer(svc))
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().String()
}

func TestGRPCMTLS_AuthorizedClientSucceeds(t *testing.T) {
	ca, _ := spiffe.NewCA("vsp.local")
	addr := startMTLSGRPCPDP(t, ca)

	pepSVID, _ := ca.Mint("spiffe://vsp.local/ns/wallet/sa/vsp-wallet-svc")
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(spiffe.MTLSClientConfig(pepSVID, ca.Bundle()))))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	resp, err := grpcpdp.NewClient(conn).Evaluate(context.Background(), settle("AAL3", 9_000_000))
	if err != nil {
		t.Fatalf("evaluate over mTLS gRPC: %v", err)
	}
	if !resp.Decision {
		t.Fatal("expected allow over mTLS gRPC")
	}
}

func TestGRPCMTLS_ForeignClientRejected(t *testing.T) {
	ca, _ := spiffe.NewCA("vsp.local")
	addr := startMTLSGRPCPDP(t, ca)

	// Client SVID minted by a foreign CA: the server must reject the handshake.
	foreign, _ := spiffe.NewCA("vsp.local")
	badSVID, _ := foreign.Mint("spiffe://vsp.local/ns/wallet/sa/vsp-wallet-svc")
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(spiffe.MTLSClientConfig(badSVID, foreign.Bundle()))))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := grpcpdp.NewClient(conn).Evaluate(ctx, settle("AAL3", 9_000_000)); err == nil {
		t.Fatal("expected RPC failure for a foreign-CA client certificate")
	}
}
