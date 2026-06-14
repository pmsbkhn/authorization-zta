package grpcpdp_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pmsbkhn/authorization-zta/internal/authzen"
	"github.com/pmsbkhn/authorization-zta/internal/engine"
	"github.com/pmsbkhn/authorization-zta/internal/grpcpdp"
	"github.com/pmsbkhn/authorization-zta/internal/pdp"
	"github.com/pmsbkhn/authorization-zta/internal/token"
	"github.com/pmsbkhn/authorization-zta/policies"
	authzenv1 "github.com/pmsbkhn/authorization-zta/proto/authzen/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// dialPDP starts a real gRPC PDP (embedded OPA) and returns a connected client.
func dialPDP(t *testing.T) *grpcpdp.Client {
	t.Helper()
	mods, _ := policies.Modules()
	data, _ := policies.Data()
	eng, err := engine.New(context.Background(), mods, data, engine.DefaultDecisionQuery)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	svc := pdp.New(eng, token.NewIssuer([]byte("test"), 5*time.Minute))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	authzenv1.RegisterAccessEvaluationServer(srv, grpcpdp.NewServer(svc))
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return grpcpdp.NewClient(conn)
}

func settle(aal string, amount int) authzen.Request {
	return authzen.Request{
		Subject:  authzen.Subject{Type: "user", ID: "u-1", Properties: map[string]any{"auth_assurance_level": aal}},
		Action:   authzen.Action{Name: "wallet:settle", Properties: map[string]any{"method": "POST"}},
		Resource: authzen.Resource{Type: "wallet:account", ID: "acc-1", Properties: map[string]any{"amount": amount, "currency": "VND"}},
		Context:  map[string]any{"authz_profile": "edge", "source_ip": "10.0.0.1"},
	}
}

func TestGRPC_AllowAndDeny(t *testing.T) {
	c := dialPDP(t)
	ctx := context.Background()

	resp, err := c.Evaluate(ctx, settle("AAL3", 9_000_000))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !resp.Decision {
		t.Fatal("AAL3 high-value should allow over gRPC")
	}
	if resp.Context == nil || resp.Context.DecisionToken == nil || resp.Context.DecisionToken.Value == "" {
		t.Fatal("allow over gRPC must carry a decision token")
	}

	resp, err = c.Evaluate(ctx, settle("AAL2", 9_000_000))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision {
		t.Fatal("AAL2 high-value should deny over gRPC")
	}
	found := false
	for _, ob := range resp.Context.Obligations {
		if ob.Type == authzen.ObligationStepUp && ob.Details["required_acr"] == "AAL3" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected step_up→AAL3 obligation over gRPC, got %+v", resp.Context.Obligations)
	}
}

func TestGRPC_ValidationErrorIsInvalidArgument(t *testing.T) {
	c := dialPDP(t)
	bad := settle("AAL3", 9_000_000)
	bad.Action.Name = "settle" // breaks <domain>:<action>

	_, err := c.Evaluate(context.Background(), bad)
	if err == nil {
		t.Fatal("expected gRPC error for malformed request")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}
