package services

import (
	"fmt"

	"github.com/pmsbkhn/authorization-zta/internal/authz/grpcpdp"
	"github.com/pmsbkhn/authorization-zta/internal/authz/pep"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// PDPGRPCClient dials the PDP's gRPC endpoint over mTLS using this workload's
// SVID (from the same SVID material as the rest of the mesh) and returns a
// pep.PDP. It requires mTLS to be configured — a PEP must authenticate to the
// PDP with its SVID, never call it in the clear.
func PDPGRPCClient(addr string) (pep.PDP, error) {
	cfg, ok, err := LoadClientTLS()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("services: PDP gRPC needs an SVID (SPIFFE_ENDPOINT_SOCKET / SVID_*) but none configured")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, fmt.Errorf("services: dial PDP gRPC: %w", err)
	}
	return grpcpdp.NewClient(conn), nil
}

// PDPGRPCServerCreds returns a grpc.ServerOption establishing mTLS from the
// workload's SVID, and whether mTLS is configured.
func PDPGRPCServerCreds() (grpc.ServerOption, bool, error) {
	cfg, ok, err := LoadServerTLS()
	if err != nil || !ok {
		return nil, ok, err
	}
	return grpc.Creds(credentials.NewTLS(cfg)), true, nil
}
