package grpcpdp

import (
	"context"
	"fmt"

	"github.com/pmsbkhn/authorization-zta/internal/authz/authzen"
	authzenv1 "github.com/pmsbkhn/authorization-zta/proto/authzen/v1"
	"google.golang.org/grpc"
)

// Client calls a PDP over gRPC. It implements pep.PDP, so a PEP can use the gRPC
// transport in place of the HTTP pdpclient with no other change.
type Client struct {
	conn *grpc.ClientConn
	rpc  authzenv1.AccessEvaluationClient
}

// NewClient builds a gRPC PDP client over an existing connection. The caller
// owns the connection's lifecycle (and TLS/credentials — e.g. an mTLS SVID).
func NewClient(conn *grpc.ClientConn) *Client {
	return &Client{conn: conn, rpc: authzenv1.NewAccessEvaluationClient(conn)}
}

// Evaluate sends one evaluation over gRPC and returns the decision.
func (c *Client) Evaluate(ctx context.Context, req authzen.Request) (authzen.Response, error) {
	in, err := requestToProto(req)
	if err != nil {
		return authzen.Response{}, fmt.Errorf("grpcpdp: encode request: %w", err)
	}
	out, err := c.rpc.Evaluate(ctx, in)
	if err != nil {
		return authzen.Response{}, fmt.Errorf("grpcpdp: evaluate: %w", err)
	}
	return responseFromProto(out), nil
}
