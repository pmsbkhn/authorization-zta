package grpcpdp

import (
	"context"
	"errors"

	"github.com/pmsbkhn/authorization-zta/internal/authz/authzen"
	authzenv1 "github.com/pmsbkhn/authorization-zta/proto/authzen/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Evaluator is the decision dependency (pdp.Service satisfies it).
type Evaluator interface {
	Evaluate(ctx context.Context, req authzen.Request) (authzen.Response, error)
}

// Server adapts an Evaluator to the generated AccessEvaluation gRPC service.
type Server struct {
	authzenv1.UnimplementedAccessEvaluationServer
	eval Evaluator
}

// NewServer wraps an Evaluator as a gRPC AccessEvaluation server.
func NewServer(eval Evaluator) *Server { return &Server{eval: eval} }

// Evaluate handles the gRPC RPC: convert in, evaluate, convert out. A contract
// violation maps to InvalidArgument; an internal failure to Internal. Mirrors
// the HTTP facade's status mapping.
func (s *Server) Evaluate(ctx context.Context, in *authzenv1.EvaluationRequest) (*authzenv1.EvaluationResponse, error) {
	resp, err := s.eval.Evaluate(ctx, requestFromProto(in))
	if err != nil {
		var ve *authzen.ValidationError
		if errors.As(err, &ve) {
			return nil, status.Error(codes.InvalidArgument, ve.Error())
		}
		return nil, status.Error(codes.Internal, "evaluation failed")
	}
	return responseToProto(resp)
}
