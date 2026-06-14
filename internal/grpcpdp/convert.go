// Package grpcpdp exposes the PDP over gRPC and lets a PEP call it over gRPC,
// as an efficient alternative to the JSON/HTTP facade for the internal data path
// (design-v3 §6.1). It converts between the in-process authzen types and the
// generated protobuf messages; the open `properties`/`context` objects ride in
// google.protobuf.Struct so no business attribute needs a fixed proto field.
package grpcpdp

import (
	"github.com/pmsbkhn/authorization-zta/internal/authzen"
	authzenv1 "github.com/pmsbkhn/authorization-zta/proto/authzen/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// requestToProto converts the contract request into its protobuf form.
func requestToProto(r authzen.Request) (*authzenv1.EvaluationRequest, error) {
	subProps, err := mapToStruct(r.Subject.Properties)
	if err != nil {
		return nil, err
	}
	actProps, err := mapToStruct(r.Action.Properties)
	if err != nil {
		return nil, err
	}
	resProps, err := mapToStruct(r.Resource.Properties)
	if err != nil {
		return nil, err
	}
	ctx, err := mapToStruct(r.Context)
	if err != nil {
		return nil, err
	}
	return &authzenv1.EvaluationRequest{
		Subject:  &authzenv1.Subject{Type: r.Subject.Type, Id: r.Subject.ID, Properties: subProps},
		Action:   &authzenv1.Action{Name: r.Action.Name, Properties: actProps},
		Resource: &authzenv1.Resource{Type: r.Resource.Type, Id: r.Resource.ID, Properties: resProps},
		Context:  ctx,
	}, nil
}

// requestFromProto converts a protobuf request back into the contract type.
func requestFromProto(p *authzenv1.EvaluationRequest) authzen.Request {
	var r authzen.Request
	if s := p.GetSubject(); s != nil {
		r.Subject = authzen.Subject{Type: s.GetType(), ID: s.GetId(), Properties: s.GetProperties().AsMap()}
	}
	if a := p.GetAction(); a != nil {
		r.Action = authzen.Action{Name: a.GetName(), Properties: a.GetProperties().AsMap()}
	}
	if res := p.GetResource(); res != nil {
		r.Resource = authzen.Resource{Type: res.GetType(), ID: res.GetId(), Properties: res.GetProperties().AsMap()}
	}
	r.Context = p.GetContext().AsMap()
	return r
}

// responseToProto converts the contract response into its protobuf form.
func responseToProto(resp authzen.Response) (*authzenv1.EvaluationResponse, error) {
	out := &authzenv1.EvaluationResponse{Decision: resp.Decision}
	if resp.Context == nil {
		return out, nil
	}
	out.ReasonCode = resp.Context.ReasonCode
	if dt := resp.Context.DecisionToken; dt != nil {
		out.DecisionToken = &authzenv1.DecisionToken{Value: dt.Value, TtlSeconds: int32(dt.TTLSeconds)}
	}
	for _, ob := range resp.Context.Obligations {
		details, err := mapToStruct(ob.Details)
		if err != nil {
			return nil, err
		}
		out.Obligations = append(out.Obligations, &authzenv1.Obligation{Type: ob.Type, Details: details})
	}
	return out, nil
}

// responseFromProto converts a protobuf response back into the contract type.
func responseFromProto(p *authzenv1.EvaluationResponse) authzen.Response {
	rc := &authzen.ResponseContext{ReasonCode: p.GetReasonCode()}
	if dt := p.GetDecisionToken(); dt != nil {
		rc.DecisionToken = &authzen.DecisionToken{Value: dt.GetValue(), TTLSeconds: int(dt.GetTtlSeconds())}
	}
	for _, ob := range p.GetObligations() {
		rc.Obligations = append(rc.Obligations, authzen.Obligation{Type: ob.GetType(), Details: ob.GetDetails().AsMap()})
	}
	return authzen.Response{Decision: p.GetDecision(), Context: rc}
}

// mapToStruct converts a property map to a protobuf Struct (nil → nil).
func mapToStruct(m map[string]any) (*structpb.Struct, error) {
	if len(m) == 0 {
		return nil, nil
	}
	return structpb.NewStruct(m)
}
