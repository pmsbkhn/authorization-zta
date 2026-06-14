package authzen

import (
	"errors"
	"testing"
)

func baseValidRequest() Request {
	return Request{
		Subject: Subject{Type: SubjectTypeUser, ID: "u-1", Properties: map[string]any{
			"auth_assurance_level": AAL2,
		}},
		Action:   Action{Name: "wallet:settle"},
		Resource: Resource{Type: "wallet:account", ID: "acc-1"},
		Context:  map[string]any{"authz_profile": string(ProfileEdge)},
	}
}

func TestValidate_Valid(t *testing.T) {
	r := baseValidRequest()
	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid request, got: %v", err)
	}
}

func TestValidate_Issues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		want   string // substring expected in the aggregated error
	}{
		{"bad subject type", func(r *Request) { r.Subject.Type = "robot" }, "subject.type"},
		{"missing subject id", func(r *Request) { r.Subject.ID = "" }, "subject.id is required"},
		{"action not colon pair", func(r *Request) { r.Action.Name = "settle" }, "action.name"},
		{"resource not colon pair", func(r *Request) { r.Resource.Type = "account" }, "resource.type"},
		{"domain mismatch", func(r *Request) { r.Resource.Type = "bill:invoice" }, "domain mismatch"},
		{"missing profile", func(r *Request) { delete(r.Context, "authz_profile") }, "authz_profile is required"},
		{"bad profile", func(r *Request) { r.Context["authz_profile"] = "internal" }, "must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := baseValidRequest()
			tt.mutate(&r)
			err := r.Validate()
			if err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected *ValidationError, got %T", err)
			}
			if !containsSub(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

func TestAccessors(t *testing.T) {
	r := baseValidRequest()
	r.Subject.Properties["act"] = map[string]any{"type": "workload", "id": "spiffe://x"}
	r.Context["correlation_id"] = "trace-9"
	r.Context["pep"] = map[string]any{"id": "edge-gw"}

	if got := r.AuthZProfile(); got != ProfileEdge {
		t.Errorf("AuthZProfile = %q, want %q", got, ProfileEdge)
	}
	if got := r.CorrelationID(); got != "trace-9" {
		t.Errorf("CorrelationID = %q, want trace-9", got)
	}
	if got := r.PEPID(); got != "edge-gw" {
		t.Errorf("PEPID = %q, want edge-gw", got)
	}
	if got := r.Subject.AuthAssuranceLevel(); got != AAL2 {
		t.Errorf("AAL = %q, want %q", got, AAL2)
	}
	if act, ok := r.Subject.ActSubject(); !ok || act["id"] != "spiffe://x" {
		t.Errorf("ActSubject = %v, %v", act, ok)
	}
}

func containsSub(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
