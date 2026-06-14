// Package authzen defines the OpenID AuthZEN 1.0 data contract as specialized
// for the VSP System (the "VSP Standard Contract", see docs/design-v3.md §3).
//
// The wire format follows the AuthZEN 1.0 Access Evaluation API: a request is a
// {subject, action, resource, context} tuple and a response is a {decision,
// context} tuple. AuthZEN leaves `properties` / `context` open-ended; VSP layers
// a naming convention and a set of well-known properties on top so the policy
// engine (OPA) can classify and route every request deterministically.
package authzen

// Profile is the value of context.authz_profile. It is the primary routing key:
// it tells the PDP which policy chain (edge / east-west / partner) to apply and
// which contextual invariants to enforce.
type Profile string

const (
	ProfileEdge     Profile = "edge"
	ProfileEastWest Profile = "east_west"
	ProfilePartner  Profile = "partner"
)

// SubjectType enumerates the allowed subject.type values (VSP §3.1).
const (
	SubjectTypeUser     = "user"
	SubjectTypeWorkload = "workload"
)

// Authentication Assurance Levels (NIST 800-63), carried in
// subject.properties.auth_assurance_level and used by step-up logic.
const (
	AAL1 = "AAL1"
	AAL2 = "AAL2"
	AAL3 = "AAL3"
)

// Subject is the entity requesting access (a user or a workload).
type Subject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is the operation being attempted, named "<domain>:<action>".
type Action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource is the target of the action, typed "<domain>:<entity>".
type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Request is a single AuthZEN Access Evaluation request.
type Request struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// Response is a single AuthZEN Access Evaluation response. `decision` is the
// only field AuthZEN mandates; VSP carries decision_token and obligations inside
// `context`.
type Response struct {
	Decision bool             `json:"decision"`
	Context  *ResponseContext `json:"context,omitempty"`
}

// ResponseContext is the VSP-specific shape of the response `context` object.
type ResponseContext struct {
	// DecisionToken is present when Decision == true: a short-lived,
	// verifiable token a downstream PEP can present to skip re-evaluation.
	DecisionToken *DecisionToken `json:"decision_token,omitempty"`
	// Obligations are side-effects the PEP must carry out (step_up, log, ...).
	Obligations []Obligation `json:"obligations,omitempty"`
	// ReasonCode is a machine-readable explanation, useful when Decision == false.
	ReasonCode string `json:"reason_code,omitempty"`
}

// DecisionToken is a time-boxed proof of a positive decision.
type DecisionToken struct {
	Value      string `json:"value"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// Obligation types understood by VSP PEPs.
const (
	ObligationStepUp = "step_up"
	ObligationLog    = "log"
)

// Obligation is an instruction the PEP must fulfil regardless of the decision.
type Obligation struct {
	Type    string         `json:"type"`
	Details map[string]any `json:"details,omitempty"`
}

// --- Typed accessors for well-known VSP properties -------------------------
//
// These keep policy-adjacent Go code from string-typing into the open maps and
// centralize the contract's well-known keys.

// AuthZProfile returns context.authz_profile, or "" if absent/malformed.
func (r *Request) AuthZProfile() Profile {
	if v, ok := r.Context["authz_profile"].(string); ok {
		return Profile(v)
	}
	return ""
}

// CorrelationID returns context.correlation_id for tracing/audit, or "".
func (r *Request) CorrelationID() string {
	if v, ok := r.Context["correlation_id"].(string); ok {
		return v
	}
	return ""
}

// PEPID returns context.pep.id (the identifier of the calling PEP), or "".
func (r *Request) PEPID() string {
	pep, ok := r.Context["pep"].(map[string]any)
	if !ok {
		return ""
	}
	if v, ok := pep["id"].(string); ok {
		return v
	}
	return ""
}

// AuthAssuranceLevel returns subject.properties.auth_assurance_level, or "".
func (s *Subject) AuthAssuranceLevel() string {
	if v, ok := s.Properties["auth_assurance_level"].(string); ok {
		return v
	}
	return ""
}

// ActSubject returns the delegated actor (subject.properties.act) and whether it
// was present. On the east-west chain this carries the SPIFFE id of the calling
// workload (delegation).
func (s *Subject) ActSubject() (map[string]any, bool) {
	act, ok := s.Properties["act"].(map[string]any)
	return act, ok
}
