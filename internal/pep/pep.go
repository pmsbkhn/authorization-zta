// Package pep is the Policy Enforcement Point library shared by every guard in
// the data path (the Edge gateway and the East-West sidecars). A PEP enforces;
// it never decides. The decision is the PDP's job — the PEP runs the L0/L1/L2
// "ladder" (design-v3 §2) and turns the PDP's verdict + obligations into the
// right transport-level outcome for its profile.
//
//	L0  channel/peer   — verify the caller's workload identity (SVID). East-West
//	                     only; the Edge terminates user TLS upstream.
//	L1  invocation     — is this route allowed for this PEP at all? (route guard)
//	L2  resource/action — ask the PDP, passing subject/action/resource/context.
//
// Cheap checks first: a failed L0/L1 never reaches the PDP.
package pep

import (
	"context"

	"github.com/pmsbkhn/authorization-zta/internal/authzen"
)

// Propagation headers. In production the subject/assurance/actor would come from
// validated tokens and the mTLS peer certificate (SVID); modelling them as
// headers keeps milestone 2 runnable without a full PKI while preserving the
// exact information flow.
const (
	HeaderSubjectID      = "X-Vsp-Subject-Id"
	HeaderAAL            = "X-Vsp-Aal"
	HeaderCallerSpiffe   = "X-Vsp-Caller-Spiffe" // delegation actor / mTLS peer
	HeaderResourceID     = "X-Vsp-Resource-Id"   // optional resource instance id
	HeaderPartnerID      = "X-Vsp-Partner-Id"    // partner profile only
	HeaderCorrelationID  = "X-Correlation-Id"    // trace id, propagated end-to-end
	HeaderStepUpRequired = "X-Step-Up-Required"  // bubble-up signal; value = required ACR
	HeaderDecisionToken  = "X-Decision-Token"    // PDP decision token, passed downstream on allow
)

// PDP is the decision dependency a PEP calls (pdpclient.Client satisfies it).
type PDP interface {
	Evaluate(ctx context.Context, req authzen.Request) (authzen.Response, error)
}

// Route maps an inbound invocation (method + exact path) to the AuthZEN action
// and resource the PDP reasons about, plus which JSON body fields to lift into
// resource.properties (e.g. "amount", "currency").
type Route struct {
	Method        string
	Path          string
	Action        string
	ResourceType  string
	ResourceProps []string
}

// OutcomeKind is the PEP's classification of a request after the ladder runs.
type OutcomeKind int

const (
	// Allow: forward to the protected workload.
	Allow OutcomeKind = iota
	// DropL0: peer/channel identity failed — drop the connection.
	DropL0
	// DenyRoute: L1 route guard rejected the invocation.
	DenyRoute
	// DenyForbidden: PDP denied with no remediation.
	DenyForbidden
	// DenyStepUp: PDP denied but a stronger authentication would satisfy it.
	DenyStepUp
)

// Outcome is the result of enforcement, carrying everything the transport layer
// needs to respond.
type Outcome struct {
	Kind          OutcomeKind
	ReasonCode    string
	RequiredACR   string // set when Kind == DenyStepUp
	CorrelationID string
	DecisionToken string // set when Kind == Allow and the PDP minted one
}
