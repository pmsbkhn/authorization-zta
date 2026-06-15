package pep

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/pmsbkhn/authorization-zta/internal/authz/authzen"
	"github.com/pmsbkhn/authorization-zta/internal/authz/token"
	"github.com/pmsbkhn/authorization-zta/internal/ports/pip"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Config wires a PEP to its profile, route guard, PDP and (for East-West) the
// workload attestor used at L0.
type Config struct {
	Profile  authzen.Profile
	PEPID    string
	Routes   []Route
	PDP      PDP
	Attestor pip.WorkloadAttestor // required when Profile == east_west
	Logger   *slog.Logger
	// RequirePeerSVID forbids the X-Vsp-Caller-Spiffe header fallback: the
	// delegation actor MUST come from a verified mTLS peer certificate. Set this
	// whenever the PEP is served over mTLS (production); leaving it false enables
	// a dev mode where the header stands in for a missing SVID.
	RequirePeerSVID bool
	// TokenVerifier, when set, lets the PEP honor a presented decision token
	// (X-Decision-Token) and short-circuit the PDP call for an identical request
	// within the token's TTL. Leave nil to always call the PDP.
	TokenVerifier TokenVerifier
	// Revocations, when set, is consulted before any allow path (including the
	// decision-token fast-path): a revoked subject is denied immediately, which
	// is how CAEP signals override still-valid cached decisions (design-v3 §6.2).
	Revocations RevocationChecker
}

// TokenVerifier verifies a decision token string and returns its claims.
// token.Issuer satisfies it.
type TokenVerifier interface {
	Verify(tok string) (token.Claims, error)
}

// RevocationChecker reports whether a subject's session has been revoked.
// caep.RevocationCache satisfies it.
type RevocationChecker interface {
	IsRevoked(subject string) bool
}

// PEP enforces a single profile's policy on inbound requests.
type PEP struct {
	cfg Config
	log *slog.Logger
}

// New builds a PEP. It panics on obvious misconfiguration so the mistake surfaces
// at startup, not as a silent allow at runtime.
func New(cfg Config) *PEP {
	if cfg.PDP == nil {
		panic("pep: PDP is required")
	}
	if cfg.Profile == authzen.ProfileEastWest && cfg.Attestor == nil {
		panic("pep: east_west profile requires an Attestor for the L0 check")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &PEP{cfg: cfg, log: log}
}

// Check runs the L0→L1→L2 ladder for one request and returns the Outcome. It does
// not write a response; the caller's transport layer (Middleware) maps Outcome to
// HTTP per profile. Check restores r.Body so the protected handler can read it.
func (p *PEP) Check(r *http.Request) Outcome {
	cid := r.Header.Get(HeaderCorrelationID)
	if cid == "" {
		cid = newCorrelationID()
	}

	// L0 — channel/peer. East-West must present an attested workload SVID. The
	// caller identity comes from the cryptographically verified mTLS peer
	// certificate (its SPIFFE URI SAN), not a spoofable header.
	caller, present := p.peerIdentity(r)
	if p.cfg.Profile == authzen.ProfileEastWest {
		if !present {
			return Outcome{Kind: DropL0, ReasonCode: "l0_no_peer_svid", CorrelationID: cid}
		}
		// Even a valid SVID can be revoked out of band (SPIRE revocation).
		ok, err := p.cfg.Attestor.ValidateSVID(r.Context(), caller)
		if err != nil || !ok {
			return Outcome{Kind: DropL0, ReasonCode: "l0_peer_not_attested", CorrelationID: cid}
		}
	}

	// L1 — invocation. Is this route permitted for this PEP at all?
	route, ok := p.matchRoute(r.Method, r.URL.Path)
	if !ok {
		return Outcome{Kind: DenyRoute, ReasonCode: "l1_route_not_permitted", CorrelationID: cid}
	}

	// Continuous evaluation: a CAEP-signalled revocation denies immediately,
	// before the decision-token fast-path or the PDP — closing the cached-
	// decision window (design-v3 §6.2).
	if p.cfg.Revocations != nil {
		if subj := r.Header.Get(HeaderSubjectID); subj != "" && p.cfg.Revocations.IsRevoked(subj) {
			return Outcome{Kind: DenyForbidden, ReasonCode: "session_revoked", CorrelationID: cid}
		}
	}

	// L2 — resource/action. Build the AuthZEN request.
	req, err := p.buildRequest(r, route, cid, caller)
	if err != nil {
		return Outcome{Kind: DenyForbidden, ReasonCode: "l2_request_build_failed", CorrelationID: cid}
	}

	// L2 fast-path: a valid decision token for the *identical* request lets us
	// skip the PDP round-trip within the token's TTL.
	if out, ok := p.tryDecisionToken(r, req, cid); ok {
		return out
	}

	resp, err := p.cfg.PDP.Evaluate(r.Context(), req)
	if err != nil {
		// Fail closed: no clean decision means deny.
		p.log.Error("pdp call failed", "correlation_id", cid, "err", err)
		return Outcome{Kind: DenyForbidden, ReasonCode: "l2_pdp_unavailable", CorrelationID: cid}
	}

	return p.classify(resp, cid)
}

// classify turns an AuthZEN response into a PEP Outcome.
func (p *PEP) classify(resp authzen.Response, cid string) Outcome {
	if resp.Decision {
		out := Outcome{Kind: Allow, CorrelationID: cid}
		if resp.Context != nil {
			if resp.Context.ReasonCode != "" {
				out.ReasonCode = resp.Context.ReasonCode
			}
			if resp.Context.DecisionToken != nil {
				out.DecisionToken = resp.Context.DecisionToken.Value
			}
		}
		return out
	}

	// Denied: a step_up obligation means the subject can remediate by
	// re-authenticating to a higher assurance level.
	if resp.Context != nil {
		for _, ob := range resp.Context.Obligations {
			if ob.Type == authzen.ObligationStepUp {
				acr, _ := ob.Details["required_acr"].(string)
				return Outcome{Kind: DenyStepUp, RequiredACR: acr, ReasonCode: resp.Context.ReasonCode, CorrelationID: cid}
			}
		}
	}
	rc := "forbidden"
	if resp.Context != nil && resp.Context.ReasonCode != "" {
		rc = resp.Context.ReasonCode
	}
	return Outcome{Kind: DenyForbidden, ReasonCode: rc, CorrelationID: cid}
}

// aalRank orders the assurance levels for "at least" comparisons. Unknown → 0.
var aalRank = map[string]int{"AAL1": 1, "AAL2": 2, "AAL3": 3}

// tryDecisionToken honors a presented X-Decision-Token if it is valid and binds
// to exactly this request. The match is deliberately strict: subject, action,
// resource identity, the resource-properties digest, and an assurance level at
// least as strong as the token's. Any mismatch (including an expired token)
// returns ok=false so the caller falls back to a fresh PDP evaluation — never a
// silent allow.
func (p *PEP) tryDecisionToken(r *http.Request, req authzen.Request, cid string) (Outcome, bool) {
	if p.cfg.TokenVerifier == nil {
		return Outcome{}, false
	}
	raw := r.Header.Get(HeaderDecisionToken)
	if raw == "" {
		return Outcome{}, false
	}
	claims, err := p.cfg.TokenVerifier.Verify(raw)
	if err != nil {
		return Outcome{}, false
	}
	if claims.Subject != req.Subject.ID ||
		claims.Action != req.Action.Name ||
		claims.Resource != req.Resource.Type+"/"+req.Resource.ID ||
		claims.ResDigest != token.ResourceDigest(req.Resource.Properties) {
		return Outcome{}, false
	}
	if aalRank[req.Subject.AuthAssuranceLevel()] < aalRank[claims.AAL] {
		return Outcome{}, false
	}
	return Outcome{Kind: Allow, ReasonCode: "decision_token_reuse", CorrelationID: cid, DecisionToken: raw}, true
}

// peerIdentity resolves the calling workload's SPIFFE id. It prefers the mTLS
// peer certificate, which by the time the handler runs has already been verified
// and authorized (member of the trust domain) during the TLS handshake — so the
// id is trustworthy. The X-Vsp-Caller-Spiffe header is only consulted as a dev
// fallback when RequirePeerSVID is false.
func (p *PEP) peerIdentity(r *http.Request) (string, bool) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if id, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0]); err == nil {
			return id.String(), true
		}
	}
	if !p.cfg.RequirePeerSVID {
		if h := r.Header.Get(HeaderCallerSpiffe); h != "" {
			return h, true
		}
	}
	return "", false
}

func (p *PEP) matchRoute(method, path string) (Route, bool) {
	for _, rt := range p.cfg.Routes {
		if rt.Method == method && rt.Path == path {
			return rt, true
		}
	}
	return Route{}, false
}

// buildRequest assembles the VSP Standard Contract request from the HTTP request,
// the matched route, and the propagation headers.
func (p *PEP) buildRequest(r *http.Request, route Route, cid, caller string) (authzen.Request, error) {
	props, err := p.resourceProps(r, route)
	if err != nil {
		return authzen.Request{}, err
	}

	subject := authzen.Subject{
		Type: authzen.SubjectTypeUser,
		ID:   r.Header.Get(HeaderSubjectID),
		Properties: map[string]any{
			"auth_assurance_level": r.Header.Get(HeaderAAL),
		},
	}
	// East-West: record the delegation actor (the calling workload).
	if p.cfg.Profile == authzen.ProfileEastWest && caller != "" {
		subject.Properties["act"] = map[string]any{"type": authzen.SubjectTypeWorkload, "id": caller}
	}

	ctx := map[string]any{
		"authz_profile":  string(p.cfg.Profile),
		"correlation_id": cid,
		"pep":            map[string]any{"id": p.cfg.PEPID},
	}
	switch p.cfg.Profile {
	case authzen.ProfileEdge:
		ctx["source_ip"] = clientIP(r)
	case authzen.ProfilePartner:
		ctx["partner_id"] = r.Header.Get(HeaderPartnerID)
	}

	return authzen.Request{
		Subject:  subject,
		Action:   authzen.Action{Name: route.Action, Properties: map[string]any{"method": r.Method}},
		Resource: authzen.Resource{Type: route.ResourceType, ID: r.Header.Get(HeaderResourceID), Properties: props},
		Context:  ctx,
	}, nil
}

// resourceProps lifts the configured body fields into resource.properties,
// restoring r.Body so the protected handler can still read it.
func (p *PEP) resourceProps(r *http.Request, route Route) (map[string]any, error) {
	if len(route.ResourceProps) == 0 {
		return map[string]any{}, nil
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw)) // restore for downstream

	props := map[string]any{}
	if len(raw) > 0 {
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, err
		}
		for _, key := range route.ResourceProps {
			if v, ok := body[key]; ok {
				props[key] = v
			}
		}
	}
	return props, nil
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func newCorrelationID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "cid-" + hex.EncodeToString(b[:])
}
