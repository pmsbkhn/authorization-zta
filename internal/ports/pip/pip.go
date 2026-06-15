// Package pip defines the Policy Information Point seams the Control Plane
// depends on (design-v3 §1): the Identity Provider, the SPIRE workload attestor,
// and the immutable Policy Store. They are interfaces so milestone 1 can run
// against in-memory mocks (internal/mock) while production swaps in real IdP /
// SPIRE / S3 implementations without changing the PDP.
package pip

import "context"

// IdentityProvider enriches a subject with attributes the PEP did not (or should
// not) send — roles, entitlements, current assurance level, account posture. In
// the design, OPA "pulls context" from the IdP during evaluation.
type IdentityProvider interface {
	// LookupSubject returns additional attributes for the given subject id.
	LookupSubject(ctx context.Context, subjectID string) (map[string]any, error)
}

// WorkloadAttestor validates the SPIFFE identity (SVID) of a calling workload.
// It backs the L0 channel/peer check and the east-west delegation actor check.
type WorkloadAttestor interface {
	// ValidateSVID reports whether the given SPIFFE id is currently attested.
	ValidateSVID(ctx context.Context, spiffeID string) (bool, error)
}

// PolicyStore is the immutable, versioned bundle store (S3 in the design). The
// PDP/PEP pulls the latest compiled OPA bundle from it. Milestone 1 embeds the
// bundle in the binary instead; this seam is where the GitOps pull flow attaches.
type PolicyStore interface {
	// LatestBundle returns the newest published bundle and its version tag.
	LatestBundle(ctx context.Context) (data []byte, version string, err error)
}
