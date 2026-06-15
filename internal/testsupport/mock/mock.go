// Package mock provides in-memory implementations of the pip seams for
// milestone 1 ("OPA real, everything else mocked"). Each type is intentionally
// trivial and deterministic so tests and local runs are reproducible. Replace
// these with real IdP / SPIRE / S3 clients in later milestones.
package mock

import (
	"context"
	"fmt"

	"github.com/pmsbkhn/authorization-zta/internal/ports/pip"
)

// Compile-time assurance the mocks satisfy the pip seams.
var (
	_ pip.IdentityProvider = (*IdentityProvider)(nil)
	_ pip.WorkloadAttestor = (*WorkloadAttestor)(nil)
	_ pip.PolicyStore      = (*PolicyStore)(nil)
)

// IdentityProvider returns canned subject attributes from an in-memory table.
type IdentityProvider struct {
	Subjects map[string]map[string]any
}

func (m *IdentityProvider) LookupSubject(_ context.Context, subjectID string) (map[string]any, error) {
	if attrs, ok := m.Subjects[subjectID]; ok {
		return attrs, nil
	}
	return map[string]any{}, nil
}

// WorkloadAttestor treats any spiffe:// id as attested unless it is in Revoked.
// This is a stand-in for SPIRE SVID validation.
type WorkloadAttestor struct {
	Revoked map[string]bool
}

func (m *WorkloadAttestor) ValidateSVID(_ context.Context, spiffeID string) (bool, error) {
	if len(spiffeID) < len("spiffe://") || spiffeID[:len("spiffe://")] != "spiffe://" {
		return false, fmt.Errorf("mock: %q is not a spiffe id", spiffeID)
	}
	return !m.Revoked[spiffeID], nil
}

// PolicyStore serves a fixed in-memory bundle. The embedded-bundle milestone does
// not pull from it, but main reports its readiness to document the seam.
type PolicyStore struct {
	Bundle  []byte
	Version string
}

func (m *PolicyStore) LatestBundle(_ context.Context) ([]byte, string, error) {
	return m.Bundle, m.Version, nil
}
