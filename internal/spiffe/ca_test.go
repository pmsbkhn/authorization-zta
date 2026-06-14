package spiffe

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func TestCA_MintAndVerify(t *testing.T) {
	ca, err := NewCA("vsp.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	svid, err := ca.Mint("spiffe://vsp.local/ns/billing/sa/multi-bill-svc")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The leaf's SPIFFE id is recoverable from its URI SAN.
	id, err := x509svid.IDFromCert(svid.Certificates[0])
	if err != nil {
		t.Fatalf("id from cert: %v", err)
	}
	if id.String() != "spiffe://vsp.local/ns/billing/sa/multi-bill-svc" {
		t.Fatalf("id = %q", id.String())
	}

	bundle := ca.Bundle()
	t.Logf("bundle authorities: %d", len(bundle.X509Authorities()))

	// The leaf must verify against the trust bundle — this is exactly what the
	// mTLS peer verification does.
	if _, _, err := x509svid.Verify(svid.Certificates, bundle); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
