package rebac_test

import (
	"context"
	"os"
	"testing"

	"github.com/pmsbkhn/authorization-zta/internal/pdp"
	"github.com/pmsbkhn/authorization-zta/internal/rebac"
)

// The ReBAC engine must be a drop-in pdp.Engine so the PDP can route to it.
var _ pdp.Engine = (*rebac.Engine)(nil)

func settleReq(subjectID string) map[string]any {
	return map[string]any{
		"subject":  map[string]any{"type": "user", "id": subjectID},
		"action":   map[string]any{"name": "wallet:settle"},
		"resource": map[string]any{"type": "wallet:account", "id": "acc-1"},
		"context":  map[string]any{"authz_profile": "edge"},
	}
}

// Live check against a running OpenFGA seeded by deploy/rebac/run-rebac.sh
// (owner tuple: user:u-1 owner account:acc-1). Skipped unless OPENFGA_* is set.
func TestReBAC_Live(t *testing.T) {
	ep, store := os.Getenv("OPENFGA_ENDPOINT"), os.Getenv("OPENFGA_STORE")
	if ep == "" || store == "" {
		t.Skip("set OPENFGA_ENDPOINT and OPENFGA_STORE (see deploy/rebac/run-rebac.sh)")
	}
	eng := rebac.New(rebac.Config{Endpoint: ep, StoreID: store, ModelID: os.Getenv("OPENFGA_MODEL")})
	ctx := context.Background()

	owner, err := eng.Eval(ctx, settleReq("u-1"))
	if err != nil {
		t.Fatalf("eval owner: %v", err)
	}
	if !owner.Allow || owner.ReasonCode != "rebac_relationship_ok" {
		t.Fatalf("owner should be allowed via relationship, got allow=%v reason=%q", owner.Allow, owner.ReasonCode)
	}

	stranger, err := eng.Eval(ctx, settleReq("u-2"))
	if err != nil {
		t.Fatalf("eval stranger: %v", err)
	}
	if stranger.Allow {
		t.Fatal("a subject with no ownership relationship must be denied")
	}
}
