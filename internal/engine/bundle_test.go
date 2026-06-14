package engine_test

import (
	"context"
	"os/exec"
	"testing"

	"github.com/pmsbkhn/authorization-zta/internal/engine"
)

// The PDP must produce identical decisions whether policies are embedded or
// loaded from a published OPA bundle. This builds a bundle with `opa build`
// (skipped if the CLI is absent) and checks a headline decision matches.
func TestNewFromBundle_MatchesEmbedded(t *testing.T) {
	opa, err := exec.LookPath("opa")
	if err != nil {
		t.Skip("opa CLI not installed; skipping bundle build test")
	}
	dir := t.TempDir()
	out := dir + "/bundle.tar.gz"
	if b, err := exec.Command(opa, "build", "-b", "../../policies", "--ignore", "*_test.rego", "-o", out).CombinedOutput(); err != nil {
		t.Fatalf("opa build: %v\n%s", err, b)
	}
	tarball, err := exec.Command("cat", out).Output()
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	eng, err := engine.NewFromBundle(context.Background(), tarball, engine.DefaultDecisionQuery)
	if err != nil {
		t.Fatalf("NewFromBundle: %v", err)
	}
	d, err := eng.Eval(context.Background(), edgeSettle("AAL3", 9_000_000))
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !d.Allow || d.ReasonCode != "wallet_settle_high_value_aal3" {
		t.Fatalf("bundle decision mismatch: allow=%v reason=%q", d.Allow, d.ReasonCode)
	}
}
