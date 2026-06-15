package engine

import (
	"bytes"
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/bundle"
)

// NewFromBundle compiles an engine from a signed/unsigned OPA bundle tarball
// (the artifact GitOps publishes to the immutable policy store, design-v3 §5.3).
// It is the pull-from-store counterpart to New(embedded modules): the PDP can
// load exactly the bundle CI built and published, rather than what was baked
// into the binary.
func NewFromBundle(ctx context.Context, tarball []byte, queryPath string) (*Engine, error) {
	b, err := bundle.NewReader(bytes.NewReader(tarball)).Read()
	if err != nil {
		return nil, fmt.Errorf("engine: reading bundle: %w", err)
	}
	modules := make(map[string]string, len(b.Modules))
	for _, m := range b.Modules {
		modules[m.Path] = string(m.Raw)
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("engine: bundle contains no policy modules")
	}
	return New(ctx, modules, b.Data, queryPath)
}
