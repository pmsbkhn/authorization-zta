// Package policies embeds the OPA policy bundle (hierarchical Rego + data.json)
// into the binary so the PDP ships as a single self-contained artifact and the
// embedded OPA engine has no runtime filesystem dependency.
//
// In production these same files are what GitOps compiles into an OPA bundle and
// pushes to immutable storage (design-v3 §5.3); embedding is the "OPA real,
// everything else mocked" milestone-1 stand-in for that pull-from-store flow.
package policies

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// Embeds the framework policy only: the entrypoint/router (main.rego) and the
// reusable subpackages vsp.global (schema), vsp.lib (helpers), vsp.profiles
// (per-hop invariants), plus the base data document. Business domain policy
// (vsp.domain.<x>) is NOT embedded here — an adopter supplies it via
// services.PDPConfig.ExtraModules or a compiled bundle (the reference VSP domain
// lives under examples/vsp/policies). The `*.rego` glob also pulls in *_test.rego
// at the root, which Modules() filters out.
//
//go:embed *.rego global profiles lib data.json
var bundle embed.FS

// Modules returns every embedded .rego file keyed by its bundle-relative path
// (e.g. "domain/wallet.rego"). The keys are used as module names when compiling.
func Modules() (map[string]string, error) {
	mods := make(map[string]string)
	err := fs.WalkDir(bundle, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		// Skip *_test.rego: those are fitness functions run by `opa test`, not
		// part of the decision bundle loaded at runtime.
		if strings.HasSuffix(path, "_test.rego") {
			return nil
		}
		b, err := bundle.ReadFile(path)
		if err != nil {
			return err
		}
		mods[path] = string(b)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("policies: walking bundle: %w", err)
	}
	if len(mods) == 0 {
		return nil, fmt.Errorf("policies: no .rego modules embedded")
	}
	return mods, nil
}

// Data returns the parsed data.json (the data-driven requirements document,
// design-v3 §5.2) as the OPA base document tree.
func Data() (map[string]any, error) {
	b, err := bundle.ReadFile("data.json")
	if err != nil {
		return nil, fmt.Errorf("policies: reading data.json: %w", err)
	}
	var data map[string]any
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("policies: parsing data.json: %w", err)
	}
	return data, nil
}
