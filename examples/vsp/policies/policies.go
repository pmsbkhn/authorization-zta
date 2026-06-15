// Package vsppolicies embeds the VSP *reference* business domain policy
// (vsp.domain.wallet / vsp.domain.bill) and its data-driven requirements. It is
// the adopter-supplied half of the policy split: the reusable framework policy
// (router, schema, lib, profiles) ships in the core `policies` package, and this
// package layers the demo's domain rules on top via services.PDPConfig.ExtraModules.
//
// A real adopter would have their own equivalent of this package (or publish a
// compiled bundle to the policy store); nothing here is part of the platform core.
package vsppolicies

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

//go:embed domain data.json
var bundle embed.FS

// Modules returns each embedded domain .rego keyed by its bundle-relative path
// (e.g. "domain/wallet.rego"), matching the key scheme the framework uses so the
// two merge cleanly when compiled together.
func Modules() (map[string]string, error) {
	mods := make(map[string]string)
	err := fs.WalkDir(bundle, "domain", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") || strings.HasSuffix(path, "_test.rego") {
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
		return nil, fmt.Errorf("vsppolicies: walking domain: %w", err)
	}
	return mods, nil
}

// Data returns the demo's data-driven requirements (required_attributes) as the
// OPA base document overlay.
func Data() (map[string]any, error) {
	b, err := bundle.ReadFile("data.json")
	if err != nil {
		return nil, fmt.Errorf("vsppolicies: reading data.json: %w", err)
	}
	var data map[string]any
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("vsppolicies: parsing data.json: %w", err)
	}
	return data, nil
}

// MustModules / MustData are convenience wrappers for wiring code; the embedded
// files are compile-time constants, so an error here is a build-time defect.
func MustModules() map[string]string {
	m, err := Modules()
	if err != nil {
		panic(err)
	}
	return m
}

func MustData() map[string]any {
	d, err := Data()
	if err != nil {
		panic(err)
	}
	return d
}
