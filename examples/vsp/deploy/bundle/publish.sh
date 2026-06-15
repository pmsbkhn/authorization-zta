#!/usr/bin/env bash
# GitOps publish step (design-v3 §5.3): gate on fitness functions, compile the
# OPA bundle, and push it to the immutable, versioned policy store. CI would run
# this on merge; bundlepush refuses to overwrite (object lock) — each publish is
# a new retained version for safe rollback.
#
# Env: S3_ENDPOINT (default localhost:9000), S3_ACCESS_KEY, S3_SECRET_KEY,
#      S3_BUCKET (default vsp-policy-bundles).
set -euo pipefail
cd "$(dirname "$0")/../../../.."   # repo root

BUNDLE=$(mktemp -d)/bundle.tar.gz
# A published bundle combines the reusable framework policy (core) with the VSP
# reference domain (examples/vsp) — exactly the framework + own-domain split an
# adopter ships. bundlepush is a core ops tool.
FRAMEWORK=policies/
DOMAIN=examples/vsp/policies/

echo "==> Fitness functions (opa test)"
opa test "$FRAMEWORK" "$DOMAIN" >/dev/null
echo "    pass"

echo "==> Compiling bundle"
opa build -b "$FRAMEWORK" -b "$DOMAIN" --ignore '*_test.rego' -o "$BUNDLE"

echo "==> Publishing to immutable store"
go run ./cmd/bundlepush -file "$BUNDLE"
