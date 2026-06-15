#!/usr/bin/env bash
# Prove the ReBAC (Zanzibar-style) engine behind pdp.Engine: run OpenFGA, define
# an account/owner/can_settle model, grant user:u-1 owner of account:acc-1, then
# run the live engine test — owner is allowed, a stranger is denied, purely by
# relationship (design-v3 §6.3).
#
# Reset: docker rm -f vsp-openfga
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT=8089
docker rm -f vsp-openfga >/dev/null 2>&1 || true
echo "==> Starting OpenFGA"
docker run -d --name vsp-openfga -p ${PORT}:8080 openfga/openfga run >/dev/null
until curl -fsS localhost:${PORT}/healthz >/dev/null 2>&1; do sleep 1; done
EP="http://localhost:${PORT}"

echo "==> Creating store + authorization model"
SID=$(curl -s -X POST $EP/stores -H 'content-type: application/json' -d '{"name":"vsp"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
MID=$(curl -s -X POST $EP/stores/$SID/authorization-models -H 'content-type: application/json' -d '{
 "schema_version":"1.1",
 "type_definitions":[
  {"type":"user"},
  {"type":"account","relations":{"owner":{"this":{}},"can_settle":{"computedUserset":{"relation":"owner"}}},
   "metadata":{"relations":{"owner":{"directly_related_user_types":[{"type":"user"}]},"can_settle":{}}}}
 ]}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["authorization_model_id"])')

echo "==> Granting user:u-1 owner of account:acc-1"
curl -s -X POST $EP/stores/$SID/write -H 'content-type: application/json' \
  -d '{"writes":{"tuple_keys":[{"user":"user:u-1","relation":"owner","object":"account:acc-1"}]}}' >/dev/null

echo "==> Running live ReBAC engine test"
OPENFGA_ENDPOINT=$EP OPENFGA_STORE=$SID OPENFGA_MODEL=$MID go test ./internal/rebac/ -run TestReBAC_Live -v
