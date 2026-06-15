#!/usr/bin/env bash
# Prove UpstreamAuthority "vault": SPIRE's CA is signed by a real Vault PKI, so
# SVIDs chain to the Vault-managed root. Self-contained; reuses the M8 node certs.
#
# Reset: docker compose -f deploy/vault/compose.yaml down -v
set -euo pipefail
cd "$(dirname "$0")"

[ -f ../spire/certs/node-ca.crt ] || (cd ../.. && go run ./cmd/nodecert -out deploy/spire/certs)

echo "==> Starting Vault (dev)"
docker compose up -d vault
until docker compose exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root vault vault status >/dev/null 2>&1; do sleep 1; done

echo "==> Initializing Vault PKI root"
V() { docker compose exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root vault vault "$@"; }
V secrets enable pki >/dev/null 2>&1 || true
V secrets tune -max-lease-ttl=87600h pki >/dev/null
V write pki/root/generate/internal common_name="VSP Vault Root CA" ttl=87600h >/dev/null 2>&1 || true
# Fetch the Vault root → the agent's trust bundle.
V read -field=certificate pki/cert/ca > ../spire/certs/vault-root.crt
echo "    vault root → deploy/spire/certs/vault-root.crt"

echo "==> Starting SPIRE (UpstreamAuthority vault) + agent"
docker compose up -d spire-server
until docker compose exec -T spire-server /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1; do sleep 1; done
docker compose up -d spire-agent
until docker compose exec -T spire-server /opt/spire/bin/spire-server agent list 2>/dev/null | grep -q 'spiffe://'; do sleep 1; done
echo "    agent attested (x509pop)"

echo "==> Verifying SVID chain"
docker compose exec -T spire-server /opt/spire/bin/spire-server bundle show > /tmp/vsp-spire-bundle.pem 2>/dev/null
echo -n "    SPIRE trust bundle subject: "; openssl x509 -in /tmp/vsp-spire-bundle.pem -noout -subject 2>/dev/null
echo -n "    Vault root subject:         "; openssl x509 -in ../spire/certs/vault-root.crt -noout -subject 2>/dev/null
if diff -q <(openssl x509 -in /tmp/vsp-spire-bundle.pem -noout -pubkey 2>/dev/null) \
           <(openssl x509 -in ../spire/certs/vault-root.crt -noout -pubkey 2>/dev/null) >/dev/null; then
  echo "    ✓ SPIRE trust bundle IS the Vault-issued root — SVIDs chain to Vault PKI"
else
  echo "    ✗ bundle does not match Vault root"; exit 1
fi
