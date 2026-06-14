#!/usr/bin/env bash
# Bring up the full VSP mesh on a real SPIRE deployment and drive the demo flow.
#
# Production-grade SPIRE (M8): the agent attests with an X.509 node cert
# (x509pop) — no join token — and SVIDs chain to an org upstream root CA. The
# workloads still block on the Workload API until their registration entries
# exist, so we attest the agent, register entries, THEN start the workloads.
#
# Reset with: docker compose -f deploy/compose.yaml down -v
set -euo pipefail
cd "$(dirname "$0")"

TD=vsp.local
SS() { docker compose exec -T spire-server /opt/spire/bin/spire-server "$@"; }

echo "==> Generating PKI (upstream root, node CA, agent node cert)"
[ -f spire/certs/agent-svid.crt ] || (cd .. && go run ./cmd/nodecert -out deploy/spire/certs)

echo "==> Starting SPIRE server"
docker compose up -d spire-server
until SS healthcheck >/dev/null 2>&1; do sleep 1; done

echo "==> Starting SPIRE agent (x509pop auto-attestation)"
docker compose up -d spire-agent
until SS agent list 2>/dev/null | grep -q 'spiffe://'; do sleep 1; done
AGENT_ID=$(SS agent list 2>/dev/null | sed -n 's/^SPIFFE ID *: *//p' | head -1 | tr -d '\r ')
echo "    agent attested: $AGENT_ID"

echo "==> Registering workload entries (unix:uid selectors)"
entry() { SS entry create -parentID "$AGENT_ID" -spiffeID "$1" -selector "unix:uid:$2" >/dev/null 2>&1 || true; }
entry "spiffe://$TD/ns/edge/sa/api-gateway"        10003
entry "spiffe://$TD/ns/billing/sa/multi-bill-svc"  10002
entry "spiffe://$TD/ns/wallet/sa/vsp-wallet-svc"   10001
entry "spiffe://$TD/ns/pdp/sa/pdp-svc"             10004

echo "==> Starting workloads (SVIDs delivered via SPIRE Workload API)"
docker compose up -d --build --no-recreate pdp wallet multibill gateway
until curl -fsS localhost:8088/healthz >/dev/null 2>&1; do sleep 1; done
echo "    mesh ready on http://localhost:8088"

pay() { # aal amount
  curl -s -o /tmp/zta-body.json -w "%{http_code} | step-up=%header{X-Step-Up-Required}" \
    -X POST localhost:8088/pay -H 'Content-Type: application/json' \
    -H "X-Vsp-Subject-Id: u-1" -H "X-Vsp-Aal: $1" -H "X-Vsp-Resource-Id: inv-1" \
    -d "{\"amount\":$2,\"currency\":\"VND\"}"
  echo " | $(cat /tmp/zta-body.json)"
}

echo
echo "Internal hops gateway→multibill→wallet run on mTLS with SPIRE-issued SVIDs."
echo
echo "1) High-value (9,000,000) at AAL2 → expect 401 + bubbled step-up to AAL3"
pay AAL2 9000000
echo "2) Same payment retried at AAL3 → expect 200 settled"
pay AAL3 9000000
echo "3) Low-value (1,000,000) at AAL2 → expect 200 settled"
pay AAL2 1000000
echo
echo "4) CAEP: push session-revoked for u-1 to the wallet PEP, then settle"
docker compose exec -T wallet /app/caepemit -subject u-1 https://localhost:8082/events >/dev/null 2>&1 || true
echo -n "   after revoke (expect 403 session_revoked): "; pay AAL3 1000000
docker compose exec -T wallet /app/caepemit -type session-restored -subject u-1 https://localhost:8082/events >/dev/null 2>&1 || true
echo -n "   after restore (expect 200 settled):        "; pay AAL3 1000000
echo
echo "==> Done. Inspect SVIDs: docker compose -f deploy/compose.yaml exec spire-server /opt/spire/bin/spire-server entry show"
