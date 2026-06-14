#!/usr/bin/env bash
# Bring up the full VSP mesh on a real SPIRE deployment and drive the demo flow.
#
# Order matters: the SPIRE agent needs a one-time join token, and the workloads
# block on the Workload API until their registration entries exist — so we issue
# the token, attest the agent, register entries, THEN start the workloads. The
# agent is started once and kept intact (--no-recreate); JOIN_TOKEN stays
# exported so compose never sees command drift and recreates it with an empty
# token.
#
# Reset with: docker compose -f deploy/compose.yaml down -v
set -euo pipefail
cd "$(dirname "$0")"

TD=vsp.local
SS() { docker compose exec -T spire-server /opt/spire/bin/spire-server "$@"; }

echo "==> Starting SPIRE server"
docker compose up -d spire-server
until SS healthcheck >/dev/null 2>&1; do sleep 1; done

echo "==> Issuing join token and starting SPIRE agent"
export JOIN_TOKEN
JOIN_TOKEN=$(SS token generate -spiffeID "spiffe://$TD/agent" 2>/dev/null | sed -n 's/^Token: //p' | tr -d '\r ')
docker compose up -d spire-agent
until SS agent list 2>/dev/null | grep -q 'spiffe://'; do sleep 1; done
AGENT_ID=$(SS agent list 2>/dev/null | sed -n 's/^SPIFFE ID *: *//p' | head -1 | tr -d '\r ')
echo "    agent attested: $AGENT_ID"

echo "==> Registering workload entries (unix:uid selectors)"
entry() { SS entry create -parentID "$AGENT_ID" -spiffeID "$1" -selector "unix:uid:$2" >/dev/null 2>&1 || true; }
entry "spiffe://$TD/ns/edge/sa/api-gateway"        10003
entry "spiffe://$TD/ns/billing/sa/multi-bill-svc"  10002
entry "spiffe://$TD/ns/wallet/sa/vsp-wallet-svc"   10001

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
echo "==> Done. Inspect SVIDs: docker compose -f deploy/compose.yaml exec spire-server /opt/spire/bin/spire-server entry show"
