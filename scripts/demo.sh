#!/usr/bin/env bash
# End-to-end demo of the cross-PEP bubble-up step-up flow (design-v3 §4).
#
# Boots the full data path on localhost:
#   client → gateway(:8088, Edge PEP) → multibill(:8081) → wallet(:8082, East-West PEP) → pdp(:8080)
# then drives three requests through it.
#
# Usage: ./scripts/demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PDP_ADDR=${PDP_ADDR:-:8080}
WALLET_ADDR=${WALLET_ADDR:-:8082}
MULTIBILL_ADDR=${MULTIBILL_ADDR:-:8081}
GATEWAY_ADDR=${GATEWAY_ADDR:-:8088}

set +m # disable job-control notifications so cleanup is quiet
BIN=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null && wait "$p" 2>/dev/null || true; done; rm -rf "$BIN"; }
trap cleanup EXIT

echo "==> Building binaries"
go build -o "$BIN/pdp"       ./cmd/pdp
go build -o "$BIN/wallet"    ./cmd/wallet
go build -o "$BIN/multibill" ./cmd/multibill
go build -o "$BIN/gateway"   ./cmd/gateway

echo "==> Starting services"
PDP_ADDR="$PDP_ADDR" "$BIN/pdp" >/tmp/zta-pdp.log 2>&1 & PIDS+=($!)
PDP_URL="http://localhost${PDP_ADDR}"
WALLET_ADDR="$WALLET_ADDR" PDP_URL="$PDP_URL" "$BIN/wallet" >/tmp/zta-wallet.log 2>&1 & PIDS+=($!)
WALLET_URL="http://localhost${WALLET_ADDR}"
MULTIBILL_ADDR="$MULTIBILL_ADDR" WALLET_URL="$WALLET_URL" "$BIN/multibill" >/tmp/zta-multibill.log 2>&1 & PIDS+=($!)
MULTIBILL_URL="http://localhost${MULTIBILL_ADDR}"
GATEWAY_ADDR="$GATEWAY_ADDR" PDP_URL="$PDP_URL" MULTIBILL_URL="$MULTIBILL_URL" "$BIN/gateway" >/tmp/zta-gateway.log 2>&1 & PIDS+=($!)
GW="http://localhost${GATEWAY_ADDR}"

echo "==> Waiting for health"
for url in "$PDP_URL" "$WALLET_URL" "$MULTIBILL_URL" "$GW"; do
  for _ in $(seq 1 50); do curl -fsS "$url/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
done

pay() { # aal amount
  curl -s -o /tmp/zta-body.json -w "%{http_code} | step-up=%header{X-Step-Up-Required}" \
    -X POST "$GW/pay" -H 'Content-Type: application/json' \
    -H "X-Vsp-Subject-Id: u-1" -H "X-Vsp-Aal: $1" -H "X-Vsp-Resource-Id: inv-1" \
    -d "{\"amount\":$2,\"currency\":\"VND\"}"
  echo " | $(cat /tmp/zta-body.json)"
}

echo
echo "1) High-value (9,000,000) at AAL2 → expect 401 + bubbled step-up to AAL3"
pay AAL2 9000000
echo
echo "2) Same payment retried at AAL3 → expect 200 settled"
pay AAL3 9000000
echo
echo "3) Low-value (1,000,000) at AAL2 → expect 200 settled (no step-up)"
pay AAL2 1000000
echo
echo "==> Done. Service logs in /tmp/zta-*.log"
