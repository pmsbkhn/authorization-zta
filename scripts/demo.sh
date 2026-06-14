#!/usr/bin/env bash
# End-to-end demo of the cross-PEP bubble-up step-up flow (design-v3 §4) with
# BOTH internal hops secured by real mTLS / SPIFFE X509-SVID (L0, §2).
#
#   client ──http──> gateway(:8088, Edge PEP)
#                        │ mTLS (SVID)
#                        ▼
#                    multibill(:8081)
#                        │ mTLS (SVID)
#                        ▼
#                    wallet(:8082, East-West PEP) ──> pdp(:8080)
#
# svidmint stands in for SPIRE: it issues the trust bundle + per-workload SVIDs.
# (A real SPIRE agent would be used by setting SPIFFE_ENDPOINT_SOCKET instead.)
# Usage: ./scripts/demo.sh
set -euo pipefail
set +m # quiet job-control notifications
cd "$(dirname "$0")/.."

PDP_ADDR=${PDP_ADDR:-:8080}
WALLET_ADDR=${WALLET_ADDR:-:8082}
MULTIBILL_ADDR=${MULTIBILL_ADDR:-:8081}
GATEWAY_ADDR=${GATEWAY_ADDR:-:8088}

BIN=$(mktemp -d); CERTS="$BIN/certs"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null && wait "$p" 2>/dev/null || true; done; rm -rf "$BIN"; }
trap cleanup EXIT

wait_port() { for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&-; return 0; }; sleep 0.1; done; echo "port $1 not up"; return 1; }
port() { echo "${1#:}"; }

echo "==> Building binaries"
for c in pdp wallet multibill gateway svidmint; do go build -o "$BIN/$c" "./cmd/$c"; done

echo "==> Minting SPIFFE SVIDs (svidmint = stand-in for SPIRE)"
"$BIN/svidmint" -out "$CERTS"   # default entries: gateway, multibill, wallet

echo "==> Starting services"
PDP_ADDR="$PDP_ADDR" "$BIN/pdp" >/tmp/zta-pdp.log 2>&1 & PIDS+=($!)
PDP_URL="http://localhost${PDP_ADDR}"

# Wallet: mTLS server. multibill: mTLS server (for gateway) + mTLS client (to wallet).
WALLET_ADDR="$WALLET_ADDR" PDP_URL="$PDP_URL" \
  SVID_BUNDLE="$CERTS/ca.pem" SVID_CERT="$CERTS/wallet.crt" SVID_KEY="$CERTS/wallet.key" \
  "$BIN/wallet" >/tmp/zta-wallet.log 2>&1 & PIDS+=($!)
WALLET_URL="https://localhost${WALLET_ADDR}"

MULTIBILL_ADDR="$MULTIBILL_ADDR" WALLET_URL="$WALLET_URL" \
  SVID_BUNDLE="$CERTS/ca.pem" SVID_CERT="$CERTS/multibill.crt" SVID_KEY="$CERTS/multibill.key" \
  "$BIN/multibill" >/tmp/zta-multibill.log 2>&1 & PIDS+=($!)
MULTIBILL_URL="https://localhost${MULTIBILL_ADDR}"

# Gateway: mTLS client to multibill (presents its own SVID); plain HTTP to users.
GATEWAY_ADDR="$GATEWAY_ADDR" PDP_URL="$PDP_URL" MULTIBILL_URL="$MULTIBILL_URL" \
  SVID_BUNDLE="$CERTS/ca.pem" SVID_CERT="$CERTS/gateway.crt" SVID_KEY="$CERTS/gateway.key" \
  "$BIN/gateway" >/tmp/zta-gateway.log 2>&1 & PIDS+=($!)
GW="http://localhost${GATEWAY_ADDR}"

echo "==> Waiting for ports"
for a in "$PDP_ADDR" "$WALLET_ADDR" "$MULTIBILL_ADDR" "$GATEWAY_ADDR"; do wait_port "$(port "$a")"; done

pay() { # aal amount
  curl -s -o /tmp/zta-body.json -w "%{http_code} | step-up=%header{X-Step-Up-Required}" \
    -X POST "$GW/pay" -H 'Content-Type: application/json' \
    -H "X-Vsp-Subject-Id: u-1" -H "X-Vsp-Aal: $1" -H "X-Vsp-Resource-Id: inv-1" \
    -d "{\"amount\":$2,\"currency\":\"VND\"}"
  echo " | $(cat /tmp/zta-body.json)"
}

echo
echo "Wallet's East-West PEP derives the delegation actor from multibill's mTLS"
echo "client certificate (SPIFFE SVID) — no X-Vsp-Caller-Spiffe header involved."
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
