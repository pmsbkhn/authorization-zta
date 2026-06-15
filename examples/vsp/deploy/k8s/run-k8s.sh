#!/usr/bin/env bash
# Prove the cloud-native node attestor k8s_psat: create a k3d cluster, deploy
# SPIRE (server + agent DaemonSet), and confirm the agent attests using a
# projected ServiceAccount token validated by the Kubernetes TokenReview API.
#
# Reset: k3d cluster delete vsp
set -euo pipefail
cd "$(dirname "$0")"

if ! k3d cluster list 2>/dev/null | grep -q '^vsp '; then
  echo "==> Creating k3d cluster 'vsp'"
  k3d cluster create vsp --servers 1 --agents 0 --wait
fi
kubectl config use-context k3d-vsp >/dev/null

echo "==> Deploying SPIRE (k8s_psat)"
kubectl apply -f spire.yaml >/dev/null
kubectl -n spire rollout status deploy/spire-server --timeout=180s
kubectl -n spire rollout status ds/spire-agent --timeout=180s

echo "==> Verifying node attestation"
SRV=$(kubectl -n spire get pod -l app=spire-server -o jsonpath='{.items[0].metadata.name}')
# Wait for the agent to attest.
for _ in $(seq 1 30); do
  kubectl -n spire exec "$SRV" -- /opt/spire/bin/spire-server agent list 2>/dev/null | grep -q 'k8s_psat' && break
  sleep 2
done
echo -n "    agent id: "
kubectl -n spire exec "$SRV" -- /opt/spire/bin/spire-server agent list 2>/dev/null | sed -n 's/^SPIFFE ID *: *//p' | head -1
if kubectl -n spire exec "$SRV" -- /opt/spire/bin/spire-server agent list 2>/dev/null | grep -q 'k8s_psat'; then
  echo "    ✓ agent attested via k8s_psat (projected SA token → TokenReview)"
else
  echo "    ✗ agent did not attest"; exit 1
fi
