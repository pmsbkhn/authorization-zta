# Spec 13 — Deployment Topology

**Gói:** `deploy/`, `scripts/`
**Vai trò:** Cách hệ thống được đóng gói và chạy thật: container, SPIRE thật, biến thể Vault/k8s/ReBAC,
GitOps publish, demo. Khung hóa **C4, C7, C11**.
**View liên quan:** Deployment (VP-7), Security/Trust (VP-5).

---

## 1. Container (deploy/Dockerfile)

Multi-stage: build `golang:1.26`, `CGO_ENABLED=0` (static) → 5 binary daemon
(`pdp, gateway, multibill, wallet, caepemit`); runtime `gcr.io/distroless/static-debian12` (không
shell/libc). CLI tools (`svidmint, nodecert, bundlepush`) không vào image — chạy ngoài.

## 2. Compose tham chiếu (deploy/compose.yaml) — trust domain `vsp.local`

```
user ─http→ gateway(:8088) ─mTLS→ multibill(:8081) ─mTLS→ wallet(:8082) ─gRPC/mTLS→ pdp(:8080,9090)
                 └──────── SVID do SPIRE agent cấp qua Workload API (volume wlapi) ────────┘
```

| Service | Image | UID | Cổng | Env nổi bật |
|---|---|---|---|---|
| spire-server | spire-server:1.15.1 | 0 | (8081 nội bộ) | trust `vsp.local`, NodeAttestor **x509pop**, UpstreamAuthority **disk** |
| spire-agent | spire-agent:1.15.1 | 0 | — | tự attest x509pop, WorkloadAttestor `unix`, socket dùng chung |
| pdp | build | 10004 | 8080, 9090 gRPC | `PDP_TOKEN_SECRET=compose-demo-secret`, `PDP_GRPC_ADDR=:9090` |
| wallet | build | 10001 | 8082 | `PDP_GRPC_ADDR=pdp:9090`, `CAEP_SECRET=compose-caep-secret` |
| multibill | build | 10002 | 8081 | `WALLET_URL=https://wallet:8082` (mTLS) |
| gateway | build | 10003 | 8088:8088 | `MULTIBILL_URL=https://multibill:8081`, `PDP_GRPC_ADDR=pdp:9090` |

Volumes: `wlapi` (Workload API socket), `server-data`, `agent-data`. mTLS hops: gateway→multibill,
multibill→wallet, PEP→PDP (gRPC). Workload attest theo `unix:uid` (mỗi service một uid).

## 3. Orchestration (deploy/run.sh)

```
1. PKI: go run ./cmd/nodecert -out deploy/spire/certs  (upstream-root + node-CA + agent node cert)
2. spire-server up (healthcheck)
3. spire-agent up — tự attest x509pop (không join token); poll tới khi agent xuất hiện
4. register entries (parentID=agent, selector unix:uid):
     edge/api-gateway→10003  billing/multi-bill-svc→10002  wallet/vsp-wallet-svc→10001  pdp/pdp-svc→10004
5. workloads up --build (pdp,wallet,multibill,gateway); chờ gateway /healthz
6. demo (mục 6)
Reset: docker compose -f deploy/compose.yaml down -v
```

## 4. Biến thể triển khai

| Thư mục | Mục đích | Điểm chính |
|---|---|---|
| `deploy/vault/` (`run-vault.sh`, `compose.yaml`, `server-vault.conf`) | **UpstreamAuthority Vault** (M12) | Vault dev → enable PKI → root `VSP Vault Root CA` → SPIRE `UpstreamAuthority "vault"` ký intermediate → SVID chain về Vault root (verify `bundle show` trùng pubkey) |
| `deploy/k8s/` (`spire.yaml`, `run-k8s.sh`) | **k8s_psat** trên k3d (M13) | SPIRE server (Deployment + RBAC TokenReview) + agent (DaemonSet, projected SA token, hostPID); agent id `…/spire/agent/k8s_psat/vsp-cluster/<uid>`; CA 24h/SVID 1h |
| `deploy/rebac/` (`run-rebac.sh`) | **OpenFGA** (M14) | OpenFGA :8089 → store `vsp` + model (`account.owner`/`can_settle`) + tuple → live test owner allow / stranger deny |
| `deploy/bundle/publish.sh` | **GitOps publish** (M10) | `opa test` (gate) → `opa build --ignore '*_test.rego'` → `bundlepush` (object-lock GOVERNANCE + versioning) |

## 5. Demo in-process (scripts/demo.sh)

Mint SVID bằng `svidmint`, boot 4 service (chặng multibill→wallet mTLS thật), 3 ca rồi tự dọn:

| # | Input (`POST :8088/pay`, `u-1`, `inv-1`) | Kỳ vọng | Lý do |
|---|---|---|---|
| 1 | AAL2, amount 9.000.000 | **401** + `X-Step-Up-Required: AAL3` | high-value đòi AAL3; Wallet 403→Gateway dịch 401 |
| 2 | AAL3, amount 9.000.000 | **200** settled | AAL3 đủ |
| 3 | AAL2, amount 1.000.000 | **200** settled | low-value, AAL2 đủ |

`run.sh` (SPIRE thật) chạy thêm: revoke (`caepemit`) → **403 session_revoked** → restore → **200**.

## 6. Hướng tối ưu / vận hành

- **Secret production**: compose dùng `compose-demo-secret`/`compose-caep-secret`, Vault dev-mode root
  token, KeyManager disk → cần secret management thật + HA SPIRE server. *C11.*
- **Observability stack** chưa đóng gói (không Prometheus/Tempo/Loki trong compose); correlation id đã
  sẵn, cần exporter + dashboards. *C12.*
- **PDP plain-HTTP :8080 vẫn mở** song song gRPC mTLS :9090 — production nên đóng HTTP nội bộ hoặc đặt
  sau mesh để mọi chặng PEP→PDP đều mTLS.
- **Node attestor đám mây khác** (`aws_iid`…) và **federation đa trust-domain** là mở rộng tiếp.
- k8s manifest dùng `hostPID: true` (cần cho WorkloadAttestor unix) — lưu ý security hardening pod.
