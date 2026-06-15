# authorization-zta

Hệ thống **Authorization dùng chung** theo chuẩn **Zero Trust Architecture (ZTA)** cho VSP System — facade **OpenID AuthZEN 1.0** đặt trước một **PDP** nhúng **OPA** (Open Policy Agent).

Thiết kế chi tiết: [`docs/design-v3.md`](docs/design-v3.md).

---

## Milestone 1 — Control Plane lõi (đã hoàn thành)

Phạm vi M1: **PDP + AuthZEN facade + OPA thật (nhúng làm thư viện)**. Các PIP còn lại (IdP / SPIRE / Policy Store S3) là **interface + mock**, sẵn sàng thay bản thật ở M2+.

| Thành phần | Vai trò | Trạng thái |
|---|---|---|
| AuthZEN 1.0 Facade (`internal/api`) | Endpoint `POST /access/v1/evaluation`, ẩn nội bộ PDP/OPA | ✅ |
| PDP / Unified Router (`internal/pdp`) | Validate contract → eval engine → mint token → dựng response | ✅ |
| Embedded OPA Engine (`internal/engine`) | Nhúng OPA làm thư viện, compile bundle 1 lần, eval in-process | ✅ |
| Hierarchical Rego (`policies/`) | `global` → `lib` (data-driven) → `profiles` → `domain` | ✅ |
| Decision Token (`internal/token`) | Token HS256 có TTL, gắn chặt vào tuple đã cấp quyền | ✅ |
| PIP seams + mocks (`internal/pip`, `internal/mock`) | IdP / SPIRE / PolicyStore dạng interface | ✅ (mock) |
| Fitness functions | `opa test` (9 ca) + Go tests E2E | ✅ |

---

## Milestone 2 — PEP layer + bubble-up step-up (đã hoàn thành)

Phạm vi M2: dựng **Data Plane / PEP layer** đầy đủ và hiện thực hóa **Bubble-up Pattern (§4)** xuyên chặng. Toàn bộ chuỗi chạy thật được:

```
client ──> gateway(:8088)      ──> multibill(:8081) ──> wallet(:8082)        ──> pdp(:8080)
           Edge PEP (edge)          (delegation)          East-West PEP (east_west)   Control Plane
```

| Thành phần | Vai trò | Trạng thái |
|---|---|---|
| PEP library (`internal/pep`) | Phễu **L0** (SVID/peer) → **L1** (route guard) → **L2** (gọi PDP); fail-closed; map Outcome→HTTP theo profile | ✅ |
| PDP client (`internal/pdpclient`) | Client AuthZEN cho PEP; non-200 = deny | ✅ |
| Edge PEP — Gateway (`cmd/gateway`) | Authorize `bill:pay` (profile=edge), reverse-proxy Multi-Bill, dịch bubble-up → **401 challenge** | ✅ |
| Multi-Bill (`cmd/multibill`) | Gọi Wallet để settle, gắn SPIFFE làm **delegation actor**, **bubble-up** `X-Step-Up-Required` | ✅ |
| VSP Wallet (`cmd/wallet`) | East-West PEP (profile=east_west); step-up → **403 + header** (không challenge) | ✅ |
| E2E integration test | Wiring cả 4 service in-process, kiểm chứng bubble-up + retry AAL3 | ✅ |

**Bubble-up step-up hoạt động (đã verify live + test):**
1. User `bill:pay` 9.000.000đ ở **AAL2** → Edge cho qua (`bill:pay` chỉ cần AAL2).
2. Multi-Bill gọi Wallet `wallet:settle` (9M) → Wallet East-West PEP hỏi PDP → **deny + `step_up→AAL3`**.
3. Wallet PEP **không challenge** (không có session user) → trả **403 + `X-Step-Up-Required: AAL3`**.
4. Multi-Bill dội ngược header lên Gateway.
5. Gateway (Edge PEP) dịch thành **HTTP 401** challenge để UI bật MFA.
6. User MFA → **AAL3** → retry → settle thành công (**200**).

> Lưu ý M2: danh tính workload (`act`) ban đầu propagate qua header `X-Vsp-Caller-Spiffe`. M3 thay bằng mTLS/SVID thật.

---

## Milestone 3 — mTLS + SPIFFE SVID thật ở L0 (đã hoàn thành)

Phạm vi M3: thay header propagation bằng **mutual TLS thật** với **SPIFFE X509-SVID**. Chặng East-West (`multibill → wallet`) giờ là mTLS; **delegation actor (`act`) lấy từ client cert đã verify**, không thể giả mạo bằng header.

| Thành phần | Vai trò | Trạng thái |
|---|---|---|
| SPIFFE CA (`internal/spiffe`) | CA in-process **đóng vai SPIRE**: mint X509-SVID (URI SAN `spiffe://`), trust bundle, dựng `tls.Config` mTLS qua `go-spiffe/v2` | ✅ |
| `cmd/svidmint` | Cấp `ca.pem` + SVID cert/key cho từng workload ra disk (stand-in cho SPIRE Workload API) | ✅ |
| PEP L0 (`internal/pep`) | Lấy SPIFFE id từ **peer cert đã verify** (`r.TLS`), không từ header; cờ `RequirePeerSVID` | ✅ |
| Wallet mTLS server | Yêu cầu + verify + authorize client SVID (member of trust domain) | ✅ |
| Multi-Bill mTLS client | Trình SVID của chính nó khi gọi Wallet; bỏ header caller | ✅ |
| E2E mTLS tests | Happy-path qua mTLS, **no-cert → drop ở handshake (L0)**, **foreign CA → reject ở handshake** | ✅ |

**Điều mTLS đảm bảo (đã verify live + test):**
- mTLS **thật**: handshake, xác minh chuỗi chứng chỉ và authorize trust-domain đều thật (lib `go-spiffe/v2`); chỉ phần *cấp phát* CA là mock thay cho SPIRE.
- **Drop-connection ở L0 (§2):** client không có SVID → rớt ngay tại TLS handshake, không chạm PEP/PDP.
- **Chống giả mạo:** cert ký bởi CA lạ bị từ chối ở handshake. Danh tính `act` của PDP nhận được là **mật mã**, không phải header.
- **Phân tách đúng:** danh tính *workload* = mTLS/SVID (mật mã); danh tính *user* (`subject`/`aal`) = vẫn propagate (production sẽ là signed token).

> **Mock vs thật:** SVID/mTLS thật; SPIRE control-plane (server/agent + Workload API + rotation) vẫn mock bằng `cmd/svidmint` ghi cert ra disk.

---

## Milestone 4 — SVID rotation, SPIRE-ready, mTLS mọi chặng nội bộ (đã hoàn thành)

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| Source abstraction (`internal/spiffe`) | `Source` triển khai `x509svid.Source`+`x509bundle.Source`; `tls.Config` đọc SVID mới mỗi handshake | ✅ |
| **SVID rotation** | `CA.RotatingSource` re-mint SVID theo chu kỳ (mô phỏng SPIRE rotation); unit test xác nhận SVID đổi | ✅ |
| **SPIRE-ready** | Có `SPIFFE_ENDPOINT_SOCKET` → dùng `workloadapi.X509Source` (SPIRE agent thật); không có → fallback file/rotating | ✅ |
| **mTLS cả 2 chặng** | `gateway → multibill` cũng mTLS (gateway trình SVID, multibill verify); E2E `BothHopsSecured` | ✅ |

## Milestone 5 — Decision token re-use (PEP fast-path) (đã hoàn thành)

PEP sâu chấp nhận `X-Decision-Token` hợp lệ và **bỏ qua PDP** cho request giống hệt trong TTL.

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| Token binding an toàn | Token ràng `subject+action+resource+aal+**digest(resource.properties)**` — token low-value **không** dùng được cho high-value | ✅ |
| PEP fast-path | `Check` verify token trước L2; khớp tuple + digest + AAL ≥ → Allow, không gọi PDP; sai → fallback PDP (không bao giờ allow ngầm) | ✅ |
| Token propagation | PEP echo token qua response header; Multi-Bill cache theo tuple + replay | ✅ |
| Chứng minh end-to-end | E2E: settle lần 1 (PDP up) → **tắt PDP** → settle giống hệt vẫn 200 (fast-path); amount khác → fail | ✅ |

---

## Milestone 6 — Protobuf/gRPC AuthZEN contract (đã hoàn thành)

Bổ sung kênh **gRPC** cho luồng nội bộ song song với facade JSON/HTTP (§6.1).

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| Proto contract (`proto/authzen/v1`) | `AccessEvaluation.Evaluate`; `properties`/`context` dùng `google.protobuf.Struct` → không cần schema cứng cho thuộc tính nghiệp vụ | ✅ |
| gRPC server (`internal/grpcpdp`) | Bọc `pdp.Service`; validation→`InvalidArgument`, lỗi nội bộ→`Internal` (khớp HTTP) | ✅ |
| gRPC client | Implement `pep.PDP` → **drop-in** thay `pdpclient` HTTP, không đổi PEP | ✅ |
| PDP phục vụ gRPC | `cmd/pdp` mở thêm gRPC khi set `PDP_GRPC_ADDR` (song song HTTP `:8080`) | ✅ |
| Roundtrip test | allow + decision_token + obligation `step_up`, và validation→`InvalidArgument`, qua wire thật | ✅ |

Regen stubs: `./proto/generate.sh` (cần `protoc` + `protoc-gen-go`/`protoc-gen-go-grpc`).

---

## Milestone 7 — SPIRE thật qua Docker Compose (đã hoàn thành)

Thay `svidmint` bằng **SPIRE server + agent thật** (`ghcr.io/spiffe/spire:1.15.1`). SVID được cấp qua **Workload API** — không còn cert tĩnh trên disk. Code Go **không đổi** (đã SPIRE-ready từ M4: tự dùng `SPIFFE_ENDPOINT_SOCKET`).

```
user ──http──> gateway ──mTLS──> multibill ──mTLS──> wallet ──http──> pdp
                  └──────── SVID do SPIRE agent cấp qua Workload API ────────┘
```

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| SPIRE server | trust domain `vsp.local`, sqlite + memory keys, node attestor `join_token` | ✅ |
| SPIRE agent | join-token attestation, `WorkloadAttestor unix`, Workload API socket chia sẻ qua volume | ✅ |
| Workload attestation | `unix:uid` — mỗi service chạy 1 uid riêng (10001/2/3), agent `pid:host` để resolve caller | ✅ |
| Containerize | `deploy/Dockerfile` build 4 binary (static, distroless); `deploy/compose.yaml` | ✅ |
| Orchestration | `deploy/run.sh`: server → join token → agent → registration entries → workloads → demo | ✅ |
| Chạy thật | full stack lên, flow bubble-up + retry + low-value **đúng cả 3 ca**, mTLS mọi chặng nội bộ với SVID SPIRE | ✅ |

### Chạy demo SPIRE thật

```bash
cd deploy && ./run.sh
# Reset: docker compose -f deploy/compose.yaml down -v
# Xem SVID đã đăng ký:
docker compose -f deploy/compose.yaml exec spire-server /opt/spire/bin/spire-server entry show
```

> **Mock vs thật (sau M7):** OPA, mTLS+SVID, SPIRE control-plane, gRPC, decision token — thật. Node attestation còn dùng `join_token` (demo) — nâng lên production ở M8.

---

## Milestone 8 — Node attestation production + UpstreamAuthority (đã hoàn thành)

Nâng SPIRE từ demo-grade lên production: bỏ `join_token`/`insecure_bootstrap`/keys in-memory.

| Hạng mục | Trước (M7) | Sau (M8) |
|---|---|---|
| Node attestation | `join_token` (bearer, single-use, dễ recreate-crash) | **`x509pop`** — agent chứng minh bằng X.509 node cert (ký bởi node-CA), tự attest, `reattestable` |
| CA gốc | SPIRE self-signed | **UpstreamAuthority `disk`** — SVID chain về **org upstream root CA** |
| Bootstrap | `insecure_bootstrap = true` | `trust_bundle_path` pin upstream root → verify server bằng mật mã |
| Signing keys | KeyManager `memory` | KeyManager `disk` (bền qua restart) |
| PKI | — | `cmd/nodecert` sinh upstream-root + node-CA + agent node cert (key 0600, **không commit**) |

**Đã verify live:**
- Agent ID = `spiffe://vsp.local/spire/agent/x509pop/<fingerprint>`, log `Node attestation was successful … x509pop` (không token).
- `spire-server bundle show` == **VSP Upstream Root CA** → mọi SVID chain về root tổ chức.
- Toàn bộ flow bubble-up + retry + low-value vẫn đúng cả 3 ca; code Go không đổi.

`run.sh` giờ đơn giản hơn hẳn: sinh PKI → server → agent (tự attest) → entries → workloads (hết màn xoay token).

---

## Milestone 9 — gRPC-over-mTLS PEP→PDP end-to-end (đã hoàn thành)

PEP gọi PDP qua **gRPC bảo vệ bằng mTLS** (SVID), thay HTTP. Giờ **mọi chặng** đều mTLS: `gateway→PDP`, `wallet→PDP` (gRPC/mTLS), `gateway→multibill`, `multibill→wallet`.

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| PDP gRPC mTLS | `cmd/pdp` mở gRPC creds SVID khi có Workload API; client lạ/không cert bị từ chối ở handshake | ✅ |
| PEP gRPC client | `services.PDPGRPCClient` dial PDP bằng SVID; `grpcpdp.Client` (impl `pep.PDP`) cắm vào qua `WalletConfig.PDP`/`GatewayConfig.PDP` | ✅ |
| PDP có SVID riêng | entry `spiffe://vsp.local/ns/pdp/sa/pdp-svc` (uid 10004) | ✅ |
| Test | gRPC-mTLS: SVID hợp lệ qua được, **foreign-CA bị reject ở handshake** | ✅ |
| Chạy thật | log `PDP gRPC listening (mTLS)` + `wallet/gateway → PDP over gRPC/mTLS`; flow đúng cả 3 ca | ✅ |

---

## Milestone 10 — GitOps + immutable S3 (MinIO) bundle store (đã hoàn thành)

PDP **pull** OPA bundle từ object store bất biến thay vì embed (design-v3 §5.3). `pip.PolicyStore` giờ có bản thật.

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| S3 PolicyStore (`internal/bundlestore`) | minio-go, `LatestBundle` lấy bundle + version id | ✅ |
| Engine từ bundle (`engine.NewFromBundle`) | parse OPA bundle tarball → modules+data; test khớp embedded | ✅ |
| Publish (GitOps) (`cmd/bundlepush` + `deploy/bundle/publish.sh`) | `opa test` (gate) → `opa build` → upload **WORM** (object-lock + versioning) | ✅ |
| PDP pull | `S3_ENDPOINT` set → `engine.NewFromBundle` từ bundle S3; không set → embed | ✅ |
| Verify live | publish lên MinIO → PDP pull (log version) → quyết định đúng; republish = **version mới**, bản cũ giữ nguyên | ✅ |

```bash
docker run -d -p 9000:9000 minio/minio server /data
S3_ENDPOINT=localhost:9000 ./deploy/bundle/publish.sh           # test→build→push (immutable)
S3_ENDPOINT=localhost:9000 go run ./cmd/pdp                     # PDP pulls bundle from S3
```

> **Mock vs thật (sau M10):** OPA, mTLS+SVID toàn mesh, SPIRE production, decision token, **PolicyStore S3 bất biến** — thật. Node attestor `x509pop`→`k8s_psat` (M13); UpstreamAuthority `disk`→Vault (M12); IdP vẫn interface+mock.

---

## Milestone 11 — CAEP push revocation/posture (đã hoàn thành)

Vòng **CAEP/SSF**: Control Plane đẩy Security Event Token (SET) thu hồi session tới PEP; PEP **deny ngay**, đè lên decision token còn hạn (đóng khe hở của quyết định đã cache, §6.2).

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| SET (`internal/caep`) | token ký HS256 (kiểu RFC 8417): `session-revoked`/`session-restored`; tamper/forge bị từ chối | ✅ |
| Transmitter / Receiver | Control Plane ký + push; PEP `POST /events` verify + cập nhật `RevocationCache` | ✅ |
| PEP enforcement | `Check` kiểm revocation **trước** fast-path token & PDP → subject bị thu hồi = deny `session_revoked` | ✅ |
| `cmd/caepemit` | tool admin đẩy SET; push qua **mTLS** bằng SVID khi có Workload API | ✅ |
| Test | sign/verify, push→cache, **revocation đè token hợp lệ**, và E2E xuyên chain | ✅ |
| Live trên SPIRE | `caepemit` (trong container, SVID riêng) push qua mTLS → settle **403 session_revoked**; restore → **200** | ✅ |

> **Mock vs thật (sau M11):** thêm **CAEP push revocation thật** (mTLS). Còn lại: UpstreamAuthority Vault (M12), cloud attestor k8s_psat (M13), ReBAC (M14); IdP vẫn interface+mock.

---

## Milestone 12 — UpstreamAuthority Vault (HashiCorp Vault PKI) (đã hoàn thành)

Thay UpstreamAuthority `disk` bằng **Vault PKI thật**: SPIRE gửi CSR intermediate tới `pki/root/sign-intermediate` của Vault → mọi SVID chain về root do Vault quản lý.

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| Vault PKI | `hashicorp/vault` (dev), enable `pki` + generate root `VSP Vault Root CA` | ✅ |
| SPIRE config | `server-vault.conf`: `UpstreamAuthority "vault"` (token auth) + x509pop | ✅ |
| Agent trust bundle | lấy Vault root → `bundle.crt` của agent | ✅ |
| Verify live | `spire-server bundle show` **trùng pubkey** Vault root → SVID chain về Vault PKI | ✅ |

```bash
deploy/vault/run-vault.sh    # vault → init PKI → SPIRE(vault upstream) → verify chain
# Reset: docker compose -f deploy/vault/compose.yaml down -v
```

---

## Milestone 13 — Cloud-native node attestor k8s_psat (k3d) (đã hoàn thành)

Triển khai SPIRE trên **Kubernetes thật** (k3d) với node attestor **`k8s_psat`**: agent chứng minh danh tính node bằng **projected ServiceAccount token**, server validate qua **Kubernetes TokenReview API**. Đây là attestor production cho k8s (không token/cert thủ công) — đối ứng đám mây của x509pop.

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| Cluster | `k3d` (k8s 1.35-in-docker) | ✅ |
| Manifests (`deploy/k8s/spire.yaml`) | SPIRE server (Deployment + RBAC TokenReview) + agent (DaemonSet, projected token) | ✅ |
| Node attestation | agent id `spiffe://vsp.local/spire/agent/k8s_psat/vsp-cluster/<uid>`, `reattestable=true` | ✅ |
| Verify live | server log `node_attestor_type=k8s_psat … attestation request completed`; agent `Node attestation was successful` | ✅ |

```bash
deploy/k8s/run-k8s.sh        # k3d create → deploy SPIRE → verify k8s_psat attestation
# Reset: k3d cluster delete vsp
```

---

## Milestone 14 — ReBAC (OpenFGA) sau pdp.Engine (§6.3) (đã hoàn thành)

Engine **quan hệ kiểu Zanzibar** (OpenFGA) thỏa **cùng `pdp.Engine`** như OPA, nên PDP có thể route tới nó hoặc compose với OPA mà không đổi facade/PEP.

| Hạng mục | Chi tiết | Trạng thái |
|---|---|---|
| ReBAC engine (`internal/rebac`) | gọi OpenFGA `/check`; map `subject→user`, `action verb→can_<verb>`, `resource→object` | ✅ |
| Drop-in `pdp.Engine` | `var _ pdp.Engine = (*rebac.Engine)(nil)` — cắm thẳng vào `pdp.New(engine, issuer)` | ✅ |
| Mô hình quan hệ | `account` với `owner`/`can_settle`; tuple `user:u-1 owner account:acc-1` | ✅ |
| Verify live | owner → allow (`rebac_relationship_ok`), stranger → deny — **thuần quan hệ** | ✅ |

```bash
deploy/rebac/run-rebac.sh    # OpenFGA → model + tuple → live engine test
# Reset: docker rm -f vsp-openfga
```

> **Trạng thái cuối:** lõi quyết định/enforcement, mTLS+SVID toàn mesh, SPIRE production (x509pop + k8s_psat + Vault upstream), gRPC, decision token, CAEP, PolicyStore S3 bất biến, và ReBAC — **đều thật**. Còn lại thuần production-hardening: IdP enrich thật, node attestor đám mây khác (`aws_iid`…), HA/secret management.

---

## Yêu cầu

- **Go** ≥ 1.22 (dùng method-based routing của `net/http.ServeMux`). Đã test với 1.26.
- **OPA CLI** (tùy chọn) — chỉ để chạy fitness functions Rego độc lập: `brew install opa`.

## Chạy

### Demo nhanh toàn chuỗi (khuyến nghị)

```bash
./scripts/demo.sh   # mint SVID + boot 4 service (East-West chạy mTLS thật), chạy 3 ca rồi tự dọn
```

Kết quả mong đợi: (1) AAL2 9M → `401 step-up=AAL3`, (2) AAL3 9M → `200 settled`, (3) AAL2 1M → `200 settled`.
Demo cấp SVID bằng `cmd/svidmint` và chạy chặng `multibill → wallet` qua mTLS.

### Chạy thủ công từng service

> Không set `SVID_*` → wallet chạy **plain HTTP dev mode** (L0 tin header `X-Vsp-Caller-Spiffe`). Set `SVID_BUNDLE`/`SVID_CERT`/`SVID_KEY` → bật mTLS (xem `scripts/demo.sh`).

```bash
go run ./cmd/pdp                                 # Control Plane PDP   :8080
PDP_URL=http://localhost:8080 go run ./cmd/wallet        # Wallet + East-West PEP :8082
WALLET_URL=http://localhost:8082 go run ./cmd/multibill  # Multi-Bill          :8081
PDP_URL=http://localhost:8080 MULTIBILL_URL=http://localhost:8081 go run ./cmd/gateway  # Edge PEP :8088

# Gọi qua Edge Gateway (bubble-up step-up):
curl -i -X POST localhost:8088/pay -H 'Content-Type: application/json' \
  -H 'X-Vsp-Subject-Id: u-1' -H 'X-Vsp-Aal: AAL2' -H 'X-Vsp-Resource-Id: inv-1' \
  -d '{"amount":9000000,"currency":"VND"}'      # → 401 + X-Step-Up-Required: AAL3
```

### Chỉ chạy PDP (Control Plane)

```bash
PDP_ADDR=:8080 PDP_TOKEN_SECRET=change-me PDP_TOKEN_TTL=5m go run ./cmd/pdp
```

### Ví dụ gọi (AuthZEN Access Evaluation)

**ALLOW** — `wallet:settle` 9.000.000đ với AAL3:

```bash
curl -s -X POST localhost:8080/access/v1/evaluation -H 'Content-Type: application/json' -d '{
  "subject":{"type":"user","id":"u-1","properties":{"auth_assurance_level":"AAL3"}},
  "action":{"name":"wallet:settle","properties":{"method":"POST"}},
  "resource":{"type":"wallet:account","id":"acc-1","properties":{"amount":9000000,"currency":"VND"}},
  "context":{"authz_profile":"edge","source_ip":"10.0.0.1","correlation_id":"trace-1"}
}'
```

→ `{"decision":true,"context":{"decision_token":{...,"ttl_seconds":300},"obligations":[{"type":"log",...}],"reason_code":"wallet_settle_high_value_aal3"}}`

**DENY + STEP-UP** — cùng giao dịch nhưng AAL2:

→ `{"decision":false,"context":{"obligations":[{"type":"step_up","details":{"required_acr":"AAL3","method":"mfa"}},...],"reason_code":"step_up_required"}}`

## Test

```bash
go test ./...        # Go unit + E2E tests (compile + eval OPA thật)
opa test policies/ -v # Fitness functions Rego (9 ca)
```

---

## Cấu trúc

> **Nền tảng vs Demo:** repo tách rõ **lõi nền tảng ZTA** (authorization tại 3 chặng — tái sử dụng) khỏi
> **reference adopter VSP** (Gateway/Multi-Bill/Wallet — chỉ là demo, nằm dưới `examples/vsp/`). Chi
> tiết kiến trúc: [`docs/architecture/`](docs/architecture/).

```
# ── LÕI NỀN TẢNG (tái sử dụng) ────────────────────────────────────────────────
cmd/
  pdp/               # PDP generic (framework embed + S3 bundle pull) — adopter cấp domain riêng
  caepemit/          # ops tool: đẩy CAEP SET (thu hồi/khôi phục session)
  bundlepush/        # ops tool: publish OPA bundle lên policy store bất biến (WORM)
internal/
  authz/             # LÕI AUTHORIZATION (3 chặng)
    authzen/         #   VSP Standard Contract (types) + validation naming-convention
    api/             #   AuthZEN 1.0 HTTP facade
    pdp/             #   Unified Router + port pdp.Engine
    engine/          #   OPA nhúng (compile + eval) → engine.Decision
    rebac/           #   ReBAC/OpenFGA engine (drop-in pdp.Engine)
    token/           #   decision_token (HS256, TTL, ràng tuple+digest)
    pep/             #   PEP library: L0/L1/L2 ladder + bubble-up (edge→401, east_west→403)
    pdpclient/       #   HTTP client AuthZEN cho PEP
    grpcpdp/         #   gRPC PDP server + client (impl pep.PDP)
  identity/spiffe/   # WORKLOAD AUTHENTICATION: CA/mint SVID/rotation/Source/mTLS (go-spiffe) — module lân cận
  signals/caep/      # CONTINUOUS EVALUATION: SET (RFC 8417) + RevocationCache — module lân cận
  policystore/bundlestore/  # adapter S3 (MinIO) cho policy bundle
  ports/pip/         # SPI: IdP / WorkloadAttestor / PolicyStore (Policy Information Points)
  services/          # platform wiring tái dùng: PDPService/Handler, mTLS (mtls.go), gRPC (grpc.go)
  testsupport/       # mock/ (fake các PIP) + policyfixture/ (synthetic domain cho test lõi)
policies/            # KHUNG policy nền tảng (embed) — KHÔNG có domain nghiệp vụ
  main.rego          #   vsp.authz — entrypoint/router, fail-closed
  global/ lib/ profiles/   # vsp.global / vsp.lib / vsp.profiles
  data.json          #   required_attributes rỗng (adopter cấp domain data)
proto/authzen/v1/    # Protobuf/gRPC AuthZEN contract + generated *.pb.go

# ── REFERENCE ADOPTER (demo, KHÔNG thuộc lõi) ─────────────────────────────────
examples/vsp/
  cmd/{pdp,gateway,multibill,wallet,svidmint,nodecert}/   # workload + tool demo
  app/               # wiring demo (Gateway/Multibill/Wallet) + DemoPDPConfig + E2E tests
  policies/          # vsp.domain.{wallet,bill} + data.json + authz_test.rego (domain nghiệp vụ)
  deploy/            # SPIRE thật: Dockerfile + compose.yaml + spire/ + run.sh + vault/ + k8s/ + rebac/
  scripts/demo.sh    # demo in-process (svidmint + 4 service, mTLS East-West)
```

> Lõi nạp domain của adopter qua `services.PDPConfig.ExtraModules`/`ExtraData` (in-process) hoặc một
> compiled bundle từ S3 (production). Demo dùng `examples/vsp/app.DemoPDPConfig` để ghép
> `examples/vsp/policies` lên khung. Lõi hiện vẫn nằm trong `internal/` (chưa import được từ module
> khác) — bước đưa ra `pkg/`/module riêng là việc tiếp theo nếu muốn nhúng như thư viện ngoài.

### Nguyên tắc thiết kế đã áp dụng

- **Fail-closed tuyệt đối:** thiếu allow tường minh = từ chối. Policy undefined, domain lạ, sai schema → `decision:false`.
- **Phân tầng phễu trong Rego:** `main.rego` chạy lần lượt schema → required-attrs → profile invariants → domain; vi phạm ở tầng nào chặn ngay trước khi vào nghiệp vụ.
- **Dynamic dispatch theo domain:** router lấy `data.vsp.domain[<domain>].verdict` theo prefix của `resource.type`; thêm domain mới = thêm 1 file Rego, không sửa router.
- **Data-driven requirements (§5.2):** yêu cầu thuộc tính tách khỏi code, nằm trong `data.json`.
- **Engine-agnostic:** PDP phụ thuộc OPA qua interface `pdp.Engine` → sau này ghép ReBAC/Zanzibar (§6.3) không đụng facade.

---

## Next steps (theo §6 + lộ trình)

- [x] ~~**Full E2E PEP layer**~~ — Edge PEP + East-West PEP + bubble-up step-up (M2).
- [x] ~~**mTLS/SVID thật ở L0**~~ — mTLS + SPIFFE X509-SVID, cả 2 chặng nội bộ (M3–M4).
- [x] ~~**SVID rotation + SPIRE-ready**~~ — rotation + `workloadapi` khi có `SPIFFE_ENDPOINT_SOCKET` (M4).
- [x] ~~**Decision token re-use**~~ — PEP fast-path, ràng digest, sống sót PDP outage (M5).
- [x] ~~**Protobuf/gRPC contract**~~ — `AccessEvaluation.Evaluate`, client drop-in cho PEP (M6).
- [x] ~~**SPIRE daemon thật**~~ — spire-server/agent qua docker-compose, SVID qua Workload API (M7).
- [x] ~~**Node attestor production + UpstreamAuthority**~~ — x509pop + UpstreamAuthority disk + keys bền (M8).
- [x] ~~**Cloud-native attestor `k8s_psat`**~~ — SPIRE trên k3d, projected SA token + TokenReview (M13).
- [x] ~~**UpstreamAuthority Vault**~~ — Vault PKI ký intermediate (M12).
- [x] ~~**gRPC qua mTLS end-to-end**~~ — PEP→PDP gRPC/mTLS (M9).
- [ ] Wire mock PIP còn lại vào hot path (IdP enrich subject; revocation/posture qua attestor).
- [ ] **GitOps + immutable S3 bundle store** thật, PDP/PEP pull bundle (§5.3) — thay cho embed.
- [x] ~~**CAEP push thu hồi session/posture**~~ — SET transmitter/receiver + PEP deny tức thì (M11).
- [ ] **ReBAC/Zanzibar** sau interface `pdp.Engine` (§6.3) — M14.
- [ ] Asymmetric signing cho decision_token (PDP ký private key, PEP verify public key).
```
