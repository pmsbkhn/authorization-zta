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

```
cmd/
  pdp/               # Control Plane PDP (AuthZEN facade + OPA)
  gateway/           # Edge PEP / API Gateway (profile=edge)
  multibill/         # Multi-Bill workload (delegation + bubble-up; mTLS client)
  wallet/            # VSP Wallet workload + East-West PEP (profile=east_west; mTLS server)
  svidmint/          # cấp CA + SVID ra disk (stand-in cho SPIRE)
internal/
  authzen/           # VSP Standard Contract (types) + validation naming-convention
  api/               # AuthZEN 1.0 HTTP facade
  pdp/               # Unified Router: orchestration ra quyết định
  engine/            # OPA nhúng (compile + eval) → engine.Decision
  token/             # decision_token (HS256, có TTL, ràng buộc tuple)
  pep/               # PEP library: L0/L1/L2 ladder + bubble-up (edge→401, east_west→403)
  pdpclient/         # HTTP client AuthZEN cho PEP
  spiffe/            # SPIFFE CA in-process + mint X509-SVID + tls.Config mTLS (go-spiffe)
  services/          # wiring từng process thành http.Handler (cmd mỏng + E2E test)
  pip/               # interface IdP / SPIRE / PolicyStore (Policy Information Points)
  mock/              # mock của các PIP
policies/            # OPA bundle (embed vào binary)
  main.rego          #   vsp.authz — entrypoint/router, fail-closed
  global/            #   vsp.global — validate schema naming-convention
  lib/               #   vsp.lib — AAL ordering, obligation builders, required_attributes (data-driven)
  profiles/          #   vsp.profiles — invariant theo chặng (edge/east_west/partner)
  domain/            #   vsp.domain.{wallet,bill} — logic nghiệp vụ
  data.json          #   required_attributes (§5.2) — thêm service = sửa JSON, không chạm code
  authz_test.rego    #   fitness functions
```

### Nguyên tắc thiết kế đã áp dụng

- **Fail-closed tuyệt đối:** thiếu allow tường minh = từ chối. Policy undefined, domain lạ, sai schema → `decision:false`.
- **Phân tầng phễu trong Rego:** `main.rego` chạy lần lượt schema → required-attrs → profile invariants → domain; vi phạm ở tầng nào chặn ngay trước khi vào nghiệp vụ.
- **Dynamic dispatch theo domain:** router lấy `data.vsp.domain[<domain>].verdict` theo prefix của `resource.type`; thêm domain mới = thêm 1 file Rego, không sửa router.
- **Data-driven requirements (§5.2):** yêu cầu thuộc tính tách khỏi code, nằm trong `data.json`.
- **Engine-agnostic:** PDP phụ thuộc OPA qua interface `pdp.Engine` → sau này ghép ReBAC/Zanzibar (§6.3) không đụng facade.

---

## Next steps (theo §6 + lộ trình)

- [x] ~~**Full E2E PEP layer**~~ — Edge PEP + East-West PEP + bubble-up step-up (M2).
- [x] ~~**mTLS/SVID thật ở L0**~~ — mTLS + SPIFFE X509-SVID cho chặng East-West (M3).
- [ ] **SPIRE thật** thay `svidmint`: SPIRE server/agent + Workload API + SVID rotation; mTLS cho mọi chặng nội bộ (gồm gateway→multibill).
- [ ] Wire mock PIP còn lại vào hot path (IdP enrich subject; revocation/posture qua attestor).
- [ ] **Decision token re-use:** PEP sâu chấp nhận `X-Decision-Token` AAL3 để bỏ qua re-eval trong TTL.
- [ ] **Protobuf contract** cho luồng gRPC nội bộ (§6.1).
- [ ] **GitOps + immutable S3 bundle store** thật, PDP/PEP pull bundle (§5.3) — thay cho embed.
- [ ] **Dynamic Attributes Cache / CAEP** push thu hồi session/posture (§6.2).
- [ ] Asymmetric signing cho decision_token (PDP ký private key, PEP verify public key).
```
