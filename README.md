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

> **L0/L1/L2 & bubble-up step-up (§2, §4):** OPA đã phát obligation `step_up` đúng (xem demo bên dưới). Phần *thực thi* L0/L1 tại PEP và logic dội ngược header `X-Step-Up-Required` thuộc về **PEP layer** — sẽ làm ở milestone Full E2E.

---

## Yêu cầu

- **Go** ≥ 1.22 (dùng method-based routing của `net/http.ServeMux`). Đã test với 1.26.
- **OPA CLI** (tùy chọn) — chỉ để chạy fitness functions Rego độc lập: `brew install opa`.

## Chạy

```bash
# Khởi động PDP (mặc định :8080)
go run ./cmd/pdp
# hoặc đổi port / secret / ttl:
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
cmd/pdp/             # main: nạp bundle, dựng engine + PDP + facade, serve HTTP
internal/
  authzen/           # VSP Standard Contract (types) + validation naming-convention
  api/               # AuthZEN 1.0 HTTP facade
  pdp/               # Unified Router: orchestration ra quyết định
  engine/            # OPA nhúng (compile + eval) → engine.Decision
  token/             # decision_token (HS256, có TTL, ràng buộc tuple)
  pip/               # interface IdP / SPIRE / PolicyStore (Policy Information Points)
  mock/              # mock của các PIP cho M1
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

- [ ] **Full E2E PEP layer:** Edge PEP (API Gateway) + East-West Sidecar, thực thi L0 (mTLS/SVID) & L1 (route guard), và **bubble-up** `X-Step-Up-Required` → 401 challenge.
- [ ] Wire mock PIP vào hot path (IdP enrich subject, SPIRE attest SVID ở L0).
- [ ] **Protobuf contract** cho luồng gRPC nội bộ (§6.1).
- [ ] **GitOps + immutable S3 bundle store** thật, PDP/PEP pull bundle (§5.3) — thay cho embed.
- [ ] **Dynamic Attributes Cache / CAEP** push thu hồi session/posture (§6.2).
- [ ] Asymmetric signing cho decision_token (PDP ký private key, PEP verify public key).
```
