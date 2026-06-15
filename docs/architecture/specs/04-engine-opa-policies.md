# Spec 04 — OPA Engine + Hierarchical Rego

**Gói:** `internal/authz/engine`, `policies/`
**Vai trò:** Adapter OPA nhúng (impl `pdp.Engine`) + bộ policy Rego phân cấp data-driven. Khung hóa
**C2** (fail-closed), **C6** (compile-once), **C8/C10** (policy lifecycle).
**View liên quan:** Logical (VP-2), Policy-Lifecycle (VP-6).

---

## 1. Engine adapter (internal/authz/engine)

```go
const DefaultDecisionQuery = "data.vsp.authz.decision"           // opa.go:19
type Decision struct {                                            // opa.go:24
    Allow       bool
    Obligations []map[string]any
    ReasonCode  string
}
type Engine struct { query rego.PreparedEvalQuery }               // opa.go:36 (an toàn concurrency)
func New(ctx, modules map[string]string, data map[string]any, queryPath string) (*Engine, error) // opa.go:43
func NewFromBundle(ctx, tarball []byte, queryPath string) (*Engine, error)                        // bundle.go:16
func (e *Engine) Eval(ctx, input any) (Decision, error)           // opa.go:69
```

- **`New`**: compile modules + data thành `PreparedEvalQuery` **một lần lúc khởi động** → lỗi compile
  lộ ngay khi boot, không phải mỗi request (C6). Data nạp vào `inmem` store.
- **`NewFromBundle`**: đọc OPA bundle tarball (artifact GitOps) → trích modules + data → gọi `New`.
  Test xác nhận khớp engine embedded.
- **`Eval`**: chạy prepared query với `input`; **fail-closed**: kết quả rỗng/undefined →
  `Decision{Allow:false, ReasonCode:"policy_undefined"}` (opa.go:69–84). `parseDecision` (opa.go:88)
  mặc định mọi field về zero-value; obligation chỉ nhận object unmarshal được thành `map[string]any`.

## 2. Cây policy phân cấp (policies/)

Embed qua `policies.go` (`//go:embed *.rego global profiles domain lib data.json`); `Modules()` bỏ
`*_test.rego`; `Data()` parse `data.json`.

```
main.rego  package vsp.authz   entrypoint: decision   (fail-closed default "default_deny")
  ├─ global/schema.rego    vsp.global    — schema_violations (naming-convention, defense-in-depth)
  ├─ lib/lib.rego          vsp.lib       — aal_rank/aal_at_least, step_up()/audit(), missing_required_violations
  ├─ profiles/profiles.rego vsp.profiles — violations theo chặng (edge/east_west/partner)
  ├─ domain/wallet.rego    vsp.domain.wallet — verdict nghiệp vụ
  ├─ domain/bill.rego      vsp.domain.bill   — verdict nghiệp vụ
  └─ data.json             required_attributes (data-driven §5.2)
```

### 2.1. Phễu quyết định trong main.rego

```
all_violations := global.schema_violations ∪ lib.missing_required_violations ∪ profiles.violations
if all_violations ≠ ∅       → deny, reason_code="request_invalid", obligations=[audit("audit_denied")], +violations
elif domain_verdict undefined → deny, reason_code="unknown_domain", +audit("audit_denied")
else                         → {allow, obligations, reason_code} = domain_verdict
domain := split(input.resource.type, ":")[0]
domain_verdict := data.vsp.domain[domain].verdict      # dynamic dispatch
```

Thêm domain mới = thêm file `domain/<x>.rego` với `default verdict := {allow:false,…}` — router không
đổi.

### 2.2. Gate 2 — data-driven (lib/lib.rego + data.json)

```rego
missing_required_violations contains msg if {
  some attr in data.required_attributes[input.action.name]
  not input.resource.properties[attr]
  msg := sprintf("missing required attribute %q for action %q", [attr, input.action.name])
}
```
`data.json`: `{ "required_attributes": { "wallet:settle": ["amount","currency"], "bill:pay": ["amount","currency"] } }`.
Thêm yêu cầu = sửa JSON, **không chạm code** (§5.2). *CR-6:* PEP phải lift đúng các field này từ body.

### 2.3. Gate 3 — profile invariants (profiles/profiles.rego)

- `edge` → cần `context.source_ip`.
- `east_west` → cần `subject.properties.act` và `act` phải là **workload có `spiffe://` id hợp lệ**
  (CR-5).
- `partner` → cần `context.partner_id`.

### 2.4. Gate 4 — domain logic (ví dụ wallet.rego)

| Điều kiện | Kết quả | reason_code |
|---|---|---|
| `wallet:settle`, amount > 5.000.000, AAL≥3 | allow + audit_success | `wallet_settle_high_value_aal3` |
| `wallet:settle`, amount > 5.000.000, AAL<3 | **deny + step_up(AAL3) + audit_denied** | `step_up_required` |
| `wallet:settle`, amount ≤ 5.000.000, AAL≥2 | allow + audit_success | `wallet_settle_standard` |
| `wallet:read`, AAL≥1 | allow | `wallet_read_ok` |
| (mặc định) | deny | `wallet_action_not_permitted` |

`bill.rego`: `bill:pay` cần AAL≥2 (`bill_pay_ok`); `bill:read` cần AAL≥1.

### 2.5. Lib helper

- `aal_rank := {"AAL1":1,"AAL2":2,"AAL3":3}`; `aal_at_least(have,want)`.
- `step_up(acr) := {type:"step_up", details:{required_acr:acr, method:"mfa"}}`.
- `audit(level) := {type:"log", details:{level:level}}`.

## 3. Kiểm thử (fitness functions)

- `policies/authz_test.rego` — `opa test policies/` (9 ca) là **gate GitOps** (xem [spec 13](13-deployment-topology.md)).
- `internal/authz/engine/opa_test.go`, `bundle_test.go` — eval thật + khớp embedded↔bundle.

## 4. Hướng tối ưu

- **Ngưỡng nghiệp vụ hardcode** (`high_value_threshold := 5000000` trong wallet.rego) → cân nhắc đưa vào
  `data.json` để data-driven hoàn toàn (đổi ngưỡng không sửa Rego). *C8.*
- **Partial evaluation / decision logging của OPA** chưa khai thác — có thể bật decision logs để audit
  (C12) và dùng partial eval để đẩy một phần logic xuống PEP (C6).
- **Bundle signing**: hiện `NewFromBundle` đọc tarball chưa verify chữ ký OPA bundle; immutability dựa
  vào WORM S3, nhưng thêm signature verification sẽ chặt hơn (C8).
- Obligation từ OPA là `[]map[string]any` thứ tự theo policy — nếu nhiều domain phát obligation cần
  quy ước hợp nhất rõ ràng.
