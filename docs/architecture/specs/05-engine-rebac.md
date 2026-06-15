# Spec 05 — ReBAC Engine (OpenFGA / Zanzibar)

**Gói:** `internal/authz/rebac`
**Vai trò:** Engine quan hệ kiểu Zanzibar, **thỏa cùng `pdp.Engine`** như OPA → drop-in. Khung hóa
**C10** (mở rộng mô hình quyền).
**View liên quan:** Logical (VP-2).

---

## 1. Public API (internal/authz/rebac/rebac.go)

```go
type Config struct { Endpoint string; StoreID string; ModelID string }  // rebac.go:29
type Engine struct { cfg Config; http *http.Client }                    // rebac.go:36 (timeout 5s)
func New(cfg Config) *Engine                                            // rebac.go:42
func (e *Engine) Eval(ctx, input any) (engine.Decision, error)          // rebac.go:48
var _ pdp.Engine = (*rebac.Engine)(nil)                                 // drop-in
```

## 2. Ánh xạ AuthZEN → quan hệ OpenFGA

| AuthZEN | OpenFGA | Hàm |
|---|---|---|
| `subject.id` | `user:<id>` | inline |
| `action` `<dom>:<verb>` | relation `can_<verb>` | `relationFor` (rebac.go:109) |
| `resource.type` `<dom>:<ent>` + `resource.id` | object `<ent>:<id>` | `objectFor` (rebac.go:118) |

Ví dụ: `(user u-1, wallet:settle, wallet:account/acc-1)` → `Check(user:u-1, can_settle, account:acc-1)`.

`check()` (rebac.go:80) POST `{Endpoint}/stores/{StoreID}/check` với `tuple_key{user,relation,object}`
(+ `authorization_model_id` nếu có), kỳ vọng `200 {"allowed": bool}`.

## 3. Kết quả & fail-closed (C2)

| Tình huống | Decision |
|---|---|
| input không phải `map[string]any` | `{Allow:false, ReasonCode:"rebac_bad_input"}` |
| relation/object/user rỗng (không map được) | `{Allow:false, ReasonCode:"rebac_unmapped_request"}` |
| OpenFGA cho phép | `{Allow:true, ReasonCode:"rebac_relationship_ok"}` |
| OpenFGA từ chối | `{Allow:false, ReasonCode:"rebac_no_relationship"}` |
| lỗi HTTP/decode | trả error (PDP → 500/PEP deny) |

## 4. Triển khai tham chiếu

`deploy/rebac/run-rebac.sh`: OpenFGA (:8089) → store `vsp` → model (`account` với `owner`/`can_settle`)
→ tuple `user:u-1 owner account:acc-1` → test live: owner allow, stranger deny.

## 5. Kiểm thử

- `internal/authz/rebac/rebac_test.go` (+ `TestReBAC_Live` chạy khi có OpenFGA).

## 6. Hướng tối ưu / giới hạn

- **Không phát obligation**: ReBAC chỉ allow/deny thuần quan hệ; không có step_up/audit như OPA. Để
  compose ABAC (OPA) + ReBAC trong cùng quyết định cần lớp composition ở `pdp.Service` (xem
  [spec 03](03-pdp-router.md) §6). *AD-2/C10.*
- **Model OpenFGA chưa GitOps hóa** như bundle Rego (versioning/immutable) — bất đối xứng vòng đời với
  OPA. *C8.*
- **Không cache**: mỗi `Eval` là 1 HTTP call tới OpenFGA → cân nhắc cache quan hệ hoặc dùng
  `check`-batch. *C6.*
- `ModelID` rỗng → OpenFGA dùng model mới nhất; nên pin `ModelID` để quyết định tất định.
