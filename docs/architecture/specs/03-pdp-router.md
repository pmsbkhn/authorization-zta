# Spec 03 — PDP / Unified Router

**Gói:** `internal/authz/pdp`
**Vai trò:** "Bộ não" orchestration của Control Plane: validate → eval engine → mint token → dựng
response. Định nghĩa **port `pdp.Engine`** — chốt cho engine-agnostic. Khung hóa **C1, C2, C10**.
**View liên quan:** Logical (VP-2), Process (VP-4).

---

## 1. Public API (internal/authz/pdp/pdp.go)

```go
type Engine interface {                                          // pdp.go:22
    Eval(ctx context.Context, input any) (engine.Decision, error)
}
type Service struct { engine Engine; issuer *token.Issuer }      // pdp.go:27
func New(e Engine, issuer *token.Issuer) *Service                // pdp.go:33
func (s *Service) Evaluate(ctx context.Context, req authzen.Request) (authzen.Response, error) // pdp.go:42
```

**`Engine` là interface trung tâm của toàn hệ thống.** OPA (`engine.Engine`) và ReBAC (`rebac.Engine`)
đều thỏa nó (`var _ pdp.Engine = (*rebac.Engine)(nil)`), nên `pdp.New` nhận engine nào cũng được mà
facade/PEP không đổi (AD-2, CR-8).

## 2. Pipeline Evaluate (pdp.go:42–60)

```
1. req.Validate()        → trả error (ValidationError) ⇒ facade map 400/InvalidArgument
2. toInput(req)          → map[string]any qua JSON roundtrip (engine thấy đúng shape contract) — pdp.go:112
3. s.engine.Eval(input)  → engine.Decision   (lỗi engine ⇒ "pdp: engine eval: %w")
4. s.assemble(req, dec)  → authzen.Response
```

## 3. Assemble response (pdp.go:64–89)

- `ReasonCode`, `Obligations` lấy thẳng từ `engine.Decision` (`toObligations`, pdp.go:92).
- **Chỉ mint token khi `dec.Allow == true`** — claims:
  ```go
  token.Claims{
    Subject: req.Subject.ID, Action: req.Action.Name,
    Resource: req.Resource.Type + "/" + req.Resource.ID,
    AAL: req.Subject.AuthAssuranceLevel(),
    ResDigest: token.ResourceDigest(req.Resource.Properties),
    CorrelationID: req.CorrelationID(),
  }
  ```
  Gắn `DecisionToken{Value, TTLSeconds: issuer.TTLSeconds()}`.

> **CR-2/CR-4:** cách dựng `Resource` (`Type+"/"+ID`) và `ResDigest` ở đây phải **đồng nhất tuyệt đối**
> với cách PEP so khớp ở fast-path (`internal/authz/pep/enforce.go`). Lệch → fast-path luôn miss (an toàn
> nhưng mất hiệu năng) hoặc tệ hơn.

## 4. Fail-closed & lỗi (C2)

- Validate fail → error (không tạo response allow).
- Engine trả Decision rỗng/undefined → `engine` đã đảm bảo `Allow:false` (xem [spec 04](04-engine-opa-policies.md)).
- Lỗi mint token → `"pdp: issuing decision token: %w"` (facade → 500).

## 5. Kiểm thử

- `internal/authz/pdp/pdp_test.go` — validate→error; allow→có token; deny→không token; obligations map đúng.

## 6. Hướng tối ưu

- **`engine.Decision` là mẫu số chung**: cần đủ tổng quát khi thêm engine mới. ReBAC hiện không phát
  obligation → nếu muốn compose ABAC+ReBAC, `Service` cần một bước **policy composition** (gọi nhiều
  engine, hợp nhất Decision). *AD-2/C10.*
- **Subject enrichment**: hiện `Evaluate` dùng nguyên `req`; chưa gọi `pip.IdentityProvider` để bồi
  thuộc tính trước khi eval. Đây là chỗ tự nhiên để nối IdP vào hot path (C12).
- **Engine routing động**: hiện engine được chọn lúc wiring (`pdp.New`). Muốn route theo domain/profile
  (OPA cho domain này, ReBAC cho domain kia) cần thêm logic chọn engine trong `Evaluate`.
