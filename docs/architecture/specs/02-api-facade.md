# Spec 02 — AuthZEN 1.0 HTTP Facade

**Gói:** `internal/authz/api`
**Vai trò:** Phơi bày facade AuthZEN 1.0 qua HTTP, ẩn hoàn toàn PDP/engine bên trong. Khung hóa **C3**.
**View liên quan:** Logical (VP-2), Information (VP-3).

---

## 1. Public API (internal/authz/api/handler.go)

```go
type Evaluator interface {                                   // handler.go:18
    Evaluate(ctx context.Context, req authzen.Request) (authzen.Response, error)
}
type Handler struct { eval Evaluator; log *slog.Logger }      // handler.go:23
func NewHandler(eval Evaluator, log *slog.Logger) *Handler    // handler.go:29
func (h *Handler) Routes() *http.ServeMux                     // handler.go:38
```

`pdp.Service` thỏa `Evaluator`. Routes (method-based, Go ≥1.22):

| Route | Handler | Ý nghĩa |
|---|---|---|
| `POST /access/v1/evaluation` | `handleEvaluation` | Endpoint AuthZEN chuẩn |
| `GET /healthz` | `handleHealth` | Liveness |

## 2. Luồng xử lý request (handler.go:49–84)

1. **Decode JSON** với `DisallowUnknownFields()` → lỗi parse ⇒ **400 `invalid_json`**.
2. Gọi `h.eval.Evaluate(ctx, req)` (validate diễn ra bên trong `pdp.Service`).
3. **Map lỗi:**
   - `*authzen.ValidationError` ⇒ **400 `contract_violation`** + mảng `issues`.
   - Lỗi khác ⇒ **500 `internal_error`** (không lộ chi tiết nội bộ).
4. **Log quyết định**: `correlation_id`, `profile`, `action`, `resource`, `pep`, `allow`.
5. Trả **200** với `authzen.Response` JSON.

## 3. Đặc tính & lỗi

- Facade **không tự ra quyết định** — chỉ là adapter HTTP cho `Evaluator`. Đối xứng với gRPC facade
  (`internal/authz/grpcpdp`): cùng một `Evaluator`, hai transport (CR-2).
- Status code khớp giữa HTTP và gRPC: contract violation → 400/`InvalidArgument`; lỗi nội bộ →
  500/`Internal`.
- Không bao giờ trả 500 cho một deny hợp lệ: deny là `200 {decision:false}` (Zero Trust outcome bình
  thường, không phải lỗi).

## 4. Hướng tối ưu

- **Observability**: hiện log structured qua `slog`; thiếu metric (đếm allow/deny theo profile/reason)
  và trace exporter. *C12.* Correlation id đã sẵn để gắn span.
- **Batch endpoint**: AuthZEN hỗ trợ evaluations (số nhiều); chưa hiện thực — sẽ giảm round-trip cho
  luồng nội bộ. *C6.*
- **Rate limiting / payload size guard** chưa có ở facade.
