# Spec 06 — Decision Token

**Gói:** `internal/authz/token`
**Vai trò:** Bằng chứng quyết-định-cho-phép có TTL, ràng chặt vào tuple đã cấp quyền. Cho phép PEP
fast-path (bỏ PDP) và sống sót PDP outage. Khung hóa **C6** (hiệu năng), **C7** (khả dụng).
**View liên quan:** Information (VP-3), Process (VP-4).

---

## 1. Public API (internal/authz/token/token.go)

```go
type Claims struct {                                  // token.go:30
    Subject       string `json:"sub"`
    Action        string `json:"act"`
    Resource      string `json:"res"`   // "Type/ID"
    AAL           string `json:"aal"`
    ResDigest     string `json:"rd,omitempty"`
    CorrelationID string `json:"cid,omitempty"`
    IssuedAt      int64  `json:"iat"`
    ExpiresAt     int64  `json:"exp"`
}
func ResourceDigest(props map[string]any) string                 // token.go:45
type Issuer struct { secret []byte; ttl time.Duration; now func() time.Time }  // token.go:55
func NewIssuer(secret []byte, ttl time.Duration) *Issuer         // token.go:62
func (i *Issuer) TTLSeconds() int                                // token.go:67
func (i *Issuer) Issue(c Claims) (string, error)                 // token.go:71
func (i *Issuer) Verify(tok string) (Claims, error)              // token.go:85
```

`Issuer` thỏa `pep.TokenVerifier` → vừa mint (PDP) vừa verify (PEP) bằng cùng secret.

## 2. Định dạng & ký

- Định dạng **hai phần** (không phải JWT): `base64url(payloadJSON) + "." + base64url(HMAC-SHA256(body))`.
- `Issue`: đóng dấu `IssuedAt=now`, `ExpiresAt=now+ttl`; ký HS256 (token.go:71).
- `Verify`: tách `body.sig` → **so HMAC constant-time** `hmac.Equal` (token.go:95) → decode claims →
  kiểm hết hạn (`now >= exp`).

## 3. Ràng buộc an toàn (binding)

`ResourceDigest` = SHA-256 trên `json.Marshal(props)` (khóa sort tất định), base64url. Token vì thế
ràng `sub + act + res + aal + digest(resource.properties)`:

- Token cấp cho **9.000.000đ AAL3** không dùng lại được cho giao dịch khác amount (digest khác) hay
  user/action/resource khác.
- AAL trong token là AAL **đã đạt**; PEP fast-path yêu cầu `token.aal ≥ request.aal`.

> **CR-4 (correspondence quan trọng):** PDP mint digest và PEP verify digest **phải dùng đúng một thuật
> toán** (`token.ResourceDigest`). Lệch khóa-sort/encoding → fast-path miss vĩnh viễn.

## 4. Kiểm thử

- `internal/authz/token/token_test.go` — issue/verify, hết hạn, tamper signature, digest binding.

## 5. Hướng tối ưu / giới hạn

- **Đối xứng (HS256)**: secret dùng chung giữa PDP và mọi PEP. *AD-8.* → backlog: **asymmetric**
  (PDP ký private key, PEP verify public key) để PEP không giữ secret mint được token. (README
  next-step).
- **Không có revocation nội tại**: token còn hạn vẫn hợp lệ về mặt chữ ký; thu hồi dựa vào CAEP đè ở
  PEP (xem [spec 10](10-caep-revocation.md)) — kiểm revocation **trước** fast-path.
- **TTL tĩnh** (mặc định 300s qua `PDP_TOKEN_TTL`): cân nhắc TTL theo rủi ro (giá trị giao dịch cao →
  TTL ngắn).
- Thiếu `jti`/audience → không phân biệt token theo PEP đích; cân nhắc thêm khi đa PEP.
