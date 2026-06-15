# Spec 10 — CAEP / Continuous Access Evaluation

**Gói:** `internal/signals/caep`
**Vai trò:** Vòng CAEP/SSF: Control Plane push Security Event Token (SET) thu hồi/khôi phục session tới
PEP; PEP deny ngay, **đè quyết định đã cache** (token còn hạn). Khung hóa **C9** (đánh giá liên tục).
**View liên quan:** Process (VP-4), Security/Trust (VP-5).

---

## 1. SET — Security Event Token (internal/signals/caep/caep.go)

```go
const EventSessionRevoked="session-revoked"; EventSessionRestored="session-restored"  // caep.go:27
type Event  struct { Type string `json:"type"`; Subject string `json:"sub"`; IssuedAt int64 `json:"iat"` }  // caep.go:33
type Signer struct { secret []byte; now func() time.Time }  // caep.go:40
func NewSigner(secret []byte) *Signer                       // caep.go:46
func (s *Signer) Sign(e Event) (string, error)              // caep.go:49  → base64url(json)+"."+base64url(HMAC)
func (s *Signer) Verify(set string) (Event, error)          // caep.go:60  (HMAC constant-time; reject tamper/forge)
```

Kiểu RFC 8417, ký HS256 trên payload JSON compact; secret dùng chung transmitter/receiver.

## 2. Cache thu hồi (internal/signals/caep/cache.go)

```go
type RevocationCache struct { mu sync.RWMutex; revoked map[string]bool }  // cache.go:8
func NewRevocationCache() *RevocationCache                                 // cache.go:14
func (c *RevocationCache) Apply(e Event)        // revoked→set true; restored→delete  cache.go:19
func (c *RevocationCache) IsRevoked(subject string) bool   // RLock, hot-path; impl pep.RevocationChecker  cache.go:31
```

## 3. Transmitter / Receiver (internal/signals/caep/http.go)

```go
type Sink interface { Apply(Event) }                              // http.go:13 (RevocationCache thỏa)
type Receiver struct { signer *Signer; sink Sink }                // http.go:18
func NewReceiver(signer, sink) *Receiver; func (r *Receiver) Handler() http.HandlerFunc  // http.go:24/29
type Transmitter struct { signer; subscribers []string; client *http.Client }  // http.go:48
func NewTransmitter(signer, subscribers) *Transmitter             // http.go:56 (timeout 5s)
func NewTransmitterWithClient(signer, subscribers, client) *Transmitter  // http.go:63 (mTLS client)
func (t *Transmitter) Emit(ctx, e Event) error                    // http.go:69 (fan-out, trả lỗi đầu tiên)
```

- **Receiver.Handler** (PEP `POST /events`): đọc body → `Verify` → `sink.Apply`. Trả **400** (read
  error), **401** (SET invalid), **202** (accepted). Content-type `application/secevent+jwt`.
- **Transmitter.Emit**: ký + POST tới mọi subscriber (best-effort, trả lỗi đầu tiên).

## 4. Enforcement (đóng khe hở cache)

PEP kiểm `Revocations.IsRevoked(subject)` **trước** fast-path token & PDP (xem
[spec 07](07-pep-library.md) §2). Vì vậy subject bị thu hồi = deny `session_revoked` ngay cả khi đang
giữ decision token còn hạn (C9). Đã verify live: revoke → settle 403 `session_revoked`; restore → 200.

## 5. Công cụ & kiểm thử

- `cmd/caepemit` — admin push SET; qua mTLS (SVID) khi có Workload API.
- `internal/signals/caep/caep_test.go` — sign/verify, tamper reject, push→cache, revocation đè token, E2E chain.

## 6. Hướng tối ưu / giới hạn

- **Cache in-RAM, mất khi PEP restart** — không bền, không chia sẻ giữa replica. *AD-10.* → cân nhắc
  store chia sẻ (Redis) hoặc rehydrate từ transmitter lúc khởi động.
- **Best-effort fan-out**: subscriber lỗi không retry; SET không có nonce/expiry chống replay rõ ràng
  ngoài `iat`. → cân nhắc ack/retry + TTL.
- **Chỉ revocation session**; posture/device signals khác chưa dùng kênh này (C9 mở rộng).
- HS256 đối xứng (như decision token) — backlog asymmetric.
