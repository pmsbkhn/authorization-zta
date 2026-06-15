# Spec 08 — gRPC Transport (AuthZEN qua gRPC/mTLS)

**Gói:** `internal/authz/grpcpdp`, `proto/authzen/v1`
**Vai trò:** Kênh gRPC song song facade HTTP cho luồng nội bộ (tối ưu serialization/latency), client
drop-in cho PEP. Khung hóa **C6** (hiệu năng), **C4** (mTLS).
**View liên quan:** Logical (VP-2), Process (VP-4), Security (VP-5).

---

## 1. Server (internal/authz/grpcpdp/server.go)

```go
type Evaluator interface { Evaluate(ctx, authzen.Request) (authzen.Response, error) }  // server.go:14
type Server struct { authzenv1.UnimplementedAccessEvaluationServer; eval Evaluator }    // server.go:19
func NewServer(eval Evaluator) *Server                                                  // server.go:25
func (s *Server) Evaluate(ctx, *EvaluationRequest) (*EvaluationResponse, error)         // server.go:30
```

Bọc `pdp.Service` (cùng `Evaluator` như facade HTTP → CR-2). **Map lỗi khớp HTTP:**
- `*authzen.ValidationError` → `codes.InvalidArgument` (≈ HTTP 400).
- lỗi khác → `codes.Internal` "evaluation failed" (≈ HTTP 500).

## 2. Client (internal/authz/grpcpdp/client.go)

```go
type Client struct { conn *grpc.ClientConn; rpc authzenv1.AccessEvaluationClient }  // client.go:14
func NewClient(conn *grpc.ClientConn) *Client                                       // client.go:21
func (c *Client) Evaluate(ctx, authzen.Request) (authzen.Response, error)           // client.go:26
```

Impl `pep.PDP` → **drop-in thay `pdpclient` HTTP** mà PEP không đổi. Caller sở hữu `conn` (gắn
TLS/credentials mTLS).

## 3. Chuyển đổi JSON ↔ Protobuf (convert.go)

- `requestToProto`/`requestFromProto`, `responseToProto`/`responseFromProto`.
- `properties`/`context`/`details` ↔ `google.protobuf.Struct` (`mapToStruct`, convert.go:89; map rỗng →
  nil). Nhờ Struct, **không cần schema cứng** cho thuộc tính nghiệp vụ (AD-12).

## 4. mTLS

PDP mở gRPC creds SVID khi có Workload API (`services.PDPGRPCServerCreds`); PEP dial bằng SVID
(`services.PDPGRPCClient`). Client lạ/không cert bị từ chối **ở handshake** (xem
[spec 09](09-spiffe-identity.md), [spec 12](12-services-and-cmd.md)).

## 5. Kiểm thử

- `internal/authz/grpcpdp/grpcpdp_test.go` — roundtrip allow + decision_token + obligation; validation →
  `InvalidArgument`.
- `internal/authz/grpcpdp/mtls_test.go` — SVID hợp lệ qua; **foreign-CA reject ở handshake**.

## 6. Hướng tối ưu / giới hạn

- **Struct mất type-safety** cho properties (đánh đổi AD-12) — như spec 01.
- Chưa có **streaming/batch** RPC (chỉ unary `Evaluate`) → batch evaluation sẽ giảm round-trip nội bộ
  (C6).
- Chưa có deadline/retry policy chuẩn ở client; nên đặt budget per-call để phối hợp với fail-closed PEP.
- Regen stub thủ công (`proto/generate.sh`); cần `protoc` + plugin Go.
