# Spec 01 — AuthZEN Data Contract (VSP Standard Contract)

**Gói:** `internal/authz/authzen`, `proto/authzen/v1`
**Vai trò:** Hợp đồng dữ liệu đi qua mọi biên (HTTP & gRPC). Khung hóa concern **C3** (hợp đồng ổn
định, engine-agnostic) và **C12** (truy vết).
**View liên quan:** Information (VP-3).

---

## 1. Mục đích

AuthZEN 1.0 cho phép tự do định nghĩa `properties`. VSP áp một bộ **naming-convention** lên trên để OPA
phân loại và định tuyến chính xác (design-v3 §3). Gói này là *nguồn sự thật* về kiểu dữ liệu và quy tắc
hợp lệ; nó không phụ thuộc gói nào khác trong hệ thống → an toàn để dùng chung.

## 2. Kiểu dữ liệu (internal/authz/authzen/types.go)

```go
type Subject struct {                      // types.go:37
    Type       string         `json:"type"`        // "user" | "workload"
    ID         string         `json:"id"`
    Properties map[string]any `json:"properties,omitempty"`
}
type Action struct {                       // types.go:44
    Name       string         `json:"name"`        // "<domain>:<action>"
    Properties map[string]any `json:"properties,omitempty"`
}
type Resource struct {                     // types.go:50
    Type       string         `json:"type"`        // "<domain>:<entity>"
    ID         string         `json:"id,omitempty"`
    Properties map[string]any `json:"properties,omitempty"`
}
type Request struct {                      // types.go:57
    Subject  Subject; Action Action; Resource Resource
    Context  map[string]any `json:"context,omitempty"`
}
type Response struct {                     // types.go:67
    Decision bool             `json:"decision"`
    Context  *ResponseContext `json:"context,omitempty"`
}
type ResponseContext struct {              // types.go:73
    DecisionToken *DecisionToken `json:"decision_token,omitempty"`
    Obligations   []Obligation   `json:"obligations,omitempty"`
    ReasonCode    string         `json:"reason_code,omitempty"`
}
type DecisionToken struct { Value string; TTLSeconds int }   // types.go:84
type Obligation    struct { Type string; Details map[string]any }  // types.go:96
```

### Hằng số

| Nhóm | Giá trị | Vị trí |
|---|---|---|
| `Profile` | `ProfileEdge="edge"`, `ProfileEastWest="east_west"`, `ProfilePartner="partner"` | types.go:14 |
| Subject type | `SubjectTypeUser="user"`, `SubjectTypeWorkload="workload"` | types.go:23 |
| AAL (NIST 800-63) | `AAL1`,`AAL2`,`AAL3` | types.go:29 |
| Obligation | `ObligationStepUp="step_up"`, `ObligationLog="log"` | types.go:90 |

### Accessor tiện ích

- `Request.AuthZProfile() Profile` (`context.authz_profile`) — types.go:107
- `Request.CorrelationID() string` (`context.correlation_id`) — types.go:114
- `Request.PEPID() string` (`context.pep.id`) — types.go:122
- `Subject.AuthAssuranceLevel() string` (`subject.properties.auth_assurance_level`) — types.go:134
- `Subject.ActSubject() (map[string]any, bool)` (`subject.properties.act`) — types.go:142

## 3. Validation (internal/authz/authzen/validate.go)

`func (r *Request) Validate() error` (validate.go:30) — **không fail-fast**, gom mọi vi phạm vào
`*ValidationError{ Issues []string }` (validate.go:15). Quy tắc:

| # | Quy tắc | Dòng |
|---|---|---|
| 1 | `Subject.Type` ∈ {user, workload} (bắt buộc) | 34 |
| 2 | `Subject.ID` không rỗng | 42 |
| 3 | `Action.Name` khớp `<domain>:<action>` | 47 |
| 4 | `Resource.Type` khớp `<domain>:<entity>` | 55 |
| 5 | Action và Resource **cùng domain** | 64 |
| 6 | `context.authz_profile` ∈ {edge, east_west, partner} (bắt buộc) | 73 |

Regex token: `^[a-z][a-z0-9_-]*$` (validate.go:11); helper `isColonPair` (89), `domainOf` (98).

> **CR-1 (correspondence):** cùng quy tắc naming được lặp lại trong Rego `global/schema.rego`
> (defense-in-depth). Đổi quy tắc ở đây thì phải đổi cả Rego.

## 4. Hợp đồng Protobuf (proto/authzen/v1/authzen.proto)

Map 1-1 với contract JSON; thuộc tính tự do dùng `google.protobuf.Struct`:

```protobuf
service AccessEvaluation { rpc Evaluate(EvaluationRequest) returns (EvaluationResponse); }
message Subject  { string type=1; string id=2; google.protobuf.Struct properties=3; }
message Action   { string name=1; google.protobuf.Struct properties=2; }
message Resource { string type=1; string id=2; google.protobuf.Struct properties=3; }
message EvaluationRequest  { Subject subject=1; Action action=2; Resource resource=3; google.protobuf.Struct context=4; }
message DecisionToken { string value=1; int32 ttl_seconds=2; }
message Obligation    { string type=1; google.protobuf.Struct details=2; }
message EvaluationResponse { bool decision=1; DecisionToken decision_token=2; repeated Obligation obligations=3; string reason_code=4; }
```

Stub `*.pb.go` sinh bằng `proto/generate.sh`. Chuyển đổi Struct↔map ở `internal/authz/grpcpdp/convert.go`
(xem [spec 08](08-grpc-transport.md)).

## 5. Kiểm thử

- `internal/authz/authzen/validate_test.go` — phủ từng quy tắc naming và gom issues.

## 6. Giới hạn hiện tại & hướng tối ưu

- **Không kiểm kiểu thuộc tính nghiệp vụ**: `properties` là `map[string]any` tự do; `amount` kiểu sai
  (string thay vì number) sẽ lọt validate Go và chỉ "trượt" logic Rego. *AD-1/AD-12.* → cân nhắc
  validation tuỳ chọn (schema registry) cho action quan trọng.
- **Hai nguồn naming-rule** (Go + Rego) phải đồng bộ thủ công (CR-1).
- gRPC dùng `Struct` → mất type-safety tĩnh cho properties (đánh đổi của AD-12).
