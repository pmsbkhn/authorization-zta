# Spec 07 — PEP Library (phễu L0/L1/L2)

**Gói:** `internal/authz/pep`, `internal/authz/pdpclient`
**Vai trò:** Màng thực thi đặt trước workload: phễu L0→L1→L2, fast-path token, revocation override,
map outcome→HTTP theo profile, bubble-up step-up. Khung hóa **C1, C2, C5, C6, C7, C9**.
**View liên quan:** Process (VP-4), Logical (VP-2).

---

## 1. Public API (internal/authz/pep)

```go
// Header propagation (pep.go:25)
HeaderSubjectID="X-Vsp-Subject-Id"; HeaderAAL="X-Vsp-Aal"; HeaderCallerSpiffe="X-Vsp-Caller-Spiffe"
HeaderResourceID="X-Vsp-Resource-Id"; HeaderPartnerID="X-Vsp-Partner-Id"; HeaderCorrelationID="X-Correlation-Id"
HeaderStepUpRequired="X-Step-Up-Required"; HeaderDecisionToken="X-Decision-Token"

type PDP interface { Evaluate(ctx, authzen.Request) (authzen.Response, error) }   // pep.go:37
type Route struct { Method, Path, Action, ResourceType string; ResourceProps []string }  // pep.go:44
type OutcomeKind int  // Allow, DropL0, DenyRoute, DenyForbidden, DenyStepUp     // pep.go:52
type Outcome struct { Kind OutcomeKind; ReasonCode, RequiredACR, CorrelationID, DecisionToken string }  // pep.go:70

type Config struct {                                                            // enforce.go:21
    Profile authzen.Profile; PEPID string; Routes []Route; PDP PDP
    Attestor pip.WorkloadAttestor   // bắt buộc khi Profile==east_west
    Logger *slog.Logger
    RequirePeerSVID bool            // cấm fallback header; act phải từ peer cert đã verify
    TokenVerifier TokenVerifier     // bật fast-path (M5)
    Revocations RevocationChecker   // bật CAEP override (M11)
}
type TokenVerifier interface { Verify(string) (token.Claims, error) }           // enforce.go:45
type RevocationChecker interface { IsRevoked(subject string) bool }             // enforce.go:49
func New(cfg Config) *PEP            // panic nếu PDP nil, hoặc east_west thiếu Attestor — enforce.go:63
func (p *PEP) Check(r *http.Request) Outcome                                     // enforce.go:80
func (p *PEP) Middleware(next http.Handler) http.Handler                        // middleware.go:19
```

## 2. Phễu Check (enforce.go:80–168)

```
L0 (east_west): peerIdentity(r) — ưu tiên r.TLS.PeerCertificates[0] → x509svid.IDFromCert
      RequirePeerSVID=false ⇒ fallback header X-Vsp-Caller-Spiffe (dev)
      no peer  → DropL0("l0_no_peer_svid");  attestor.ValidateSVID=false → "l0_peer_not_attested"
L1: khớp (method,path) với Routes → không khớp → DenyRoute("l1_route_not_permitted")
[M11] Revocations.IsRevoked(subject)? → DenyForbidden("session_revoked")   ◀ TRƯỚC fast-path & PDP
L2: buildRequest(r, route)
      [M5] tryDecisionToken(): TokenVerifier.Verify(X-Decision-Token) +
           khớp sub/act/res/rd + token.aal ≥ req.aal → Allow("decision_token_reuse")  (bỏ PDP)
      else PDP.Evaluate(req): lỗi/non-200 → DenyForbidden("l2_pdp_unavailable")  (fail-closed)
      classify(resp): allow→Allow(+token) | obligation step_up→DenyStepUp(acr) | else DenyForbidden
```

- `buildRequest` (enforce.go:233): dựng `authzen.Request`; east_west thêm `subject.properties.act =
  {type:workload, id:caller}`; edge thêm `source_ip`; partner thêm `partner_id`; lift body fields theo
  `route.ResourceProps` (`resourceProps`, enforce.go:273 — **đọc rồi phục hồi `r.Body`** cho handler).
- `aalRank` map (enforce.go:171); AAL lạ → 0.

## 3. Map Outcome → HTTP (middleware.go:19–68)

| Kind | edge | east_west / partner |
|---|---|---|
| Allow | 200 + set `X-Decision-Token` (req&resp) + `X-Correlation-Id`; gọi next | như edge |
| DenyStepUp | **401** JSON `{error:step_up_required, required_acr, method:mfa}` + `X-Step-Up-Required` | **403** JSON `{error:step_up_required, required_acr}` + `X-Step-Up-Required` |
| DropL0 | 403 `{error: reason}` | 403 |
| DenyRoute / DenyForbidden | 403 `{error: reason}` | 403 |

Đây là hiện thực **Bubble-up Pattern** (design-v3 §4, C5): chỉ edge (có session user) mới challenge
401; service sâu trả 403 + header để dội ngược.

## 4. HTTP client AuthZEN (internal/authz/pdpclient/client.go)

```go
func New(baseURL string) *Client          // endpoint = baseURL+"/access/v1/evaluation"; http timeout 5s
func (c *Client) Evaluate(ctx, req) (authzen.Response, error)
```
**Non-200 = deny**: `resp.StatusCode != 200` → error `"pdpclient: pdp returned HTTP %d"` (fail-closed,
C2). Impl `pep.PDP`. Có thể thay drop-in bằng gRPC client (`grpcpdp.Client`, [spec 08](08-grpc-transport.md)).

## 5. Kiểm thử

- `internal/authz/pep/enforce_test.go` — fast-path bỏ PDP; **revocation đè token hợp lệ**; digest mismatch →
  fallback PDP.

## 6. Hướng tối ưu / giới hạn

- **PDP outage chỉ fail-closed mỗi request** — không có **circuit breaker / negative cache**; mọi
  request đều thử PDP rồi deny. *C7.* → cân nhắc breaker + đo tỉ lệ fast-path hit (C6).
- **Không metric**: thiếu đếm outcome theo kind/reason/profile và latency theo tầng. *C12.*
- **Revocation in-RAM** (qua `caep.RevocationCache`) mất khi PEP restart (xem [spec 10](10-caep-revocation.md)).
- Client timeout cố định 5s (HTTP); chưa cấu hình được per-route/budget.
