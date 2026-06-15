# Spec 12 — Service Wiring & Entrypoints

**Gói:** `internal/services`, `cmd/*`
**Vai trò:** Lắp ráp các thành phần thành process chạy được (`http.Handler` + mTLS + gRPC), và các
entrypoint mỏng đọc cấu hình từ env. Khung hóa **C11** (vận hành), kết nối mọi view.
**View liên quan:** Deployment (VP-7), Logical (VP-2).

---

## 1. Wiring config (internal/services)

### PDP (services/pdp.go)
```go
type PDPConfig struct { TokenSecret []byte; TokenTTL time.Duration; Logger *slog.Logger; Bundle []byte }  // :20
func PDPService(ctx, cfg) (*pdp.Service, error)   // bundle S3 → engine.NewFromBundle; else policies embed → engine.New; + token.NewIssuer  // :32
func PDPHandler(ctx, cfg) (*api.Handler, error)   // :60
```

### Gateway — Edge PEP (services/gateway.go)
```go
type GatewayConfig struct { PDPURL string; PDP pep.PDP; UpstreamURL string; UpstreamTLS *tls.Config; Logger *slog.Logger }
```
Reverse-proxy `httputil.NewSingleHostReverseProxy` tới Multi-Bill; **`ModifyResponse` chặn
`X-Step-Up-Required` từ upstream → rewrite 401** challenge `{error:step_up_required, required_acr,
method:mfa}`. PEP guard `POST /pay` (`bill:pay` / `bill:invoice` / props `[amount,currency]`);
`GET /healthz` bypass. `PDP` (gRPC) override `PDPURL` (HTTP); `UpstreamTLS` → proxy qua mTLS.

### Multi-Bill — delegation + token cache (services/multibill.go)
```go
type MultibillConfig struct { WalletURL, SelfSpiffe string; Logger; HTTPClient *http.Client; CacheDecisionTokens bool }
```
`POST /pay` → gọi Wallet `/settle`, copy header `X-Vsp-Subject-Id|Aal|Resource-Id|Correlation-Id`;
delegation actor: mTLS → từ client cert, else header `X-Vsp-Caller-Spiffe=SelfSpiffe`. **Token cache**
key `subject|aal|resource|body` → replay decision token để bỏ PDP lookup ở Wallet; bubble-up
`X-Step-Up-Required` nguyên vẹn.

### Wallet — East-West PEP (services/wallet.go)
```go
type WalletConfig struct { PDPURL string; PDP pep.PDP; Attestor *mock.WorkloadAttestor; Logger;
    RequirePeerSVID bool; TokenSecret []byte; CAEPSecret []byte }
```
PEP guard `POST /settle` (`wallet:settle`/`wallet:account`); `RequirePeerSVID=true` khi mTLS; `TokenSecret`
≠∅ → bật fast-path verify; `CAEPSecret` ≠∅ → đăng ký `POST /events` (CAEP receiver + RevocationCache).
Step-up → 403 bubble-up.

### mTLS & gRPC (services/mtls.go, services/grpc.go)
- `LoadServerTLS()/LoadClientTLS() (*tls.Config, bool, error)`: ưu tiên **Workload API**
  (`SPIFFE_ENDPOINT_SOCKET` → `spiffe.FromWorkloadAPI`), fallback **file tĩnh** (`SVID_CERT/KEY/BUNDLE`,
  `SVID_TRUST_DOMAIN` mặc định `vsp.local`), nếu không → `(nil,false,nil)` = dev plain-HTTP.
- `PDPGRPCClient(addr) (pep.PDP, error)`: dial gRPC bằng client mTLS → `grpcpdp.NewClient`.
- `PDPGRPCServerCreds() (grpc.ServerOption, bool, error)`: server creds từ mTLS.

## 2. Entrypoints (cmd/*) — biến môi trường & cổng

| Binary | Vai trò | Env (mặc định) | Cổng |
|---|---|---|---|
| `pdp` | Control Plane | `PDP_ADDR`(`:8080`), `PDP_GRPC_ADDR`(—), `PDP_TOKEN_SECRET`(`dev-insecure-secret-change-me`), `PDP_TOKEN_TTL`(`300s`), `S3_ENDPOINT`(—)/`S3_ACCESS_KEY`(`minioadmin`)/`S3_SECRET_KEY`(`minioadmin`)/`S3_BUCKET`(`vsp-policy-bundles`)/`S3_OBJECT`(`bundle.tar.gz`), `SPIFFE_ENDPOINT_SOCKET`, `SVID_*` | 8080 HTTP, gRPC tùy `PDP_GRPC_ADDR` |
| `gateway` | Edge PEP | `PDP_URL`(`http://localhost:8080`), `PDP_GRPC_ADDR`(—), `MULTIBILL_URL`(`http://localhost:8081`), `GATEWAY_ADDR`(`:8088`), `SPIFFE_ENDPOINT_SOCKET`, `SVID_*` | 8088 (public) |
| `multibill` | Delegation | `WALLET_URL`(`http://localhost:8082`), `MULTIBILL_SPIFFE`(`spiffe://vsp.local/ns/billing/sa/multi-bill-svc`), `MULTIBILL_ADDR`(`:8081`), `SPIFFE_*`/`SVID_*` | 8081 |
| `wallet` | East-West PEP | `PDP_URL`(`http://localhost:8080`), `PDP_GRPC_ADDR`(—), `WALLET_ADDR`(`:8082`), `PDP_TOKEN_SECRET`(`dev-insecure-secret-change-me`), `CAEP_SECRET`(—), `SPIFFE_*`/`SVID_*` | 8082 |
| `svidmint` | Mock cấp SVID ra disk | flags `-trust-domain`(`vsp.local`), `-out`(`./certs`), args `name=spiffe://…` | — |
| `nodecert` | PKI production (x509pop) | flags `-out`(`./certs`), `-agent-cn`(`spire-agent`) | — |
| `caepemit` | Admin push SET | flags `-secret`(env `CAEP_SECRET`), `-subject`, `-type`(`session-revoked`), args = receiver URLs | — |
| `bundlepush` | GitOps publish | flags/env `S3_*` (như pdp), `-file`(`bundle.tar.gz`), `-retain-days`(`1`) | — |

**Mặc định bảo mật cần lưu ý:** `PDP_TOKEN_SECRET`/`S3` creds có giá trị **dev mặc định**; production
PHẢI override (xem [AD-5], C2/C11).

## 3. SPIFFE ID đăng ký (trust domain `vsp.local`)

| Workload | SPIFFE ID | UID (compose) |
|---|---|---|
| gateway | `spiffe://vsp.local/ns/edge/sa/api-gateway` | 10003 |
| multibill | `spiffe://vsp.local/ns/billing/sa/multi-bill-svc` | 10002 |
| wallet | `spiffe://vsp.local/ns/wallet/sa/vsp-wallet-svc` | 10001 |
| pdp | `spiffe://vsp.local/ns/pdp/sa/pdp-svc` | 10004 |

## 4. Hướng tối ưu

- **Cấu hình rải qua nhiều env không validate tập trung** — nên có bước validate config lúc boot
  (fail-fast nếu thiếu secret production). *C11.*
- Wiring tĩnh chọn engine/transport lúc khởi động; chưa hot-reload bundle/policy hay đổi engine runtime.
- `cmd` đọc env trực tiếp; cân nhắc lớp config (precedence file/env/flag) thống nhất.
