# Spec 09 — Workload Identity / SPIFFE-SVID

**Gói:** `internal/identity/spiffe`
**Vai trò:** Danh tính workload bằng mật mã: CA in-process (stand-in SPIRE ở dev), mint X509-SVID,
rotation, Source abstraction, mTLS `tls.Config` qua `go-spiffe/v2`, đường SPIRE-ready. Khung hóa **C4**
(không giả mạo), **C11** (vận hành).
**View liên quan:** Security/Trust (VP-5), Deployment (VP-7).

---

## 1. CA in-process (internal/identity/spiffe/ca.go)

```go
type CA struct { td spiffeid.TrustDomain; caCert *x509.Certificate; caKey crypto.Signer }  // ca.go:38
func NewCA(trustDomain string) (*CA, error)                  // ca.go:45  (ECDSA P256, root ~10 năm)
func (c *CA) TrustDomain() spiffeid.TrustDomain              // ca.go:74
func (c *CA) Bundle() *x509bundle.Bundle                     // ca.go:77
func (c *CA) Mint(spiffeID string) (*x509svid.SVID, error)   // ca.go:87  (SVID TTL 24h, URI SAN spiffe://)
func (c *CA) MTLSServerConfig(svid, bundle) *tls.Config      // ca.go:135 (AuthorizeMemberOf trust domain)
func (c *CA) MTLSClientConfig(svid, bundle) *tls.Config      // ca.go:141
```

`Mint`: kiểm ID thuộc trust domain; cert `KeyUsageDigitalSignature` + ExtKeyUsage Server/Client Auth;
URI SAN = SPIFFE id.

## 2. Source abstraction + rotation (internal/identity/spiffe/source.go)

```go
type Source struct { svid x509svid.Source; bundle x509bundle.Source; td; closer func() error }  // source.go:23
func (s *Source) ServerTLS() *tls.Config; func (s *Source) ClientTLS() *tls.Config              // source.go:32/37
func (s *Source) Close() error
func FromWorkloadAPI(ctx, trustDomain, socketPath string) (*Source, error)   // source.go:53 (SPIRE thật)
func RotatingSource(ctx, spiffeID string, every time.Duration) (*Source, error)  // source.go:72 (dev/test)
```

- **`Source` đọc SVID mỗi handshake** (`GetX509SVID`, source.go:120) → **rotation trong suốt** với
  caller.
- **`FromWorkloadAPI`**: nối SPIRE agent qua `SPIFFE_ENDPOINT_SOCKET` → `workloadapi.X509Source`
  (production: SPIRE attest + rotate).
- **`RotatingSource`**: mint từ CA in-process và re-mint theo chu kỳ (`rotating`, mutex-guarded) — mô
  phỏng rotation; unit test xác nhận SVID đổi.

## 3. I/O PEM (internal/identity/spiffe/pem.go)

`WriteSVID` (cert 0644 / key PKCS8 0600), `WriteBundle`, `LoadSVID`, `LoadBundle` — dùng bởi `svidmint`
ghi cert ra disk (stand-in Workload API ở demo dev).

## 4. Mô hình tin cậy & PKI (qua các mốc)

```
Org/Vault Root ─UpstreamAuthority─▶ SPIRE intermediate ─▶ X509-SVID/workload
  M8  UpstreamAuthority "disk"  (nodecert: upstream-root + node-CA + agent node cert)
  M12 UpstreamAuthority "vault" (Vault PKI sign-intermediate) → SVID chain về Vault root
Node attestation: M8 x509pop (agent chứng minh bằng node cert)  |  M13 k8s_psat (projected SA token → TokenReview)
```

**Bảo đảm (đã verify):** không SVID → rớt ở **TLS handshake (L0/§2)**, không chạm PEP/PDP; CA lạ →
reject ở handshake. `act` của PDP nhận là mật mã, không phải header.

## 5. Kiểm thử

- `ca_test.go`, `source_test.go` (rotation), `handshake_test.go` (no-cert drop, foreign-CA reject).

## 6. Hướng tối ưu / giới hạn

- **CA in-process là mock cấp phát** — production dùng SPIRE thật (đã có ở `deploy/`); chỉ dùng
  `RotatingSource`/`svidmint` cho dev. *C11.*
- **HA SPIRE server + secret management**: Vault hiện dev-mode (root token), KeyManager disk; cần HA +
  secret thật cho production. *C11.*
- SVID TTL 24h ở CA mock; SPIRE thật cấu hình ngắn hơn (k8s 1h) — nên thống nhất chính sách TTL/rotation.
- Trust domain đơn (`vsp.local`); federation đa trust-domain chưa có.
