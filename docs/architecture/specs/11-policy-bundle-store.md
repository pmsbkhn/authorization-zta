# Spec 11 — Policy Bundle Store + PIP Seams

**Gói:** `internal/policystore/bundlestore`, `internal/ports/pip`, `internal/testsupport/mock`
**Vai trò:** Nguồn policy bất biến (S3 WORM) + các seam thông tin (IdP / WorkloadAttestor /
PolicyStore). Khung hóa **C8** (vòng đời policy), **C12** (enrich/audit), tính thay-thế-được của Control
Plane.
**View liên quan:** Policy-Lifecycle (VP-6), Logical (VP-2).

---

## 1. PIP seams (internal/ports/pip/pip.go)

```go
type IdentityProvider interface { LookupSubject(ctx, subjectID string) (map[string]any, error) }  // pip.go:13
type WorkloadAttestor interface { ValidateSVID(ctx, spiffeID string) (bool, error) }              // pip.go:20
type PolicyStore     interface { LatestBundle(ctx) (data []byte, version string, err error) }     // pip.go:28
```

Ba ranh giới để M1 chạy với mock và sau đó thay bản thật **không đụng PDP**:
- `IdentityProvider` — bồi thuộc tính subject (roles/entitlements/posture) OPA cần.
- `WorkloadAttestor` — validate SVID của workload gọi tới (backs L0 + delegation actor).
- `PolicyStore` — bundle bất biến, versioned (đường GitOps pull).

## 2. Mock (internal/testsupport/mock/mock.go)

`var _ pip.* = (*mock.*)(nil)` (compile-time). `IdentityProvider` (canned table), `WorkloadAttestor`
(mọi `spiffe://` attested trừ `Revoked`), `PolicyStore` (bundle cố định). Dùng ở M1 và test.

## 3. S3 PolicyStore thật (internal/policystore/bundlestore/s3.go)

```go
type Config struct { Endpoint, AccessKey, SecretKey, Bucket, Object string; UseSSL bool }  // s3.go:19
type Store  struct { cfg Config; client *minio.Client }   // s3.go:29   var _ pip.PolicyStore = (*Store)(nil)
func New(cfg Config) (*Store, error)                       // s3.go:37 (minio-go, static creds V4)
func (s *Store) LatestBundle(ctx) ([]byte, string, error)  // s3.go:50 (GetObject + Stat().VersionID)
```

Bucket bật **versioning + object-lock** → bundle đã publish **không bị overwrite**; mọi version giữ lại
để rollback/audit (design-v3 §5.3, C8). PDP chọn nguồn: `S3_ENDPOINT` set → pull
(`engine.NewFromBundle`); không set → bundle embed.

## 4. GitOps publish (xem cmd/bundlepush, deploy/bundle/publish.sh — [spec 13](13-deployment-topology.md))

```
opa test (gate) → opa build → bundlepush: PutObject Mode=GOVERNANCE retain-days → version id mới
```

## 5. Hướng tối ưu / giới hạn

- **IdP còn mock, chưa vào hot path** — PDP hiện chỉ dùng AAL từ header; nối `IdentityProvider` thật
  vào `pdp.Service.Evaluate` để enrich subject. *C12.* (next-step README).
- **`WorkloadAttestor` ở PEP** hiện dùng `mock.WorkloadAttestor` (mọi spiffe attested trừ revoked);
  production nên nối nguồn attestation/revocation SPIRE thật.
- **OpenFGA model chưa qua cùng pipeline immutable** như bundle Rego (bất đối xứng vòng đời, C8).
- Thiếu **bundle signature verification** sau khi pull (immutability dựa WORM; thêm chữ ký sẽ chặt hơn).
- **PEP chưa tự pull bundle** — chỉ PDP pull; sidecar PEP pull trực tiếp là hướng mở rộng (C8).
