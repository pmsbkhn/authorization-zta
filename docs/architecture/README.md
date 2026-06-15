# Tài liệu Kiến trúc — authorization-zta

Bộ tài liệu này mô tả kiến trúc của một **nền tảng (platform) Zero Trust Authorization tái sử dụng
được**, soạn theo cấu trúc của **ISO/IEC/IEEE 42010:2011 — Systems and software engineering —
Architecture description**.

> **Định vị:** Hệ thống cần mô tả **là chính nền tảng ZTA**, dùng để triển khai vào nhiều hệ thống khác
> nhau. Các service nghiệp vụ **VSP (Gateway / Multi-Bill / VSP Wallet)** chỉ là **reference adopter**
> (triển khai mẫu) để chứng minh nền tảng chạy đầu-cuối — không thuộc lõi nền tảng. Xem ranh giới
> core↔demo và view Adoption/Packaging trong AD.

Mục tiêu: cung cấp bức tranh đầy đủ, chính xác ở mức mã nguồn về **cấu trúc hiện tại** (M1→M14) để làm
nền cho việc **tối ưu khả năng được áp dụng** (tái sử dụng, đóng gói, mở rộng) và tối ưu kỹ thuật (hiệu
năng, vận hành, bảo mật).

> **Cập nhật sau refactor tách module (platform-first):** lõi đã được gom nhóm theo concern dưới
> `internal/{authz,identity,signals,policystore,ports,testsupport}`, và **reference adopter VSP**
> (Gateway/Multi-Bill/Wallet + domain policy + deploy) đã tách hẳn sang `examples/vsp/`. Khung policy
> nền tảng ở `policies/`; domain nghiệp vụ ở `examples/vsp/policies` (nạp qua
> `PDPConfig.ExtraModules`). `go build ./...` + `go test ./...` xanh. Cây thư mục mới: xem
> [README gốc §Cấu trúc](../../README.md). Các spec mô tả **lõi nền tảng**; ví dụ minh họa ở
> `examples/vsp`. Việc còn lại để nhúng từ repo khác: đưa lõi ra khỏi `internal/` (AD §7.0).

## Cách tổ chức

| Tài liệu | Vai trò |
|---|---|
| [`architecture-description.md`](architecture-description.md) | **Tài liệu Mô tả Kiến trúc (AD)** theo ISO 42010: stakeholders, concerns, viewpoints, views, decisions, correspondences. Đọc trước. |
| [`specs/`](specs/) | **Tech spec từng module** — chi tiết hợp đồng, kiểu dữ liệu, luồng điều khiển, cấu hình, lỗi, và điểm tối ưu của mỗi thành phần. |

### Index tech spec theo module

| # | Spec | Gói mã nguồn | Mặt phẳng |
|---|---|---|---|
| 01 | [AuthZEN Data Contract](specs/01-authzen-contract.md) | `internal/authz/authzen`, `proto/authzen/v1` | Control Plane (hợp đồng) |
| 02 | [AuthZEN HTTP Facade](specs/02-api-facade.md) | `internal/authz/api` | Control Plane |
| 03 | [PDP / Unified Router](specs/03-pdp-router.md) | `internal/authz/pdp` | Control Plane |
| 04 | [OPA Engine + Hierarchical Rego](specs/04-engine-opa-policies.md) | `internal/authz/engine`, `policies/` | Control Plane |
| 05 | [ReBAC Engine (OpenFGA)](specs/05-engine-rebac.md) | `internal/authz/rebac` | Control Plane |
| 06 | [Decision Token](specs/06-decision-token.md) | `internal/authz/token` | Control Plane ↔ PEP |
| 07 | [PEP Library (L0/L1/L2)](specs/07-pep-library.md) | `internal/authz/pep`, `internal/authz/pdpclient` | PEP Layer |
| 08 | [gRPC Transport](specs/08-grpc-transport.md) | `internal/authz/grpcpdp`, `proto/authzen/v1` | Control Plane ↔ PEP |
| 09 | [Workload Identity / SPIFFE-SVID](specs/09-spiffe-identity.md) | `internal/identity/spiffe` | Trust fabric |
| 10 | [CAEP / Continuous Evaluation](specs/10-caep-revocation.md) | `internal/signals/caep` | Control Plane ↔ PEP |
| 11 | [Policy Bundle Store + PIP seams](specs/11-policy-bundle-store.md) | `internal/policystore/bundlestore`, `internal/ports/pip`, `internal/testsupport/mock` | Control Plane |
| 12 | [Service Wiring & Entrypoints](specs/12-services-and-cmd.md) | `internal/services`, `cmd/` | Tất cả |
| 13 | [Deployment Topology](specs/13-deployment-topology.md) | `deploy/`, `scripts/` | Vận hành |

## Tài liệu nguồn liên quan

- [`../design-v3.md`](../design-v3.md) — thiết kế gốc (v3), Implementation Ready. AD này **mở rộng và
  hiện thực hóa** thiết kế đó với những gì đã được code thật qua M1→M14.
- [`../../README.md`](../../README.md) — nhật ký mốc (milestone log) M1→M14, hướng dẫn chạy/test.

## Quy ước

- Trích dẫn mã nguồn theo dạng `gói/tệp.go:dòng`.
- Tiếng Việt là ngôn ngữ chính; thuật ngữ kỹ thuật chuẩn (PEP, PDP, mTLS, SVID, obligation…) giữ
  nguyên tiếng Anh.
- "Đã verify" = có test tự động và/hoặc đã chạy live theo README; "seam" = ranh giới interface để
  thay thế triển khai.
