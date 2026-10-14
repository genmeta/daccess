# Changelog

## [0.1.1] - 2026-10-14

### Added

- Add owner-authenticated `PUT /std/contact/{name}` with retry semantics and no implicit access grants.
- Return derived contact ids and the incoming direction in contact lists.
- Query expired pending reviews with `GET /std/acl/reviews?status=expired`, return `requested_at`, and delete them through `DELETE /std/acl/review/{id}`.

### Fixed

- Accept fresh contact applications from the same authenticated applicant and revoke superseded pending receipts atomically; preserve active contacts, exact access rules and old application retry results.

### Changed

- Use the crate-named library root `src/daccess.rs`; retain the `access_control` Rust library name, public service API and database schema.

### Release versions

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `daccess` | 0.1.0 | 0.1.1 |

## [0.1.0] - 2026-10-12

### Changed

- Publish the standalone name-based authorization library as daccess.
- Keep access_control as the Rust library name and downstream dependency alias.
- Provide SQLite-backed access policies, persistent approvals and contact polling.
- Mount management routes under /std; keep the frontend in Pishoo.

### Release versions

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `daccess` | first release | 0.1.0 |
