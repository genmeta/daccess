# Changelog

## [Unreleased]

- Move ACL objects and review/status IDs to query parameters; expose review lists at `/std/acl/review/list`.
- Remove contact HTTP PUT and provide a host-only Rust method for pending outbound identity bindings, retaining subject and deletion guards.
- Keep POST message rules/reviews independent from PUT; do not migrate management grants from removed object paths.
- Trigger review from business requests with `If-Reviewed: waiting|break`; keep waiting reviews in memory and return `400 need_review` for asynchronous reviews.
- Persist review decisions as ordinary per-user ACL rules, release matching live requests, and retain authorization across subsequent requests and restarts until revoked.
- Merge live and persistent pending reviews with explicit kinds, cancellation cleanup and stable identity/method/path deduplication.
- Keep new friend requests pending independently of requested interface permissions; acceptance does not grant ACL access.

- Unify contact management under `/std/contact` and `/std/contact/list`; use POST `/std/contact` for remote applications and GET `/std/contact?name=NAME` for authenticated relationship queries.
- Authorize management and receipt requests through ordinary ACL rules without additional owner-only checks.
- Upgrade the database structure to schema v2 with contact update timestamps, expiry parameters and incremental deletion records; preserve existing data and ACL rules without path conversions, default grants or database replacement.
- Parse flattened pagination query numbers so contact lists accept explicit page and page_size values alongside filters.
- Preserve identity-specific approval checks while allowing Named/All grants independently of historical contact SubjectIds.

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
