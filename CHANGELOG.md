# Changelog

## Unreleased

- Add owner-authenticated contact resource PUT and retry semantics without importing access rules.
- Return derived contact id and list incoming direction for the host integration.
- Use the crate-named library root src/daccess.rs.

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
