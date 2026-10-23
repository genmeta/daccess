# Release preparation for v0.2.0

This release changes the contact and ACL HTTP protocol and adds explicit request-driven approval states. The crate is `daccess`; the Rust library remains `access_control`.

## Scope

- Move ACL objects and review/status IDs to query parameters; unify contact resources under `/std/contact` and `/std/contact/list`.
- Return asynchronous approval as HTTP 202 with `status: pending_review`, `review_id` and `status_url`; keep waiting requests separate.
- Support one-use decisions and remembered ACL rules, preserve identity binding, and report consumed, denied and expired rounds.
- Upgrade existing SQLite state transactionally through schema v3 while preserving contacts, ACLs and historical review results. No default permission grants or database replacement are introduced.

See [CHANGELOG.md](CHANGELOG.md) and [SPEC.md](SPEC.md). Pishoo and Message must consume the matching approval protocol; Workspace must send the explicit `remember` field only after confirming the supported decision modes.

## Validation

Use a checkout without ancestor Cargo path overrides and preserve the tracked registry lockfile. The existing PR workflow runs formatting, Clippy, tests and the publication dry run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features -- --test-threads=1
cargo publish --dry-run --locked
```

## Publication

Prepared version: `0.2.0`. Planned tag: `v0.2.0`. After the PR is merged and required checks pass, create an annotated release tag; the existing tag workflow publishes the crate and GitHub Release. PR preparation does not publish or deploy.

The workflow uses `CARGO_REGISTRY_TOKEN` when configured, otherwise its existing Trusted Publishing configuration. Downstream crates use the new version or a reachable, pinned Git revision containing these changes. Publish the ACL library before switching downstream release manifests to the crates.io version.
