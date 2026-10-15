# Release preparation for v0.1.1

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `daccess` | 0.1.0 | 0.1.1 |

## Scope and dependencies

This patch release adds owner-managed contact resources, derived contact response fields and expired review management, and fixes fresh application replacement. The public Rust service API, library name and database schema remain unchanged. See [CHANGELOG.md](CHANGELOG.md) and [SPEC.md](SPEC.md).

There are no unpublished Genmeta upstream dependencies. Manifest versions use Cargo's compatible-version requirements. No sibling checkout or Git patch is required.

## Validation and lockfiles

Keep the tracked Cargo.lock resolved from crates.io. Run Cargo from a checkout outside directories containing ancestor path patches; do not commit a lockfile generated with local overrides. Preserve unrelated dependency versions when refreshing the release lockfile.

Before merging and tagging, require formatting, Clippy, tests and the publish dry run in the existing `publish-crates.yml` workflow to pass on the release commit. Local manifest, lockfile and package-content checks do not replace compilation or runtime tests.

## Publication

Planned tag: `v0.1.1`. After the preparation PR is merged and its checks pass, use an annotated tag with the changelog entry as its release notes. Tag-triggered GitHub Actions publishes the crate and creates the GitHub Release; preparation does not publish or deploy.

The published package is `daccess`; the Rust library remains `access_control`. Downstream manifests use `access_control = { package = "daccess", version = "0.1.1" }`.

The workflow uses the existing `CARGO_REGISTRY_TOKEN` repository secret when configured, for both first and subsequent publications. Without that secret, existing crates use Trusted Publishing for genmeta/daccess and `publish-crates.yml`; first publication requires an API token.
