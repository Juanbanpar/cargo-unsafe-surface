# Development guide

## Layout

```
crates/
  unsafe-surface-core/      # stable serializable analysis model (no logic)
  unsafe-surface-cargo/     # cargo metadata discovery; the only Cargo client
  unsafe-surface-analysis/  # parse → index → classify → graph → reach → report
  unsafe-surface-report/    # text / JSON / SARIF rendering (pure formatting)
  cargo-unsafe-surface/     # CLI: args, orchestration, policy evaluation
tests/fixtures/             # independent fixture workspaces (never built)
docs/                       # model, threat model, schema, policy
```

Dependency direction is strictly `cli → analysis → cargo/core` and
`cli → report → core`. The core model has no logic and no dependencies
beyond serde/thiserror.

## Checks

```console
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

## Toolchain notes

* MSRV is **1.85** (`rust-version` in the workspace manifest; verified
  in CI).
* Integration tests run the real binary against `tests/fixtures/` in
  offline mode; fixtures are *parsed*, never built, and are excluded
  from the main workspace.

## Testing conventions

* Unit tests live next to the code; end-to-end tests in
  `crates/*/tests/`.
* Snapshots use `insta` (`INSTA_UPDATE=always cargo test` to bless;
  review diffs before committing). Important fields are *also* asserted
  structurally; snapshots must not hide semantic regressions.
* Property tests use `proptest` for reachability and path validity.
* Tests must be deterministic, offline and isolated (tempdirs).

## CI

`.github/workflows/ci.yml` (required for PRs): fmt, clippy `-D warnings`,
tests on stable + MSRV (1.85.0), docs, release build, all on Linux.

`.github/workflows/advisory.yml` (weekly/manual): `cargo deny`, coverage,
macOS/Windows builds. Advisory failures are reviewed during maintenance;
they never gate PRs.
