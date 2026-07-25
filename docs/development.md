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
docs/                       # model, threat model, schema, policy, ADRs
```

Dependency direction is strictly `cli → analysis → cargo/core` and
`cli → report → core`. The core model has no logic and no dependencies
beyond serde/thiserror.

## Required checks (must pass before every commit)

```console
cargo fmt --all
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-features
```

Milestone commits additionally require:

```console
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps   # RUSTDOCFLAGS=-Dwarnings in CI
```

Optional but configured: `cargo deny check` (licences/advisories),
`cargo llvm-cov` (coverage), `cargo bench -p unsafe-surface-analysis`
(graph benchmarks), `cargo machete` (unused deps).

## Toolchain notes

* MSRV is **1.85** (`rust-version` in the workspace manifest; verified
  in CI).
* Development on Fedora Silverblue (or any host without a system C
  toolchain) works inside a toolbox/distrobox container with `gcc`
  installed: `toolbox enter`, then use cargo normally. The host-only
  rustup toolchain cannot link without `cc`.
* Integration tests run the real binary against `tests/fixtures/` in
  offline mode; fixtures are *parsed*, never built, and are excluded
  from the main workspace.

## Testing conventions

* Unit tests live next to the code; end-to-end tests in
  `crates/*/tests/`.
* Snapshots use `insta` (`INSTA_UPDATE=always cargo test` to bless;
  review diffs before committing). Important fields are *also* asserted
  structurally — snapshots must not hide semantic regressions.
* Property tests use `proptest` for reachability and path validity.
* Every bug fix ships with a regression test.
* Tests must be deterministic, offline and isolated (tempdirs).

## CI

`.github/workflows/ci.yml` (required for PRs): fmt, clippy `-D warnings`,
tests on stable + MSRV (1.85.0), docs, release build — all on Linux.

`.github/workflows/advisory.yml` (weekly/manual): `cargo deny`,
coverage via `cargo-llvm-cov`, macOS/Windows builds, nightly tests.
Advisory failures are reviewed during maintenance; they never gate PRs.

**Action pinning**: actions that check out code are pinned to immutable
commit hashes. Tooling actions (`dtolnay/rust-toolchain`,
`swatinem/rust-cache`, `taiki-e/install-action`) are pinned to tags
because their moving tool inputs have no stable per-release hashes; this
trade-off is documented inline in the workflows. Dependabot keeps both
 ecosystems updated.

## Adding a new unsafe-op kind

1. Add the variant to `UnsafeOpKind` (core) with label + serde name.
2. Detect it in `classify.rs` (or in graph resolution).
3. Add SARIF rule mapping (`sarif.rs` `RULE_KINDS`).
4. Tests: classifier unit test, fixture example, report test.
5. Update `docs/analysis-model.md` and this list if the pipeline shape
   changes.
