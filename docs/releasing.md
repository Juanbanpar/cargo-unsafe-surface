# Release process

Releases are cut from `main` when the milestone's acceptance criteria
are met.

## Checklist

1. **Quality gates green**: fmt, clippy, tests (stable + MSRV), docs,
   release build — locally and in CI.
2. **Version bump**: update `workspace.package.version` in the root
   `Cargo.toml`; run `cargo check` to refresh `Cargo.lock`; commit as
   `Release vX.Y.Z`.
3. **Changelog**: summarize user-visible changes, schema changes and
   new limitations honestly (including anything that became *less*
   accurate).
4. **Tag**: `git tag -s vX.Y.Z -m "vX.Y.Z"` and push with
   `git push --tags`.
5. **Publish** (maintainers only): crates are published in dependency
   order, waiting for each to become available:
   `unsafe-surface-core` → `unsafe-surface-cargo` →
   `unsafe-surface-analysis` → `unsafe-surface-report` →
   `cargo-unsafe-surface`. Use `cargo publish --dry-run` first.
6. **GitHub release**: attach the text/JSON/SARIF sample outputs and
   the changelog entry.

## Versioning policy

* The CLI and libraries share a workspace version.
* 0.x: breaking changes may happen in minor releases and are documented
  in the changelog; the JSON schema version only bumps on incompatible
  report changes.
* Once public APIs stabilize, evaluate `cargo-semver-checks` in CI.
