# Threat model

`cargo-unsafe-surface` analyses repositories it does not trust. This
document states what the tool protects against, how, and what remains
the user's responsibility.

## Assets at risk

* The machine running the analysis (code execution, file system).
* The integrity of the report (forged or hidden findings, terminal
  injection).
* Availability (denial of service via pathological input).

## Guarantees of the default analysis path

1. **No code from the analysed repository is executed.** The default
   backend never runs `build.rs`, procedural macros, target binaries,
   tests or scripts from the analysed project. Discovery uses
   `cargo metadata`, which reads manifests and the lockfile without
   executing project code. The only external programs run are `cargo
   metadata` and `rustc --print cfg` (a read-only query against the
   *installed* toolchain).

2. **Dependencies are never downloaded.** If dependency sources are not
   already present locally, they are reported as unavailable; the tool
   does not fetch them. `--offline` additionally prevents Cargo from any
   network access during resolution.

3. **Output is sanitized.** Identifiers and paths in the report come
   from the analysed repository. All strings interpolated into text
   output have control characters (including the ANSI escape character)
   replaced, so a malicious crate cannot forge report sections or attack
   terminal emulators. JSON output is escaped by construction.

4. **Input size is bounded.** Per-file size (4 MiB default), files per
   crate, total files, module depth and graph node counts are limited.
   Breaches produce diagnostics; the analyser skips the offending unit
   and continues.

5. **Cycles and traversal tricks are contained.** Module cycles and
   symlink loops are stopped by canonical-path tracking and depth
   limits. `#[path = "..."]` is honoured (it is part of the language)
   but every resolved file goes through the same size/count limits; file
   reads are limited to module files reachable from crate roots.

6. **No hidden state.** Analysis is deterministic and free of global
   mutable state; the same inputs produce byte-identical reports.

## Known residual risks (user responsibility)

* **`cargo metadata` may create or update `Cargo.lock`** in the analysed
  workspace as a side effect of dependency resolution. Use `--offline`
  on a clean checkout if this is undesirable.
* **CPU and memory usage** on enormous workspaces is bounded but not
  small: limits are tuned for "much larger than real projects", not for
  minimal footprint. An adversary can still make analysis *slow* within
  those bounds.
* **Malformed Cargo metadata** (a tampered registry cache, hostile
  manifests) can mislead discovery. The tool validates what it consumes
  (paths must exist, sources must parse) and reports anomalies as
  diagnostics, but it trusts Cargo's view of the world.
* **Supply-chain of the tool itself**: CI pins code-handling actions to
  commit hashes, dependency updates flow through Dependabot PRs, and
  `cargo deny` runs as an advisory check.

## What the tool does NOT promise

* It is not a sandbox: do not point it at directories where file reads
  themselves are dangerous (named pipes, device files). Reads are
  limited to regular files under crate module trees.
* It does not detect malicious code semantics; it reports unsafe and
  FFI *surface*, not intent.
* If a future compiler-based backend that executes proc macros is ever
  added, it will be an explicitly opt-in mode with its own documented
  trust implications.
