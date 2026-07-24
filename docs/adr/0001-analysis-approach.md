# ADR 0001: syn-based source analysis as the default backend

* Status: accepted
* Date: 2026-07-24

## Context

`cargo-unsafe-surface` must construct an approximate call graph of a Rust
workspace, classify unsafe constructs, and map every finding back to a
source location. Several implementation strategies exist, with different
trade-offs in accuracy, maintainability, toolchain compatibility, build
complexity, and — critically for this tool — the trust relationship with
the analysed repository.

The analysed repository is treated as **untrusted input**: by default the
tool must not execute `build.rs`, procedural macros, target binaries or
tests from the analysed project.

## Decision

The default (and currently only) analysis backend is **static source
analysis with `syn`**, combined with `cargo metadata` for workspace and
dependency discovery.

* `cargo metadata` reads manifests and the lockfile; it never executes
  code from the analysed repository.
* Sources are parsed directly with `syn` (full-fidelity syntax tree with
  `proc-macro2` span locations), including dependency sources already
  present in the local Cargo registry cache when
  `--include-dependencies` is used. The tool never downloads dependencies
  itself; missing sources are reported as diagnostics.
* Name resolution is heuristic: direct path calls are resolved against a
  crate-local item index and `use` imports; method calls are resolved by
  unique-name matching across known impls and marked as *inferred*.
  Calls that cannot be resolved are reported explicitly as *unresolved*
  and are never treated as safe.
* `#[cfg]` attributes are evaluated with a limited evaluator fed by
  `rustc --print cfg` (a read-only compiler query) and the feature set
  reported by `cargo metadata`. Unknown predicates are treated as true
  (over-approximation, which is the safe direction for an audit tool)
  and recorded in the analysis limitations.

The backend is isolated behind an internal module boundary
(`unsafe-surface-analysis`), so a compiler-based backend can be added
later without changing the core model or reporting layers.

## Consequences

* Works on stable Rust; MSRV 1.85.
* No code from the analysed repository is executed in the default mode.
* Deterministic, reproducible output; no dependency on compiler internals.
* Macro-generated code (including proc-macro output) is invisible to the
  analysis; call edges through macros, function pointers and dynamic
  dispatch are approximated or reported as unresolved. This is the main
  accuracy limitation and is documented prominently in the README and in
  every report's `limitations` section.

## Rejected alternatives

### `rustc_driver` / MIR

* Requires a nightly toolchain and couples the project to unstable,
  private compiler APIs that change every release; maintenance cost is
  high and permanent.
* Compiling the analysed crate requires executing its build scripts and
  procedural macros, which violates the default trust model. A sandboxed
  opt-in mode would be acceptable but is a large separate project.
* Considered for a future opt-in `--backend rustc` mode behind the same
  internal abstraction, with clearly documented trust implications.

### rust-analyzer libraries

* Provide high-quality semantic analysis, but the crates are released as
  "unstable, no semver guarantees" snapshots with a very large dependency
  tree; pinning and upgrading them is disproportionately expensive for
  the accuracy gain over our heuristic resolver at MVP stage.

### rustdoc JSON (`rustdoc-types`)

* Requires nightly (`-Z unstable-options --output-format json`) and
  executes proc macros/build scripts during the documentation build.
* Exposes items but not bodies, so call-graph edges and unsafe blocks
  inside function bodies cannot be recovered. Fundamentally
  insufficient for reachability.

### Hybrid (syn + optional compiler pass)

Kept as a future option; the internal model (`unsafe-surface-core`) is
deliberately backend-agnostic so this remains possible.
