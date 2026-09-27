# Analysis model

This document describes how `cargo-unsafe-surface` models a Rust program.
The stable types live in the `unsafe-surface-core` crate; the pipeline
that produces them lives in `unsafe-surface-analysis`.

## Backend choice

The backend parses sources with `syn` and discovers packages with
`cargo metadata`. It runs on stable Rust and never executes build
scripts, proc macros or binaries from the analysed repository.
`rustc_driver`/MIR and rustdoc JSON were rejected: both need nightly and
execute project code. rust-analyzer's crates were rejected: unstable
API and a large dependency tree. The model is backend-agnostic, so a
compiler backend can be added later.

## Pipeline

```
cargo metadata ──▶ discovery (packages, targets, dep closure, features)
       │
       ▼
source loading ──▶ per crate instance: module walk + #[cfg] evaluation
       │
       ▼
indexing ──▶ symbol tables: items, impls, unions, static muts, imports
       │
       ▼
classification ──▶ per-function unsafe ops + call sites; structural findings
       │
       ▼
call graph ──▶ heuristic name resolution; edges; unresolved calls
       │
       ▼
entry points ──▶ --bin main / --lib public API / --entry paths
       │
       ▼
reachability ──▶ BFS; shortest path per reachable node
       │
       ▼
report model ──▶ findings, structural findings, unresolved calls,
                  diagnostics, limitations, summary
```

## Crate instances

A package's library and each of its binaries are separate compilation
units sharing one crate name. The model tracks **instances**: `crate::`
stays inside the caller's instance, while `name::` from a binary resolves
to the library instance (extern-crate semantics), matching `rustc`.

## Findings vs structural findings

* **Findings** are unsafe operations inside function bodies. They are
  reachability-gated: each carries one shortest call path from an entry
  point, or is marked `unreachable`.
* **Structural findings** are module-level constructs that are part of a
  crate's unsafe surface by construction: `unsafe impl`, `unsafe trait`,
  `static mut`, extern blocks, foreign function declarations, and manual
  `Send`/`Sync` impls. They are always reported.

## Confidence levels

* `confirmed`: direct syntactic evidence, or a call resolved to a unique
  known item.
* `inferred`: heuristic evidence. Method calls resolved by unique-name
  matching, raw-pointer dereferences inferred from unsafe contexts,
  mutable-static accesses matched by name, `*_unchecked` calls.

## Edge kinds

* `direct`: path call resolved to a unique known item (confirmed).
* `inferred_method`: method call resolved by unique-name matching
  (inferred). Small ambiguity sets (up to 8 candidates) produce
  *may-call* inferred edges to every candidate. This over-approximates,
  so ambiguity never hides reachable unsafe code. Larger sets are
  reported as `ambiguous_method` unresolved calls.

## Unresolved calls

Every call site that cannot be resolved is reported with a machine-
readable reason: `unknown_name`, `ambiguous_method`, `dynamic_dispatch`,
`function_pointer`, `macro_expansion`, `standard_library`,
`dependency_sources_unavailable`, `unsupported_construct`.

Unresolved calls are **analysis uncertainty**, not evidence of safety.
Standard-library calls are expected and counted separately; all other
unresolved calls feed `fail_on_unresolved_calls` /
`maximum_unresolved_calls` policy rules.

## Classification heuristics worth knowing

| Construct | Detection | Confidence |
| --- | --- | --- |
| `unsafe {}` block | syntax | confirmed |
| `unsafe fn` / calls to it | syntax / resolved callee | confirmed (direct) / inferred (method) |
| FFI calls | resolved callee declared in `extern` block without `safe fn` | confirmed |
| raw pointer deref | dereference expr in unsafe context | inferred |
| `transmute` | call path ending in `transmute`/`transmute_copy` | confirmed |
| inline assembly | `asm!`/`global_asm!`/`naked_asm!` macro | confirmed |
| union field read | field access in unsafe context on param/`let` annotated with a known union | confirmed |
| `static mut` access | path matching a known `static mut` name | inferred |
| `MaybeUninit` | path containing `MaybeUninit` | inferred |
| unchecked APIs | method name containing `_unchecked` | inferred |

## `SAFETY:` detection

The scanner walks upward from each unsafe construct (up to 16 lines,
crossing blank lines, attributes and comment lines) and reports a
justification when it finds a comment starting with `SAFETY:` or a doc
`# Safety` section.

## `#[cfg]` evaluation

Known keys are evaluated against `rustc --print cfg` and the resolved
feature set from Cargo. `test` is always false (shipped code, not test
builds). Unknown predicates (e.g. build-script cfgs) keep the item
(over-approximation) and are counted in diagnostics.

## Entry-point selection

* `--bin NAME`: the `main` function of that binary target.
* `--lib`: every `pub` function of the library (over-approximation of the
  public API, since visibility through `pub use` re-exports and
  restricted visibilities is not modelled).
* `--entry crate::path::func`: an explicit item path. A `crate::` prefix
  matches no crate by name; the item path is looked up in every analysed
  crate instance (one entry point per instance that defines it).
* Default: all binary targets of the selected packages; if none exist,
  their libraries.

## Reachability

Multi-source BFS from all entry points. BFS gives shortest paths (in
number of calls); ties are broken deterministically by node id. One
shortest path per finding is reported.

## Limits

The analyser enforces resource limits (per-file size, files per crate,
module depth, graph nodes, listed findings/unresolved calls). Every
limit breach is a diagnostic; nothing is silently dropped. See
`Limits` in `unsafe-surface-analysis`.
