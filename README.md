# cargo-unsafe-surface

A Cargo subcommand that determines **which unsafe operations are reachable
from selected entry points** in a Rust program.

`cargo-unsafe-surface` goes beyond counting `unsafe` blocks. It parses the
sources of your workspace (and optionally its dependencies), builds an
approximate call graph, and reports the actual unsafe and foreign-code
exposure of an application or library — including the call paths that lead
there.

> **This tool provides an approximation, not a proof.** A clean report
> does not demonstrate that a program is safe, and a finding does not
> demonstrate that a program is unsound. See
> [Analysis model](docs/analysis-model.md) and
> [Limitations](#limitations).

## What it answers

* Which `unsafe` functions, blocks, traits and impls are reachable from a
  binary entry point?
* Which safe public APIs eventually invoke unsafe code?
* Which reachable paths cross an FFI boundary, and through which
  dependencies?
* Where are manual `Send`/`Sync` impls, raw pointer dereferences,
  `transmute`, inline assembly, unions, `static mut`, `MaybeUninit` and
  `*_unchecked` calls?
* What is a shortest call path from an entry point to each unsafe
  operation?
* Which unsafe operations exist but are *not* reachable from the selected
  entry points?
* Which unsafe operations lack a `SAFETY:` justification comment?
* Which calls could not be resolved (analysis uncertainty)?

## Installation

```console
cargo install --path crates/cargo-unsafe-surface   # from a checkout
# or, once published:
cargo install cargo-unsafe-surface
```

Requires stable Rust 1.85+ and Cargo. Linux is the primary platform;
macOS and Windows build in CI.

## Usage

```console
cargo unsafe-surface --bin server
cargo unsafe-surface --lib
cargo unsafe-surface --package my-package --include-dependencies
cargo unsafe-surface --entry crate::api::process_request
cargo unsafe-surface --format json --output report.json
cargo unsafe-surface --format sarif --output results.sarif
cargo unsafe-surface --policy policy.toml
```

Key flags: `--lib`, `--bin NAME`, `--package SPEC`, `--entry PATH`,
`--include-dependencies`, `--include-dev-dependencies` (dev-deps are
excluded by default), `--format text|json|sarif`, `--output FILE`,
`--policy FILE`, `--features`, `--all-features`,
`--no-default-features`, `--target TRIPLE`, `--offline`,
`--manifest-path PATH`.

Default target selection: all binary targets of the selected packages;
if none exist, their library public API.

### Exit codes

| Code | Meaning                                |
| ---- | -------------------------------------- |
| 0    | Analysis succeeded, no policy violations |
| 1    | Operational failure (discovery, I/O, usage, invalid policy file) |
| 2    | Policy violations found                |

### Example output

```text
Unsafe Surface Report

Entry points:
  server::main

Summary:
  Reachable unsafe operations: 12
  Reachable FFI calls:         1
  Manual Send/Sync impls:      2
  ...

Finding 2
  Kind:          FFI call
  Confidence:    confirmed
  Justification: present
  Location:      ffiwrap/src/lib.rs:10:18
  Package:       ffiwrap 0.3.0 (workspace)
  Target:        ffiwrap::socket
  Path:
    server::main
    -> ffiwrap::create_socket  (server/src/main.rs:10)
    -> ffiwrap::socket
```

## Policy mode

```toml
[policy]
deny_reachable_inline_assembly = true
deny_reachable_mutable_statics = true
maximum_reachable_ffi_calls = 10
require_safety_comments = true
fail_on_unresolved_calls = false

[dependencies]
deny = ["deprecated-native-wrapper"]
allow_unsafe = ["libc", "socket2"]
```

Violations exit with code 2; malformed policies are configuration errors
(exit 1). Unresolved calls are never treated as safe — strict
environments can fail on them via `fail_on_unresolved_calls` or
`maximum_unresolved_calls`. See [docs/policy.md](docs/policy.md).

## How it works

1. **Discovery** — `cargo metadata` locates packages, targets and
   dependency sources. No code from the analysed repository is executed
   (no build scripts, no proc macros, no binaries).
2. **Parsing** — sources are parsed with `syn`; the module tree is walked
   with a limited `#[cfg]` evaluator (features from Cargo, target cfgs
   from `rustc --print cfg`).
3. **Classification** — a syntax visitor detects 18 classes of unsafe
   operations plus `SAFETY:` comments.
4. **Call graph** — call sites are resolved heuristically (imports,
   module scopes, crate paths; methods by unique-name matching).
   Everything unresolvable is reported explicitly with a reason.
5. **Reachability** — BFS from the entry points yields shortest call
   paths to every reachable unsafe operation.

Details: [docs/analysis-model.md](docs/analysis-model.md) ·
[ADR 0001](docs/adr/0001-analysis-approach.md) ·
[JSON schema](docs/json-schema.md)

## Limitations

Rust call-graph construction is fundamentally hard. This tool is
deliberately conservative about what it claims:

* macro expansions (including proc macros) are **not analysed** — calls
  produced by macros are invisible;
* method calls are resolved by unique-name matching and may be attributed
  to the wrong impl;
* trait objects, function pointers, closures and generics are only
  partially resolved (reported as unresolved with precise reasons);
* raw pointer dereferences are *inferred* from dereference expressions in
  unsafe contexts;
* `#[cfg]` evaluation is approximate — unknown predicates are treated as
  enabled (over-approximation);
* the standard library is not analysed.

Every report carries its uncertainty: unresolved calls, inferred
confidence levels, diagnostics and a `limitations` section are part of
the output — never silently dropped.

## Security

The analysed repository is treated as **untrusted input**: the default
analysis path executes nothing from it. The tool defends against
oversized inputs, cyclic module structures, path traversal via
`#[path]`, denial-of-service through graph size, and terminal escape
injection in output. See [docs/threat-model.md](docs/threat-model.md).

## Development

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo bench -p unsafe-surface-analysis
```

See [docs/development.md](docs/development.md),
[CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/releasing.md](docs/releasing.md).

## License

Licensed under the [GNU General Public License v3.0](LICENSE) or (at your
option) any later version (`GPL-3.0-or-later`).
