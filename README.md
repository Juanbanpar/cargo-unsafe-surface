# cargo-unsafe-surface

`cargo-unsafe-surface` is a Cargo subcommand for tracing unsafe operations and
foreign-function calls from selected entry points in a Rust project.

It parses workspace sources, builds an approximate call graph, and shows which
unsafe operations are reachable and how execution can reach them. Dependencies
can be included when their sources are already available in the local Cargo
registry or git cache.

> **This is a static approximation, not a proof of safety or unsoundness.** A
> clean report does not prove that a program is safe, and a reported finding
> does not prove that the program is unsound. See the
> [analysis model](docs/analysis-model.md) and [limitations](#limitations).

## Why this exists

A raw count of `unsafe` blocks says little about the part of a program that is
actually exposed. An unsafe operation may be unreachable from the binary,
library API, or function under review. It may also sit behind several layers of
calls that make manual inspection difficult.

`cargo-unsafe-surface` separates reachable and unreachable findings. For each
reachable finding, it records a call path from an entry point to the operation.
It also reports:

- reachable FFI calls and the packages that provide them;
- unsafe traits and impls, manual `Send` and `Sync` impls, mutable statics,
  extern blocks, and foreign function declarations;
- unsafe operations without a nearby `SAFETY:` comment;
- unresolved call sites, including the reason resolution failed;
- confidence levels and analysis diagnostics.

The tool never executes code from the project being analysed. Build scripts,
procedural macros, and project binaries are not run.

## Installation

From a checkout:

```console
cargo install --path crates/cargo-unsafe-surface
```

Once the crate is published:

```console
cargo install cargo-unsafe-surface
```

Requires stable Rust 1.85 or later and Cargo. Linux is the primary platform;
macOS and Windows builds are covered by CI.

## Quick start

Run the command from a Cargo project:

```console
cargo unsafe-surface
```

With no target or entry-point flags, the tool analyses every binary target in
the selected packages.

Common examples:

```console
# One binary target
cargo unsafe-surface --bin server

# The public API of a library target
cargo unsafe-surface --lib

# One or more packages
cargo unsafe-surface --package my-package
cargo unsafe-surface --package a --package b

# Explicit function entry points
cargo unsafe-surface --entry crate::api::process_request
cargo unsafe-surface --entry server::main --entry netlib::run

# Dependencies whose sources are already on disk
cargo unsafe-surface --include-dependencies

# Include dev-dependencies as well
cargo unsafe-surface --include-dependencies --include-dev-dependencies

# Feature selection
cargo unsafe-surface --features tls,compress
cargo unsafe-surface --all-features
cargo unsafe-surface --no-default-features

# Evaluate #[cfg] for another target
cargo unsafe-surface --target aarch64-unknown-linux-gnu

# Machine-readable output
cargo unsafe-surface --format json --output report.json
cargo unsafe-surface --format sarif --output results.sarif

# Enforce a policy
cargo unsafe-surface --policy policy.toml

# Prevent network access during Cargo dependency resolution
cargo unsafe-surface --offline

# Analyse a project outside the current directory
cargo unsafe-surface --manifest-path /path/to/project/Cargo.toml
```

## Entry points and analysis scope

Without `--package`, Cargo workspace default members are selected. If the
workspace does not declare default members, all members are selected.

Entry points can come from several sources:

- `--bin NAME` uses the named binary's `main` function;
- `--lib` uses the public API of the library target;
- `--entry PATH` adds an explicit function.

These options are additive: `--entry` adds to the target selection instead
of replacing it. For example, `--bin server --entry netlib::run` starts from
both entry points, and `--entry netlib::run` alone still includes every
binary target of the selected packages. Without `--bin` or `--lib`, every
binary target in the selected packages is used.

Dependency analysis is limited to source code already present in the local
Cargo registry or git caches. The tool does not download dependency sources.
Dev-dependencies are excluded by default because they are not part of the
shipped artifact. Build dependencies are always excluded.

## Report contents

Each finding identifies:

- the operation kind;
- source location;
- the package, and the called target for calls to unsafe functions and
  FFI;
- confidence level;
- whether a `SAFETY:` justification was found;
- a call path, when the finding is reachable.

Classified operation kinds include unsafe blocks, unsafe functions, calls to
unsafe functions, FFI calls, raw pointer dereferences, `transmute`, inline
assembly, union field access, mutable static access, `MaybeUninit` use, and
unchecked API calls.

Unreachable unsafe operations are listed separately. Calls that cannot be
resolved are not treated as safe; they are reported with a reason such as an
unknown name, ambiguous method, dynamic dispatch, function pointer, macro
expansion, standard-library code, or unavailable dependency sources.

### Output formats

Text output is the default:

```console
cargo unsafe-surface --format text
```

JSON output uses a versioned schema documented in
[docs/json-schema.md](docs/json-schema.md). SARIF is available for integration
with code-scanning tools.

### Example output

```text
Unsafe Surface Report

Tool: cargo-unsafe-surface 0.1.0
Schema version: 1

Entry points:
  server::main

Summary:
  Reachable unsafe operations: 12
  Reachable unsafe functions:  2
  Reachable FFI calls:         1
  Manual Send/Sync impls:      2
  ...

Finding 2
  Kind:          FFI call
  Confidence:    confirmed
  Justification: present
  Location:      ffiwrap/src/lib.rs:10:14
  Package:       ffiwrap 0.3.0 (workspace)
  Target:        ffiwrap::socket
  Enclosing:     ffiwrap::create_socket
  Path:
    server::main
    -> ffiwrap::create_socket  (server/src/main.rs:10)
    -> ffiwrap::socket
```

## Policy mode

A policy file can turn findings into CI failures:

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

Policy violations exit with code 2. An invalid policy file is an operational
error and exits with code 1.

Unresolved calls remain visible even when they do not fail the policy. Stricter
configurations can reject them with `fail_on_unresolved_calls` or
`maximum_unresolved_calls`.

See [docs/policy.md](docs/policy.md) for the full policy format.

## CLI reference

| Flag | Default | Effect |
| --- | --- | --- |
| `--manifest-path PATH` | current directory | Analyse the Cargo project at `PATH`. |
| `--package SPEC` | workspace default members | Analyse only the named package. Repeatable. |
| `--lib` | off | Use the library target's public API as entry points. |
| `--bin NAME` | off | Use the named binary's `main` function as an entry point. Repeatable. |
| `--entry PATH` | none | Add an explicit function entry point, such as `crate::api::process`. Repeatable. |
| `--include-dependencies` | off | Analyse dependency sources found in local Cargo registry and git caches. |
| `--include-dev-dependencies` | off | Include dev-dependencies. |
| `--exclude-dev-dependencies` | on | Exclude dev-dependencies; conflicts with `--include-dev-dependencies`. |
| `--features LIST` | none | Enable a comma-separated list of features. |
| `--all-features` | off | Enable every feature in each selected package. |
| `--no-default-features` | off | Disable default features. |
| `--target TRIPLE` | host target | Evaluate `#[cfg]` for another target triple. |
| `--format FORMAT` | `text` | Select `text`, `json`, or `sarif` output. |
| `--output FILE` | standard output | Write the report to a file. |
| `--policy FILE` | none | Evaluate a policy after analysis. |
| `--offline` | off | Prevent Cargo from using the network during dependency resolution. |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Analysis completed with no policy violations. |
| 1 | Operational failure, including discovery, I/O, usage, or policy parsing errors. |
| 2 | Policy violations were found. |

## Analysis model

The analysis runs in five stages:

1. **Discovery.** `cargo metadata` locates packages, targets, and dependency
   sources.
2. **Parsing.** `syn` parses the source tree. A limited `#[cfg]` evaluator uses
   Cargo feature selection and target configuration from `rustc --print cfg`.
3. **Classification.** A syntax visitor identifies 18 classes of unsafe
   operations and checks for `SAFETY:` comments.
4. **Call-graph construction.** Call sites are resolved heuristically from
   imports, module scopes, crate paths, and unique method names.
5. **Reachability.** Breadth-first search finds the shortest known path from an
   entry point to each reachable unsafe operation.

See [docs/analysis-model.md](docs/analysis-model.md) for implementation details.

## Limitations

Rust call-graph construction cannot be made complete from source syntax alone.
The current analysis has the following limits:

- Macro expansions, including procedural macros, are not analysed. Calls
  generated by macros are invisible to the call graph.
- Method calls are matched by unique name and can be assigned to the wrong
  implementation.
- Trait objects, function pointers, closures, and generics are only partially
  resolved.
- Raw pointer dereferences are inferred from dereference expressions inside
  unsafe contexts.
- `#[cfg]` evaluation is approximate. Unknown predicates are treated as enabled,
  which can over-approximate the analysed code.
- The standard library is not analysed.

Reports retain this uncertainty through unresolved-call records, confidence
levels, diagnostics, and a limitations section.

## Security model

The analysed repository is untrusted input. The default analysis path does not
execute its build scripts, procedural macros, binaries, or other project code.

The implementation includes protections against oversized inputs, cyclic
module structures, path traversal through `#[path]`, excessive graph growth,
and terminal escape injection in generated output.

See [docs/threat-model.md](docs/threat-model.md) for details.

## Development

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo bench -p unsafe-surface-analysis
```

See [docs/development.md](docs/development.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the [GNU General Public License v3.0](LICENSE), or, at your
option, any later version (`GPL-3.0-or-later`).
