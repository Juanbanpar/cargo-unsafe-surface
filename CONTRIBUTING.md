# Contributing

Contributions are licensed under GPL-3.0-or-later.

## Ground rules

* The tool reports **approximations with explicit uncertainty**. Never
  present inferred results as confirmed, and never drop unresolved
  calls or diagnostics silently.
* Minimal, justified dependencies. Check `deny.toml` before adding one.
* No `unsafe` in the tool itself (`#![forbid(unsafe_code)]` everywhere).
* No uncontrolled panics in normal execution paths; library crates use
  structured errors (`thiserror`), the CLI aggregates with `anyhow`.
* Deterministic output: ordered maps, no HashMap iteration in output
  paths, no wall-clock or randomness in reports.

## Workflow

1. Keep commits focused and update docs when behaviour changes.
2. Run the checks from
   [docs/development.md](docs/development.md) before pushing.
3. Bug fixes must include a regression test.

## JSON schema stability

The JSON report schema is versioned (`schema_version: 1`). Within a
version, only additive changes are allowed. Breaking changes require a
schema version bump and a migration note in
[docs/json-schema.md](docs/json-schema.md).
