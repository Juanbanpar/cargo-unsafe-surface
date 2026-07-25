# Contributing

Thanks for your interest! This project welcomes bug reports, fixes,
analysis-accuracy improvements and documentation work. Contributions are
licensed under the project's licence, GPL-3.0-or-later.

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

1. Discuss large changes in an issue first.
2. Follow the commit discipline: atomic commits, imperative messages,
   tests included, docs updated when behaviour changes. Do not mix
   refactors with behaviour changes or formatting with features.
3. Run the required checks from
   [docs/development.md](docs/development.md) before pushing.
4. Bug fixes must include a regression test.
5. If you change anything described in `docs/` (analysis model, threat
   model, schema, policy, CI), update the documents in the same commit.

## JSON schema stability

The JSON report schema is versioned (`schema_version: 1`). Within a
version, only additive changes are allowed. Breaking changes require a
schema version bump and a note in the changelog.
