//! Source analysis, call-graph construction and reachability for
//! `cargo-unsafe-surface`.
//!
//! The default backend parses Rust sources with `syn`; it never executes
//! build scripts, procedural macros or binaries from the analysed
//! repository. See `docs/adr/0001-analysis-approach.md` for the rationale.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
