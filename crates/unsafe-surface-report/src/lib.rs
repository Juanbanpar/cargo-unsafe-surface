//! Text, JSON and SARIF reporting for `cargo-unsafe-surface`.
//!
//! This crate is a pure formatting layer: it consumes the serializable
//! report model produced by the analysis layer and never inspects source
//! code or the call graph directly.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
