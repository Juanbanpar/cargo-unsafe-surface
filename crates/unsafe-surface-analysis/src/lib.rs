//! Source analysis, call-graph construction and reachability for
//! `cargo-unsafe-surface`.
//!
//! The default backend parses Rust sources with `syn`; it never executes
//! build scripts, procedural macros or binaries from the analysed
//! repository. See `docs/adr/0001-analysis-approach.md` for the rationale.
//!
//! # Pipeline
//!
//! 1. [`source`] walks a crate's module tree starting at the crate root,
//!    honouring `#[cfg]` gates (over-approximating unknown predicates) and
//!    enforcing [`Limits`] against denial-of-service.
//! 2. [`index`] builds per-crate symbol tables (items, impls, unions,
//!    mutable statics, imports).
//! 3. Classification, call-graph construction and reachability build on
//!    these structures.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cfg_eval;
pub mod classify;
pub mod error;
pub mod graph;
#[cfg(test)]
mod graph_tests;
pub mod index;
pub mod justify;
pub mod limits;
pub mod reach;
pub mod resolve;
pub mod source;

pub use classify::{classify_crate, CallSite, CalleeRef, CrateAnalysis, FunctionRecord};
pub use error::AnalysisError;
pub use graph::{build_call_graph, CallGraph, CrateInput, EdgeMeta, GraphNode, NodeId};
pub use limits::Limits;
pub use reach::Reachability;
