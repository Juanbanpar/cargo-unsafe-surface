//! Core analysis model for `cargo-unsafe-surface`.
//!
//! This crate defines the stable, serializable intermediate representation
//! shared by the analysis and reporting layers. It intentionally contains no
//! analysis logic: every important concept (crates, items, call sites, unsafe
//! boundaries, confidence, diagnostics) is an explicit type.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod model;

pub use model::*;
