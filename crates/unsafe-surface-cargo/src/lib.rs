//! Cargo workspace and target discovery for `cargo-unsafe-surface`.
//!
//! This crate is the only place that talks to Cargo. It wraps
//! `cargo metadata` — which reads manifests and the lockfile but **never
//! executes build scripts, procedural macros or any other code from the
//! analysed repository** — and turns the result into a typed discovery
//! model for the analysis layer.
//!
//! Note: `cargo metadata` may create or update `Cargo.lock` in the
//! analysed workspace as a side effect of dependency resolution. Pass
//! [`DiscoveryOptions::offline`] to avoid network access during resolution.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cfg;
mod discover;
mod error;

pub use cfg::{query_rustc_cfg, CfgValues};
pub use discover::{
    discover, DiscoveredPackage, DiscoveredWorkspace, DiscoveryOptions, SelectedTarget, TargetKind,
};
pub use error::CargoError;
