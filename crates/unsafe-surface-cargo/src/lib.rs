//! Cargo workspace and target discovery for `cargo-unsafe-surface`.
//!
//! Wraps `cargo metadata` to locate packages, targets and dependency sources
//! without executing any code from the analysed repository.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
