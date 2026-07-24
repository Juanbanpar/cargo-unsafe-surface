//! Structured errors for the analysis layer.
//!
//! Per-file problems (unreadable files, syntax errors, limit breaches) are
//! **not** errors: they become [`unsafe_surface_core::Diagnostic`]s so that
//! one bad file never aborts the analysis of an entire workspace. Errors in
//! this type are reserved for failures that make analysis of a whole crate
//! impossible.

use std::path::PathBuf;

/// Errors produced while analysing a crate.
#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    /// The crate root file could not be read at all.
    #[error("cannot read crate root {path:?}: {message}")]
    CrateRootUnreadable {
        /// The crate root path.
        path: PathBuf,
        /// Underlying I/O message.
        message: String,
    },
}
