//! Structured errors for the discovery layer.

use std::path::PathBuf;

/// Errors produced while discovering the workspace.
#[derive(Debug, thiserror::Error)]
pub enum CargoError {
    /// `cargo metadata` failed to run or returned malformed data.
    #[error("cargo metadata failed: {0}")]
    Metadata(#[from] cargo_metadata::Error),

    /// `rustc --print cfg` failed.
    #[error("querying rustc configuration failed: {0}")]
    RustcCfg(String),

    /// The user selected a package that is not a workspace member.
    #[error("package `{0}` is not a member of the workspace")]
    UnknownPackage(String),

    /// The user selected a target that does not exist.
    #[error("target `{name}` of kind {kind} was not found in the selected packages")]
    TargetNotFound {
        /// Requested target name.
        name: String,
        /// Requested target kind (`lib` or `bin`).
        kind: &'static str,
    },

    /// No packages ended up selected.
    #[error("no packages selected for analysis")]
    NoPackages,

    /// A required path was not valid UTF-8 or did not exist.
    #[error("invalid path {0:?}: {1}")]
    InvalidPath(PathBuf, &'static str),
}
