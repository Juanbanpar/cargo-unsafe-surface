//! Core analysis model for `cargo-unsafe-surface`.
//!
//! This crate defines the stable, serializable intermediate representation
//! shared by the analysis and reporting layers. It intentionally contains no
//! analysis logic: every important concept (packages, items, call sites,
//! unsafe boundaries, confidence, diagnostics) is an explicit type instead
//! of a loosely structured string.
//!
//! The types here are backend-agnostic: the default `syn`-based source
//! backend and any future compiler-based backend both produce this model.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod calls;
mod ids;
mod ops;
mod report;

pub use calls::{EdgeKind, FunctionKind, PathStep, UnresolvedCall, UnresolvedReason};
pub use ids::{
    Confidence, DependencyOrigin, ItemPath, PackageId, Severity, SourceLocation, ToolInfo,
};
pub use ops::{SafetyJustification, UnsafeOpKind, UnsafeOperation};
pub use report::{
    AnalysisConfiguration, Diagnostic, EntryPoint, EntryPointKind, Finding, PackageInfo,
    Reachability, ReportModel, StructuralFinding, SummaryCounts, SCHEMA_VERSION,
};
