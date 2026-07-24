//! The serializable analysis report model.
//!
//! [`ReportModel`] is the single exchange format between the analysis layer
//! and the reporting layer. It is also the public JSON schema; see
//! `docs/json-schema.md`. The schema is versioned via [`SCHEMA_VERSION`]
//! and evolves backwards-compatibly within a schema version.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::calls::{PathStep, UnresolvedCall};
use crate::ids::{ItemPath, PackageId, Severity, SourceLocation, ToolInfo};
use crate::ops::{SafetyJustification, UnsafeOpKind, UnsafeOperation};

/// Current JSON schema version of [`ReportModel`].
pub const SCHEMA_VERSION: u32 = 1;

/// An analysis diagnostic: something the user should know about the
/// completeness of the results. Diagnostics are never silently dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// How severe the issue is for result completeness.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
    /// Related source location, when applicable.
    pub location: Option<SourceLocation>,
}

impl Diagnostic {
    /// Creates an info diagnostic.
    #[must_use]
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            message: message.into(),
            location: None,
        }
    }

    /// Creates a warning diagnostic.
    #[must_use]
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            location: None,
        }
    }

    /// Creates an error diagnostic.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            location: None,
        }
    }

    /// Attaches a location.
    #[must_use]
    pub fn at(mut self, location: SourceLocation) -> Self {
        self.location = Some(location);
        self
    }
}

/// How an unsafe operation relates to the selected entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// At least one call path from an entry point reaches the enclosing
    /// function.
    Reachable,
    /// The operation exists in the analysed sources but no analysed entry
    /// point reaches it.
    Unreachable,
    /// A module-level construct (impl block, static, extern block, …) for
    /// which function-level reachability does not apply.
    Structural,
}

/// An unsafe operation tied to its enclosing function and, when reachable,
/// to one shortest call path from an entry point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable index of the finding within the report (0-based, ordered).
    pub id: u64,
    /// The unsafe operation.
    pub operation: UnsafeOperation,
    /// The function whose body contains the operation.
    pub enclosing_item: ItemPath,
    /// The package that contributes the code.
    pub package: PackageId,
    /// Reachability from the selected entry points.
    pub reachability: Reachability,
    /// One shortest call path from an entry point to the enclosing
    /// function. `None` for unreachable findings.
    pub path: Option<Vec<PathStep>>,
}

/// A module-level unsafe construct: `unsafe impl`, `unsafe trait`,
/// `static mut`, extern blocks and foreign function declarations.
///
/// These are reported independently of call-graph reachability; they are
/// part of the unsafe *surface* of a crate by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralFinding {
    /// The class of construct.
    pub kind: UnsafeOpKind,
    /// The package that contributes the code.
    pub package: PackageId,
    /// Where the construct is defined.
    pub location: SourceLocation,
    /// Human-readable detail (e.g. `unsafe impl Send for MyType`).
    pub detail: String,
    /// Whether a safety justification comment was found.
    pub justification: SafetyJustification,
}

/// How an entry point was selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EntryPointKind {
    /// `main` of a binary target selected with `--bin` (or by default).
    BinaryMain {
        /// Name of the binary target.
        target: String,
    },
    /// Public API of a library target selected with `--lib`.
    LibraryApi {
        /// Name of the library target.
        target: String,
    },
    /// An explicit path given with `--entry`.
    Explicit,
}

/// A resolved analysis entry point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPoint {
    /// The function acting as entry point.
    pub item: ItemPath,
    /// How it was selected.
    pub kind: EntryPointKind,
}

/// A package whose sources were analysed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    /// Package identity.
    pub id: PackageId,
    /// Directory containing the package manifest, for display.
    pub root: String,
    /// Whether the package's sources could be read.
    pub sources_available: bool,
}

/// The analysis configuration embedded in every report for
/// reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AnalysisConfiguration {
    /// Selected package names (empty means workspace default members).
    pub packages: Vec<String>,
    /// Whether dependency sources were analysed.
    pub include_dependencies: bool,
    /// Whether dev-dependencies were included.
    pub include_dev_dependencies: bool,
    /// Explicit `--entry` paths as given on the command line.
    pub explicit_entries: Vec<String>,
    /// Enabled Cargo features, if specified.
    pub features: Vec<String>,
    /// Whether `--all-features` was used.
    pub all_features: bool,
    /// Whether `--no-default-features` was used.
    pub no_default_features: bool,
    /// Compilation target triple used for `cfg` evaluation, if overridden.
    pub target: Option<String>,
}

/// Aggregate counts for the report header.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SummaryCounts {
    /// Reachable unsafe operations of all kinds (excluding structural
    /// findings).
    pub reachable_unsafe_operations: u64,
    /// Reachable `unsafe fn` definitions.
    pub reachable_unsafe_functions: u64,
    /// Reachable calls to foreign functions.
    pub reachable_ffi_calls: u64,
    /// Manual `Send`/`Sync` implementations (structural).
    pub manual_send_sync_impls: u64,
    /// Reachable inline assembly sites.
    pub inline_assembly_sites: u64,
    /// Reachable transmutes.
    pub transmutes: u64,
    /// Reachable raw pointer dereferences.
    pub raw_pointer_dereferences: u64,
    /// Unsafe operations present but not reachable from the entry points.
    pub unreachable_unsafe_operations: u64,
    /// Total unresolved call sites.
    pub unresolved_calls: u64,
    /// Reachable operation counts per kind.
    pub reachable_by_kind: BTreeMap<UnsafeOpKind, u64>,
}

/// The complete, versioned analysis report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportModel {
    /// JSON schema version (`1`).
    pub schema_version: u32,
    /// Tool that produced the report.
    pub tool: ToolInfo,
    /// Analysis configuration.
    pub configuration: AnalysisConfiguration,
    /// Analysed packages, sorted by name.
    pub packages: Vec<PackageInfo>,
    /// Resolved entry points, sorted by path.
    pub entry_points: Vec<EntryPoint>,
    /// Aggregate counts.
    pub summary: SummaryCounts,
    /// All findings, reachable and unreachable, deterministically ordered.
    pub findings: Vec<Finding>,
    /// Module-level unsafe constructs, deterministically ordered.
    pub structural_findings: Vec<StructuralFinding>,
    /// Unresolved call sites, deterministically ordered and capped; see
    /// [`ReportModel::unresolved_calls_total`].
    pub unresolved_calls: Vec<UnresolvedCall>,
    /// Total number of unresolved calls before capping.
    pub unresolved_calls_total: u64,
    /// Analysis diagnostics (parse errors, missing sources, …).
    pub diagnostics: Vec<Diagnostic>,
    /// Statements about the limits of the analysis that apply to this
    /// report.
    pub limitations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{Confidence, DependencyOrigin};

    fn sample_report() -> ReportModel {
        ReportModel {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo {
                name: "cargo-unsafe-surface".into(),
                version: "0.1.0".into(),
            },
            configuration: AnalysisConfiguration::default(),
            packages: vec![PackageInfo {
                id: PackageId::new("demo", Some("0.1.0".into()), DependencyOrigin::Workspace),
                root: "/demo".into(),
                sources_available: true,
            }],
            entry_points: vec![],
            summary: SummaryCounts::default(),
            findings: vec![Finding {
                id: 0,
                operation: UnsafeOperation::new(
                    UnsafeOpKind::FfiCall,
                    SourceLocation::new("src/lib.rs", 10, 9),
                )
                .with_confidence(Confidence::Confirmed),
                enclosing_item: ItemPath::parse("demo::sys::connect").unwrap(),
                package: PackageId::new("demo", Some("0.1.0".into()), DependencyOrigin::Workspace),
                reachability: Reachability::Reachable,
                path: Some(vec![]),
            }],
            structural_findings: vec![],
            unresolved_calls: vec![],
            unresolved_calls_total: 0,
            diagnostics: vec![Diagnostic::warning("example")],
            limitations: vec!["approximate call graph".into()],
        }
    }

    #[test]
    fn report_roundtrips_through_json() {
        let report = sample_report();
        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: ReportModel = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
    }

    #[test]
    fn schema_version_is_serialized() {
        let value = serde_json::to_value(sample_report()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["tool"]["name"], "cargo-unsafe-surface");
        assert_eq!(value["findings"][0]["operation"]["kind"], "ffi_call");
        assert_eq!(value["findings"][0]["reachability"], "reachable");
    }

    #[test]
    fn diagnostics_builders() {
        assert_eq!(Diagnostic::info("a").severity, Severity::Info);
        assert_eq!(Diagnostic::warning("a").severity, Severity::Warning);
        assert_eq!(Diagnostic::error("a").severity, Severity::Error);
        let at = Diagnostic::warning("a").at(SourceLocation::new("f.rs", 1, 1));
        assert_eq!(at.location.unwrap().file, "f.rs");
    }
}
