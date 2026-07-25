//! SARIF 2.1.0 rendering.
//!
//! Maps findings to SARIF results so they can be consumed by GitHub code
//! scanning and compatible systems. Rules are the [`UnsafeOpKind`] values;
//! result locations point at the operation's source location. Confidence
//! and reachability are carried as result properties.
//!
//! Only *reachable* findings and structural findings become results:
//! unreachable code is informational inventory, not an alert. Unresolved
//! calls are emitted as a single aggregated `unresolved-calls` result per
//! crate when present, since code scanning needs actionable locations.

use serde::Serialize;
use unsafe_surface_core::{Confidence, Reachability, ReportModel, UnsafeOpKind};

use crate::ReportError;

/// Renders the report as a SARIF 2.1.0 log (pretty-printed JSON).
///
/// # Errors
///
/// Returns [`ReportError::Json`] when serialization fails.
pub fn render_sarif(report: &ReportModel) -> Result<String, ReportError> {
    let log = build_log(report);
    Ok(serde_json::to_string_pretty(&log)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    tool: Tool,
    results: Vec<Result_>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver {
    name: String,
    version: String,
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: String,
    name: String,
    short_description: Message,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Result_ {
    rule_id: String,
    level: &'static str,
    message: Message,
    locations: Vec<Location>,
    properties: Properties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: u32,
    start_column: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Properties {
    confidence: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<Vec<String>>,
}

/// All rule kinds (stable ids in snake_case, matching the JSON schema).
const RULE_KINDS: &[UnsafeOpKind] = &[
    UnsafeOpKind::UnsafeBlock,
    UnsafeOpKind::UnsafeFn,
    UnsafeOpKind::UnsafeFnCall,
    UnsafeOpKind::UnsafeTrait,
    UnsafeOpKind::UnsafeTraitImpl,
    UnsafeOpKind::SendImpl,
    UnsafeOpKind::SyncImpl,
    UnsafeOpKind::ForeignFunction,
    UnsafeOpKind::ExternBlock,
    UnsafeOpKind::FfiCall,
    UnsafeOpKind::RawPointerDeref,
    UnsafeOpKind::Transmute,
    UnsafeOpKind::InlineAssembly,
    UnsafeOpKind::UnionFieldAccess,
    UnsafeOpKind::MutableStaticAccess,
    UnsafeOpKind::MutableStaticDefinition,
    UnsafeOpKind::MaybeUninitUse,
    UnsafeOpKind::UncheckedCall,
];

fn build_log(report: &ReportModel) -> SarifLog {
    let mut rules: Vec<Rule> = RULE_KINDS
        .iter()
        .map(|kind| Rule {
            id: rule_id(*kind),
            name: format!("{kind:?}"),
            short_description: Message {
                text: kind.label().to_owned(),
            },
        })
        .collect();
    rules.push(Rule {
        id: "unresolved-calls".to_owned(),
        name: "UnresolvedCalls".to_owned(),
        short_description: Message {
            text: "call sites that could not be resolved (analysis uncertainty)".to_owned(),
        },
    });

    let mut results = Vec::new();
    for finding in &report.findings {
        if finding.reachability != Reachability::Reachable {
            continue;
        }
        let op = &finding.operation;
        results.push(Result_ {
            rule_id: rule_id(op.kind),
            level: level(op.confidence),
            message: Message {
                text: format!(
                    "reachable {} in {} ({})",
                    op.kind.label(),
                    finding.enclosing_item,
                    finding.package
                ),
            },
            locations: vec![location(
                &op.location.file,
                op.location.line,
                op.location.column,
            )],
            properties: Properties {
                confidence: confidence(op.confidence),
                package: Some(finding.package.to_string()),
                path: finding
                    .path
                    .as_ref()
                    .map(|steps| steps.iter().map(|s| s.item.to_string()).collect()),
            },
        });
    }
    for finding in &report.structural_findings {
        results.push(Result_ {
            rule_id: rule_id(finding.kind),
            level: "warning",
            message: Message {
                text: format!("{} ({})", finding.detail, finding.package),
            },
            locations: vec![location(
                &finding.location.file,
                finding.location.line,
                finding.location.column,
            )],
            properties: Properties {
                confidence: "confirmed",
                package: Some(finding.package.to_string()),
                path: None,
            },
        });
    }
    if report.unresolved_calls_total > 0 {
        // Aggregate uncertainty as one result at the first unresolved site.
        let first = &report.unresolved_calls[0];
        results.push(Result_ {
            rule_id: "unresolved-calls".to_owned(),
            level: "note",
            message: Message {
                text: format!(
                    "{} call site(s) could not be resolved; they are not treated as safe",
                    report.unresolved_calls_total
                ),
            },
            locations: vec![location(
                &first.location.file,
                first.location.line,
                first.location.column,
            )],
            properties: Properties {
                confidence: "inferred",
                package: None,
                path: None,
            },
        });
    }

    SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: report.tool.name.clone(),
                    version: report.tool.version.clone(),
                    information_uri: "https://github.com/Juanbanpar/cargo-unsafe-surface",
                    rules,
                },
            },
            results,
        }],
    }
}

fn rule_id(kind: UnsafeOpKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{kind:?}"))
}

fn level(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Confirmed => "warning",
        Confidence::Inferred => "note",
    }
}

fn confidence(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Confirmed => "confirmed",
        Confidence::Inferred => "inferred",
    }
}

fn location(file: &str, line: u32, column: u32) -> Location {
    Location {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation {
                uri: file.replace('\\', "/"),
            },
            region: Region {
                start_line: line,
                start_column: column,
            },
        },
    }
}
