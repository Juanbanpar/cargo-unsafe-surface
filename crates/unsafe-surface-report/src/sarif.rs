//! SARIF 2.1.0 rendering.
//!
//! Maps the report model onto SARIF results for GitHub code scanning and
//! compatible systems. Rules are the [`UnsafeOpKind`] values and result
//! locations point at the operation's source location; columns are
//! Unicode code points, declared via `run.columnKind`.
//!
//! Every finding becomes a result: reachable ones at their confidence
//! level, unreachable ones as `note`-level results (inventory, not
//! alerts). Structural findings and diagnostics are included as well,
//! and unresolved calls are emitted as a single aggregated
//! `unresolved-calls` result when present, since code scanning needs
//! actionable locations.

use serde::Serialize;
use unsafe_surface_core::{Confidence, Reachability, ReportModel, Severity, UnsafeOpKind};

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
    column_kind: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    invocations: Vec<Invocation>,
    results: Vec<Result_>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<RunProperties>,
}

/// One tool invocation, carrying the analysis diagnostics.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    execution_successful: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_execution_notifications: Vec<Notification>,
}

/// A diagnostic reported during the invocation.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Notification {
    level: &'static str,
    message: Message,
}

/// Run-level property bag for values SARIF has no dedicated slot for.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunProperties {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    analysis_limitations: Vec<String>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    justification: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finding_id: Option<u64>,
}

/// All rule kinds (stable ids in snake_case, matching the JSON schema).
const UNRESOLVED_RULE_ID: &str = "unresolved-calls";

fn build_log(report: &ReportModel) -> SarifLog {
    let mut rules: Vec<Rule> = UnsafeOpKind::ALL
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
        id: UNRESOLVED_RULE_ID.to_owned(),
        name: "UnresolvedCalls".to_owned(),
        short_description: Message {
            text: "call sites that could not be resolved (analysis uncertainty)".to_owned(),
        },
    });

    let mut results = Vec::new();
    for finding in &report.findings {
        let op = &finding.operation;
        let reachable = finding.reachability == Reachability::Reachable;
        let mut text = format!(
            "{} {} in {} ({})",
            if reachable {
                "reachable"
            } else {
                "unreachable"
            },
            op.kind.label(),
            finding.enclosing_item,
            finding.package
        );
        if let Some(detail) = &op.detail {
            let label = match op.kind {
                UnsafeOpKind::FfiCall | UnsafeOpKind::UnsafeFnCall => "target",
                _ => "detail",
            };
            text.push_str(&format!(", {label}: {detail}"));
        }
        text.push_str(&format!(" — justification: {}", op.justification.label()));
        if !reachable {
            text.push_str(" — present but not reachable from the entry points");
        }
        results.push(Result_ {
            rule_id: rule_id(op.kind),
            level: if reachable {
                level(op.confidence)
            } else {
                // Unreachable code is inventory, not an alert.
                "note"
            },
            message: Message { text },
            locations: vec![location(
                &op.location.file,
                op.location.line,
                op.location.column,
            )],
            properties: Properties {
                confidence: op.confidence.label(),
                justification: Some(op.justification.label()),
                package: Some(finding.package.to_string()),
                path: finding
                    .path
                    .as_ref()
                    .map(|steps| steps.iter().map(|s| s.item.to_string()).collect()),
                finding_id: Some(finding.id),
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
                justification: Some(finding.justification.label()),
                package: Some(finding.package.to_string()),
                path: None,
                finding_id: None,
            },
        });
    }
    if report.unresolved_calls_total > 0 {
        // Aggregate uncertainty as one result at the first unresolved site.
        // The listed sites are capped independently of the total, so the
        // list can be empty (see `ReportModel::unresolved_calls`); the
        // aggregate result is then reported without a location.
        let locations = report
            .unresolved_calls
            .first()
            .map(|first| {
                vec![location(
                    &first.location.file,
                    first.location.line,
                    first.location.column,
                )]
            })
            .unwrap_or_default();
        results.push(Result_ {
            rule_id: UNRESOLVED_RULE_ID.to_owned(),
            level: "note",
            message: Message {
                text: format!(
                    "{} call site(s) could not be resolved; they are not treated as safe",
                    report.unresolved_calls_total
                ),
            },
            locations,
            properties: Properties {
                confidence: "inferred",
                justification: None,
                package: None,
                path: None,
                finding_id: None,
            },
        });
    }

    let invocations = if report.diagnostics.is_empty() {
        Vec::new()
    } else {
        vec![Invocation {
            execution_successful: true,
            tool_execution_notifications: report
                .diagnostics
                .iter()
                .map(|diagnostic| Notification {
                    level: match diagnostic.severity {
                        Severity::Info => "note",
                        Severity::Warning => "warning",
                        Severity::Error => "error",
                    },
                    message: Message {
                        text: diagnostic.message.clone(),
                    },
                })
                .collect(),
        }]
    };

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
            column_kind: "unicodeCodePoints",
            invocations,
            results,
            properties: (!report.limitations.is_empty()).then(|| RunProperties {
                analysis_limitations: report.limitations.clone(),
            }),
        }],
    }
}

fn rule_id(kind: UnsafeOpKind) -> String {
    kind.as_str().to_owned()
}

fn level(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Confirmed => "warning",
        Confidence::Inferred => "note",
    }
}

fn location(file: &str, line: u32, column: u32) -> Location {
    Location {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation {
                uri: artifact_uri(file),
            },
            region: Region {
                start_line: line,
                start_column: column,
            },
        },
    }
}

/// Percent-encodes a path into a valid SARIF `artifactLocation.uri`
/// (RFC 3986): separators are normalized to `/`, characters outside the
/// unreserved set are encoded, and absolute paths get a `file:` scheme so
/// a Windows drive letter or UNC host cannot be read as a URI scheme.
fn artifact_uri(file: &str) -> String {
    let path = file.replace('\\', "/");
    let mut uri = String::new();
    let rest = if let Some(rest) = path.strip_prefix("//") {
        // UNC path: `//server/share/…` → `file://server/share/…`.
        uri.push_str("file://");
        rest
    } else if let Some(rest) = path.strip_prefix('/') {
        // Absolute POSIX path: `/home/…` → `file:///home/…`.
        uri.push_str("file:///");
        rest
    } else if path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && path.as_bytes().get(1) == Some(&b':')
    {
        // Windows drive letter: `C:/…` → `file:///C:/…`, keeping the
        // drive literal so `C:` cannot read as a URI scheme.
        uri.push_str("file:///");
        uri.push_str(&path[..2]);
        &path[2..]
    } else {
        path.as_str()
    };
    for (index, segment) in rest.split('/').enumerate() {
        if index > 0 {
            uri.push('/');
        }
        for byte in segment.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                uri.push(byte as char);
            } else {
                uri.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    uri
}
