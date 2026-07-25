//! Tests for the text and JSON renderers.
//!
//! Snapshots guard the overall layout; important fields are *also*
//! asserted structurally so semantic regressions cannot hide in a blessed
//! snapshot.

use unsafe_surface_core::*;
use unsafe_surface_report::{render, OutputFormat};

fn sample_report() -> ReportModel {
    let package = |name: &str, version: &str| {
        PackageId::new(name, Some(version.to_owned()), DependencyOrigin::Workspace)
    };
    ReportModel {
        schema_version: SCHEMA_VERSION,
        tool: ToolInfo {
            name: "cargo-unsafe-surface".into(),
            version: "0.1.0".into(),
        },
        configuration: AnalysisConfiguration {
            include_dependencies: true,
            ..AnalysisConfiguration::default()
        },
        packages: vec![
            PackageInfo {
                id: package("server", "0.1.0"),
                root: "server".into(),
                sources_available: true,
            },
            PackageInfo {
                id: package("ffiwrap", "0.3.0"),
                root: "ffiwrap".into(),
                sources_available: true,
            },
        ],
        entry_points: vec![EntryPoint {
            item: ItemPath::parse("server::main").unwrap(),
            kind: EntryPointKind::BinaryMain {
                target: "server".into(),
            },
        }],
        summary: SummaryCounts {
            reachable_unsafe_operations: 2,
            reachable_unsafe_functions: 0,
            reachable_ffi_calls: 1,
            manual_send_sync_impls: 1,
            inline_assembly_sites: 0,
            transmutes: 0,
            raw_pointer_dereferences: 0,
            unreachable_unsafe_operations: 1,
            unresolved_calls: 1,
            reachable_by_kind: [(UnsafeOpKind::FfiCall, 1), (UnsafeOpKind::UnsafeBlock, 1)]
                .into_iter()
                .collect(),
        },
        findings: vec![
            Finding {
                id: 0,
                operation: UnsafeOperation::new(
                    UnsafeOpKind::UnsafeBlock,
                    SourceLocation::new("server/src/main.rs", 4, 5),
                )
                .with_justification(SafetyJustification::Absent),
                enclosing_item: ItemPath::parse("server::main").unwrap(),
                package: package("server", "0.1.0"),
                reachability: Reachability::Reachable,
                path: Some(vec![PathStep {
                    item: ItemPath::parse("server::main").unwrap(),
                    call_site: None,
                    edge_confidence: None,
                }]),
            },
            Finding {
                id: 1,
                operation: UnsafeOperation::new(
                    UnsafeOpKind::FfiCall,
                    SourceLocation::new("ffiwrap/src/lib.rs", 10, 18),
                )
                .with_justification(SafetyJustification::Present)
                .with_detail("ffiwrap::socket"),
                enclosing_item: ItemPath::parse("ffiwrap::create_socket").unwrap(),
                package: package("ffiwrap", "0.3.0"),
                reachability: Reachability::Reachable,
                path: Some(vec![
                    PathStep {
                        item: ItemPath::parse("server::main").unwrap(),
                        call_site: Some(SourceLocation::new("server/src/main.rs", 3, 5)),
                        edge_confidence: Some(Confidence::Confirmed),
                    },
                    PathStep {
                        item: ItemPath::parse("ffiwrap::create_socket").unwrap(),
                        call_site: None,
                        edge_confidence: None,
                    },
                ]),
            },
            Finding {
                id: 2,
                operation: UnsafeOperation::new(
                    UnsafeOpKind::FfiCall,
                    SourceLocation::new("ffiwrap/src/lib.rs", 14, 18),
                )
                .with_detail("ffiwrap::socket"),
                enclosing_item: ItemPath::parse("ffiwrap::never_called").unwrap(),
                package: package("ffiwrap", "0.3.0"),
                reachability: Reachability::Unreachable,
                path: None,
            },
        ],
        structural_findings: vec![StructuralFinding {
            kind: UnsafeOpKind::SendImpl,
            package: package("netlib", "0.2.0"),
            location: SourceLocation::new("netlib/src/lib.rs", 3, 1),
            detail: "unsafe impl Send for Handle".into(),
            justification: SafetyJustification::Present,
        }],
        unresolved_calls: vec![UnresolvedCall {
            caller: ItemPath::parse("server::ghost_call").unwrap(),
            callee_text: "does_not_exist".into(),
            location: SourceLocation::new("server/src/main.rs", 7, 5),
            reason: UnresolvedReason::UnknownName,
        }],
        unresolved_calls_total: 1,
        diagnostics: vec![Diagnostic::warning("something is incomplete")],
        limitations: vec!["approximate call graph".into()],
    }
}

#[test]
fn text_report_matches_snapshot() {
    let text = render(&sample_report(), OutputFormat::Text).unwrap();
    insta::assert_snapshot!(text);
}

#[test]
fn text_report_contains_key_fields_structurally() {
    let text = render(&sample_report(), OutputFormat::Text).unwrap();
    // Header and summary.
    assert!(text.contains("Unsafe Surface Report"));
    assert!(text.contains("  server::main"));
    assert!(text.contains("Reachable FFI calls:         1"));
    // The FFI finding with its reconstructed path.
    assert!(text.contains("Kind:          FFI call"));
    assert!(text.contains("ffiwrap 0.3.0 (workspace)"));
    assert!(text.contains("-> ffiwrap::create_socket"));
    assert!(text.contains("-> ffiwrap::socket"));
    // Unreachable section distinguishes the dead call.
    assert!(text.contains("ffiwrap::never_called — FFI call"));
    // Structural + unresolved sections.
    assert!(text.contains("[manual Send implementation] netlib 0.2.0"));
    assert!(text.contains("server::ghost_call -> does_not_exist"));
    assert!(text.contains("unknown name"));
    // Diagnostics and limitations.
    assert!(text.contains("[warning] something is incomplete"));
    assert!(text.contains("- approximate call graph"));
}

#[test]
fn json_report_roundtrips() {
    let report = sample_report();
    let json = render(&report, OutputFormat::Json).unwrap();
    let parsed: ReportModel = serde_json::from_str(&json).unwrap();
    assert_eq!(report, parsed);

    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["summary"]["reachable_ffi_calls"], 1);
    assert_eq!(value["findings"][1]["operation"]["kind"], "ffi_call");
    assert_eq!(value["findings"][1]["path"][0]["item"]["krate"], "server");
}

#[test]
fn text_output_is_deterministic() {
    let a = render(&sample_report(), OutputFormat::Text).unwrap();
    let b = render(&sample_report(), OutputFormat::Text).unwrap();
    assert_eq!(a, b);
}

#[test]
fn control_characters_are_sanitized() {
    let mut report = sample_report();
    report.findings[0].operation.detail = Some("\u{1b}[31mEVIL\u{1b}[0m".into());
    let text = render(&report, OutputFormat::Text).unwrap();
    assert!(
        !text.contains('\u{1b}'),
        "escape character leaked into output"
    );
}
