//! Analysis orchestration.
//!
//! The engine drives the whole pipeline — parse, index, classify, link
//! the call graph, resolve entry points, compute reachability — and
//! assembles the serializable [`ReportModel`] consumed by the reporting
//! layer. It is deliberately free of CLI concerns so it can be driven
//! from tests and future frontends.

use unsafe_surface_cargo::{CfgValues, DiscoveredWorkspace, SelectedTarget, TargetKind};
use unsafe_surface_core::{
    AnalysisConfiguration, Diagnostic, EntryPoint, EntryPointKind, Finding, ItemPath, PackageId,
    PackageInfo, Reachability as FindingReachability, ReportModel, StructuralFinding,
    SummaryCounts, ToolInfo, UnresolvedCall, UnresolvedReason, SCHEMA_VERSION,
};

use crate::cfg_eval::CfgEvaluator;
use crate::classify::{classify_crate, CrateAnalysis};
use crate::error::AnalysisError;
use crate::graph::{build_call_graph, CallGraph, CrateInput, NodeId};
use crate::index::{build_index, CrateIndex};
use crate::limits::{FileBudget, Limits};
use crate::reach::Reachability;
use crate::source::{parse_crate, ParseContext, ParsedCrate};

/// Configuration of one analysis run.
#[derive(Debug, Clone, Default)]
pub struct AnalysisConfig {
    /// Selected package names (empty = workspace default members).
    pub packages: Vec<String>,
    /// Whether dependency sources are analysed.
    pub include_dependencies: bool,
    /// Whether dev-dependencies were included in the universe.
    pub include_dev_dependencies: bool,
    /// Explicit `--entry` paths.
    pub explicit_entries: Vec<String>,
    /// Cargo feature selection (for report reproducibility).
    pub features: Vec<String>,
    /// `--all-features`.
    pub all_features: bool,
    /// `--no-default-features`.
    pub no_default_features: bool,
    /// Compilation target triple override.
    pub target: Option<String>,
    /// Resource limits.
    pub limits: Limits,
}

/// The result of one analysis run: the report plus the internal state
/// needed by tests and future frontends.
#[derive(Debug)]
pub struct AnalysisOutcome {
    /// The serializable report.
    pub report: ReportModel,
    /// The constructed call graph.
    pub graph: CallGraph,
    /// The computed reachability.
    pub reachability: Reachability,
}

/// One parsed and classified crate instance.
struct CrateBundle {
    package: PackageId,
    is_lib: bool,
    /// Binary target name when the instance is a binary.
    bin_name: Option<String>,
    parsed: ParsedCrate,
    index: CrateIndex,
    analysis: CrateAnalysis,
}

/// Runs the full analysis.
///
/// # Errors
///
/// Returns [`AnalysisError`] only when a *selected* crate root cannot be
/// read; every other problem degrades to a diagnostic in the report.
pub fn analyze(
    workspace: &DiscoveredWorkspace,
    targets: &[SelectedTarget],
    cfg_values: &CfgValues,
    config: &AnalysisConfig,
) -> Result<AnalysisOutcome, AnalysisError> {
    let mut diagnostics: Vec<Diagnostic> = workspace
        .warnings
        .iter()
        .map(|w| Diagnostic::info(w.clone()))
        .collect();

    // 1. Parse and classify every crate instance. One file budget spans
    //    the whole run (see `Limits::max_total_files`).
    let files = FileBudget::new();
    let mut bundles: Vec<CrateBundle> = Vec::new();
    for package in &workspace.packages {
        let selected = workspace.selected.contains(&package.id);
        if !selected && !config.include_dependencies {
            continue;
        }
        if !package.sources_available {
            diagnostics.push(Diagnostic::warning(format!(
                "sources of package {} are not available locally; calls into it are \
                 reported as unresolved",
                package.id
            )));
            continue;
        }

        // Instances: the library (also needed by the package's own bins
        // for cross-resolution) plus, for selected packages, each
        // selected binary target. Dependency binaries are never analysed:
        // they cannot be linked against.
        let mut roots: Vec<(std::path::PathBuf, bool, Option<String>)> = Vec::new();
        if let Some(lib_root) = &package.lib_root {
            roots.push((lib_root.clone().into(), true, None));
        }
        if selected {
            for target in targets {
                if target.package == package.id && target.kind == TargetKind::Bin {
                    roots.push((target.root.clone().into(), false, Some(target.name.clone())));
                }
            }
        }

        for (root, is_lib, bin_name) in roots {
            let evaluator = CfgEvaluator::new(cfg_values, &package.enabled_features);
            let context = ParseContext {
                cfg: evaluator,
                limits: &config.limits,
                display_root: Some(workspace.workspace_root.as_std_path()),
                files: &files,
            };
            match parse_crate(&root, &context) {
                Ok(parsed) => {
                    if parsed.unknown_cfg_items > 0 {
                        diagnostics.push(Diagnostic::info(format!(
                            "{}: {} items kept with unknown #[cfg] predicates \
                             (over-approximation)",
                            package.id, parsed.unknown_cfg_items
                        )));
                    }
                    diagnostics.extend(parsed.diagnostics.iter().map(|d| Diagnostic {
                        severity: d.severity,
                        message: format!("{}: {}", package.id, d.message),
                        location: d.location.clone(),
                    }));
                    let index = build_index(&parsed);
                    let analysis = classify_crate(&parsed, &index, &package.id);
                    bundles.push(CrateBundle {
                        package: package.id.clone(),
                        is_lib,
                        bin_name,
                        parsed,
                        index,
                        analysis,
                    });
                }
                Err(error) if selected => return Err(error),
                Err(error) => {
                    diagnostics.push(Diagnostic::error(format!(
                        "dependency {} could not be parsed: {error}",
                        package.id
                    )));
                }
            }
        }
    }

    // 2. Build the call graph (libraries first so path lookup prefers
    // them, matching extern-crate semantics).
    bundles.sort_by_key(|b| !b.is_lib);
    let inputs: Vec<CrateInput<'_>> = bundles
        .iter()
        .map(|bundle| CrateInput {
            package: &bundle.package,
            is_lib: bundle.is_lib,
            parsed: &bundle.parsed,
            index: &bundle.index,
            analysis: &bundle.analysis,
        })
        .collect();
    let analysed_names: std::collections::BTreeSet<String> =
        bundles.iter().map(|b| b.package.crate_name()).collect();
    let unavailable: std::collections::BTreeSet<String> = workspace
        .all_dependency_crate_names
        .difference(&analysed_names)
        .cloned()
        .collect();
    let graph = build_call_graph(&inputs, &config.limits, unavailable);
    diagnostics.extend(graph.diagnostics.iter().cloned());

    // 3. Resolve entry points.
    let (entry_points, entry_nodes, entry_diagnostics) =
        resolve_entries(&graph, &bundles, targets, config);
    diagnostics.extend(entry_diagnostics);

    // 4. Reachability.
    let reachability = Reachability::compute(&graph, &entry_nodes);

    // 5. Assemble the report.
    let report = assemble_report(
        workspace,
        config,
        &bundles,
        &graph,
        &reachability,
        entry_points,
        diagnostics,
    );

    Ok(AnalysisOutcome {
        report,
        graph,
        reachability,
    })
}

/// Resolves selected targets and explicit entries to graph nodes.
fn resolve_entries(
    graph: &CallGraph,
    bundles: &[CrateBundle],
    targets: &[SelectedTarget],
    config: &AnalysisConfig,
) -> (Vec<EntryPoint>, Vec<NodeId>, Vec<Diagnostic>) {
    let mut entry_points = Vec::new();
    let mut nodes = Vec::new();
    let mut diagnostics = Vec::new();

    for target in targets {
        // Find the instance for this target: the bin instance for
        // binaries, the lib instance for libraries.
        let instance = bundles.iter().position(|b| match target.kind {
            TargetKind::Bin => {
                b.package == target.package && b.bin_name.as_deref() == Some(target.name.as_str())
            }
            TargetKind::Lib => b.package == target.package && b.is_lib,
        });
        let Some(instance) = instance else {
            diagnostics.push(Diagnostic::warning(format!(
                "target {} of package {} was not analysed",
                target.name, target.package
            )));
            continue;
        };
        match target.kind {
            TargetKind::Bin => {
                let main = vec!["main".to_owned()];
                match graph.node_in(instance, &main) {
                    Some(id) => {
                        entry_points.push(EntryPoint {
                            item: graph.nodes[id as usize].path.clone(),
                            kind: EntryPointKind::BinaryMain {
                                target: target.name.clone(),
                            },
                        });
                        nodes.push(id);
                    }
                    None => diagnostics.push(Diagnostic::warning(format!(
                        "binary target {} has no `main` function in the analysis",
                        target.name
                    ))),
                }
            }
            TargetKind::Lib => {
                // Approximation: every `pub` function of the library is an
                // entry point (documented in the limitations).
                let mut count = 0;
                for (id, node) in graph.nodes.iter().enumerate() {
                    if node.instance == instance && node.is_pub {
                        entry_points.push(EntryPoint {
                            item: node.path.clone(),
                            kind: EntryPointKind::LibraryApi {
                                target: target.name.clone(),
                            },
                        });
                        nodes.push(id as NodeId);
                        count += 1;
                    }
                }
                if count == 0 {
                    diagnostics.push(Diagnostic::warning(format!(
                        "library target {} exposes no public functions in the analysis",
                        target.name
                    )));
                }
            }
        }
    }

    for raw in &config.explicit_entries {
        let ids = match ItemPath::parse(raw) {
            // `crate::…` names no crate of its own: match the item path
            // against every analysed crate instance (see
            // docs/analysis-model.md, "Entry-point selection").
            Ok(path) if path.krate == "crate" => graph.nodes_matching(&path.segments),
            Ok(path) => graph.node(&path).into_iter().collect(),
            Err(error) => {
                diagnostics.push(Diagnostic::error(format!(
                    "invalid entry point `{raw}`: {error}"
                )));
                continue;
            }
        };
        if ids.is_empty() {
            diagnostics.push(Diagnostic::warning(format!(
                "entry point `{raw}` was not found in the analysed sources"
            )));
            continue;
        }
        for id in ids {
            entry_points.push(EntryPoint {
                item: graph.nodes[id as usize].path.clone(),
                kind: EntryPointKind::Explicit,
            });
            nodes.push(id);
        }
    }

    entry_points.sort_by(|a, b| a.item.cmp(&b.item));
    entry_points.dedup_by(|a, b| a.item == b.item);
    nodes.sort_unstable();
    nodes.dedup();
    (entry_points, nodes, diagnostics)
}

/// Builds the final report model.
#[allow(clippy::too_many_arguments)]
fn assemble_report(
    workspace: &DiscoveredWorkspace,
    config: &AnalysisConfig,
    bundles: &[CrateBundle],
    graph: &CallGraph,
    reachability: &Reachability,
    entry_points: Vec<EntryPoint>,
    mut diagnostics: Vec<Diagnostic>,
) -> ReportModel {
    let (findings, mut summary, mut finding_diagnostics) =
        collect_findings(graph, reachability, &config.limits);
    diagnostics.append(&mut finding_diagnostics);

    let structural_findings = collect_structural(bundles);
    summary.manual_send_sync_impls = structural_findings
        .iter()
        .filter(|s| {
            matches!(
                s.kind,
                unsafe_surface_core::UnsafeOpKind::SendImpl
                    | unsafe_surface_core::UnsafeOpKind::SyncImpl
            )
        })
        .count() as u64;

    let (unresolved_calls, unresolved_total, std_calls) =
        collect_unresolved(graph, &config.limits, &mut diagnostics);
    summary.unresolved_calls = unresolved_total;

    ReportModel {
        schema_version: SCHEMA_VERSION,
        tool: ToolInfo {
            name: "cargo-unsafe-surface".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        configuration: AnalysisConfiguration {
            packages: config.packages.clone(),
            include_dependencies: config.include_dependencies,
            include_dev_dependencies: config.include_dev_dependencies,
            explicit_entries: config.explicit_entries.clone(),
            features: config.features.clone(),
            all_features: config.all_features,
            no_default_features: config.no_default_features,
            target: config.target.clone(),
        },
        packages: collect_packages(workspace, config),
        entry_points,
        summary,
        findings,
        structural_findings,
        unresolved_calls,
        unresolved_calls_total: unresolved_total,
        diagnostics,
        limitations: default_limitations(std_calls),
    }
}

/// Findings from node operations, in deterministic order and with ids
/// assigned. Returns the findings, the operation-count summary and the
/// list-capping diagnostics.
fn collect_findings(
    graph: &CallGraph,
    reachability: &Reachability,
    limits: &Limits,
) -> (Vec<Finding>, SummaryCounts, Vec<Diagnostic>) {
    let mut findings: Vec<Finding> = Vec::new();
    let mut summary = SummaryCounts::default();
    let mut diagnostics = Vec::new();
    let mut reachable_by_kind = std::collections::BTreeMap::new();

    for (id, node) in graph.nodes.iter().enumerate() {
        if node.ops.is_empty() {
            continue;
        }
        let id = id as NodeId;
        let reachable = reachability.is_reachable(id);
        let path = if reachable {
            reachability.path_to(graph, id)
        } else {
            None
        };
        for op in &node.ops {
            if reachable {
                summary.reachable_unsafe_operations += 1;
                *reachable_by_kind.entry(op.kind).or_insert(0) += 1;
                match op.kind {
                    unsafe_surface_core::UnsafeOpKind::UnsafeFn => {
                        summary.reachable_unsafe_functions += 1;
                    }
                    unsafe_surface_core::UnsafeOpKind::FfiCall => {
                        summary.reachable_ffi_calls += 1;
                    }
                    unsafe_surface_core::UnsafeOpKind::InlineAssembly => {
                        summary.inline_assembly_sites += 1;
                    }
                    unsafe_surface_core::UnsafeOpKind::Transmute => {
                        summary.transmutes += 1;
                    }
                    unsafe_surface_core::UnsafeOpKind::RawPointerDeref => {
                        summary.raw_pointer_dereferences += 1;
                    }
                    _ => {}
                }
            } else {
                summary.unreachable_unsafe_operations += 1;
            }
            findings.push(Finding {
                id: 0, // assigned after sorting
                operation: op.clone(),
                enclosing_item: node.path.clone(),
                package: node.package.clone(),
                reachability: if reachable {
                    FindingReachability::Reachable
                } else {
                    FindingReachability::Unreachable
                },
                path: path.clone(),
            });
        }
    }
    summary.reachable_by_kind = reachable_by_kind;

    // Deterministic finding order: reachable first, then by location.
    findings.sort_by(|a, b| {
        (
            a.reachability,
            &a.enclosing_item,
            &a.operation.location,
            a.operation.kind,
        )
            .cmp(&(
                b.reachability,
                &b.enclosing_item,
                &b.operation.location,
                b.operation.kind,
            ))
    });
    let total_findings = findings.len();
    if total_findings > limits.max_findings_listed {
        diagnostics.push(Diagnostic::warning(format!(
            "finding list capped at {} of {} (counts in the summary are complete)",
            limits.max_findings_listed, total_findings
        )));
        findings.truncate(limits.max_findings_listed);
    }
    for (id, finding) in findings.iter_mut().enumerate() {
        finding.id = id as u64;
    }
    (findings, summary, diagnostics)
}

/// Structural findings from all analysed crates, sorted and deduplicated.
fn collect_structural(bundles: &[CrateBundle]) -> Vec<StructuralFinding> {
    let mut structural: Vec<StructuralFinding> = bundles
        .iter()
        .flat_map(|b| b.analysis.structural.iter().cloned())
        .collect();
    structural
        .sort_by(|a, b| (&a.package, a.kind, &a.location).cmp(&(&b.package, b.kind, &b.location)));
    structural
        .dedup_by(|a, b| a.package == b.package && a.kind == b.kind && a.location == b.location);
    structural
}

/// Unresolved call sites with the standard-library ones counted apart:
/// those are expected, everything else is analysis uncertainty. Returns
/// the (possibly capped) list, its complete total and the number of
/// standard-library call sites.
fn collect_unresolved(
    graph: &CallGraph,
    limits: &Limits,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<UnresolvedCall>, u64, u64) {
    let mut unresolved: Vec<_> = graph.unresolved.clone();
    let std_calls = unresolved
        .iter()
        .filter(|u| matches!(u.reason, UnresolvedReason::StandardLibrary))
        .count() as u64;
    unresolved.retain(|u| !matches!(u.reason, UnresolvedReason::StandardLibrary));
    unresolved.sort_by(|a, b| {
        (&a.caller, &a.location, &a.callee_text).cmp(&(&b.caller, &b.location, &b.callee_text))
    });
    let total = unresolved.len() as u64;
    if unresolved.len() > limits.max_unresolved_calls_listed {
        diagnostics.push(Diagnostic::info(format!(
            "unresolved-call list capped at {} of {}",
            limits.max_unresolved_calls_listed, total
        )));
        unresolved.truncate(limits.max_unresolved_calls_listed);
    }
    (unresolved, total, std_calls)
}

/// Packages analysed (plus unavailable ones for transparency).
fn collect_packages(workspace: &DiscoveredWorkspace, config: &AnalysisConfig) -> Vec<PackageInfo> {
    workspace
        .packages
        .iter()
        .filter(|p| workspace.selected.contains(&p.id) || config.include_dependencies)
        .map(|p| PackageInfo {
            id: p.id.clone(),
            root: p.manifest_dir.to_string(),
            sources_available: p.sources_available,
        })
        .collect()
}

/// The limitations disclosed in every report.
fn default_limitations(std_calls: u64) -> Vec<String> {
    let mut limitations = vec![
        "the call graph is approximate: trait objects, function pointers, closures and \
         generic instantiations are only partially resolved"
            .to_owned(),
        "macro expansions (including procedural macros) are not analysed; calls produced \
         by macros are invisible"
            .to_owned(),
        "method calls are resolved by unique-name matching: small ambiguity sets add \
         inferred may-call edges to every candidate; large sets are reported unresolved"
            .to_owned(),
        "raw pointer dereferences are inferred from dereference expressions inside unsafe \
         contexts"
            .to_owned(),
        "#[cfg] evaluation is approximate; unknown predicates are treated as enabled".to_owned(),
        "library entry points include every public function (over-approximation of the \
         public API)"
            .to_owned(),
        "items nested inside function bodies are attributed to the enclosing function".to_owned(),
        "the standard library is not analysed; calls into it are not followed".to_owned(),
    ];
    if std_calls > 0 {
        limitations.push(format!(
            "{std_calls} call sites target the standard library (expected; excluded from \
             the unresolved-call list)"
        ));
    }
    limitations
}
