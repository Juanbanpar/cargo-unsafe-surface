//! Call-graph construction.
//!
//! Nodes are the analysed functions (free functions, methods, trait
//! default methods and foreign functions). Edges come from resolving the
//! call sites collected during classification. Resolution also attaches
//! *resolution-dependent* unsafe operations to callers:
//!
//! * calling an `unsafe fn` adds [`UnsafeOpKind::UnsafeFnCall`];
//! * calling a foreign function adds [`UnsafeOpKind::FfiCall`] — the FFI
//!   boundary crossing.
//!
//! Unresolvable call sites become explicit [`UnresolvedCall`]s. The graph
//! is deterministic: nodes are inserted in crate order (sorted by package
//! name) and adjacency sets use [`BTreeMap`].

use std::collections::{BTreeMap, BTreeSet};

use unsafe_surface_core::{
    Confidence, Diagnostic, EdgeKind, FunctionKind, ItemPath, PackageId, SafetyJustification,
    SourceLocation, UnresolvedCall, UnsafeOpKind, UnsafeOperation,
};

use crate::classify::{CalleeRef, CrateAnalysis};
use crate::index::CrateIndex;
use crate::justify::find_justification;
use crate::limits::Limits;
use crate::resolve::{resolve_method_call, resolve_path_call, GlobalIndex, Resolution};
use crate::source::ParsedCrate;

/// Identifier of a graph node (position in [`CallGraph::nodes`]).
pub type NodeId = u32;

/// One edge of the call graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeMeta {
    /// How the edge was established.
    pub kind: EdgeKind,
    /// The call site in the caller.
    pub call_site: SourceLocation,
}

/// A node of the call graph.
#[derive(Debug)]
pub struct GraphNode {
    /// Fully qualified item path (including crate name).
    pub path: ItemPath,
    /// Owning package.
    pub package: PackageId,
    /// Callable kind.
    pub kind: FunctionKind,
    /// Whether the item is `pub`.
    pub is_pub: bool,
    /// Whether this is an `unsafe fn` (foreign functions count).
    pub is_unsafe_fn: bool,
    /// Definition location.
    pub location: SourceLocation,
    /// Unsafe operations in the body (syntactic + resolution-dependent).
    pub ops: Vec<UnsafeOperation>,
}

/// The approximate call graph of the analysis universe.
#[derive(Debug, Default)]
pub struct CallGraph {
    /// All nodes; insertion order is deterministic.
    pub nodes: Vec<GraphNode>,
    /// `(crate name, item path)` → node id.
    pub index: BTreeMap<(String, Vec<String>), NodeId>,
    /// Adjacency map: caller → (callee → edge).
    pub edges: Vec<BTreeMap<NodeId, EdgeMeta>>,
    /// Call sites that could not be resolved.
    pub unresolved: Vec<UnresolvedCall>,
    /// Non-fatal graph-construction diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

impl CallGraph {
    /// Node lookup by fully qualified path.
    #[must_use]
    pub fn node(&self, path: &ItemPath) -> Option<NodeId> {
        self.index
            .get(&(path.krate.clone(), path.segments.clone()))
            .copied()
    }

    /// Number of edges in the graph.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.iter().map(BTreeMap::len).sum()
    }
}

/// One analysed crate feeding graph construction.
pub struct CrateInput<'a> {
    /// Package identity.
    pub package: &'a PackageId,
    /// Parsed sources (needed for safety-comment lookup of resolution-
    /// dependent operations).
    pub parsed: &'a ParsedCrate,
    /// Symbol index.
    pub index: &'a CrateIndex,
    /// Classification results.
    pub analysis: &'a CrateAnalysis,
}

/// Builds the call graph over all analysed crates.
#[must_use]
pub fn build_call_graph(inputs: &[CrateInput<'_>], limits: &Limits) -> CallGraph {
    let mut graph = CallGraph::default();

    // Pass 1: create nodes.
    let mut truncated = false;
    for input in inputs {
        let krate = input.package.crate_name();
        for record in &input.analysis.functions {
            if graph.nodes.len() >= limits.max_graph_nodes {
                if !truncated {
                    graph.diagnostics.push(Diagnostic::error(format!(
                        "graph node limit ({}) exceeded; remaining functions are not \
                         represented and calls to them become unresolved",
                        limits.max_graph_nodes
                    )));
                    truncated = true;
                }
                break;
            }
            let id = graph.nodes.len() as NodeId;
            graph.nodes.push(GraphNode {
                path: ItemPath::new(krate.clone(), record.path.clone()),
                package: input.package.clone(),
                kind: record.kind.clone(),
                is_pub: record.is_pub,
                is_unsafe_fn: record.is_unsafe_fn,
                location: record.location.clone(),
                ops: record.ops.clone(),
            });
            graph.edges.push(BTreeMap::new());
            graph.index.insert((krate.clone(), record.path.clone()), id);
        }
    }

    let crate_names: Vec<String> = inputs.iter().map(|i| i.package.crate_name()).collect();
    let crate_refs: Vec<(&str, &CrateIndex)> = inputs
        .iter()
        .zip(&crate_names)
        .map(|(input, name)| (name.as_str(), input.index))
        .collect();
    let global = GlobalIndex::new(&crate_refs, unavailable_crates(inputs));

    // Pass 2: resolve call sites into edges (and attach call ops).
    for input in inputs {
        let krate = input.package.crate_name();
        for record in &input.analysis.functions {
            let Some(&caller_id) = graph.index.get(&(krate.clone(), record.path.clone())) else {
                continue; // node was truncated by the node limit
            };
            for call in &record.calls {
                let resolution = match &call.callee {
                    CalleeRef::Path { segments } => {
                        resolve_path_call(&global, record, &krate, segments)
                    }
                    CalleeRef::Method {
                        name,
                        receiver_is_self,
                    } => resolve_method_call(&global, record, name, *receiver_is_self),
                };
                match resolution {
                    Resolution::Callable(target) => {
                        let Some(&callee_id) = graph
                            .index
                            .get(&(target.krate.clone(), target.segments.clone()))
                        else {
                            // Target has no node (truncated): treat as
                            // unresolved rather than dropping the call.
                            graph.unresolved.push(UnresolvedCall {
                                caller: ItemPath::new(krate.clone(), record.path.clone()),
                                callee_text: callee_text(&call.callee),
                                location: call.location.clone(),
                                reason: unsafe_surface_core::UnresolvedReason::UnknownName,
                            });
                            continue;
                        };
                        let edge_kind = match &call.callee {
                            CalleeRef::Method {
                                receiver_is_self: false,
                                ..
                            } => EdgeKind::InferredMethod,
                            _ => EdgeKind::Direct,
                        };
                        // First edge to a callee wins; call-site iteration
                        // is deterministic.
                        graph.edges[caller_id as usize]
                            .entry(callee_id)
                            .or_insert(EdgeMeta {
                                kind: edge_kind,
                                call_site: call.location.clone(),
                            });
                        attach_call_ops(
                            &mut graph,
                            caller_id,
                            callee_id,
                            &call.location,
                            edge_kind.confidence(),
                            input,
                            &record.module,
                        );
                    }
                    Resolution::NotCallable => {}
                    Resolution::Unresolved(reason) => {
                        graph.unresolved.push(UnresolvedCall {
                            caller: ItemPath::new(krate.clone(), record.path.clone()),
                            callee_text: callee_text(&call.callee),
                            location: call.location.clone(),
                            reason,
                        });
                    }
                }
            }
        }
    }

    graph
}

/// Dependency crates that appear in sources but were not analysed.
fn unavailable_crates<'a>(inputs: &[CrateInput<'a>]) -> BTreeSet<&'a str> {
    // With the current pipeline every discovered package is parsed, so the
    // set is empty; the hook exists for the dependency-analysis mode where
    // registry sources may be missing.
    let _ = inputs;
    BTreeSet::new()
}

/// Attaches resolution-dependent unsafe operations to the caller node.
fn attach_call_ops(
    graph: &mut CallGraph,
    caller_id: NodeId,
    callee_id: NodeId,
    call_site: &SourceLocation,
    confidence: Confidence,
    input: &CrateInput<'_>,
    caller_module: &[String],
) {
    let (callee_unsafe, callee_extern, callee_path) = {
        let callee = &graph.nodes[callee_id as usize];
        (
            callee.is_unsafe_fn,
            matches!(callee.kind, FunctionKind::Extern),
            callee.path.to_string(),
        )
    };
    if !callee_unsafe {
        return;
    }
    // Safety comments are looked up in the caller's source text.
    let justification = input
        .parsed
        .modules
        .iter()
        .find(|m| m.path == caller_module)
        .map(|m| find_justification(&m.text, call_site.line))
        .unwrap_or(SafetyJustification::Absent);

    let kind = if callee_extern {
        UnsafeOpKind::FfiCall
    } else {
        UnsafeOpKind::UnsafeFnCall
    };
    let op = UnsafeOperation::new(kind, call_site.clone())
        .with_confidence(confidence)
        .with_justification(justification)
        .with_detail(callee_path);
    graph.nodes[caller_id as usize].ops.push(op);
}

/// Display text for a callee reference.
fn callee_text(callee: &CalleeRef) -> String {
    match callee {
        CalleeRef::Path { segments } => segments.join("::"),
        CalleeRef::Method { name, .. } => format!("<receiver>.{name}"),
    }
}
