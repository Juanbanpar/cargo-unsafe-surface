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
//! A package's library and each of its binaries are separate *crate
//! instances* (separate compilation units sharing a crate name); node keys
//! include the instance so same-named items in different instances never
//! collide. Within one instance, path lookup keeps the first definition
//! (duplicates arise from cfg-gated siblings), while every definition keeps
//! its own node and edges.
//!
//! Unresolvable call sites become explicit [`UnresolvedCall`]s. The graph
//! is deterministic: nodes are inserted in input order and adjacency sets
//! use [`BTreeMap`].

use std::collections::{BTreeMap, BTreeSet};

use unsafe_surface_core::{
    Confidence, Diagnostic, EdgeKind, FunctionKind, ItemPath, PackageId, SafetyJustification,
    SourceLocation, UnresolvedCall, UnresolvedReason, UnsafeOpKind, UnsafeOperation,
};

use crate::classify::{CalleeRef, CrateAnalysis};
use crate::index::CrateIndex;
use crate::justify::Justifications;
use crate::limits::Limits;
use crate::resolve::{
    resolve_method_call, resolve_path_call, GlobalIndex, Instance, InstanceId, Resolution,
};
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
    /// Crate instance this node belongs to.
    pub instance: InstanceId,
    /// Owning package.
    pub package: PackageId,
    /// Callable kind.
    pub kind: FunctionKind,
    /// Whether the item is `pub`.
    pub is_pub: bool,
    /// Whether calling this item requires `unsafe` (`unsafe fn`, or a
    /// foreign function without a `safe fn` declaration).
    pub is_unsafe_fn: bool,
    /// Definition location.
    pub location: SourceLocation,
    /// Unsafe operations in the body (syntactic + resolution-dependent).
    pub ops: Vec<UnsafeOperation>,
}

/// Describes one crate instance in the graph.
#[derive(Debug, Clone)]
pub struct InstanceInfo {
    /// Crate name (source-level).
    pub crate_name: String,
    /// Whether the instance is the package's library target.
    pub is_lib: bool,
    /// Owning package.
    pub package: PackageId,
}

/// The approximate call graph of the analysis universe.
#[derive(Debug, Default)]
pub struct CallGraph {
    /// All nodes; insertion order is deterministic.
    pub nodes: Vec<GraphNode>,
    /// Crate instances.
    pub instances: Vec<InstanceInfo>,
    /// `(instance, item path)` → node id.
    pub index: BTreeMap<(InstanceId, Vec<String>), NodeId>,
    /// Adjacency map: caller → (callee → edge).
    pub edges: Vec<BTreeMap<NodeId, EdgeMeta>>,
    /// Call sites that could not be resolved.
    pub unresolved: Vec<UnresolvedCall>,
    /// Non-fatal graph-construction diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

impl CallGraph {
    /// Node lookup by fully qualified path. Searches instances in
    /// insertion order (libraries are inserted first by the engine), so a
    /// lib/bin name collision resolves to the library.
    #[must_use]
    pub fn node(&self, path: &ItemPath) -> Option<NodeId> {
        self.instances.iter().enumerate().find_map(|(id, info)| {
            if info.crate_name == path.krate {
                self.index.get(&(id, path.segments.clone())).copied()
            } else {
                None
            }
        })
    }

    /// Node lookup restricted to one instance.
    #[must_use]
    pub fn node_in(&self, instance: InstanceId, path: &[String]) -> Option<NodeId> {
        self.index.get(&(instance, path.to_vec())).copied()
    }

    /// Node lookup for item paths that name no crate (`crate::…` entry
    /// paths): every instance is searched, in instance order (libraries
    /// first), returning one node per instance that defines the item.
    #[must_use]
    pub fn nodes_matching(&self, segments: &[String]) -> Vec<NodeId> {
        self.index
            .iter()
            .filter(|((_, path), _)| path.as_slice() == segments)
            .map(|(_, &id)| id)
            .collect()
    }

    /// Number of edges in the graph.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.iter().map(BTreeMap::len).sum()
    }
}

/// One analysed crate instance feeding graph construction.
pub struct CrateInput<'a> {
    /// Package identity.
    pub package: &'a PackageId,
    /// Whether this instance is the package's library target.
    pub is_lib: bool,
    /// Parsed sources (needed for safety-comment lookup of resolution-
    /// dependent operations).
    pub parsed: &'a ParsedCrate,
    /// Symbol index.
    pub index: &'a CrateIndex,
    /// Classification results.
    pub analysis: &'a CrateAnalysis,
}

/// Builds the call graph over all analysed crate instances.
///
/// `unavailable_crates` are dependency crates known to Cargo but not
/// analysed; calls into them are reported with
/// [`UnresolvedReason::DependencySourceUnavailable`].
#[must_use]
pub fn build_call_graph(
    inputs: &[CrateInput<'_>],
    limits: &Limits,
    unavailable_crates: BTreeSet<String>,
) -> CallGraph {
    let mut graph = CallGraph::default();

    // Pass 1: register instances and create nodes.
    for input in inputs {
        graph.instances.push(InstanceInfo {
            crate_name: input.package.crate_name(),
            is_lib: input.is_lib,
            package: input.package.clone(),
        });
    }
    // Node id of every `analysis.functions` record in order; `None` when
    // the record was dropped by the node limit. Pass 2 uses these instead
    // of looking nodes up by path, because several records can share one
    // path (cfg-gated siblings, colliding impl method paths).
    let mut record_nodes: Vec<Option<NodeId>> = Vec::new();
    let mut truncated = false;
    for (instance, input) in inputs.iter().enumerate() {
        for record in &input.analysis.functions {
            if graph.nodes.len() >= limits.max_graph_nodes {
                record_nodes.push(None);
                if !truncated {
                    graph.diagnostics.push(Diagnostic::error(format!(
                        "graph node limit ({}) exceeded; remaining functions are not \
                         represented and calls to them become unresolved",
                        limits.max_graph_nodes
                    )));
                    truncated = true;
                }
                continue;
            }
            let id = graph.nodes.len() as NodeId;
            graph.nodes.push(GraphNode {
                path: ItemPath::new(input.package.crate_name(), record.path.clone()),
                instance,
                package: input.package.clone(),
                kind: record.kind.clone(),
                is_pub: record.is_pub,
                is_unsafe_fn: record.is_unsafe_fn,
                location: record.location.clone(),
                ops: record.ops.clone(),
            });
            graph.edges.push(BTreeMap::new());
            // First definition wins for path lookup, matching the symbol
            // index; the duplicate keeps its own node and edges.
            graph
                .index
                .entry((instance, record.path.clone()))
                .or_insert(id);
            record_nodes.push(Some(id));
        }
    }

    let global = GlobalIndex::new(
        inputs
            .iter()
            .map(|input| Instance {
                crate_name: input.package.crate_name(),
                is_lib: input.is_lib,
                index: input.index,
            })
            .collect(),
        unavailable_crates,
    );

    // Pass 2: resolve call sites into edges (and attach call ops).
    let mut caller_nodes = record_nodes.iter();
    for (instance, input) in inputs.iter().enumerate() {
        // Safety-comment lookups share one line index per module.
        let justifications: BTreeMap<&[String], Justifications<'_>> = input
            .parsed
            .modules
            .iter()
            .map(|module| (module.path.as_slice(), Justifications::new(&module.text)))
            .collect();
        for record in &input.analysis.functions {
            let Some(caller_id) = caller_nodes.next().copied().flatten() else {
                continue; // node was truncated by the node limit
            };
            for call in &record.calls {
                let resolution = match &call.callee {
                    CalleeRef::Path { segments } => {
                        resolve_path_call(&global, record, instance, segments)
                    }
                    CalleeRef::Method {
                        name,
                        receiver_is_self,
                        receiver_local,
                    } => resolve_method_call(
                        &global,
                        record,
                        name,
                        *receiver_is_self,
                        receiver_local.as_deref(),
                    ),
                    CalleeRef::Computed { reason, .. } => Resolution::Unresolved(reason.clone()),
                };
                // Safety comments are looked up in the caller's source.
                let justification = justifications
                    .get(record.module.as_slice())
                    .map(|scanner| scanner.find(call.location.line))
                    .unwrap_or(SafetyJustification::Absent);
                match resolution {
                    Resolution::MayCall(candidates) => {
                        let candidate_count = candidates.len();
                        let mut linked = 0;
                        for (callee_instance, target) in candidates {
                            if let Some(&callee_id) =
                                graph.index.get(&(callee_instance, target.segments.clone()))
                            {
                                graph.edges[caller_id as usize].entry(callee_id).or_insert(
                                    EdgeMeta {
                                        kind: EdgeKind::InferredMethod,
                                        call_site: call.location.clone(),
                                    },
                                );
                                attach_call_ops(
                                    &mut graph,
                                    caller_id,
                                    callee_id,
                                    &call.location,
                                    Confidence::Inferred,
                                    justification,
                                );
                                linked += 1;
                            }
                        }
                        if linked == 0 {
                            // No candidate is representable as a node
                            // (trait method declarations without bodies,
                            // a truncated graph): the call must surface
                            // as uncertainty instead of vanishing.
                            graph.unresolved.push(UnresolvedCall {
                                caller: ItemPath::new(
                                    input.package.crate_name(),
                                    record.path.clone(),
                                ),
                                callee_text: callee_text(&call.callee),
                                location: call.location.clone(),
                                reason: UnresolvedReason::AmbiguousMethod {
                                    candidates: candidate_count,
                                },
                            });
                        }
                    }
                    Resolution::Callable(callee_instance, target, edge_kind) => {
                        let Some(&callee_id) =
                            graph.index.get(&(callee_instance, target.segments.clone()))
                        else {
                            // Target has no node (truncated): treat as
                            // unresolved rather than dropping the call.
                            graph.unresolved.push(UnresolvedCall {
                                caller: ItemPath::new(
                                    input.package.crate_name(),
                                    record.path.clone(),
                                ),
                                callee_text: callee_text(&call.callee),
                                location: call.location.clone(),
                                reason: UnresolvedReason::UnknownName,
                            });
                            continue;
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
                            justification,
                        );
                    }
                    Resolution::NotCallable => {}
                    Resolution::Unresolved(reason) => {
                        graph.unresolved.push(UnresolvedCall {
                            caller: ItemPath::new(input.package.crate_name(), record.path.clone()),
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

/// Attaches resolution-dependent unsafe operations to the caller node.
fn attach_call_ops(
    graph: &mut CallGraph,
    caller_id: NodeId,
    callee_id: NodeId,
    call_site: &SourceLocation,
    confidence: Confidence,
    justification: SafetyJustification,
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
        CalleeRef::Computed { text, .. } => text.clone(),
    }
}
