//! Tests for call-graph construction and name resolution.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use tempfile::TempDir;
use unsafe_surface_cargo::CfgValues;
use unsafe_surface_core::{
    Confidence, DependencyOrigin, ItemPath, PackageId, UnresolvedReason, UnsafeOpKind,
};

use crate::cfg_eval::CfgEvaluator;
use crate::classify::classify_crate;
use crate::graph::{build_call_graph, CallGraph, CrateInput, NodeId};
use crate::index::build_index;
use crate::limits::Limits;
use crate::source::{parse_crate, ParseContext, ParsedCrate};

/// An analysed in-memory crate.
struct TestCrate {
    package: PackageId,
    parsed: ParsedCrate,
    index: crate::index::CrateIndex,
    analysis: crate::classify::CrateAnalysis,
}

/// Parses, indexes and classifies one crate rooted at `root`.
fn analyze_crate(name: &str, root: &Path, display_root: &Path) -> TestCrate {
    let values = CfgValues::new();
    let features = BTreeSet::new();
    let limits = Limits::default();
    let context = ParseContext {
        cfg: CfgEvaluator::new(&values, &features),
        limits: &limits,
        display_root: Some(display_root),
    };
    let parsed = parse_crate(root, &context).expect("crate root must parse");
    let index = build_index(&parsed);
    let package = PackageId::new(name, Some("0.1.0".into()), DependencyOrigin::Workspace);
    let analysis = classify_crate(&parsed, &index, &package);
    TestCrate {
        package,
        parsed,
        index,
        analysis,
    }
}

/// Writes files into `dir/name/…` and returns the crate root path.
fn write_crate(dir: &Path, name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let mut root = None;
    for (file, content) in files {
        let path = dir.join(name).join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        if root.is_none() {
            root = Some(path);
        }
    }
    root.unwrap()
}

/// Builds the standard two-crate test scenario:
///
/// * `app` depends on `dep` and exercises every resolution strategy;
/// * `dep` provides a safe wrapper around an unsafe fn and an FFI call.
fn scenario() -> (CallGraph, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let app_root = write_crate(
        dir.path(),
        "app",
        &[
            (
                "main.rs",
                r#"
use dep::wrapper;

mod network;

fn main() {
    wrapper();
    local_safe();
    network::run();
    crate::local_unsafe();
    let parser = Parser;
    parser.parse();
    let s = S;
    s.consume();
    missing_function();
    std::process::exit(0);
    let f: fn() = local_safe;
    f();
    let v = Vec::new();
    v.len();
}

fn local_safe() {}
unsafe fn local_unsafe() {}

struct Parser;
impl Parser {
    fn parse(&self) {}
}

struct S;
impl S {
    fn consume(self) {}
}

struct Tuple(i32);
fn make() {
    let _ = Tuple(1);
}
"#,
            ),
            (
                "network.rs",
                r#"
pub fn run() {
    dep::raw_entry();
    super::local_safe();
}
"#,
            ),
        ],
    );
    let dep_root = write_crate(
        dir.path(),
        "dep",
        &[(
            "lib.rs",
            r#"
extern "C" {
    fn c_side(x: i32) -> i32;
}

pub fn wrapper() {
    unsafe { helper() };
}

/// # Safety
/// Always safe to call.
unsafe fn helper() {}

pub unsafe fn raw_entry() {
    unsafe { c_side(1) };
}
"#,
        )],
    );

    let app = analyze_crate("app", &app_root, dir.path());
    let dep = analyze_crate("dep", &dep_root, dir.path());
    let inputs = [
        CrateInput {
            package: &dep.package,
            is_lib: true,
            parsed: &dep.parsed,
            index: &dep.index,
            analysis: &dep.analysis,
        },
        CrateInput {
            package: &app.package,
            is_lib: false,
            parsed: &app.parsed,
            index: &app.index,
            analysis: &app.analysis,
        },
    ];
    let graph = build_call_graph(&inputs, &Limits::default(), Default::default());
    (graph, dir)
}

fn path(graph: &CallGraph, id: NodeId) -> String {
    graph.nodes[id as usize].path.to_string()
}

fn callee_paths(graph: &CallGraph, caller: &str) -> Vec<String> {
    let caller_id = graph.node(&ItemPath::parse(caller).unwrap()).unwrap();
    graph.edges[caller_id as usize]
        .keys()
        .map(|id| path(graph, *id))
        .collect()
}

fn unresolved_reasons(graph: &CallGraph, callee_text: &str) -> Vec<UnresolvedReason> {
    graph
        .unresolved
        .iter()
        .filter(|u| u.callee_text == callee_text)
        .map(|u| u.reason.clone())
        .collect()
}

#[test]
fn resolves_direct_and_imported_calls() {
    let (graph, _dir) = scenario();
    let callees = callee_paths(&graph, "app::main");
    for expected in [
        "dep::wrapper",       // via `use dep::wrapper`
        "app::local_safe",    // same module
        "app::network::run",  // module-relative
        "app::local_unsafe",  // crate:: prefix
        "app::Parser::parse", // unique-name method heuristic
        "app::S::consume",    // unique-name method heuristic
    ] {
        assert!(
            callees.contains(&expected.to_owned()),
            "missing edge app::main -> {expected}; edges: {callees:?}"
        );
    }
    // Cross-module and super:: calls from network::run.
    let network_callees = callee_paths(&graph, "app::network::run");
    assert!(network_callees.contains(&"dep::raw_entry".to_owned()));
    assert!(network_callees.contains(&"app::local_safe".to_owned()));
}

#[test]
fn crate_rooted_glob_imports_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let root = write_crate(
        dir.path(),
        "globber",
        &[(
            "lib.rs",
            r#"
mod prelude {
    pub fn exposed() {}
}

use crate::prelude::*;

pub fn call() {
    exposed();
}
"#,
        )],
    );
    let globber = analyze_crate("globber", &root, dir.path());
    let inputs = [CrateInput {
        package: &globber.package,
        is_lib: true,
        parsed: &globber.parsed,
        index: &globber.index,
        analysis: &globber.analysis,
    }];
    let graph = build_call_graph(&inputs, &Limits::default(), Default::default());
    let callees = callee_paths(&graph, "globber::call");
    assert!(
        callees.contains(&"globber::prelude::exposed".to_owned()),
        "glob-imported item must resolve via `use crate::…::*`; edges: {callees:?}"
    );
}

#[test]
fn unsafe_and_ffi_calls_attach_ops_to_caller() {
    let (graph, _dir) = scenario();
    let main_id = graph.node(&ItemPath::parse("app::main").unwrap()).unwrap();
    let main = &graph.nodes[main_id as usize];
    let unsafe_call = main
        .ops
        .iter()
        .find(|op| op.kind == UnsafeOpKind::UnsafeFnCall)
        .expect("UnsafeFnCall op missing");
    assert_eq!(unsafe_call.detail.as_deref(), Some("app::local_unsafe"));
    assert_eq!(unsafe_call.confidence, Confidence::Confirmed);

    let raw_id = graph
        .node(&ItemPath::parse("dep::raw_entry").unwrap())
        .unwrap();
    let raw = &graph.nodes[raw_id as usize];
    let ffi = raw
        .ops
        .iter()
        .find(|op| op.kind == UnsafeOpKind::FfiCall)
        .expect("FfiCall op missing");
    assert_eq!(ffi.detail.as_deref(), Some("dep::c_side"));
    // The FFI edge leads to the extern node.
    let c_side_id = graph
        .node(&ItemPath::parse("dep::c_side").unwrap())
        .unwrap();
    assert!(graph.edges[raw_id as usize].contains_key(&c_side_id));
}

#[test]
fn inferred_method_edges_are_marked() {
    let (graph, _dir) = scenario();
    let main_id = graph.node(&ItemPath::parse("app::main").unwrap()).unwrap();
    let parse_id = graph
        .node(&ItemPath::parse("app::Parser::parse").unwrap())
        .unwrap();
    let edge = &graph.edges[main_id as usize][&parse_id];
    assert_eq!(edge.kind, unsafe_surface_core::EdgeKind::InferredMethod);
    assert_eq!(edge.kind.confidence(), Confidence::Inferred);
}

#[test]
fn unresolved_calls_carry_precise_reasons() {
    let (graph, _dir) = scenario();
    assert_eq!(
        unresolved_reasons(&graph, "missing_function"),
        vec![UnresolvedReason::UnknownName]
    );
    assert_eq!(
        unresolved_reasons(&graph, "std::process::exit"),
        vec![UnresolvedReason::StandardLibrary]
    );
    assert_eq!(
        unresolved_reasons(&graph, "f"),
        vec![UnresolvedReason::FunctionPointer]
    );
    assert_eq!(
        unresolved_reasons(&graph, "<receiver>.len"),
        vec![UnresolvedReason::UnknownName]
    );
    // The tuple-struct constructor is resolved but not callable: no edge,
    // no unresolved call.
    assert!(callee_paths(&graph, "app::make").is_empty());
    assert!(unresolved_reasons(&graph, "Tuple").is_empty());
}

#[test]
fn small_ambiguity_sets_become_may_call_edges() {
    let dir = tempfile::tempdir().unwrap();
    let root = write_crate(
        dir.path(),
        "solo",
        &[(
            "lib.rs",
            r#"
struct A;
impl A { fn collide(&self) {} }
struct B;
impl B { fn collide(&self) {} }
pub fn f(a: A) { a.collide(); }
"#,
        )],
    );
    let solo = analyze_crate("solo", &root, dir.path());
    let inputs = [CrateInput {
        package: &solo.package,
        is_lib: true,
        parsed: &solo.parsed,
        index: &solo.index,
        analysis: &solo.analysis,
    }];
    let graph = build_call_graph(&inputs, &Limits::default(), Default::default());
    // May-call over-approximation: BOTH candidates get inferred edges,
    // so reachable unsafe code is never hidden by ambiguity.
    let callees = callee_paths(&graph, "solo::f");
    assert!(
        callees.contains(&"solo::A::collide".to_owned()),
        "{callees:?}"
    );
    assert!(
        callees.contains(&"solo::B::collide".to_owned()),
        "{callees:?}"
    );
    let f_id = graph.node(&ItemPath::parse("solo::f").unwrap()).unwrap();
    for meta in graph.edges[f_id as usize].values() {
        assert_eq!(meta.kind, unsafe_surface_core::EdgeKind::InferredMethod);
    }
}

#[test]
fn large_ambiguity_sets_stay_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    // Ten types with a method named `collide` exceed the may-call cap.
    let mut src = String::new();
    for i in 0..10 {
        src.push_str(&format!(
            "struct T{i};
impl T{i} {{ fn collide(&self) {{}} }}
"
        ));
    }
    src.push_str(
        "pub fn f(a: T0) { a.collide(); }
",
    );
    let root = write_crate(dir.path(), "solo", &[("lib.rs", &src)]);
    let solo = analyze_crate("solo", &root, dir.path());
    let inputs = [CrateInput {
        package: &solo.package,
        is_lib: true,
        parsed: &solo.parsed,
        index: &solo.index,
        analysis: &solo.analysis,
    }];
    let graph = build_call_graph(&inputs, &Limits::default(), Default::default());
    assert_eq!(
        unresolved_reasons(&graph, "<receiver>.collide"),
        vec![UnresolvedReason::AmbiguousMethod { candidates: 10 }]
    );
}

#[test]
fn dyn_trait_receivers_are_dynamic_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let root = write_crate(
        dir.path(),
        "solo",
        &[(
            "lib.rs",
            r#"
pub trait Job { fn work(&self); }
pub struct W;
impl Job for W { fn work(&self) {} }
pub fn run(job: &dyn Job) { job.work(); }
"#,
        )],
    );
    let solo = analyze_crate("solo", &root, dir.path());
    let inputs = [CrateInput {
        package: &solo.package,
        is_lib: true,
        parsed: &solo.parsed,
        index: &solo.index,
        analysis: &solo.analysis,
    }];
    let graph = build_call_graph(&inputs, &Limits::default(), Default::default());
    assert_eq!(
        unresolved_reasons(&graph, "<receiver>.work"),
        vec![UnresolvedReason::DynamicDispatch]
    );
}

#[test]
fn self_method_calls_resolve_directly() {
    let dir = tempfile::tempdir().unwrap();
    let root = write_crate(
        dir.path(),
        "solo",
        &[(
            "lib.rs",
            r#"
struct W;
impl W {
    pub fn run(&self) { self.step(); }
    fn step(&self) {}
    pub fn assoc() { Self::run2(); }
    fn run2() {}
}
"#,
        )],
    );
    let solo = analyze_crate("solo", &root, dir.path());
    let inputs = [CrateInput {
        package: &solo.package,
        is_lib: true,
        parsed: &solo.parsed,
        index: &solo.index,
        analysis: &solo.analysis,
    }];
    let graph = build_call_graph(&inputs, &Limits::default(), Default::default());
    let callees = callee_paths(&graph, "solo::W::run");
    assert_eq!(callees, vec!["solo::W::step".to_owned()]);
    let run_id = graph
        .node(&ItemPath::parse("solo::W::run").unwrap())
        .unwrap();
    let step_id = graph
        .node(&ItemPath::parse("solo::W::step").unwrap())
        .unwrap();
    assert_eq!(
        graph.edges[run_id as usize][&step_id].kind,
        unsafe_surface_core::EdgeKind::Direct
    );
    let assoc_callees = callee_paths(&graph, "solo::W::assoc");
    assert_eq!(assoc_callees, vec!["solo::W::run2".to_owned()]);
}

#[test]
fn graph_construction_is_deterministic() {
    let (a, _dir_a) = scenario();
    let (b, _dir_b) = scenario();
    let dump = |g: &CallGraph| -> Vec<String> {
        let mut lines = Vec::new();
        for (i, node) in g.nodes.iter().enumerate() {
            lines.push(format!("node {} {}", i, node.path));
            for (to, meta) in &g.edges[i] {
                lines.push(format!("  -> {} {:?}", path(g, *to), meta.kind));
            }
            for op in &node.ops {
                lines.push(format!("  op {:?} {}", op.kind, op.location));
            }
        }
        for u in &g.unresolved {
            lines.push(format!(
                "unresolved {} {} {:?}",
                u.caller, u.callee_text, u.reason
            ));
        }
        lines
    };
    assert_eq!(dump(&a), dump(&b));
}

#[test]
fn duplicate_function_paths_keep_their_own_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let root = write_crate(
        dir.path(),
        "dup",
        &[(
            "lib.rs",
            r#"
#[cfg(unknown_predicate)]
fn dup() {
    one();
}
#[cfg(not(unknown_predicate))]
fn dup() {
    two();
}
fn one() {}
fn two() {}
"#,
        )],
    );
    let dup = analyze_crate("dup", &root, dir.path());
    let inputs = [CrateInput {
        package: &dup.package,
        is_lib: true,
        parsed: &dup.parsed,
        index: &dup.index,
        analysis: &dup.analysis,
    }];
    let graph = build_call_graph(&inputs, &Limits::default(), Default::default());

    // Both cfg-gated definitions are kept (unknown predicates are an
    // over-approximation) and each keeps its own node and call edges.
    let dup_ids: Vec<NodeId> = graph
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.path.to_string() == "dup::dup")
        .map(|(id, _)| id as NodeId)
        .collect();
    assert_eq!(dup_ids.len(), 2, "both cfg-gated siblings must be nodes");
    let callees = |id: NodeId| -> Vec<String> {
        graph.edges[id as usize]
            .keys()
            .map(|to| path(&graph, *to))
            .collect()
    };
    assert_eq!(callees(dup_ids[0]), ["dup::one"]);
    assert_eq!(callees(dup_ids[1]), ["dup::two"]);

    // Path lookup keeps the first definition (like the symbol index).
    assert_eq!(
        graph.node(&ItemPath::parse("dup::dup").unwrap()),
        Some(dup_ids[0])
    );
}

#[test]
fn node_limit_truncation_is_diagnosed() {
    let dir = tempfile::tempdir().unwrap();
    let root = write_crate(
        dir.path(),
        "solo",
        &[("lib.rs", "pub fn a() {}\npub fn b() {}\npub fn c() {}\n")],
    );
    let solo = analyze_crate("solo", &root, dir.path());
    let inputs = [CrateInput {
        package: &solo.package,
        is_lib: true,
        parsed: &solo.parsed,
        index: &solo.index,
        analysis: &solo.analysis,
    }];
    let limits = Limits {
        max_graph_nodes: 2,
        ..Limits::default()
    };
    let graph = build_call_graph(&inputs, &limits, Default::default());
    assert_eq!(graph.nodes.len(), 2);
    assert!(graph
        .diagnostics
        .iter()
        .any(|d| d.message.contains("node limit")));
}

#[test]
fn safety_comments_on_unsafe_calls_are_found() {
    let dir = tempfile::tempdir().unwrap();
    let root = write_crate(
        dir.path(),
        "solo",
        &[(
            "lib.rs",
            r#"
unsafe fn risky() {}
pub fn f() {
    // SAFETY: documented call
    unsafe { risky() };
}
"#,
        )],
    );
    let solo = analyze_crate("solo", &root, dir.path());
    let inputs = [CrateInput {
        package: &solo.package,
        is_lib: true,
        parsed: &solo.parsed,
        index: &solo.index,
        analysis: &solo.analysis,
    }];
    let graph = build_call_graph(&inputs, &Limits::default(), Default::default());
    let f_id = graph.node(&ItemPath::parse("solo::f").unwrap()).unwrap();
    let call_op = graph.nodes[f_id as usize]
        .ops
        .iter()
        .find(|op| op.kind == UnsafeOpKind::UnsafeFnCall)
        .unwrap();
    assert_eq!(
        call_op.justification,
        unsafe_surface_core::SafetyJustification::Present
    );
}
