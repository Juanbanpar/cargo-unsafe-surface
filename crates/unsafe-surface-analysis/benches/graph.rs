//! Benchmarks for call-graph construction and reachability analysis.
//!
//! Run with: `cargo bench -p unsafe-surface-analysis`. Graphs are
//! synthetic and deterministic (seeded PRNG), so results are comparable
//! across runs.

use std::collections::BTreeMap;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use unsafe_surface_analysis::{CallGraph, Reachability};
use unsafe_surface_analysis::{EdgeMeta, GraphNode, NodeId};
use unsafe_surface_core::{
    DependencyOrigin, EdgeKind, FunctionKind, ItemPath, PackageId, SourceLocation,
};

/// A simple deterministic PRNG (xorshift64) — benchmarks must not depend
/// on system entropy.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Builds a synthetic graph with `node_count` nodes and roughly
/// `edges_per_node` outgoing edges per node.
fn synthetic(node_count: usize, edges_per_node: usize, seed: u64) -> CallGraph {
    let mut graph = CallGraph::default();
    let package = PackageId::new("bench", Some("0.1.0".into()), DependencyOrigin::Workspace);
    graph
        .instances
        .push(unsafe_surface_analysis::graph::InstanceInfo {
            crate_name: "bench".into(),
            is_lib: true,
            package: package.clone(),
        });
    for i in 0..node_count {
        let path = vec![format!("f{i}")];
        let id = graph.nodes.len() as NodeId;
        graph.nodes.push(GraphNode {
            path: ItemPath::new("bench", path.clone()),
            instance: 0,
            package: package.clone(),
            kind: FunctionKind::Free,
            is_pub: true,
            is_unsafe_fn: false,
            location: SourceLocation::new("bench.rs", 1, 1),
            ops: Vec::new(),
        });
        graph.edges.push(BTreeMap::new());
        graph.index.insert((0, path), id);
    }
    let mut rng = Rng(seed | 1);
    for from in 0..node_count {
        for _ in 0..edges_per_node {
            let to = (rng.next() as usize) % node_count;
            graph.edges[from].insert(
                to as NodeId,
                EdgeMeta {
                    kind: EdgeKind::Direct,
                    call_site: SourceLocation::new("bench.rs", 1, 1),
                },
            );
        }
    }
    graph
}

fn bench_graph_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_construction");
    for size in [1_000, 10_000, 100_000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| synthetic(size, 2, 42));
        });
    }
    group.finish();
}

fn bench_reachability(c: &mut Criterion) {
    let mut group = c.benchmark_group("reachability");
    for size in [1_000, 10_000, 100_000] {
        let graph = synthetic(size, 2, 42);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| Reachability::compute(&graph, &[0]));
        });
    }
    group.finish();
}

fn bench_path_reconstruction(c: &mut Criterion) {
    let graph = synthetic(100_000, 2, 42);
    let reach = Reachability::compute(&graph, &[0]);
    // Reconstruct paths for a sample of reachable nodes.
    let targets: Vec<NodeId> = (0..100_000 as NodeId).step_by(997).collect();
    c.bench_function("path_reconstruction_100k", |b| {
        b.iter(|| {
            for &target in &targets {
                let _ = reach.path_to(&graph, target);
            }
        });
    });
}

criterion_group!(
    benches,
    bench_graph_construction,
    bench_reachability,
    bench_path_reconstruction
);
criterion_main!(benches);
