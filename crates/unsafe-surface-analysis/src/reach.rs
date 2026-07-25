//! Reachability analysis and call-path reconstruction.
//!
//! Multi-source breadth-first search from the selected entry points. BFS
//! yields *shortest* paths (in number of calls), which are the most
//! relevant for auditing: the shortest path to an unsafe operation is the
//! easiest one to review. Determinism comes from the graph's ordered
//! adjacency maps: ties between equal-length paths are broken by node id.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use unsafe_surface_core::PathStep;

use crate::graph::{CallGraph, EdgeMeta, NodeId};

/// The result of a reachability computation.
#[derive(Debug, Default)]
pub struct Reachability {
    /// Reachable nodes.
    reachable: BTreeSet<NodeId>,
    /// BFS tree: node → (parent, edge from parent). Used to reconstruct
    /// one shortest path per node.
    parent: BTreeMap<NodeId, (NodeId, EdgeMeta)>,
    /// Entry-point nodes the search started from.
    entries: Vec<NodeId>,
}

impl Reachability {
    /// Computes reachability from `entries` over `graph`.
    #[must_use]
    pub fn compute(graph: &CallGraph, entries: &[NodeId]) -> Self {
        let mut result = Reachability::default();
        let mut queue = VecDeque::new();
        for &entry in entries {
            if entry as usize >= graph.nodes.len() || !result.reachable.insert(entry) {
                continue;
            }
            result.entries.push(entry);
            queue.push_back(entry);
        }
        while let Some(current) = queue.pop_front() {
            for (&next, meta) in &graph.edges[current as usize] {
                if result.reachable.insert(next) {
                    result.parent.insert(next, (current, meta.clone()));
                    queue.push_back(next);
                }
            }
        }
        result
    }

    /// Whether the node is reachable from an entry point.
    #[must_use]
    pub fn is_reachable(&self, node: NodeId) -> bool {
        self.reachable.contains(&node)
    }

    /// Number of reachable nodes.
    #[must_use]
    pub fn reachable_count(&self) -> usize {
        self.reachable.len()
    }

    /// Reconstructs one shortest call path from an entry point to `node`.
    ///
    /// Returns `None` when the node is not reachable. The path starts at
    /// an entry point and ends at `node`; each step carries the call site
    /// and edge confidence leading to the *next* step.
    #[must_use]
    pub fn path_to(&self, graph: &CallGraph, node: NodeId) -> Option<Vec<PathStep>> {
        if !self.is_reachable(node) {
            return None;
        }
        // Walk the BFS tree from the node up to an entry.
        let mut chain = vec![node];
        let mut edge_metas = Vec::new();
        let mut current = node;
        while let Some((parent, meta)) = self.parent.get(&current) {
            chain.push(*parent);
            edge_metas.push(meta.clone());
            current = *parent;
        }
        chain.reverse();
        edge_metas.reverse();

        let mut steps = Vec::with_capacity(chain.len());
        for (index, &id) in chain.iter().enumerate() {
            let meta = edge_metas.get(index);
            steps.push(PathStep {
                item: graph.nodes[id as usize].path.clone(),
                call_site: meta.map(|m| m.call_site.clone()),
                edge_confidence: meta.map(|m| m.kind.confidence()),
            });
        }
        Some(steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use unsafe_surface_core::{
        DependencyOrigin, EdgeKind, FunctionKind, ItemPath, PackageId, SourceLocation,
    };

    /// Builds a synthetic graph from an edge list. Node `i` is named
    /// `t::f<i>`; every node exists even without edges.
    fn synthetic(node_count: usize, edge_list: &[(usize, usize)]) -> CallGraph {
        let mut graph = CallGraph::default();
        let package = PackageId::new("t", Some("0.1.0".into()), DependencyOrigin::Workspace);
        graph.instances.push(crate::graph::InstanceInfo {
            crate_name: "t".into(),
            is_lib: true,
            package: package.clone(),
        });
        for i in 0..node_count {
            let path = vec![format!("f{i}")];
            let id = graph.nodes.len() as NodeId;
            graph.nodes.push(crate::graph::GraphNode {
                path: ItemPath::new("t", path.clone()),
                instance: 0,
                package: package.clone(),
                kind: FunctionKind::Free,
                is_pub: true,
                is_unsafe_fn: false,
                location: SourceLocation::new("t.rs", 1, 1),
                ops: Vec::new(),
            });
            graph.edges.push(BTreeMap::new());
            graph.index.insert((0, path), id);
        }
        for &(from, to) in edge_list {
            graph.edges[from].insert(
                to as NodeId,
                EdgeMeta {
                    kind: EdgeKind::Direct,
                    call_site: SourceLocation::new("t.rs", 1, 1),
                },
            );
        }
        graph
    }

    /// Reference implementation: naive transitive closure.
    fn naive_reachable(graph: &CallGraph, entries: &[NodeId]) -> BTreeSet<NodeId> {
        let mut seen: BTreeSet<NodeId> = entries.iter().copied().collect();
        let mut work = true;
        while work {
            work = false;
            for (id, _) in graph.nodes.iter().enumerate() {
                if seen.contains(&(id as NodeId)) {
                    for &next in graph.edges[id].keys() {
                        work |= seen.insert(next);
                    }
                }
            }
        }
        seen
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn reachability_matches_naive_closure(
            node_count in 1usize..40,
            edge_list in prop::collection::vec(0usize..40, 0..80usize)
                .prop_map(|v| v)
                .prop_flat_map(|_| prop::collection::vec((0usize..40, 0usize..40), 0..80)),
            entries in prop::collection::vec(0usize..40, 0..5),
        ) {
            let node_count = node_count.max(1);
            let edges: Vec<(usize, usize)> = edge_list
                .into_iter()
                .map(|(a, b)| (a % node_count, b % node_count))
                .collect();
            let entries: Vec<NodeId> = entries
                .into_iter()
                .map(|e| (e % node_count) as NodeId)
                .collect();
            let graph = synthetic(node_count, &edges);
            let reach = Reachability::compute(&graph, &entries);
            let naive = naive_reachable(&graph, &entries);
            for id in 0..node_count as NodeId {
                prop_assert_eq!(
                    reach.is_reachable(id),
                    naive.contains(&id),
                    "node {} disagreement",
                    id
                );
            }
        }

        #[test]
        fn reconstructed_paths_are_valid(
            node_count in 2usize..30,
            edge_list in prop::collection::vec((0usize..30, 0usize..30), 0..60),
            entry in 0usize..30,
        ) {
            let edges: Vec<(usize, usize)> = edge_list
                .into_iter()
                .map(|(a, b)| (a % node_count, b % node_count))
                .collect();
            let entry = (entry % node_count) as NodeId;
            let graph = synthetic(node_count, &edges);
            let reach = Reachability::compute(&graph, &[entry]);

            for id in 0..node_count as NodeId {
                match reach.path_to(&graph, id) {
                    Some(steps) => {
                        // Path starts at the entry and ends at the node…
                        let ids: Vec<NodeId> = steps
                            .iter()
                            .map(|s| graph.node(&s.item).unwrap())
                            .collect();
                        prop_assert_eq!(ids.first(), Some(&entry));
                        prop_assert_eq!(ids.last(), Some(&id));
                        // …and consecutive steps are real edges.
                        for pair in ids.windows(2) {
                            prop_assert!(
                                graph.edges[pair[0] as usize].contains_key(&pair[1]),
                                "missing edge {} -> {}", pair[0], pair[1]
                            );
                        }
                        // BFS yields shortest paths: length - 1 == BFS depth.
                        let mut depth = 0;
                        let mut current = id;
                        while let Some((parent, _)) = reach.parent.get(&current) {
                            depth += 1;
                            current = *parent;
                        }
                        prop_assert_eq!(steps.len(), depth + 1);
                    }
                    None => prop_assert!(!reach.is_reachable(id)),
                }
            }
        }

        #[test]
        fn empty_entries_reach_nothing(edge_list in prop::collection::vec((0usize..10, 0usize..10), 0..20)) {
            let edges: Vec<(usize, usize)> = edge_list
                .into_iter()
                .map(|(a, b)| (a % 10, b % 10))
                .collect();
            let graph = synthetic(10, &edges);
            let reach = Reachability::compute(&graph, &[]);
            prop_assert_eq!(reach.reachable_count(), 0);
            for id in 0..10 as NodeId {
                prop_assert!(reach.path_to(&graph, id).is_none());
            }
        }
    }

    #[test]
    fn shortest_path_prefers_direct_route() {
        // 0 -> 1 -> 3 and 0 -> 2 -> 3 and 0 -> 3: path to 3 is [0, 3].
        let graph = synthetic(4, &[(0, 1), (1, 3), (0, 2), (2, 3), (0, 3)]);
        let reach = Reachability::compute(&graph, &[0]);
        let steps = reach.path_to(&graph, 3).unwrap();
        let names: Vec<String> = steps.iter().map(|s| s.item.to_string()).collect();
        assert_eq!(names, vec!["t::f0", "t::f3"]);
        // The last step carries no edge metadata.
        assert!(steps.last().unwrap().call_site.is_none());
        assert!(steps.last().unwrap().edge_confidence.is_none());
    }

    #[test]
    fn cycles_do_not_loop() {
        let graph = synthetic(3, &[(0, 1), (1, 2), (2, 0)]);
        let reach = Reachability::compute(&graph, &[0]);
        assert_eq!(reach.reachable_count(), 3);
        let steps = reach.path_to(&graph, 2).unwrap();
        assert_eq!(steps.len(), 3);
    }
}
