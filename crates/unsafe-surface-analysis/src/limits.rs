//! Resource limits protecting the analyser from hostile or pathological
//! input.
//!
//! The analysed repository is untrusted input: a malicious or generated
//! crate could contain gigantic files, pathologically deep module trees or
//! cyclic `mod` declarations. Every limit breach is reported as a
//! diagnostic and the offending unit is skipped — the analyser must never
//! abort, loop forever or exhaust memory because of input shape.

/// Configurable analysis limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size of a single source file. Larger files are skipped with
    /// a diagnostic. Default: 4 MiB (far above any hand-written Rust file;
    /// large generated files should be reviewed with a dedicated process).
    pub max_file_bytes: u64,
    /// Maximum number of files parsed per crate. Default: 20 000.
    pub max_files_per_crate: usize,
    /// Maximum module nesting depth. Cycles are also caught by canonical
    /// path tracking; this catches non-file cycles such as inline modules.
    /// Default: 64.
    pub max_module_depth: usize,
    /// Maximum number of files parsed across the whole analysis run.
    /// Default: 200 000.
    pub max_total_files: usize,
    /// Maximum number of call-graph nodes. Default: 1 000 000.
    pub max_graph_nodes: usize,
    /// Maximum number of unresolved calls listed in a report (the total is
    /// always recorded). Default: 1 000.
    pub max_unresolved_calls_listed: usize,
    /// Maximum number of findings listed in a report (counts in the summary
    /// always reflect the full analysis). Default: 100 000.
    pub max_findings_listed: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 4 * 1024 * 1024,
            max_files_per_crate: 20_000,
            max_module_depth: 64,
            max_total_files: 200_000,
            max_graph_nodes: 1_000_000,
            max_unresolved_calls_listed: 1_000,
            max_findings_listed: 100_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let limits = Limits::default();
        assert!(limits.max_file_bytes >= 1024 * 1024);
        assert!(limits.max_files_per_crate >= 1_000);
        assert!(limits.max_module_depth >= 16);
        assert!(limits.max_total_files >= limits.max_files_per_crate);
    }
}
