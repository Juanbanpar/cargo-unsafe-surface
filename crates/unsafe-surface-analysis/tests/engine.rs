//! End-to-end engine tests: discovery → parse → classify → graph →
//! reachability → report, over a real (temporary) Cargo workspace.

use std::fs;
use std::path::Path;

use unsafe_surface_analysis::{analyze, AnalysisConfig};
use unsafe_surface_cargo::{discover, query_rustc_cfg, DiscoveryOptions};
use unsafe_surface_core::{Reachability, UnsafeOpKind};

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// Builds the test workspace:
///
/// * `server` (bin) depends on `netlib` and `ffiwrap` (path deps);
/// * `netlib` (lib) has a safe wrapper around unsafe code, a manual Send
///   impl and an unreachable unsafe fn;
/// * `ffiwrap` (lib) wraps a foreign `socket` call;
/// * `ghost` (lib) is a workspace member nothing depends on.
fn make_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write(
        &root.join("Cargo.toml"),
        r#"
[workspace]
resolver = "2"
members = ["server", "netlib", "ffiwrap", "ghost"]
"#,
    );
    write(
        &root.join("server/Cargo.toml"),
        r#"
[package]
name = "server"
version = "0.1.0"
edition = "2021"

[dependencies]
netlib = { path = "../netlib" }
ffiwrap = { path = "../ffiwrap" }
"#,
    );
    write(
        &root.join("server/src/main.rs"),
        r#"
fn main() {
    netlib::run();
    ffiwrap::create_socket();
    ghost_call();
}

fn ghost_call() {
    does_not_exist();
}
"#,
    );
    write(
        &root.join("netlib/Cargo.toml"),
        r#"
[package]
name = "netlib"
version = "0.2.0"
edition = "2021"
"#,
    );
    write(
        &root.join("netlib/src/lib.rs"),
        r#"
pub struct Handle(*mut u8);
// SAFETY: the pointer is never dereferenced.
unsafe impl Send for Handle {}

pub fn run() {
    // SAFETY: header layout is checked above.
    unsafe { parse_header() };
}

/// # Safety
/// Caller must uphold the header invariants.
unsafe fn parse_header() {}

pub fn unused_unsafe_api() {
    unsafe { parse_header() };
}
"#,
    );
    write(
        &root.join("ffiwrap/Cargo.toml"),
        r#"
[package]
name = "ffiwrap"
version = "0.3.0"
edition = "2021"
"#,
    );
    write(
        &root.join("ffiwrap/src/lib.rs"),
        r#"
extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
}

pub fn create_socket() -> i32 {
    // SAFETY: arguments are always valid constants.
    unsafe { socket(2, 1, 0) }
}

pub fn never_called() -> i32 {
    unsafe { socket(2, 1, 0) }
}
"#,
    );
    write(
        &root.join("ghost/Cargo.toml"),
        r#"
[package]
name = "ghost"
version = "0.4.0"
edition = "2021"
"#,
    );
    write(
        &root.join("ghost/src/lib.rs"),
        r#"
pub fn haunted() {
    unsafe { core::ptr::read(0 as *const u8) };
}
"#,
    );

    dir
}

fn run(include_dependencies: bool) -> unsafe_surface_analysis::AnalysisOutcome {
    let dir = make_workspace();
    let options = DiscoveryOptions {
        manifest_path: Some(dir.path().join("Cargo.toml")),
        // Restricting to `server` makes non-selected workspace members
        // behave like (unanalysed) dependencies unless
        // `include_dependencies` pulls them into the universe.
        packages: vec!["server".to_owned()],
        offline: true,
        ..DiscoveryOptions::default()
    };
    let workspace = discover(&options, include_dependencies, false).unwrap();
    let targets = workspace.select_targets(false, &[]).unwrap();
    let cfg = query_rustc_cfg(None).unwrap();
    let config = AnalysisConfig {
        include_dependencies,
        ..AnalysisConfig::default()
    };
    // Keep the tempdir alive for the duration of the analysis.
    let outcome = analyze(&workspace, &targets, &cfg, &config).unwrap();
    drop(dir);
    outcome
}

#[test]
fn end_to_end_without_dependencies() {
    let outcome = run(false);
    let report = &outcome.report;

    // Entry point: the server's main.
    assert_eq!(report.entry_points.len(), 1);
    assert_eq!(report.entry_points[0].item.to_string(), "server::main");

    // Findings are only from the server crate itself (deps not analysed).
    assert!(report.findings.iter().all(|f| f.package.name == "server"));
    // The call into the unanalysed dep is unresolved.
    assert!(report
        .unresolved_calls
        .iter()
        .any(|u| u.callee_text == "does_not_exist"));
}

#[test]
fn end_to_end_with_dependencies() {
    let outcome = run(true);
    let report = &outcome.report;

    // Reachable unsafe operations from server::main.
    assert!(report.summary.reachable_unsafe_operations >= 3);
    assert_eq!(report.summary.reachable_ffi_calls, 1);
    assert_eq!(report.summary.manual_send_sync_impls, 1);

    // The FFI call is reachable with a full path across crates.
    let ffi = report
        .findings
        .iter()
        .find(|f| f.operation.kind == UnsafeOpKind::FfiCall)
        .expect("no FFI finding");
    assert_eq!(ffi.reachability, Reachability::Reachable);
    assert_eq!(ffi.package.name, "ffiwrap");
    let path = ffi.path.as_ref().expect("reachable finding has a path");
    let names: Vec<String> = path.iter().map(|s| s.item.to_string()).collect();
    assert_eq!(names, vec!["server::main", "ffiwrap::create_socket",]);
    assert_eq!(ffi.operation.detail.as_deref(), Some("ffiwrap::socket"));
    assert_eq!(
        ffi.operation.justification,
        unsafe_surface_core::SafetyJustification::Present
    );

    // The unsafe fn call inside netlib::run is reachable too.
    let unsafe_call = report
        .findings
        .iter()
        .find(|f| f.operation.kind == UnsafeOpKind::UnsafeFnCall)
        .expect("no UnsafeFnCall finding");
    let names: Vec<String> = unsafe_call
        .path
        .as_ref()
        .unwrap()
        .iter()
        .map(|s| s.item.to_string())
        .collect();
    assert_eq!(names, vec!["server::main", "netlib::run"]);

    // `ffiwrap::never_called` is unreachable: its FFI call is reported as
    // unreachable, distinctly from reachable findings.
    let unreachable: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.reachability == Reachability::Unreachable)
        .collect();
    assert!(!unreachable.is_empty());
    assert!(unreachable.iter().any(|f| {
        f.operation.kind == UnsafeOpKind::FfiCall
            && f.enclosing_item.to_string() == "ffiwrap::never_called"
    }));
    assert!(unreachable.iter().all(|f| f.path.is_none()));

    // The ghost workspace member is not a dependency of server, so it is
    // outside the analysis universe entirely.
    assert!(!unreachable.iter().any(|f| f.package.name == "ghost"));
    assert!(report.packages.iter().all(|p| p.id.name != "ghost"));

    // Structural findings: the Send impl.
    assert!(report
        .structural_findings
        .iter()
        .any(|s| s.kind == UnsafeOpKind::SendImpl && s.package.name == "netlib"));

    // Report serializes and round-trips.
    let json = serde_json::to_string_pretty(report).unwrap();
    let parsed: unsafe_surface_core::ReportModel = serde_json::from_str(&json).unwrap();
    assert_eq!(*report, parsed);
}

#[test]
fn explicit_entry_points_are_resolved() {
    let dir = make_workspace();
    let options = DiscoveryOptions {
        manifest_path: Some(dir.path().join("Cargo.toml")),
        offline: true,
        ..DiscoveryOptions::default()
    };
    let workspace = discover(&options, true, false).unwrap();
    let targets = workspace.select_targets(false, &[]).unwrap();
    let cfg = query_rustc_cfg(None).unwrap();
    let config = AnalysisConfig {
        include_dependencies: true,
        explicit_entries: vec!["netlib::run".to_owned(), "not::real".to_owned()],
        ..AnalysisConfig::default()
    };
    let outcome = analyze(&workspace, &targets, &cfg, &config).unwrap();
    let report = &outcome.report;

    // Both the default bin main and the explicit entry are present.
    assert!(report
        .entry_points
        .iter()
        .any(|e| e.item.to_string() == "netlib::run"));
    assert!(report
        .entry_points
        .iter()
        .any(|e| e.item.to_string() == "server::main"));
    // The unknown entry produced a diagnostic.
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("not::real")));
}

#[test]
fn lib_entry_selects_public_api() {
    let dir = make_workspace();
    let options = DiscoveryOptions {
        manifest_path: Some(dir.path().join("Cargo.toml")),
        packages: vec!["netlib".to_owned()],
        offline: true,
        ..DiscoveryOptions::default()
    };
    let workspace = discover(&options, false, false).unwrap();
    let targets = workspace.select_targets(true, &[]).unwrap();
    let cfg = query_rustc_cfg(None).unwrap();
    let outcome = analyze(&workspace, &targets, &cfg, &AnalysisConfig::default()).unwrap();
    let report = &outcome.report;

    // Public fns of netlib are entry points…
    let entries: Vec<String> = report
        .entry_points
        .iter()
        .map(|e| e.item.to_string())
        .collect();
    assert!(entries.contains(&"netlib::run".to_owned()), "{entries:?}");
    assert!(entries.contains(&"netlib::unused_unsafe_api".to_owned()));
    // …which makes the previously-unreachable unsafe call reachable.
    assert!(report
        .findings
        .iter()
        .all(|f| f.reachability == Reachability::Reachable
            || f.operation.kind != UnsafeOpKind::UnsafeFnCall));
}
