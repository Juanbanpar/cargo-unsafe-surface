//! End-to-end CLI tests: the real binary against the fixture workspace.
//!
//! Tests are deterministic, offline (`CARGO_NET_OFFLINE=true`) and never
//! build the fixtures — the analyser only parses them.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Path to the compiled `cargo-unsafe-surface` binary.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cargo-unsafe-surface")
}

/// Path to the fixture workspace manifest.
fn fixture_manifest() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/demo-workspace/Cargo.toml")
        .canonicalize()
        .expect("fixture workspace must exist")
}

/// Runs the CLI with the given arguments; returns (exit code, stdout, stderr).
fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(binary())
        .arg("unsafe-surface")
        .args(args)
        .env("CARGO_NET_OFFLINE", "true")
        .output()
        .expect("failed to run the CLI");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn base_args() -> Vec<String> {
    vec![
        "--manifest-path".into(),
        fixture_manifest().display().to_string(),
        "--package".into(),
        "server".into(),
        "--offline".into(),
    ]
}

#[test]
fn default_run_reports_entry_point_and_summary() {
    let args = base_args();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, stdout, stderr) = run(&args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("Unsafe Surface Report"));
    assert!(stdout.contains("  server::main"));
    assert!(stdout.contains("Summary:"));
    assert!(stdout.contains("Analysis limitations:"));
}

#[test]
fn include_dependencies_reports_ffi_paths_and_unreachable() {
    let mut args = base_args();
    args.push("--include-dependencies".into());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, stdout, stderr) = run(&args);
    assert_eq!(code, 0, "stderr: {stderr}");

    // Reachable FFI call with a full cross-crate path.
    assert!(stdout.contains("Kind:          FFI call"));
    assert!(stdout.contains("Target:        ffiwrap::socket"));
    assert!(stdout.contains("-> ffiwrap::create_socket"));
    assert!(stdout.contains("-> ffiwrap::socket"));

    // Safe wrappers are surfaced as paths through unsafe code.
    assert!(stdout.contains("-> netlib::run"));
    assert!(stdout.contains("netlib::socket::sys::open_raw"));

    // Unreachable unsafe code is distinguished from reachable code.
    assert!(stdout.contains("Unreachable unsafe operations:"));
    assert!(stdout.contains("ffiwrap::never_called — FFI call"));
    assert!(stdout.contains("server::dead_unsafe — unsafe function"));

    // Structural findings include the manual Send/Sync impls.
    assert!(stdout.contains("[manual Send implementation] netlib 0.2.0"));
    assert!(stdout.contains("[manual Sync implementation] netlib 0.2.0"));
    assert!(stdout.contains("[unsafe trait] netlib 0.2.0"));

    // Unresolved calls carry reasons. (The 2-candidate ambiguity in the
    // fixture becomes inferred may-call edges; large ambiguity sets and
    // other kinds stay unresolved — both covered by unit tests.)
    assert!(stdout.contains("function pointer"));
    assert!(stdout.contains("dynamic dispatch"));
}

#[test]
fn json_output_matches_schema() {
    let mut args = base_args();
    args.extend([
        "--include-dependencies".into(),
        "--format".into(),
        "json".into(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, stdout, stderr) = run(&args);
    assert_eq!(code, 0, "stderr: {stderr}");

    let report: unsafe_surface_core::ReportModel =
        serde_json::from_str(&stdout).expect("stdout must be valid report JSON");
    assert_eq!(report.schema_version, 1);
    assert_eq!(report.tool.name, "cargo-unsafe-surface");
    assert!(report.configuration.include_dependencies);
    assert_eq!(report.entry_points.len(), 1);
    assert_eq!(report.entry_points[0].item.to_string(), "server::main");

    use unsafe_surface_core::{Reachability, UnsafeOpKind};
    let ffi = report
        .findings
        .iter()
        .find(|f| {
            f.operation.kind == UnsafeOpKind::FfiCall && f.reachability == Reachability::Reachable
        })
        .expect("no reachable FFI finding");
    let path = ffi.path.as_ref().unwrap();
    assert_eq!(path[0].item.to_string(), "server::main");
    assert_eq!(path[1].item.to_string(), "ffiwrap::create_socket");
    assert_eq!(ffi.package.name, "ffiwrap");

    assert!(report
        .findings
        .iter()
        .any(|f| f.reachability == Reachability::Unreachable));
    assert!(!report.unresolved_calls.is_empty());
    assert!(!report.limitations.is_empty());
    assert!(report.summary.reachable_ffi_calls >= 1);
}

#[test]
fn explicit_entry_point_is_used() {
    let mut args = base_args();
    args.extend([
        "--include-dependencies".into(),
        "--entry".into(),
        "netlib::as_int".into(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, stdout, stderr) = run(&args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("  netlib::as_int"));
    // The union field access is now reachable.
    assert!(stdout.contains("Kind:          union field access"));
}

#[test]
fn lib_target_selects_public_api() {
    let manifest = fixture_manifest();
    let args = [
        "--manifest-path",
        &manifest.display().to_string(),
        "--package",
        "netlib",
        "--lib",
        "--offline",
    ];
    let (code, stdout, stderr) = run(&args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("  netlib::run"));
    assert!(stdout.contains("  netlib::as_int"));
}

#[test]
fn broken_package_reports_syntax_error_diagnostic() {
    let manifest = fixture_manifest();
    let args = [
        "--manifest-path",
        &manifest.display().to_string(),
        "--package",
        "broken",
        "--lib",
        "--offline",
    ];
    let (code, stdout, stderr) = run(&args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("syntax error"));
    // The healthy function is still analysed.
    assert!(stdout.contains("broken::healthy"));
}

#[test]
fn policy_violations_exit_with_code_2() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        "[policy]\nmaximum_reachable_ffi_calls = 0\nrequire_safety_comments = false\n",
    )
    .unwrap();

    let mut args = base_args();
    args.extend([
        "--include-dependencies".into(),
        "--policy".into(),
        policy.display().to_string(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _stdout, stderr) = run(&args);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stderr.contains("maximum_reachable_ffi_calls"));
}

#[test]
fn passing_policy_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(&policy, "[policy]\nmaximum_reachable_ffi_calls = 99\n").unwrap();

    let mut args = base_args();
    args.extend([
        "--include-dependencies".into(),
        "--policy".into(),
        policy.display().to_string(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _stdout, stderr) = run(&args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stderr.contains("policy: OK"));
}

#[test]
fn invalid_policy_is_an_operational_error() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(&policy, "[policy]\nnot_a_real_rule = true\n").unwrap();

    let mut args = base_args();
    args.extend(["--policy".into(), policy.display().to_string()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _stdout, stderr) = run(&args);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("invalid policy"));
}

#[test]
fn bad_manifest_path_is_an_operational_error() {
    let args = ["--manifest-path", "/nonexistent/Cargo.toml", "--offline"];
    let (code, _stdout, stderr) = run(&args);
    assert_eq!(code, 1);
    assert!(stderr.contains("error:"));
}

#[test]
fn output_file_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("report.json");
    let mut args = base_args();
    args.extend([
        "--format".into(),
        "json".into(),
        "--output".into(),
        output.display().to_string(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, stdout, stderr) = run(&args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout must stay empty with --output");
    let written = std::fs::read_to_string(&output).unwrap();
    let _: unsafe_surface_core::ReportModel = serde_json::from_str(&written).unwrap();
}

#[test]
fn output_is_deterministic_across_runs() {
    let mut args = base_args();
    args.extend([
        "--include-dependencies".into(),
        "--format".into(),
        "json".into(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code_a, stdout_a, _) = run(&args);
    let (code_b, stdout_b, _) = run(&args);
    assert_eq!(code_a, 0);
    assert_eq!(code_b, 0);
    assert_eq!(stdout_a, stdout_b);
}

#[test]
fn exclude_dev_dependencies_flag_is_accepted() {
    let mut args = base_args();
    args.push("--exclude-dev-dependencies".into());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _stdout, stderr) = run(&args);
    assert_eq!(code, 0, "stderr: {stderr}");
}
