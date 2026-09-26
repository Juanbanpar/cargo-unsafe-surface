//! Integration tests for workspace discovery against temporary workspaces.
//!
//! These tests run `cargo metadata` in offline mode; they never touch the
//! network and never execute code from the analysed fixtures.

use std::fs;
use std::path::Path;

use unsafe_surface_cargo::{discover, CargoError, DiscoveryOptions, TargetKind};

/// Writes a file, creating parent directories.
fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// Builds a temporary workspace:
///
/// ```text
/// app  (bin) ──depends on──▶ util (lib)
///  └─dev-depends on────────▶ devutil (lib)
/// ghost (lib, workspace member, nothing depends on it)
/// ```
///
/// `app` declares a default and a non-default feature so feature selection
/// can be asserted (`default = ["legacy"]`, plus `secure`).
fn make_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write(
        &root.join("Cargo.toml"),
        r#"
[workspace]
resolver = "2"
members = ["app", "util", "devutil", "ghost"]
"#,
    );

    write(
        &root.join("app/Cargo.toml"),
        r#"
[package]
name = "app"
version = "0.1.0"
edition = "2021"

[features]
default = ["legacy"]
legacy = []
secure = []

[dependencies]
util = { path = "../util" }

[dev-dependencies]
devutil = { path = "../devutil" }
"#,
    );
    write(&root.join("app/src/main.rs"), "fn main() {}\n");

    write(
        &root.join("util/Cargo.toml"),
        r#"
[package]
name = "util"
version = "0.2.0"
edition = "2021"
"#,
    );
    write(&root.join("util/src/lib.rs"), "pub fn helper() {}\n");

    write(
        &root.join("devutil/Cargo.toml"),
        r#"
[package]
name = "devutil"
version = "0.3.0"
edition = "2021"
"#,
    );
    write(&root.join("devutil/src/lib.rs"), "pub fn dev_helper() {}\n");

    write(
        &root.join("ghost/Cargo.toml"),
        r#"
[package]
name = "ghost"
version = "0.4.0"
edition = "2021"
"#,
    );
    write(&root.join("ghost/src/lib.rs"), "pub fn unused() {}\n");

    dir
}

fn options(root: &Path) -> DiscoveryOptions {
    DiscoveryOptions {
        manifest_path: Some(root.join("Cargo.toml")),
        offline: true,
        ..DiscoveryOptions::default()
    }
}

#[test]
fn discovers_workspace_members_and_targets() {
    let dir = make_workspace();
    let ws = discover(&options(dir.path()), false, false).unwrap();

    assert_eq!(ws.packages.len(), 4);
    assert_eq!(ws.selected.len(), 4);
    assert!(ws.warnings.is_empty(), "warnings: {:?}", ws.warnings);

    let app = ws.package_by_name("app").unwrap();
    assert_eq!(app.bin_targets.len(), 1);
    assert_eq!(app.bin_targets[0].0, "app");
    assert!(app.sources_available);

    let targets = ws.select_targets(false, &[]).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].name, "app");
    assert_eq!(targets[0].kind, TargetKind::Bin);
}

#[test]
fn selects_lib_targets_when_requested() {
    let dir = make_workspace();
    let ws = discover(&options(dir.path()), false, false).unwrap();

    let targets = ws.select_targets(true, &[]).unwrap();
    assert_eq!(targets.len(), 3);
    assert!(targets.iter().all(|t| t.kind == TargetKind::Lib));
}

#[test]
fn package_selection_is_honored() {
    let dir = make_workspace();
    let mut opts = options(dir.path());
    opts.packages = vec!["util".to_owned()];
    let ws = discover(&opts, false, false).unwrap();

    assert_eq!(ws.selected.len(), 1);
    assert_eq!(ws.selected[0].name, "util");

    // Default target selection for a lib-only package is its lib.
    let targets = ws.select_targets(false, &[]).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].kind, TargetKind::Lib);
}

#[test]
fn unknown_package_is_an_error() {
    let dir = make_workspace();
    let mut opts = options(dir.path());
    opts.packages = vec!["nope".to_owned()];
    let err = discover(&opts, false, false).unwrap_err();
    assert!(matches!(err, CargoError::UnknownPackage(name) if name == "nope"));
}

#[test]
fn unknown_bin_target_is_an_error() {
    let dir = make_workspace();
    let ws = discover(&options(dir.path()), false, false).unwrap();
    let err = ws.select_targets(false, &["nope".to_owned()]).unwrap_err();
    assert!(matches!(err, CargoError::TargetNotFound { .. }));
}

#[test]
fn dependency_closure_includes_normal_deps_only_by_default() {
    let dir = make_workspace();
    let mut opts = options(dir.path());
    opts.packages = vec!["app".to_owned()];

    let ws = discover(&opts, true, false).unwrap();
    let names: Vec<&str> = ws.packages.iter().map(|p| p.id.name.as_str()).collect();
    assert_eq!(names, ["app", "util"], "dev-deps must be excluded");

    let ws = discover(&opts, true, true).unwrap();
    let names: Vec<&str> = ws.packages.iter().map(|p| p.id.name.as_str()).collect();
    assert_eq!(names, ["app", "devutil", "util"]);
}

#[test]
fn origins_are_classified() {
    let dir = make_workspace();
    let ws = discover(&options(dir.path()), true, false).unwrap();
    for package in &ws.packages {
        assert_eq!(
            package.id.origin,
            unsafe_surface_core::DependencyOrigin::Workspace
        );
    }
}

#[test]
fn feature_flags_are_combined() {
    let dir = make_workspace();
    let enabled = |opts: DiscoveryOptions| {
        let ws = discover(&opts, false, false).unwrap();
        ws.package_by_name("app")
            .unwrap()
            .enabled_features
            .iter()
            .cloned()
            .collect::<Vec<String>>()
    };

    // Default features only.
    assert_eq!(enabled(options(dir.path())), ["default", "legacy"]);

    // `--no-default-features --features x` must keep the explicit set:
    // the flags are not mutually exclusive.
    let mut opts = options(dir.path());
    opts.no_default_features = true;
    opts.features = vec!["secure".to_owned()];
    assert_eq!(enabled(opts), ["secure"]);

    // Disabling defaults alone leaves nothing enabled.
    let mut opts = options(dir.path());
    opts.no_default_features = true;
    assert!(enabled(opts).is_empty());

    // `--all-features` still combines with the other flags.
    let mut opts = options(dir.path());
    opts.no_default_features = true;
    opts.all_features = true;
    assert_eq!(enabled(opts), ["default", "legacy", "secure"]);
}
