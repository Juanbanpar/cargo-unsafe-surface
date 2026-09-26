//! Workspace discovery on top of `cargo metadata`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;

use camino::Utf8PathBuf;
use cargo_metadata::{CargoOpt, DependencyKind, Metadata, MetadataCommand, Package};
use unsafe_surface_core::{DependencyOrigin, PackageId};

use crate::error::CargoError;

/// Options controlling workspace discovery.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryOptions {
    /// Path to the workspace manifest (`Cargo.toml`). Defaults to the
    /// current directory's manifest.
    pub manifest_path: Option<PathBuf>,
    /// Package names selected with `--package`. Empty means the workspace
    /// default members (or all members when no default is declared).
    pub packages: Vec<String>,
    /// Cargo features to enable.
    pub features: Vec<String>,
    /// Enable all features.
    pub all_features: bool,
    /// Disable default features.
    pub no_default_features: bool,
    /// Pass `--offline` to Cargo so dependency resolution never touches the
    /// network.
    pub offline: bool,
}

/// The kind of a selected compilation target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A library target (`--lib`).
    Lib,
    /// A binary target (`--bin`).
    Bin,
}

impl TargetKind {
    /// Label used in error messages.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Lib => "lib",
            Self::Bin => "bin",
        }
    }
}

/// A compilation target selected for analysis.
#[derive(Debug, Clone)]
pub struct SelectedTarget {
    /// The package owning the target.
    pub package: PackageId,
    /// Target name (`--bin NAME` uses this).
    pub name: String,
    /// Lib or bin.
    pub kind: TargetKind,
    /// The crate root source file (`src/lib.rs`, `src/main.rs`, …).
    pub root: Utf8PathBuf,
    /// Rust edition of the target.
    pub edition: String,
}

/// A package whose sources are part of the analysis universe.
#[derive(Debug, Clone)]
pub struct DiscoveredPackage {
    /// Package identity.
    pub id: PackageId,
    /// Directory containing the package manifest.
    pub manifest_dir: Utf8PathBuf,
    /// Crate root of the library target, if any.
    pub lib_root: Option<Utf8PathBuf>,
    /// Binary targets as `(name, crate root)` pairs, sorted by name.
    pub bin_targets: Vec<(String, Utf8PathBuf)>,
    /// Feature names enabled for this package after resolution.
    pub enabled_features: BTreeSet<String>,
    /// Rust edition.
    pub edition: String,
    /// Whether the package's source files are present on disk. Registry or
    /// git dependencies that were never downloaded have no readable
    /// sources; they are reported as diagnostics instead of being fetched.
    pub sources_available: bool,
}

/// The result of workspace discovery.
#[derive(Debug)]
pub struct DiscoveredWorkspace {
    /// Workspace root directory.
    pub workspace_root: Utf8PathBuf,
    /// All packages in the analysis universe: the selected workspace
    /// packages plus, when dependencies are analysed, the resolved
    /// dependency closure. Sorted by package name.
    pub packages: Vec<DiscoveredPackage>,
    /// The packages the user selected (subset of `packages`).
    pub selected: Vec<PackageId>,
    /// Non-fatal discovery issues (e.g. the resolve graph was unavailable
    /// and features were approximated).
    pub warnings: Vec<String>,
    /// Crate names (source-level, `-` normalized to `_`) of every package
    /// Cargo knows about, including dependencies that are not analysed.
    /// Lets the analysis report calls into unanalysed dependencies with a
    /// precise reason instead of "unknown name".
    pub all_dependency_crate_names: std::collections::BTreeSet<String>,
}

impl DiscoveredWorkspace {
    /// Looks up a discovered package by Cargo package name.
    #[must_use]
    pub fn package_by_name(&self, name: &str) -> Option<&DiscoveredPackage> {
        self.packages.iter().find(|p| p.id.name == name)
    }

    /// Resolves the bin/lib target selection against the selected packages.
    ///
    /// * With explicit `lib`/`bins`, exactly those targets are returned.
    ///   Target names filter across the selected packages (Cargo
    ///   semantics): a `--bin` name matches wherever it exists and is an
    ///   error only when no selected package provides it.
    /// * By default all binary targets of the selected packages are used;
    ///   if none exist, all library targets are used instead.
    ///
    /// # Errors
    ///
    /// Returns [`CargoError::TargetNotFound`] for `--bin` names no selected
    /// package provides, and [`CargoError::NoTargets`] when an explicit
    /// selection matches nothing at all.
    pub fn select_targets(
        &self,
        lib: bool,
        bins: &[String],
    ) -> Result<Vec<SelectedTarget>, CargoError> {
        let mut targets = Vec::new();
        let mut unmatched_bins: Vec<&String> = bins.iter().collect();
        for package in &self.packages {
            if !self.selected.contains(&package.id) {
                continue;
            }
            if lib {
                if let Some(root) = &package.lib_root {
                    targets.push(SelectedTarget {
                        package: package.id.clone(),
                        name: package.id.crate_name(),
                        kind: TargetKind::Lib,
                        root: root.clone(),
                        edition: package.edition.clone(),
                    });
                }
            }
            for (name, root) in &package.bin_targets {
                if !unmatched_bins.contains(&name) {
                    continue;
                }
                targets.push(SelectedTarget {
                    package: package.id.clone(),
                    name: name.clone(),
                    kind: TargetKind::Bin,
                    root: root.clone(),
                    edition: package.edition.clone(),
                });
                unmatched_bins.retain(|bin| *bin != name);
            }
        }
        if let Some(name) = unmatched_bins.first() {
            return Err(CargoError::TargetNotFound {
                name: (*name).clone(),
                kind: TargetKind::Bin.label(),
            });
        }
        if !lib && bins.is_empty() {
            // Default selection: all bins; fall back to all libs.
            for package in &self.packages {
                if !self.selected.contains(&package.id) {
                    continue;
                }
                for (name, root) in &package.bin_targets {
                    targets.push(SelectedTarget {
                        package: package.id.clone(),
                        name: name.clone(),
                        kind: TargetKind::Bin,
                        root: root.clone(),
                        edition: package.edition.clone(),
                    });
                }
            }
            if targets.is_empty() {
                for package in &self.packages {
                    if !self.selected.contains(&package.id) {
                        continue;
                    }
                    if let Some(root) = &package.lib_root {
                        targets.push(SelectedTarget {
                            package: package.id.clone(),
                            name: package.id.crate_name(),
                            kind: TargetKind::Lib,
                            root: root.clone(),
                            edition: package.edition.clone(),
                        });
                    }
                }
            }
        }
        targets.sort_by(|a, b| (&a.package.name, &a.name).cmp(&(&b.package.name, &b.name)));
        if targets.is_empty() {
            // The packages themselves were selected; the requested target
            // kinds are what did not match.
            return Err(CargoError::NoTargets);
        }
        Ok(targets)
    }
}

/// Runs workspace discovery with the given options.
///
/// `include_dev_dependencies` controls whether dev-dependency packages are
/// part of the analysis universe (they never ship in release artifacts, so
/// the default is to exclude them). Build dependencies are always excluded:
/// their unsafe code runs at compile time, not in the shipped artifact.
///
/// # Errors
///
/// Returns [`CargoError`] when `cargo metadata` fails or the requested
/// packages are not workspace members.
pub fn discover(
    options: &DiscoveryOptions,
    include_dependencies: bool,
    include_dev_dependencies: bool,
) -> Result<DiscoveredWorkspace, CargoError> {
    let metadata = load_metadata(options)?;
    let mut warnings = Vec::new();

    let workspace_members: BTreeSet<&cargo_metadata::PackageId> =
        metadata.workspace_members.iter().collect();

    // Package selection: explicit names must match workspace members.
    let selected: Vec<cargo_metadata::PackageId> = if options.packages.is_empty() {
        default_members(&metadata)
    } else {
        let mut selected = Vec::new();
        for name in &options.packages {
            match metadata
                .packages
                .iter()
                .find(|p| p.name == *name && workspace_members.contains(&p.id))
            {
                Some(package) => selected.push(package.id.clone()),
                None => return Err(CargoError::UnknownPackage(name.clone())),
            }
        }
        selected
    };
    if selected.is_empty() {
        return Err(CargoError::NoPackages);
    }

    // Determine the full analysis universe.
    let universe: Vec<cargo_metadata::PackageId> = if include_dependencies {
        match dependency_closure(&metadata, &selected, include_dev_dependencies) {
            Some(closure) => closure,
            None => {
                warnings.push(
                    "dependency resolve graph unavailable; only workspace packages are \
                     analysed and feature sets are approximated"
                        .to_owned(),
                );
                selected.clone()
            }
        }
    } else {
        selected.clone()
    };

    let resolved_features: BTreeMap<&cargo_metadata::PackageId, BTreeSet<String>> = metadata
        .resolve
        .as_ref()
        .map(|resolve| {
            resolve
                .nodes
                .iter()
                .map(|node| (&node.id, node.features.iter().cloned().collect()))
                .collect()
        })
        .unwrap_or_default();

    let mut packages = Vec::new();
    for id in &universe {
        let Some(package) = metadata.packages.iter().find(|p| &p.id == id) else {
            continue;
        };
        packages.push(discovered_package(
            package,
            &workspace_members,
            resolved_features.get(id),
        ));
    }
    packages.sort_by(|a, b| a.id.cmp(&b.id));

    let selected_ids = selected
        .iter()
        .filter_map(|id| metadata.packages.iter().find(|p| &p.id == id))
        .map(|p| core_package_id(p, &workspace_members))
        .collect();

    let all_dependency_crate_names = metadata
        .packages
        .iter()
        .map(|p| p.name.replace('-', "_"))
        .collect();

    Ok(DiscoveredWorkspace {
        workspace_root: metadata.workspace_root.clone(),
        packages,
        selected: selected_ids,
        warnings,
        all_dependency_crate_names,
    })
}

/// Runs `cargo metadata` with the requested feature selection.
fn load_metadata(options: &DiscoveryOptions) -> Result<Metadata, CargoError> {
    let mut command = MetadataCommand::new();
    if let Some(path) = &options.manifest_path {
        let utf8 = Utf8PathBuf::from_path_buf(path.clone())
            .map_err(|p| CargoError::InvalidPath(p, "manifest path is not valid UTF-8"))?;
        command.manifest_path(utf8);
    }
    // The feature flags are independent and must be combined: enabling a
    // non-default feature set is `--no-default-features --features x`.
    // `MetadataCommand` accumulates these options.
    if options.no_default_features {
        command.features(CargoOpt::NoDefaultFeatures);
    }
    if options.all_features {
        command.features(CargoOpt::AllFeatures);
    }
    if !options.features.is_empty() {
        command.features(CargoOpt::SomeFeatures(options.features.clone()));
    }
    if options.offline {
        command.other_options(vec!["--offline".to_owned()]);
    }
    Ok(command.exec()?)
}

/// The packages Cargo itself would build by default: the workspace default
/// members when declared, otherwise every workspace member.
fn default_members(metadata: &Metadata) -> Vec<cargo_metadata::PackageId> {
    let defaults = &metadata.workspace_default_members;
    if defaults.is_available() && !defaults.is_empty() {
        defaults.to_vec()
    } else {
        metadata.workspace_members.clone()
    }
}

/// Breadth-first closure of the selected packages over the resolve graph.
///
/// Returns `None` when the resolve graph is unavailable (e.g. metadata was
/// produced with `--no-deps`). Dev-dependencies are included only when
/// `include_dev_dependencies` is set; build dependencies are never
/// included (see [`discover`]). Target-specific dependency edges are always
/// followed — an over-approximation, which is the safe direction for an
/// audit tool.
fn dependency_closure(
    metadata: &Metadata,
    roots: &[cargo_metadata::PackageId],
    include_dev_dependencies: bool,
) -> Option<Vec<cargo_metadata::PackageId>> {
    let resolve = metadata.resolve.as_ref()?;
    let nodes: BTreeMap<&cargo_metadata::PackageId, &cargo_metadata::Node> =
        resolve.nodes.iter().map(|node| (&node.id, node)).collect();

    let mut seen: BTreeSet<cargo_metadata::PackageId> = roots.iter().cloned().collect();
    let mut queue: VecDeque<cargo_metadata::PackageId> = roots.iter().cloned().collect();
    while let Some(id) = queue.pop_front() {
        let Some(node) = nodes.get(&id) else {
            continue;
        };
        for dep in &node.deps {
            let wanted = dep.dep_kinds.iter().any(|kind| match kind.kind {
                DependencyKind::Normal => true,
                DependencyKind::Development => include_dev_dependencies,
                _ => false,
            });
            if wanted && seen.insert(dep.pkg.clone()) {
                queue.push_back(dep.pkg.clone());
            }
        }
    }
    Some(seen.into_iter().collect())
}

/// Maps a Cargo source ID to a [`DependencyOrigin`].
///
/// Source IDs are `<kind>+<url>` — for example `registry+https://…` or
/// `sparse+https://index.crates.io/` for registries, `git+https://…` for
/// git dependencies — with a `-` separator in older Cargo releases.
/// Path dependencies have no source ID at all.
fn source_origin(source: &str) -> DependencyOrigin {
    let kind = source
        .split_once('+')
        .or_else(|| source.split_once('-'))
        .map_or(source, |(kind, _)| kind);
    match kind {
        "registry" | "sparse" => DependencyOrigin::Registry,
        "git" => DependencyOrigin::Git,
        _ => DependencyOrigin::Unknown,
    }
}

/// Maps a Cargo package to our core [`PackageId`].
fn core_package_id(
    package: &Package,
    workspace_members: &BTreeSet<&cargo_metadata::PackageId>,
) -> PackageId {
    let origin = if workspace_members.contains(&package.id) {
        DependencyOrigin::Workspace
    } else {
        match package.source.as_ref().map(|s| s.repr.as_str()) {
            None => DependencyOrigin::Path,
            Some(source) => source_origin(source),
        }
    };
    PackageId::new(
        package.name.clone(),
        Some(package.version.to_string()),
        origin,
    )
}

/// Builds the discovery record for one package.
fn discovered_package(
    package: &Package,
    workspace_members: &BTreeSet<&cargo_metadata::PackageId>,
    resolved_features: Option<&BTreeSet<String>>,
) -> DiscoveredPackage {
    let manifest_dir = package
        .manifest_path
        .parent()
        .map(ToOwned::to_owned)
        .unwrap_or_default();

    let mut lib_root = None;
    let mut bin_targets = Vec::new();
    for target in &package.targets {
        if target.kind.contains(&cargo_metadata::TargetKind::Lib) {
            lib_root = Some(target.src_path.clone());
        } else if target.kind.contains(&cargo_metadata::TargetKind::Bin) {
            bin_targets.push((target.name.clone(), target.src_path.clone()));
        }
    }
    bin_targets.sort();

    let enabled_features = resolved_features.cloned().unwrap_or_else(|| {
        // Without a resolve graph, approximate with the declared default
        // feature; the caller records a warning in that case.
        package
            .features
            .get("default")
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect()
    });

    let sources_available = lib_root
        .iter()
        .chain(bin_targets.iter().map(|(_, root)| root))
        .all(|root| root.exists());

    DiscoveredPackage {
        id: core_package_id(package, workspace_members),
        manifest_dir,
        lib_root,
        bin_targets,
        enabled_features,
        edition: package.edition.to_string(),
        sources_available,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ids_map_to_origins() {
        // crates.io, both the git index and the sparse index, and
        // alternative registries.
        assert_eq!(
            source_origin("registry+https://github.com/rust-lang/crates.io-index"),
            DependencyOrigin::Registry
        );
        assert_eq!(
            source_origin("sparse+https://index.crates.io/"),
            DependencyOrigin::Registry
        );
        assert_eq!(
            source_origin("registry+https://example.com/my-index"),
            DependencyOrigin::Registry
        );
        // Older Cargo releases used a `-` separator.
        assert_eq!(
            source_origin("registry-https://github.com/rust-lang/crates.io-index"),
            DependencyOrigin::Registry
        );

        // Git dependencies over the usual transports.
        assert_eq!(
            source_origin("git+https://github.com/foo/bar"),
            DependencyOrigin::Git
        );
        assert_eq!(
            source_origin("git+file:///srv/mirror/bar"),
            DependencyOrigin::Git
        );

        // Anything unrecognized stays unknown: it is not treated as an
        // audited registry dependency by policy.
        assert_eq!(
            source_origin("https://example.com/mystery"),
            DependencyOrigin::Unknown
        );
        assert_eq!(source_origin(""), DependencyOrigin::Unknown);
    }
}
