//! Heuristic name resolution.
//!
//! Without type information, Rust name resolution cannot be done
//! perfectly. This module resolves call targets against the merged symbol
//! indexes of all analysed crates using a documented, deterministic
//! strategy:
//!
//! * **Crate instances**: a package's library and each of its binaries are
//!   separate compilation units sharing one crate name. The index tracks
//!   *instances*; `crate::` stays inside the caller's instance, while
//!   `name::` from a binary resolves to the library instance (extern-crate
//!   semantics), matching rustc.
//! * **Path calls** are normalized (`crate`/`self`/`super`/`Self`) and
//!   probed, in order: caller's `use` imports (body then module level),
//!   module-relative, ancestor modules, crate root, glob imports, and
//!   finally other analysed crates by their first segment. The first
//!   existing callable item wins — a deliberate approximation of Rust's
//!   scoping rules that is exact in the overwhelmingly common cases.
//! * **Method calls** on `self` resolve against the enclosing impl's
//!   `Self` type. Method calls the `Self`-type search cannot place — and
//!   all other method calls — use the *unique-name heuristic*: if exactly
//!   one analysed impl defines a method with that name, the edge is added
//!   with `EdgeKind::InferredMethod`; with several candidates the call is
//!   reported as ambiguous; with none, as unknown.
//!
//! Everything that does not resolve is an explicit
//! [`unsafe_surface_core::UnresolvedCall`] with a machine-readable
//! reason — unresolved calls are part of the analysis uncertainty and are
//! never silently treated as safe.

use std::collections::{BTreeMap, BTreeSet};

use unsafe_surface_core::{EdgeKind, ItemPath, UnresolvedReason};

use crate::classify::FunctionRecord;
use crate::index::{CrateIndex, IndexItemKind};

/// Identifier of a crate instance (library or binary compilation unit).
pub type InstanceId = usize;

/// One crate instance in the analysis universe.
pub struct Instance<'a> {
    /// Crate name (source-level, `-` normalized to `_`).
    pub crate_name: String,
    /// Whether this instance is the package's library target.
    pub is_lib: bool,
    /// The instance's symbol index.
    pub index: &'a CrateIndex,
}

/// The merged symbol universe across all analysed crate instances.
pub struct GlobalIndex<'a> {
    /// All instances.
    instances: Vec<Instance<'a>>,
    /// Crate name → instance ids, library instances first.
    by_name: BTreeMap<String, Vec<InstanceId>>,
    /// Method name → all known method item paths as `(instance, path)`.
    method_index: BTreeMap<String, Vec<(InstanceId, &'a [String])>>,
    /// Dependency crates whose sources were not analysed.
    unavailable_crates: BTreeSet<String>,
}

impl<'a> GlobalIndex<'a> {
    /// Builds the merged index from per-instance symbol indexes.
    #[must_use]
    pub fn new(instances: Vec<Instance<'a>>, unavailable_crates: BTreeSet<String>) -> Self {
        let mut by_name: BTreeMap<String, Vec<InstanceId>> = BTreeMap::new();
        // Library instances are probed first for cross-crate paths:
        // binaries of other packages are never linkable.
        let mut order: Vec<InstanceId> = (0..instances.len()).collect();
        order.sort_by_key(|&id| !instances[id].is_lib);
        for id in order {
            by_name
                .entry(instances[id].crate_name.clone())
                .or_default()
                .push(id);
        }
        let mut method_index: BTreeMap<String, Vec<(InstanceId, &[String])>> = BTreeMap::new();
        for (id, instance) in instances.iter().enumerate() {
            for (method, paths) in &instance.index.method_index {
                method_index
                    .entry(method.clone())
                    .or_default()
                    .extend(paths.iter().map(|p| (id, p.as_slice())));
            }
        }
        GlobalIndex {
            instances,
            by_name,
            method_index,
            unavailable_crates,
        }
    }

    /// The instance's own symbol index.
    #[must_use]
    pub fn instance_index(&self, instance: InstanceId) -> &'a CrateIndex {
        self.instances[instance].index
    }

    /// The crate name of an instance.
    #[must_use]
    pub fn instance_name(&self, instance: InstanceId) -> &str {
        &self.instances[instance].crate_name
    }

    /// Whether a crate with this name was analysed.
    #[must_use]
    pub fn has_crate(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// The kind of an item inside one instance.
    #[must_use]
    pub fn item_kind(&self, instance: InstanceId, path: &[String]) -> Option<IndexItemKind> {
        self.instances[instance].index.items.get(path).copied()
    }

    /// Whether the item is callable (a graph node target).
    #[must_use]
    pub fn is_callable(&self, instance: InstanceId, path: &[String]) -> bool {
        matches!(
            self.item_kind(instance, path),
            Some(
                IndexItemKind::Fn
                    | IndexItemKind::Method
                    | IndexItemKind::TraitMethod
                    | IndexItemKind::ExternFn
            )
        )
    }

    /// All known methods with a given name.
    #[must_use]
    pub fn methods_named(&self, name: &str) -> &[(InstanceId, &'a [String])] {
        self.method_index
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Methods of impl blocks whose `Self` type is `self_ty` (matched by
    /// last segment, the common case).
    #[must_use]
    pub fn methods_of_type(
        &self,
        self_ty: &[String],
        name: &str,
    ) -> Vec<(InstanceId, Vec<String>)> {
        let mut found = Vec::new();
        let Some(last) = self_ty.last() else {
            return found;
        };
        for (id, instance) in self.instances.iter().enumerate() {
            for impl_record in &instance.index.impls {
                if impl_record.self_ty.last() != Some(last) {
                    continue;
                }
                if let Some(path) = impl_record.methods.get(name) {
                    found.push((id, path.clone()));
                }
            }
        }
        found
    }

    /// Instances to probe for a path whose first segment is `name`,
    /// called from `caller`: library instances of that name first
    /// (extern-crate semantics — `name::` from a binary of the same
    /// package resolves to its library, matching rustc), then the
    /// caller's own instance when it has that name (covering libraries
    /// and binaries without a library target).
    fn probe_instances(&self, caller: InstanceId, name: &str) -> Vec<InstanceId> {
        let mut probes = Vec::new();
        if let Some(ids) = self.by_name.get(name) {
            for &id in ids {
                if self.instances[id].is_lib {
                    probes.push(id);
                }
            }
        }
        if self.instances[caller].crate_name == name && !probes.contains(&caller) {
            probes.push(caller);
        }
        probes
    }
}

/// Maximum candidate count for may-call edges. Beyond it, the edge set
/// would be noise (e.g. `.iter()` with dozens of candidates) and the
/// call stays unresolved instead.
pub const MAX_MAY_CALL_CANDIDATES: usize = 8;

/// The resolution of one call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Resolved to a callable item `(instance, item path)`. The edge kind
    /// records how resolution happened: [`EdgeKind::Direct`] for exact
    /// path and `Self`-type matches, [`EdgeKind::InferredMethod`] for the
    /// unique-name method heuristic.
    Callable(InstanceId, ItemPath, EdgeKind),
    /// Resolved to a small set of plausible callees (may-call
    /// over-approximation; all edges are marked inferred).
    MayCall(Vec<(InstanceId, ItemPath)>),
    /// Resolved to a known non-callable item (tuple-struct constructor,
    /// static, …): neither an edge nor an unresolved call.
    NotCallable,
    /// Could not be resolved.
    Unresolved(UnresolvedReason),
}

/// Resolves a path call from `caller` (in `caller_instance`).
#[must_use]
pub fn resolve_path_call(
    global: &GlobalIndex<'_>,
    caller: &FunctionRecord,
    caller_instance: InstanceId,
    segments: &[String],
) -> Resolution {
    if segments.is_empty() {
        return Resolution::Unresolved(UnresolvedReason::UnknownName);
    }
    let caller_index = global.instance_index(caller_instance);

    // `Self::…` has several candidate positions (see `resolve_self_call`).
    if segments[0] == "Self" {
        return resolve_self_call(global, caller, caller_instance, &segments[1..]);
    }

    // Normalize leading keywords into instance-relative paths.
    let normalized: Option<Vec<String>> = match segments[0].as_str() {
        "crate" => Some(segments[1..].to_vec()),
        "self" => Some([caller.module.as_slice(), &segments[1..]].concat()),
        "super" => {
            let ups = segments
                .iter()
                .take_while(|s| s.as_str() == "super")
                .count();
            let base_len = caller.module.len().saturating_sub(ups);
            Some([&caller.module[..base_len], &segments[ups..]].concat())
        }
        _ => None,
    };
    if let Some(path) = normalized {
        return classify_candidate(global, caller_instance, &path);
    }

    // Candidate probing order (see module docs).
    let first = &segments[0];
    let rest = &segments[1..];

    // 1. Exact imports visible to the caller (function body first).
    let module_imports = caller_index.imports.get(&caller.module);
    let import_sets = [Some(&caller.imports), module_imports];
    for imports in import_sets.into_iter().flatten() {
        if let Some(target) = imports.exact.get(first) {
            if let Some(resolution) =
                resolve_imported(global, caller, caller_instance, target, rest)
            {
                return resolution;
            }
        }
    }

    // 2. Module-relative and ancestor-module-relative paths.
    for depth in (0..=caller.module.len()).rev() {
        let candidate = [&caller.module[..depth], segments].concat();
        if let Some(resolution) = existing_callable(global, caller_instance, &candidate) {
            return resolution;
        }
    }

    // 3. Glob imports. Targets get the same root handling as exact
    //    imports (`crate`/`self`/`super` stay in the instance).
    for imports in import_sets.into_iter().flatten() {
        for glob in &imports.globs {
            if let Some(resolution) =
                resolve_imported(global, caller, caller_instance, glob, segments)
            {
                return resolution;
            }
        }
    }

    // 4. Cross-crate: first segment names an analysed crate.
    if let Some(resolution) = probe_by_name(global, caller_instance, segments) {
        return resolution;
    }

    // 5. Give up, with a precise reason.
    let first = first.as_str();
    if matches!(first, "std" | "core" | "alloc") || STD_PRELUDE.contains(&first) {
        return Resolution::Unresolved(UnresolvedReason::StandardLibrary);
    }
    if global.unavailable_crates.contains(first) {
        return Resolution::Unresolved(UnresolvedReason::DependencySourceUnavailable {
            krate: first.to_owned(),
        });
    }
    // A single-segment call matching a function parameter or a local
    // with a function-pointer type is a call through a function pointer
    // or closure value.
    if rest.is_empty()
        && (caller.params.iter().any(|p| p == first)
            || caller.fn_pointer_locals.iter().any(|p| p == first))
    {
        return Resolution::Unresolved(UnresolvedReason::FunctionPointer);
    }
    Resolution::Unresolved(UnresolvedReason::UnknownName)
}

/// Resolves the remainder of a `Self::…` path from `caller`.
///
/// `Self::x` is looked up in three positions, in order:
///
/// * beside the calling method — a record's path is
///   `…::SelfType[::Trait]::method`, so its prefix holds the impl block's
///   own items, trait-provided ones included;
/// * the inherent `…::SelfType::x` position;
/// * the trait's default position `…::Trait::x`, for methods of a trait
///   impl (the trait segment is what the impl path adds beyond the module
///   and the `Self` type).
fn resolve_self_call(
    global: &GlobalIndex<'_>,
    caller: &FunctionRecord,
    caller_instance: InstanceId,
    rest: &[String],
) -> Resolution {
    let Some(self_ty) = &caller.impl_self_ty else {
        return Resolution::Unresolved(UnresolvedReason::UnknownName);
    };
    let method = caller.path.len().saturating_sub(1);
    let self_end = caller.module.len() + self_ty.len();
    // The trait segment of a trait impl, `[]` otherwise.
    let extra = caller.path.get(self_end..method).unwrap_or(&[]);
    let inherent = [caller.module.as_slice(), self_ty.as_slice()].concat();
    let mut bases = vec![caller.path[..method].to_vec(), inherent];
    if !extra.is_empty() {
        bases.push([caller.module.as_slice(), extra].concat());
    }
    bases.dedup();
    for base in &bases {
        let candidate = [base.as_slice(), rest].concat();
        if let Some(resolution) = existing_callable(global, caller_instance, &candidate) {
            return resolution;
        }
    }
    Resolution::Unresolved(UnresolvedReason::UnknownName)
}

/// Resolves a method call from `caller`.
#[must_use]
pub fn resolve_method_call(
    global: &GlobalIndex<'_>,
    caller: &FunctionRecord,
    name: &str,
    receiver_is_self: bool,
    receiver_local: Option<&str>,
) -> Resolution {
    // Method calls on trait-object parameters are dynamic dispatch: the
    // concrete target is only known at the call site.
    if let Some(local) = receiver_local {
        if caller.dyn_params.iter().any(|p| p == local) {
            return Resolution::Unresolved(UnresolvedReason::DynamicDispatch);
        }
    }
    // `self.method()` with a known `Self` type: search impls of that type.
    if receiver_is_self {
        if let Some(self_ty) = &caller.impl_self_ty {
            let found = global.methods_of_type(self_ty, name);
            match found.len() {
                1 => {
                    let (instance, path) = &found[0];
                    return Resolution::Callable(
                        *instance,
                        ItemPath::new(global.instance_name(*instance), path.clone()),
                        EdgeKind::Direct,
                    );
                }
                n if n > 1 => {
                    return may_call_or_unresolved(global, found);
                }
                _ => {}
            }
        }
    }

    // Unique-name heuristic across all analysed instances: the match is
    // by name only, so its edges are inferred even for `self` receivers
    // that fell through the `Self`-type search above.
    let candidates = global.methods_named(name);
    match candidates.len() {
        1 => {
            let (instance, path) = &candidates[0];
            Resolution::Callable(
                *instance,
                ItemPath::new(global.instance_name(*instance), (*path).to_vec()),
                EdgeKind::InferredMethod,
            )
        }
        0 => Resolution::Unresolved(UnresolvedReason::UnknownName),
        n if n <= MAX_MAY_CALL_CANDIDATES => Resolution::MayCall(
            candidates
                .iter()
                .map(|(instance, path)| {
                    (
                        *instance,
                        ItemPath::new(global.instance_name(*instance), (*path).to_vec()),
                    )
                })
                .collect(),
        ),
        n => Resolution::Unresolved(UnresolvedReason::AmbiguousMethod { candidates: n }),
    }
}

/// Turns a small ambiguous candidate set into may-call edges.
fn may_call_or_unresolved(
    global: &GlobalIndex<'_>,
    found: Vec<(InstanceId, Vec<String>)>,
) -> Resolution {
    if found.len() <= MAX_MAY_CALL_CANDIDATES {
        Resolution::MayCall(
            found
                .into_iter()
                .map(|(instance, path)| {
                    (
                        instance,
                        ItemPath::new(global.instance_name(instance), path),
                    )
                })
                .collect(),
        )
    } else {
        Resolution::Unresolved(UnresolvedReason::AmbiguousMethod {
            candidates: found.len(),
        })
    }
}

/// Resolves an imported first segment plus the remaining call path.
fn resolve_imported(
    global: &GlobalIndex<'_>,
    caller: &FunctionRecord,
    caller_instance: InstanceId,
    target: &[String],
    rest: &[String],
) -> Option<Resolution> {
    // Imports rooted at `crate`/`self`/`super` stay in the instance;
    // everything else is tried in the instance and then as a crate name.
    match target.first()?.as_str() {
        "crate" => {
            let candidate = [&target[1..], rest].concat();
            existing_callable(global, caller_instance, &candidate)
        }
        "self" | "super" => {
            let base = normalize_import_target(&caller.module, target)?;
            let candidate = [base.as_slice(), rest].concat();
            existing_callable(global, caller_instance, &candidate)
        }
        _ => {
            let candidate = [target, rest].concat();
            existing_callable(global, caller_instance, &candidate)
                .or_else(|| probe_by_name(global, caller_instance, &candidate))
        }
    }
}

/// Normalizes an import target starting with `self`/`super` relative to
/// `module`.
fn normalize_import_target(module: &[String], target: &[String]) -> Option<Vec<String>> {
    match target.first()?.as_str() {
        "self" => Some([module, &target[1..]].concat()),
        "super" => {
            let ups = target.iter().take_while(|s| s.as_str() == "super").count();
            let base_len = module.len().saturating_sub(ups);
            Some([&module[..base_len], &target[ups..]].concat())
        }
        _ => Some(target.to_vec()),
    }
}

/// Returns the resolution when `path` exists as an item in `instance`.
fn existing_callable(
    global: &GlobalIndex<'_>,
    instance: InstanceId,
    path: &[String],
) -> Option<Resolution> {
    if global.is_callable(instance, path) {
        return Some(Resolution::Callable(
            instance,
            ItemPath::new(global.instance_name(instance), path.to_vec()),
            EdgeKind::Direct,
        ));
    }
    if global.item_kind(instance, path).is_some() {
        return Some(Resolution::NotCallable);
    }
    None
}

/// Returns the resolution when the path's first segment names an analysed
/// crate and the remainder names an item in one of its probe instances.
fn probe_by_name(
    global: &GlobalIndex<'_>,
    caller_instance: InstanceId,
    segments: &[String],
) -> Option<Resolution> {
    let (first, rest) = segments.split_first()?;
    for instance in global.probe_instances(caller_instance, first) {
        if let Some(resolution) = existing_callable(global, instance, rest) {
            return Some(resolution);
        }
    }
    None
}

/// Classifies a normalized instance-relative path.
fn classify_candidate(
    global: &GlobalIndex<'_>,
    instance: InstanceId,
    path: &[String],
) -> Resolution {
    existing_callable(global, instance, path)
        .unwrap_or(Resolution::Unresolved(UnresolvedReason::UnknownName))
}

/// Rust prelude items (edition 2021). Calls through them are classified
/// as standard-library calls instead of unknown names, keeping the
/// unresolved-call list meaningful. Types that require an explicit `use`
/// (`Rc`, `Arc`, `Cell`, …) are deliberately absent: they resolve through
/// imports.
const STD_PRELUDE: &[&str] = &[
    "AsMut",
    "AsRef",
    "AsyncFn",
    "AsyncFnMut",
    "AsyncFnOnce",
    "Box",
    "Clone",
    "Copy",
    "Default",
    "Deref",
    "DerefMut",
    "Drop",
    "drop",
    "Eq",
    "Err",
    "Fn",
    "FnMut",
    "FnOnce",
    "From",
    "FromIterator",
    "Into",
    "IntoIterator",
    "Iterator",
    "None",
    "Ok",
    "Option",
    "Ord",
    "PartialEq",
    "PartialOrd",
    "Result",
    "Send",
    "Sized",
    "Some",
    "String",
    "Sync",
    "ToOwned",
    "ToString",
    "TryFrom",
    "TryInto",
    "Unpin",
    "Vec",
];
