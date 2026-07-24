//! Heuristic name resolution.
//!
//! Without type information, Rust name resolution cannot be done
//! perfectly. This module resolves call targets against the merged symbol
//! indexes of all analysed crates using a documented, deterministic
//! strategy:
//!
//! * **Path calls** are normalized (`crate`/`self`/`super`/`Self`) and
//!   probed, in order: caller's `use` imports (body then module level),
//!   module-relative, ancestor modules, crate root, glob imports, and
//!   finally other analysed crates by their first segment. The first
//!   existing callable item wins — a deliberate approximation of Rust's
//!     scoping rules that is exact in the overwhelmingly common cases.
//! * **Method calls** on `self` resolve against the enclosing impl's
//!   `Self` type. Other method calls use the *unique-name heuristic*: if
//!   exactly one analysed impl defines a method with that name, the edge
//!   is added with [`EdgeKind::InferredMethod`]; with several candidates
//!   the call is reported as ambiguous; with none, as unknown.
//!
//! Everything that does not resolve is an explicit [`UnresolvedCall`] with
//! a machine-readable reason — unresolved calls are part of the analysis
//! uncertainty and are never silently treated as safe.

use std::collections::BTreeMap;

use unsafe_surface_core::{ItemPath, UnresolvedReason};

use crate::classify::FunctionRecord;
use crate::index::{CrateIndex, IndexItemKind};

/// The merged symbol universe across all analysed crates.
pub struct GlobalIndex<'a> {
    /// Crate name → (symbol index, package).
    crates: BTreeMap<&'a str, &'a CrateIndex>,
    /// Method name → all known method item paths as `(crate, path)`.
    method_index: BTreeMap<&'a str, Vec<(&'a str, &'a [String])>>,
    /// Dependency crates whose sources were not analysed.
    unavailable_crates: std::collections::BTreeSet<&'a str>,
}

impl<'a> GlobalIndex<'a> {
    /// Builds the merged index from per-crate symbol indexes.
    #[must_use]
    pub fn new(
        crates: &[(&'a str, &'a CrateIndex)],
        unavailable_crates: std::collections::BTreeSet<&'a str>,
    ) -> Self {
        let mut index = GlobalIndex {
            crates: BTreeMap::new(),
            method_index: BTreeMap::new(),
            unavailable_crates,
        };
        for (name, crate_index) in crates {
            index.crates.insert(name, crate_index);
            for (method, paths) in &crate_index.method_index {
                index
                    .method_index
                    .entry(method.as_str())
                    .or_default()
                    .extend(paths.iter().map(|p| (*name, p.as_slice())));
            }
        }
        index
    }

    /// Whether a crate with this (source-level) name was analysed.
    #[must_use]
    pub fn has_crate(&self, name: &str) -> bool {
        self.crates.contains_key(name)
    }

    /// The kind of an item, if it exists.
    #[must_use]
    pub fn item_kind(&self, krate: &str, path: &[String]) -> Option<IndexItemKind> {
        self.crates
            .get(krate)
            .and_then(|index| index.items.get(path))
            .map(|item| item.kind)
    }

    /// Whether the item is callable (a graph node target).
    #[must_use]
    pub fn is_callable(&self, krate: &str, path: &[String]) -> bool {
        matches!(
            self.item_kind(krate, path),
            Some(
                IndexItemKind::Fn { .. }
                    | IndexItemKind::Method { .. }
                    | IndexItemKind::TraitMethod { .. }
                    | IndexItemKind::ExternFn
            )
        )
    }

    /// All known methods with a given name.
    #[must_use]
    pub fn methods_named(&self, name: &str) -> &[(&'a str, &'a [String])] {
        self.method_index
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Methods of impl blocks whose `Self` type is `self_ty` (matched by
    /// last segment, the common case).
    #[must_use]
    pub fn methods_of_type(&self, self_ty: &[String], name: &str) -> Vec<(&'a str, Vec<String>)> {
        let mut found = Vec::new();
        let Some(last) = self_ty.last() else {
            return found;
        };
        for (krate, index) in &self.crates {
            for impl_record in &index.impls {
                if impl_record.self_ty.last() != Some(last) {
                    continue;
                }
                if let Some(path) = impl_record.methods.get(name) {
                    found.push((*krate, path.clone()));
                }
            }
        }
        found
    }
}

/// The resolution of one call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Resolved to a callable item.
    Callable(ItemPath),
    /// Resolved to a known non-callable item (tuple-struct constructor,
    /// static, …): neither an edge nor an unresolved call.
    NotCallable,
    /// Could not be resolved.
    Unresolved(UnresolvedReason),
}

/// Resolves a path call.
#[must_use]
pub fn resolve_path_call(
    global: &GlobalIndex<'_>,
    caller: &FunctionRecord,
    caller_crate: &str,
    segments: &[String],
) -> Resolution {
    if segments.is_empty() {
        return Resolution::Unresolved(UnresolvedReason::UnknownName);
    }
    let Some(caller_index) = global.crates.get(caller_crate).copied() else {
        return Resolution::Unresolved(UnresolvedReason::UnknownName);
    };

    // Normalize leading keywords into absolute crate-relative paths.
    let normalized: Option<(String, Vec<String>)> = match segments[0].as_str() {
        "crate" => Some((caller_crate.to_owned(), segments[1..].to_vec())),
        "self" => Some((
            caller_crate.to_owned(),
            [caller.module.as_slice(), &segments[1..]].concat(),
        )),
        "super" => {
            let ups = segments
                .iter()
                .take_while(|s| s.as_str() == "super")
                .count();
            let base_len = caller.module.len().saturating_sub(ups);
            Some((
                caller_crate.to_owned(),
                [&caller.module[..base_len], &segments[ups..]].concat(),
            ))
        }
        "Self" => caller.impl_self_ty.as_ref().map(|self_ty| {
            (
                caller_crate.to_owned(),
                [caller.module.as_slice(), self_ty.as_slice(), &segments[1..]].concat(),
            )
        }),
        _ => None,
    };
    if let Some((krate, path)) = normalized {
        return classify_candidate(global, &krate, &path);
    }

    // Candidate probing order (see module docs).
    let first = &segments[0];
    let rest = &segments[1..];

    // 1. Exact imports visible to the caller (function body first).
    let module_imports = caller_index.imports.get(&caller.module);
    let import_sets = [Some(&caller.imports), module_imports];
    for imports in import_sets.into_iter().flatten() {
        if let Some(target) = imports.exact.get(first) {
            if let Some(resolution) = resolve_imported(global, caller_crate, target, rest) {
                return resolution;
            }
        }
    }

    // 2. Module-relative and ancestor-module-relative paths.
    for depth in (0..=caller.module.len()).rev() {
        let candidate = [&caller.module[..depth], segments].concat();
        if let Some(resolution) = existing_callable(global, caller_crate, &candidate) {
            return resolution;
        }
    }

    // 3. Glob imports.
    for imports in import_sets.into_iter().flatten() {
        for glob in &imports.globs {
            if let Some(base) = normalize_import_target(&caller.module, glob) {
                let candidate = [base.as_slice(), segments].concat();
                if let Some(resolution) = existing_callable(global, caller_crate, &candidate) {
                    return resolution;
                }
                if let Some(resolution) = cross_crate_callable(global, &candidate) {
                    return resolution;
                }
            }
        }
    }

    // 4. Cross-crate: first segment names an analysed crate.
    if let Some(resolution) = cross_crate_callable(global, segments) {
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

/// Rust prelude items (edition 2021). Calls through them are classified
/// as standard-library calls instead of unknown names, keeping the
/// unresolved-call list meaningful. Types that require an explicit `use`
/// (Rc, Arc, Cell, …) are deliberately absent: they resolve through
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

/// Resolves a method call.
#[must_use]
pub fn resolve_method_call(
    global: &GlobalIndex<'_>,
    caller: &FunctionRecord,
    name: &str,
    receiver_is_self: bool,
) -> Resolution {
    // `self.method()` with a known `Self` type: search impls of that type.
    if receiver_is_self {
        if let Some(self_ty) = &caller.impl_self_ty {
            let found = global.methods_of_type(self_ty, name);
            match found.len() {
                1 => {
                    let (krate, path) = &found[0];
                    return Resolution::Callable(ItemPath::new((*krate).to_owned(), path.clone()));
                }
                n if n > 1 => {
                    return Resolution::Unresolved(UnresolvedReason::AmbiguousMethod {
                        candidates: n,
                    });
                }
                _ => {}
            }
        }
    }

    // Unique-name heuristic across all analysed crates.
    let candidates = global.methods_named(name);
    match candidates.len() {
        1 => {
            let (krate, path) = &candidates[0];
            Resolution::Callable(ItemPath::new((*krate).to_owned(), (*path).to_vec()))
        }
        0 => Resolution::Unresolved(UnresolvedReason::UnknownName),
        n => Resolution::Unresolved(UnresolvedReason::AmbiguousMethod { candidates: n }),
    }
}

/// Resolves an imported first segment plus the remaining call path.
fn resolve_imported(
    global: &GlobalIndex<'_>,
    caller_crate: &str,
    target: &[String],
    rest: &[String],
) -> Option<Resolution> {
    let base = normalize_import_target(&[], target)?;
    let candidate = [base.as_slice(), rest].concat();
    if let Some(resolution) = existing_callable(global, caller_crate, &candidate) {
        return Some(resolution);
    }
    // The import may name an extern crate (`use dep_crate::thing`).
    cross_crate_callable(global, &candidate)
}

/// Normalizes an import target starting with `crate`/`self`/`super`.
///
/// `module` is the module containing the import (only needed for
/// `self`/`super`; callers pass the real module when known).
fn normalize_import_target(module: &[String], target: &[String]) -> Option<Vec<String>> {
    match target.first()?.as_str() {
        "crate" => Some(target[1..].to_vec()),
        "self" => Some([module, &target[1..]].concat()),
        "super" => {
            let ups = target.iter().take_while(|s| s.as_str() == "super").count();
            let base_len = module.len().saturating_sub(ups);
            Some([&module[..base_len], &target[ups..]].concat())
        }
        _ => Some(target.to_vec()),
    }
}

/// Returns the resolution when `path` exists as a callable in `krate`.
fn existing_callable(global: &GlobalIndex<'_>, krate: &str, path: &[String]) -> Option<Resolution> {
    if global.is_callable(krate, path) {
        return Some(Resolution::Callable(ItemPath::new(krate, path.to_vec())));
    }
    if global.item_kind(krate, path).is_some() {
        return Some(Resolution::NotCallable);
    }
    None
}

/// Returns the resolution when the path's first segment is an analysed
/// crate and the remainder names an item in it.
fn cross_crate_callable(global: &GlobalIndex<'_>, segments: &[String]) -> Option<Resolution> {
    let (first, rest) = segments.split_first()?;
    if !global.has_crate(first) {
        return None;
    }
    if global.is_callable(first, rest) {
        return Some(Resolution::Callable(ItemPath::new(first, rest.to_vec())));
    }
    if global.item_kind(first, rest).is_some() {
        return Some(Resolution::NotCallable);
    }
    None
}

/// Classifies a normalized absolute path.
fn classify_candidate(global: &GlobalIndex<'_>, krate: &str, path: &[String]) -> Resolution {
    existing_callable(global, krate, path)
        .unwrap_or(Resolution::Unresolved(UnresolvedReason::UnknownName))
}
