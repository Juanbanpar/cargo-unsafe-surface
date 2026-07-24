//! Per-crate symbol tables.
//!
//! The index is the backbone of name resolution: it records every item
//! path in a crate, which functions are `unsafe`, which types are unions,
//! which statics are mutable, the methods of every impl block, and the
//! `use` imports of every module.
//!
//! Everything is keyed by module-relative path segments **without** the
//! crate name; the crate name is added when indexes are merged for
//! cross-crate resolution.

use std::collections::{BTreeMap, BTreeSet};

use syn::{Item, Visibility};

use crate::source::ParsedCrate;

/// The kind of an indexed item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexItemKind {
    /// A free function.
    Fn {
        /// Whether it is declared `unsafe`.
        is_unsafe: bool,
    },
    /// A method (inherent or trait impl); the item path includes the
    /// `Type::` or `Type::Trait::` component.
    Method {
        /// Whether it is declared `unsafe`.
        is_unsafe: bool,
    },
    /// A trait method (declaration or default body).
    TraitMethod {
        /// Whether it is declared `unsafe`.
        is_unsafe: bool,
    },
    /// A foreign function from an `extern "..."` block.
    ExternFn,
    /// A static item.
    Static {
        /// Whether it is `static mut`.
        mutable: bool,
    },
    /// A union type.
    Union,
    /// A trait.
    Trait {
        /// Whether it is `unsafe trait`.
        is_unsafe: bool,
    },
    /// A module.
    Module,
    /// Any other item kind (struct, enum, const, type alias, …). Tracked so
    /// path resolution can distinguish "known non-callable" from "unknown".
    Other,
}

/// An indexed item.
#[derive(Debug, Clone)]
pub struct IndexItem {
    /// Item kind.
    pub kind: IndexItemKind,
    /// Whether the item is `pub` (unrestricted). Restricted visibilities
    /// such as `pub(crate)` count as non-public for entry-point selection.
    pub is_pub: bool,
}

/// Imports declared in one module.
#[derive(Debug, Clone, Default)]
pub struct ModuleImports {
    /// `name` → target path segments (absolute, starting with `crate`,
    /// `self`, `super`, an extern crate name, or a `::`-rooted path with
    /// the leading colon marker removed).
    pub exact: BTreeMap<String, Vec<String>>,
    /// Glob import sources (`use a::b::*` → `["a", "b"]`).
    pub globs: Vec<Vec<String>>,
}

/// A trait or inherent impl block, for method resolution.
#[derive(Debug, Clone)]
pub struct ImplRecord {
    /// Module path containing the impl.
    pub module: Vec<String>,
    /// `Self` type path segments as written (generics stripped).
    pub self_ty: Vec<String>,
    /// Implemented trait path segments as written, if any.
    pub trait_ty: Option<Vec<String>>,
    /// Whether this is `unsafe impl`.
    pub is_unsafe: bool,
    /// Method names defined by this impl, mapped to their item paths
    /// (module + `Self::` + name).
    pub methods: BTreeMap<String, Vec<String>>,
}

/// The symbol index of one crate.
#[derive(Debug, Default)]
pub struct CrateIndex {
    /// All indexed items by module-relative path.
    pub items: BTreeMap<Vec<String>, IndexItem>,
    /// Method name → item paths of all known methods with that name
    /// (across all impl blocks). Used by the unique-name heuristic.
    pub method_index: BTreeMap<String, Vec<Vec<String>>>,
    /// All impl blocks.
    pub impls: Vec<ImplRecord>,
    /// Type names (last segment) of unions.
    pub unions: BTreeSet<String>,
    /// Item paths of `static mut` definitions.
    pub mutable_statics: BTreeSet<Vec<String>>,
    /// Item paths of `unsafe fn` definitions.
    pub unsafe_fns: BTreeSet<Vec<String>>,
    /// Item paths of foreign function declarations.
    pub extern_fns: BTreeSet<Vec<String>>,
    /// Imports per module path.
    pub imports: BTreeMap<Vec<String>, ModuleImports>,
}

/// Builds the index of a parsed crate.
#[must_use]
pub fn build_index(parsed: &ParsedCrate) -> CrateIndex {
    let mut index = CrateIndex::default();
    for module in &parsed.modules {
        for item in &module.items {
            index_item(&mut index, &module.path, item);
        }
    }
    index
}

fn index_item(index: &mut CrateIndex, module: &[String], item: &Item) {
    match item {
        Item::Fn(item_fn) => {
            let path = joined(module, &item_fn.sig.ident.to_string());
            let is_unsafe = item_fn.sig.unsafety.is_some();
            insert(
                index,
                path.clone(),
                IndexItem {
                    kind: IndexItemKind::Fn { is_unsafe },
                    is_pub: is_pub(&item_fn.vis),
                },
            );
            if is_unsafe {
                index.unsafe_fns.insert(path);
            }
        }
        Item::Mod(item_mod) => {
            insert(
                index,
                joined(module, &item_mod.ident.to_string()),
                IndexItem {
                    kind: IndexItemKind::Module,
                    is_pub: is_pub(&item_mod.vis),
                },
            );
        }
        Item::Static(item_static) => {
            let path = joined(module, &item_static.ident.to_string());
            let mutable = matches!(item_static.mutability, syn::StaticMutability::Mut(_));
            insert(
                index,
                path.clone(),
                IndexItem {
                    kind: IndexItemKind::Static { mutable },
                    is_pub: is_pub(&item_static.vis),
                },
            );
            if mutable {
                index.mutable_statics.insert(path);
            }
        }
        Item::Union(item_union) => {
            let name = item_union.ident.to_string();
            insert(
                index,
                joined(module, &name),
                IndexItem {
                    kind: IndexItemKind::Union,
                    is_pub: is_pub(&item_union.vis),
                },
            );
            index.unions.insert(name);
        }
        Item::Trait(item_trait) => {
            let name = item_trait.ident.to_string();
            let path = joined(module, &name);
            let is_unsafe = item_trait.unsafety.is_some();
            insert(
                index,
                path.clone(),
                IndexItem {
                    kind: IndexItemKind::Trait { is_unsafe },
                    is_pub: is_pub(&item_trait.vis),
                },
            );
            for trait_item in &item_trait.items {
                if let syn::TraitItem::Fn(method) = trait_item {
                    let method_path = joined(&path, &method.sig.ident.to_string());
                    let method_unsafe = method.sig.unsafety.is_some();
                    insert(
                        index,
                        method_path.clone(),
                        IndexItem {
                            kind: IndexItemKind::TraitMethod {
                                is_unsafe: method_unsafe,
                            },
                            is_pub: is_pub(&item_trait.vis),
                        },
                    );
                    if method_unsafe {
                        index.unsafe_fns.insert(method_path.clone());
                    }
                    index
                        .method_index
                        .entry(method.sig.ident.to_string())
                        .or_default()
                        .push(method_path);
                }
            }
        }
        Item::Impl(item_impl) => {
            index_impl(index, module, item_impl);
        }
        Item::ForeignMod(foreign_mod) => {
            for foreign_item in &foreign_mod.items {
                if let syn::ForeignItem::Fn(foreign_fn) = foreign_item {
                    let path = joined(module, &foreign_fn.sig.ident.to_string());
                    insert(
                        index,
                        path.clone(),
                        IndexItem {
                            kind: IndexItemKind::ExternFn,
                            is_pub: is_pub(&foreign_fn.vis),
                        },
                    );
                    index.extern_fns.insert(path);
                }
            }
        }
        Item::Use(item_use) => {
            let imports = index.imports.entry(module.to_vec()).or_default();
            flatten_use_tree(&item_use.tree, Vec::new(), imports);
        }
        Item::Struct(item_struct) => insert(
            index,
            joined(module, &item_struct.ident.to_string()),
            IndexItem {
                kind: IndexItemKind::Other,
                is_pub: is_pub(&item_struct.vis),
            },
        ),
        Item::Enum(item_enum) => insert(
            index,
            joined(module, &item_enum.ident.to_string()),
            IndexItem {
                kind: IndexItemKind::Other,
                is_pub: is_pub(&item_enum.vis),
            },
        ),
        Item::Const(item_const) => insert(
            index,
            joined(module, &item_const.ident.to_string()),
            IndexItem {
                kind: IndexItemKind::Other,
                is_pub: is_pub(&item_const.vis),
            },
        ),
        Item::Type(item_type) => insert(
            index,
            joined(module, &item_type.ident.to_string()),
            IndexItem {
                kind: IndexItemKind::Other,
                is_pub: is_pub(&item_type.vis),
            },
        ),
        _ => {}
    }
}

fn index_impl(index: &mut CrateIndex, module: &[String], item_impl: &syn::ItemImpl) {
    let self_ty = type_path_segments(&item_impl.self_ty);
    let trait_ty = item_impl
        .trait_
        .as_ref()
        .map(|(_, path, _)| path_segments(path));

    // Item paths for methods use `Self_ty::method` (and
    // `Self_ty::Trait::method` for trait impls) so they are unique and
    // human-readable in reports.
    let mut methods = BTreeMap::new();
    for impl_item in &item_impl.items {
        if let syn::ImplItem::Fn(method) = impl_item {
            let name = method.sig.ident.to_string();
            let mut path = module.to_vec();
            path.extend(self_ty.iter().cloned());
            if let Some(trait_ty) = &trait_ty {
                if let Some(last) = trait_ty.last() {
                    path.push(last.clone());
                }
            }
            path.push(name.clone());
            let is_unsafe = method.sig.unsafety.is_some();
            insert(
                index,
                path.clone(),
                IndexItem {
                    kind: IndexItemKind::Method { is_unsafe },
                    is_pub: is_pub(&method.vis),
                },
            );
            if is_unsafe {
                index.unsafe_fns.insert(path.clone());
            }
            index
                .method_index
                .entry(name.clone())
                .or_default()
                .push(path.clone());
            methods.insert(name, path);
        }
    }

    index.impls.push(ImplRecord {
        module: module.to_vec(),
        self_ty,
        trait_ty,
        is_unsafe: item_impl.unsafety.is_some(),
        methods,
    });
}

/// Flattens a `use` tree into exact and glob imports.
///
/// `use a::b::{self, c as d, e::*}` yields exact imports `b` and `d`, and
/// one glob source `a::b::e`.
fn flatten_use_tree(tree: &syn::UseTree, prefix: Vec<String>, imports: &mut ModuleImports) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut prefix = prefix;
            prefix.push(path.ident.to_string());
            flatten_use_tree(&path.tree, prefix, imports);
        }
        syn::UseTree::Name(name) => {
            if name.ident == "self" {
                // `use a::b::{self}` imports `b` itself under the name `b`.
                if let Some(last) = prefix.last() {
                    imports.exact.insert(last.clone(), prefix);
                }
            } else {
                let mut target = prefix;
                target.push(name.ident.to_string());
                imports.exact.insert(name.ident.to_string(), target);
            }
        }
        syn::UseTree::Rename(rename) => {
            let mut target = prefix;
            target.push(rename.ident.to_string());
            imports.exact.insert(rename.rename.to_string(), target);
        }
        syn::UseTree::Glob(_) => {
            imports.globs.push(prefix);
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use_tree(tree, prefix.clone(), imports);
            }
        }
    }
}

/// Path segments of a `syn::Path` (`a::b::C`), without generic arguments.
fn path_segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

/// Path segments of a type when it is a plain path type; empty otherwise.
fn type_path_segments(ty: &syn::Type) -> Vec<String> {
    match ty {
        syn::Type::Path(type_path) if type_path.qself.is_none() => path_segments(&type_path.path),
        _ => Vec::new(),
    }
}

fn joined(module: &[String], name: &str) -> Vec<String> {
    let mut path = module.to_vec();
    path.push(name.to_owned());
    path
}

fn insert(index: &mut CrateIndex, path: Vec<String>, item: IndexItem) {
    // First definition wins: later duplicates are usually cfg-gated
    // siblings of the first.
    index.items.entry(path).or_insert(item);
}

fn is_pub(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_eval::CfgEvaluator;
    use crate::limits::Limits;
    use crate::source::{parse_crate, ParseContext};
    use std::collections::BTreeSet;
    use std::fs;
    use unsafe_surface_cargo::CfgValues;

    /// Writes source files into a temp dir and parses+indexes the crate.
    fn index_of(files: &[(&str, &str)]) -> (CrateIndex, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut root = None;
        for (name, content) in files {
            let path = dir.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            if *name == "lib.rs" {
                root = Some(path);
            }
        }
        let values = CfgValues::new();
        let features = BTreeSet::new();
        let limits = Limits::default();
        let context = ParseContext {
            cfg: CfgEvaluator::new(&values, &features),
            limits: &limits,
            display_root: Some(dir.path()),
        };
        let parsed = parse_crate(&root.unwrap(), &context).unwrap();
        (build_index(&parsed), dir)
    }

    #[test]
    fn indexes_functions_and_unsafe_fns() {
        let (index, _dir) = index_of(&[(
            "lib.rs",
            "pub fn safe() {}\nunsafe fn risky() {}\npub unsafe fn pub_risky() {}",
        )]);
        assert_eq!(
            index.items[&vec!["safe".to_owned()]].kind,
            IndexItemKind::Fn { is_unsafe: false }
        );
        assert!(index.items[&vec!["safe".to_owned()]].is_pub);
        assert!(!index.items[&vec!["risky".to_owned()]].is_pub);
        assert!(index.unsafe_fns.contains(&vec!["risky".to_owned()]));
        assert!(index.unsafe_fns.contains(&vec!["pub_risky".to_owned()]));
    }

    #[test]
    fn indexes_impl_methods_in_method_index() {
        let (index, _dir) = index_of(&[(
            "lib.rs",
            "struct S;\nimpl S { fn method(&self) {} unsafe fn raw(&self) {} }\n\
             trait T { fn tm(&self) {} }\nunsafe trait U {}",
        )]);
        let methods = &index.method_index["method"];
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0], vec!["S".to_owned(), "method".to_owned()]);
        assert!(index
            .unsafe_fns
            .contains(&vec!["S".to_owned(), "raw".to_owned()]));
        assert_eq!(
            index.items[&vec!["T".to_owned()]].kind,
            IndexItemKind::Trait { is_unsafe: false }
        );
        assert_eq!(
            index.items[&vec!["U".to_owned()]].kind,
            IndexItemKind::Trait { is_unsafe: true }
        );
        // Trait method is indexed under the trait path.
        assert!(index
            .items
            .contains_key(&vec!["T".to_owned(), "tm".to_owned()]));
    }

    #[test]
    fn indexes_unions_statics_externs() {
        let (index, _dir) = index_of(&[(
            "lib.rs",
            "union U { a: u32, b: f32 }\nstatic mut COUNTER: u64 = 0;\nstatic OK: u64 = 0;\n\
             extern \"C\" { fn socket(domain: i32, ty: i32, protocol: i32) -> i32; }",
        )]);
        assert!(index.unions.contains("U"));
        assert!(index.mutable_statics.contains(&vec!["COUNTER".to_owned()]));
        assert_eq!(index.mutable_statics.len(), 1);
        assert!(index.extern_fns.contains(&vec!["socket".to_owned()]));
    }

    #[test]
    fn flattens_use_trees() {
        let (index, _dir) = index_of(&[(
            "lib.rs",
            "use std::io::{self, Read as R, prelude::*};\nuse crate::inner;\nmod inner { pub fn f() {} }",
        )]);
        let imports = &index.imports[&Vec::new()];
        assert_eq!(imports.exact["io"], vec!["std".to_owned(), "io".to_owned()]);
        assert_eq!(
            imports.exact["R"],
            vec!["std".to_owned(), "io".to_owned(), "Read".to_owned()]
        );
        assert_eq!(
            imports.globs,
            vec![vec![
                "std".to_owned(),
                "io".to_owned(),
                "prelude".to_owned()
            ]]
        );
        assert_eq!(
            imports.exact["inner"],
            vec!["crate".to_owned(), "inner".to_owned()]
        );
    }
}
