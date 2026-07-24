//! Classification of unsafe constructs.
//!
//! This module turns a [`ParsedCrate`] plus its [`CrateIndex`] into a
//! [`CrateAnalysis`]: per-function records carrying the unsafe operations
//! and call sites found in their bodies, plus module-level *structural*
//! findings (`unsafe impl`, `unsafe trait`, `static mut`, extern blocks).
//!
//! Classification is purely syntactic. Two heuristics deserve emphasis:
//!
//! * **Raw pointer dereference**: any dereference expression inside an
//!   unsafe context is reported as a candidate ([`Confidence::Inferred`]),
//!   because dereferencing a raw pointer requires an unsafe context while
//!   dereferencing a reference does not — but references may still be
//!   dereferenced inside one.
//! * **Union field access**: tracked through explicit type annotations on
//!   parameters and `let` bindings of the same function ([`Confidence::
//!   Confirmed`] when the annotation names a known union). Untracked
//!   aliases are missed; this is recorded in the limitations.
//!
//! Resolution-dependent operations (calls to `unsafe fn`, FFI calls) are
//! *not* produced here; they are added during call-graph construction,
//! where callee information is available.

use std::collections::BTreeSet;

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, Item};
use unsafe_surface_core::{
    Confidence, Diagnostic, FunctionKind, PackageId, SourceLocation, StructuralFinding,
    UnsafeOpKind, UnsafeOperation,
};

use crate::index::{CrateIndex, ModuleImports};
use crate::justify::find_justification;
use crate::source::ParsedCrate;

/// A reference to a callee, as written in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalleeRef {
    /// A path call `a::b::c(...)`. Segments preserve leading
    /// `crate`/`self`/`super`/`Self` keywords for resolution.
    Path {
        /// Path segments as written (generic arguments stripped).
        segments: Vec<String>,
    },
    /// A method call `receiver.name(...)`.
    Method {
        /// Method name.
        name: String,
        /// Whether the receiver is literally `self`.
        receiver_is_self: bool,
    },
}

/// A call site inside a function body.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// The callee reference.
    pub callee: CalleeRef,
    /// Where the call occurs.
    pub location: SourceLocation,
}

/// One function-like item of a crate.
#[derive(Debug)]
pub struct FunctionRecord {
    /// Module-relative item path (without the crate name).
    pub path: Vec<String>,
    /// What kind of callable this is.
    pub kind: FunctionKind,
    /// Whether the item is `pub`.
    pub is_pub: bool,
    /// Whether this is an `unsafe fn`.
    pub is_unsafe_fn: bool,
    /// Where the function is defined.
    pub location: SourceLocation,
    /// Unsafe operations found in the body (syntactic classification).
    pub ops: Vec<UnsafeOperation>,
    /// Call sites found in the body.
    pub calls: Vec<CallSite>,
    /// `Self` type segments of the enclosing impl block, if any. Used to
    /// resolve `self.method()` and `Self::method()` calls.
    pub impl_self_ty: Option<Vec<String>>,
    /// `use` imports declared inside the body.
    pub imports: ModuleImports,
}

/// The classified analysis of one crate.
#[derive(Debug)]
pub struct CrateAnalysis {
    /// Function-level records (free functions, methods, extern fns).
    pub functions: Vec<FunctionRecord>,
    /// Module-level unsafe constructs.
    pub structural: Vec<StructuralFinding>,
    /// Non-fatal classification diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Classifies a parsed crate.
#[must_use]
pub fn classify_crate(
    parsed: &ParsedCrate,
    index: &CrateIndex,
    package: &PackageId,
) -> CrateAnalysis {
    let mut analysis = CrateAnalysis {
        functions: Vec::new(),
        structural: Vec::new(),
        diagnostics: Vec::new(),
    };
    for module in &parsed.modules {
        for item in &module.items {
            classify_item(&mut analysis, index, package, module, item);
        }
    }
    analysis
}

fn classify_item(
    analysis: &mut CrateAnalysis,
    index: &CrateIndex,
    package: &PackageId,
    module: &crate::source::ParsedModule,
    item: &Item,
) {
    match item {
        Item::Fn(item_fn) => {
            let record = function_record(
                index,
                module,
                joined(&module.path, &item_fn.sig.ident.to_string()),
                FunctionKind::Free,
                is_pub(&item_fn.vis),
                item_fn.sig.unsafety.is_some(),
                &item_fn.sig,
                Some(&item_fn.block),
                None,
            );
            analysis.functions.push(record);
        }
        Item::Impl(item_impl) => {
            classify_impl(analysis, index, package, module, item_impl);
        }
        Item::Trait(item_trait) => {
            if item_trait.unsafety.is_some() {
                analysis.structural.push(StructuralFinding {
                    kind: UnsafeOpKind::UnsafeTrait,
                    package: package.clone(),
                    location: location_of(module, item_trait.ident.span()),
                    detail: format!("unsafe trait {}", item_trait.ident),
                    justification: find_justification(
                        &module.text,
                        start_line(item_trait.ident.span()),
                    ),
                });
            }
            let trait_name = item_trait.ident.to_string();
            for trait_item in &item_trait.items {
                if let syn::TraitItem::Fn(method) = trait_item {
                    let has_body = method.default.is_some();
                    let path = {
                        let mut p = joined(&module.path, &trait_name);
                        p.push(method.sig.ident.to_string());
                        p
                    };
                    let record = function_record(
                        index,
                        module,
                        path,
                        FunctionKind::TraitMethod {
                            trait_name: trait_name.clone(),
                        },
                        is_pub(&item_trait.vis),
                        method.sig.unsafety.is_some(),
                        &method.sig,
                        method.default.as_ref(),
                        Some(vec![trait_name.clone()]),
                    );
                    // Declarations without bodies produce no graph node.
                    if has_body {
                        analysis.functions.push(record);
                    }
                }
            }
        }
        Item::ForeignMod(foreign_mod) => {
            let abi = foreign_mod
                .abi
                .name
                .as_ref()
                .map(|n| n.value())
                .unwrap_or_else(|| "C".to_owned());
            analysis.structural.push(StructuralFinding {
                kind: UnsafeOpKind::ExternBlock,
                package: package.clone(),
                location: location_of(module, foreign_mod.abi.extern_token.span),
                detail: format!(
                    "{}extern \"{abi}\" block",
                    if foreign_mod.unsafety.is_some() {
                        "unsafe "
                    } else {
                        ""
                    }
                ),
                justification: find_justification(
                    &module.text,
                    start_line(foreign_mod.abi.extern_token.span),
                ),
            });
            for foreign_item in &foreign_mod.items {
                if let syn::ForeignItem::Fn(foreign_fn) = foreign_item {
                    let name = foreign_fn.sig.ident.to_string();
                    let location = location_of(module, foreign_fn.sig.ident.span());
                    analysis.structural.push(StructuralFinding {
                        kind: UnsafeOpKind::ForeignFunction,
                        package: package.clone(),
                        location: location.clone(),
                        detail: format!("extern \"{abi}\" fn {name}"),
                        justification: find_justification(
                            &module.text,
                            start_line(foreign_fn.sig.ident.span()),
                        ),
                    });
                    analysis.functions.push(FunctionRecord {
                        path: joined(&module.path, &name),
                        kind: FunctionKind::Extern,
                        is_pub: is_pub(&foreign_fn.vis),
                        is_unsafe_fn: true, // calling a foreign fn is always unsafe
                        location,
                        ops: Vec::new(),
                        calls: Vec::new(),
                        impl_self_ty: None,
                        imports: ModuleImports::default(),
                    });
                }
            }
        }
        Item::Static(item_static) => {
            if matches!(item_static.mutability, syn::StaticMutability::Mut(_)) {
                analysis.structural.push(StructuralFinding {
                    kind: UnsafeOpKind::MutableStaticDefinition,
                    package: package.clone(),
                    location: location_of(module, item_static.ident.span()),
                    detail: format!("static mut {}", item_static.ident),
                    justification: find_justification(
                        &module.text,
                        start_line(item_static.ident.span()),
                    ),
                });
            }
        }
        _ => {}
    }
}

fn classify_impl(
    analysis: &mut CrateAnalysis,
    index: &CrateIndex,
    package: &PackageId,
    module: &crate::source::ParsedModule,
    item_impl: &syn::ItemImpl,
) {
    let self_ty = type_path_string(&item_impl.self_ty);
    if let Some((_, trait_path, _)) = &item_impl.trait_ {
        let trait_name = trait_path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let kind = match trait_name.as_str() {
            // Manual Send/Sync impls are reported even without the `unsafe`
            // token (which is required by the compiler anyway): they are a
            // key audit target.
            "Send" => Some(UnsafeOpKind::SendImpl),
            "Sync" => Some(UnsafeOpKind::SyncImpl),
            _ if item_impl.unsafety.is_some() => Some(UnsafeOpKind::UnsafeTraitImpl),
            _ => None,
        };
        if let Some(kind) = kind {
            analysis.structural.push(StructuralFinding {
                kind,
                package: package.clone(),
                location: location_of(module, item_impl.impl_token.span),
                detail: format!(
                    "{}impl {} for {}",
                    if item_impl.unsafety.is_some() {
                        "unsafe "
                    } else {
                        ""
                    },
                    path_string(trait_path),
                    self_ty,
                ),
                justification: find_justification(
                    &module.text,
                    start_line(item_impl.impl_token.span),
                ),
            });
        }
    }

    let self_ty_segments = type_path_segments(&item_impl.self_ty);
    let trait_last = item_impl
        .trait_
        .as_ref()
        .and_then(|(_, p, _)| p.segments.last().map(|s| s.ident.to_string()));
    for impl_item in &item_impl.items {
        if let syn::ImplItem::Fn(method) = impl_item {
            let mut path = module.path.clone();
            path.extend(self_ty_segments.iter().cloned());
            if let Some(trait_last) = &trait_last {
                path.push(trait_last.clone());
            }
            path.push(method.sig.ident.to_string());
            let record = function_record(
                index,
                module,
                path,
                FunctionKind::Method {
                    self_ty: self_ty.clone(),
                },
                is_pub(&method.vis),
                method.sig.unsafety.is_some(),
                &method.sig,
                Some(&method.block),
                Some(self_ty_segments.clone()),
            );
            analysis.functions.push(record);
        }
    }
}

/// Builds a [`FunctionRecord`] by visiting a function body.
#[allow(clippy::too_many_arguments)]
fn function_record(
    index: &CrateIndex,
    module: &crate::source::ParsedModule,
    path: Vec<String>,
    kind: FunctionKind,
    is_pub: bool,
    is_unsafe_fn: bool,
    sig: &syn::Signature,
    block: Option<&syn::Block>,
    impl_self_ty: Option<Vec<String>>,
) -> FunctionRecord {
    let location = location_of(module, sig.ident.span());
    let mut record = FunctionRecord {
        path,
        kind,
        is_pub,
        is_unsafe_fn,
        location: location.clone(),
        ops: Vec::new(),
        calls: Vec::new(),
        impl_self_ty,
        imports: ModuleImports::default(),
    };
    if is_unsafe_fn {
        record.ops.push(
            UnsafeOperation::new(UnsafeOpKind::UnsafeFn, location).with_justification(
                find_justification(&module.text, start_line(sig.ident.span())),
            ),
        );
    }
    let Some(block) = block else {
        return record;
    };
    let mut visitor = FnBodyVisitor {
        index,
        module,
        record: &mut record,
        unsafe_depth: usize::from(is_unsafe_fn),
        union_locals: BTreeSet::new(),
    };
    visitor.collect_signature_bindings(sig);
    visitor.visit_block(block);
    record
}

/// Visitor over one function body.
struct FnBodyVisitor<'a> {
    index: &'a CrateIndex,
    module: &'a crate::source::ParsedModule,
    record: &'a mut FunctionRecord,
    /// Nesting depth of unsafe contexts (`unsafe {}` blocks; starts at 1
    /// for `unsafe fn` bodies).
    unsafe_depth: usize,
    /// Local variable names with explicitly annotated union types.
    union_locals: BTreeSet<String>,
}

impl FnBodyVisitor<'_> {
    /// Binds parameters whose type annotation names a known union.
    fn collect_signature_bindings(&mut self, sig: &syn::Signature) {
        for input in &sig.inputs {
            if let syn::FnArg::Typed(pat_type) = input {
                self.bind_if_union(&pat_type.pat, &pat_type.ty);
            }
        }
    }

    fn bind_if_union(&mut self, pat: &syn::Pat, ty: &syn::Type) {
        let is_union = type_path_segments(ty)
            .last()
            .map(|last| self.index.unions.contains(last))
            .unwrap_or(false);
        if is_union {
            collect_pat_idents(pat, &mut self.union_locals);
        }
    }

    fn op(&mut self, kind: UnsafeOpKind, span: proc_macro2::Span) -> UnsafeOperation {
        UnsafeOperation::new(kind, location_of(self.module, span))
            .with_justification(find_justification(&self.module.text, start_line(span)))
    }

    fn path_segments(expr_path: &syn::ExprPath) -> Vec<String> {
        expr_path
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect()
    }

    fn last_segment_is(segments: &[String], names: &[&str]) -> bool {
        segments
            .last()
            .map(|last| names.contains(&last.as_str()))
            .unwrap_or(false)
    }
}

impl Visit<'_> for FnBodyVisitor<'_> {
    fn visit_expr_unsafe(&mut self, node: &syn::ExprUnsafe) {
        let op = self.op(UnsafeOpKind::UnsafeBlock, node.unsafe_token.span);
        self.record.ops.push(op);
        self.unsafe_depth += 1;
        syn::visit::visit_expr_unsafe(self, node);
        self.unsafe_depth -= 1;
    }

    fn visit_expr_call(&mut self, node: &syn::ExprCall) {
        if let Expr::Path(expr_path) = &*node.func {
            let segments = Self::path_segments(expr_path);
            if Self::last_segment_is(&segments, &["transmute", "transmute_copy"]) {
                let op = self.op(UnsafeOpKind::Transmute, expr_path.path.span());
                self.record.ops.push(op.with_detail(segments.join("::")));
            } else if segments.iter().any(|s| s == "MaybeUninit") {
                // MaybeUninit::uninit() / core::mem::MaybeUninit::new() / …
                // (`MaybeUninit` is not the called segment, the method is).
                let op = self.op(UnsafeOpKind::MaybeUninitUse, expr_path.path.span());
                self.record
                    .ops
                    .push(op.with_confidence(Confidence::Inferred));
            }
            self.record.calls.push(CallSite {
                callee: CalleeRef::Path { segments },
                location: location_of(self.module, expr_path.path.span()),
            });
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &syn::ExprMethodCall) {
        let name = node.method.to_string();
        if name.contains("_unchecked") {
            let op = self.op(UnsafeOpKind::UncheckedCall, node.method.span());
            self.record.ops.push(
                op.with_confidence(Confidence::Inferred)
                    .with_detail(name.clone()),
            );
        }
        let receiver_is_self = matches!(
            &*node.receiver,
            Expr::Path(p) if p.path.is_ident("self")
        );
        self.record.calls.push(CallSite {
            callee: CalleeRef::Method {
                name,
                receiver_is_self,
            },
            location: location_of(self.module, node.method.span()),
        });
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_unary(&mut self, node: &syn::ExprUnary) {
        if matches!(node.op, syn::UnOp::Deref(_)) && self.unsafe_depth > 0 {
            // Dereference inside an unsafe context: a raw-pointer deref
            // must be in one, but a reference deref may also be — hence
            // Inferred confidence (documented heuristic).
            let op = self.op(UnsafeOpKind::RawPointerDeref, node.span());
            self.record
                .ops
                .push(op.with_confidence(Confidence::Inferred));
        }
        syn::visit::visit_expr_unary(self, node);
    }

    fn visit_expr_field(&mut self, node: &syn::ExprField) {
        if let Expr::Path(base) = &*node.base {
            if let Some(ident) = base.path.get_ident() {
                if self.union_locals.contains(&ident.to_string()) {
                    let op = self.op(UnsafeOpKind::UnionFieldAccess, node.member.span());
                    self.record.ops.push(op);
                }
            }
        }
        syn::visit::visit_expr_field(self, node);
    }

    fn visit_expr_macro(&mut self, node: &syn::ExprMacro) {
        let segments: Vec<String> = node
            .mac
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        if Self::last_segment_is(&segments, &["asm", "global_asm", "naked_asm"]) {
            let op = self.op(UnsafeOpKind::InlineAssembly, node.mac.path.span());
            self.record.ops.push(op.with_detail(segments.join("::")));
        }
        syn::visit::visit_expr_macro(self, node);
    }

    fn visit_expr_path(&mut self, node: &syn::ExprPath) {
        let segments = Self::path_segments(node);
        if let Some(last) = segments.last() {
            // Mutable static access: matched by last segment against the
            // crate's known `static mut` items (cross-module approximation,
            // documented). `self`/`Self` never match statics.
            if last != "self" && last != "Self" {
                let is_static = self
                    .index
                    .mutable_statics
                    .iter()
                    .any(|path| path.last() == Some(last));
                if is_static {
                    let op = self.op(UnsafeOpKind::MutableStaticAccess, node.path.span());
                    self.record
                        .ops
                        .push(op.with_confidence(Confidence::Inferred));
                }
                if last == "MaybeUninit" {
                    let op = self.op(UnsafeOpKind::MaybeUninitUse, node.path.span());
                    self.record
                        .ops
                        .push(op.with_confidence(Confidence::Inferred));
                }
            }
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_local(&mut self, node: &syn::Local) {
        // `let x: U = ...` is parsed as a typed pattern in syn 2.
        if let syn::Pat::Type(pat_type) = &node.pat {
            self.bind_if_union(&pat_type.pat, &pat_type.ty);
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_item_use(&mut self, node: &syn::ItemUse) {
        flatten_use_tree(&node.tree, Vec::new(), &mut self.record.imports);
        // Do not descend: the use tree contains paths, which would be
        // misclassified as expressions by `visit_expr_path` (they are not
        // visited by the default impl, but be explicit).
    }

    fn visit_item(&mut self, node: &Item) {
        // `use` declarations inside bodies feed the resolution scope…
        if let Item::Use(item_use) = node {
            self.visit_item_use(item_use);
        }
        // …but other items nested inside function bodies (inner fns,
        // impls, …) are not modelled as separate graph nodes in this
        // version; their calls are conservatively attributed to the
        // enclosing function. Recorded in the analysis limitations.
    }
}

/// Re-export of the use-tree flattener shared with the index builder.
fn flatten_use_tree(tree: &syn::UseTree, prefix: Vec<String>, imports: &mut ModuleImports) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut prefix = prefix;
            prefix.push(path.ident.to_string());
            flatten_use_tree(&path.tree, prefix, imports);
        }
        syn::UseTree::Name(name) => {
            if name.ident == "self" {
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
        syn::UseTree::Glob(_) => imports.globs.push(prefix),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use_tree(tree, prefix.clone(), imports);
            }
        }
    }
}

fn collect_pat_idents(pat: &syn::Pat, out: &mut BTreeSet<String>) {
    match pat {
        syn::Pat::Ident(ident) => {
            out.insert(ident.ident.to_string());
        }
        syn::Pat::Tuple(tuple) => {
            for elem in &tuple.elems {
                collect_pat_idents(elem, out);
            }
        }
        syn::Pat::Struct(strukt) => {
            for field in &strukt.fields {
                collect_pat_idents(&field.pat, out);
            }
        }
        syn::Pat::Reference(reference) => collect_pat_idents(&reference.pat, out),
        _ => {}
    }
}

fn type_path_segments(ty: &syn::Type) -> Vec<String> {
    match ty {
        syn::Type::Path(type_path) if type_path.qself.is_none() => type_path
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect(),
        _ => Vec::new(),
    }
}

fn type_path_string(ty: &syn::Type) -> String {
    type_path_segments(ty).join("::")
}

fn path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn joined(module: &[String], name: &str) -> Vec<String> {
    let mut path = module.to_vec();
    path.push(name.to_owned());
    path
}

fn is_pub(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

/// 1-based start line of a span.
fn start_line(span: proc_macro2::Span) -> u32 {
    u32::try_from(span.start().line).unwrap_or(u32::MAX)
}

/// Source location of a span within its module's display path.
fn location_of(module: &crate::source::ParsedModule, span: proc_macro2::Span) -> SourceLocation {
    let start = span.start();
    SourceLocation::new(
        module.file_display.clone(),
        u32::try_from(start.line).unwrap_or(u32::MAX),
        u32::try_from(start.column + 1).unwrap_or(u32::MAX),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_eval::CfgEvaluator;
    use crate::index::build_index;
    use crate::limits::Limits;
    use crate::source::{parse_crate, ParseContext};
    use std::collections::BTreeSet;
    use std::fs;
    use unsafe_surface_cargo::CfgValues;
    use unsafe_surface_core::{DependencyOrigin, SafetyJustification};

    fn analyze(files: &[(&str, &str)]) -> (CrateAnalysis, tempfile::TempDir) {
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
        let index = build_index(&parsed);
        let package = PackageId::new("demo", Some("0.1.0".into()), DependencyOrigin::Workspace);
        (classify_crate(&parsed, &index, &package), dir)
    }

    fn function<'a>(analysis: &'a CrateAnalysis, name: &str) -> &'a FunctionRecord {
        analysis
            .functions
            .iter()
            .find(|f| f.path.last().map(String::as_str) == Some(name))
            .unwrap_or_else(|| panic!("function `{name}` not found"))
    }

    fn op_kinds(record: &FunctionRecord) -> Vec<UnsafeOpKind> {
        record.ops.iter().map(|op| op.kind).collect()
    }

    #[test]
    fn detects_unsafe_fn_and_blocks_with_justification() {
        let (analysis, _dir) = analyze(&[(
            "lib.rs",
            "/// # Safety\n/// Caller ensures validity.\nunsafe fn risky() {}\n\
             fn wrapper() {\n    // SAFETY: justified\n    unsafe { core::ptr::read(0 as *const i32) };\n\
             unsafe { core::ptr::write(1 as *mut i32, 2) };\n}\n",
        )]);
        let risky = function(&analysis, "risky");
        assert!(risky.is_unsafe_fn);
        assert_eq!(op_kinds(risky), vec![UnsafeOpKind::UnsafeFn]);
        assert_eq!(risky.ops[0].justification, SafetyJustification::Present);

        let wrapper = function(&analysis, "wrapper");
        let blocks: Vec<_> = wrapper
            .ops
            .iter()
            .filter(|op| op.kind == UnsafeOpKind::UnsafeBlock)
            .collect();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].justification, SafetyJustification::Present);
        assert_eq!(blocks[1].justification, SafetyJustification::Absent);
    }

    #[test]
    fn detects_transmute_unchecked_maybeuninit() {
        let (analysis, _dir) = analyze(&[(
            "lib.rs",
            "fn f(v: Vec<u8>, x: u64, b: bool) -> u128 {\n\
             \x20   unsafe {\n\
             \x20       let _ = core::mem::transmute::<u64, f64>(x);\n\
             \x20       let _ = v.get_unchecked(0);\n\
             \x20       let _ = b.unwrap_unchecked();\n\
             \x20       let mut m = core::mem::MaybeUninit::<u128>::uninit();\n\
             \x20       m.assume_init()\n\
             \x20   }\n\
             }\n",
        )]);
        let kinds = op_kinds(function(&analysis, "f"));
        for expected in [
            UnsafeOpKind::Transmute,
            UnsafeOpKind::UncheckedCall,
            UnsafeOpKind::MaybeUninitUse,
        ] {
            assert!(kinds.contains(&expected), "missing {expected} in {kinds:?}");
        }
        let unchecked: Vec<_> = function(&analysis, "f")
            .ops
            .iter()
            .filter(|op| op.kind == UnsafeOpKind::UncheckedCall)
            .collect();
        assert_eq!(unchecked.len(), 2, "get_unchecked + unwrap_unchecked");
    }

    #[test]
    fn detects_inline_assembly() {
        let (analysis, _dir) = analyze(&[(
            "lib.rs",
            "fn f() {\n    unsafe { core::arch::asm!(\"nop\") };\n}\n",
        )]);
        let ops = &function(&analysis, "f").ops;
        let asm = ops
            .iter()
            .find(|op| op.kind == UnsafeOpKind::InlineAssembly)
            .expect("asm! not detected");
        assert_eq!(asm.detail.as_deref(), Some("core::arch::asm"));
    }

    #[test]
    fn raw_pointer_deref_only_in_unsafe_context() {
        let (analysis, _dir) = analyze(&[(
            "lib.rs",
            "fn f(p: *const i32, r: &i32) -> i32 {\n\
             \x20   let _ = *r;\n\
             \x20   unsafe { *p }\n\
             }\n\
             unsafe fn g(p: *const i32) -> i32 { *p }\n",
        )]);
        let derefs: Vec<_> = function(&analysis, "f")
            .ops
            .iter()
            .filter(|op| op.kind == UnsafeOpKind::RawPointerDeref)
            .collect();
        assert_eq!(derefs.len(), 1, "only the unsafe-context deref");
        assert_eq!(derefs[0].confidence, Confidence::Inferred);
        // unsafe fn bodies count as unsafe contexts.
        assert!(op_kinds(function(&analysis, "g")).contains(&UnsafeOpKind::RawPointerDeref));
    }

    #[test]
    fn detects_union_field_access_via_annotations() {
        let (analysis, _dir) = analyze(&[(
            "lib.rs",
            "union U { a: u32, b: f32 }\n\
             fn f(u: U) -> u32 { unsafe { u.a } }\n\
             fn g() {\n\
             \x20   let v: U = U { a: 1 };\n\
             \x20   unsafe { let _ = v.b; };\n\
             }\n",
        )]);
        let f = function(&analysis, "f");
        assert!(op_kinds(f).contains(&UnsafeOpKind::UnionFieldAccess));
        let access = f
            .ops
            .iter()
            .find(|op| op.kind == UnsafeOpKind::UnionFieldAccess)
            .unwrap();
        assert_eq!(access.confidence, Confidence::Confirmed);
        assert!(op_kinds(function(&analysis, "g")).contains(&UnsafeOpKind::UnionFieldAccess));
    }

    #[test]
    fn detects_mutable_statics() {
        let (analysis, _dir) = analyze(&[(
            "lib.rs",
            "static mut COUNTER: u64 = 0;\n\
             fn bump() {\n    unsafe { COUNTER += 1; };\n}\n",
        )]);
        assert!(analysis
            .structural
            .iter()
            .any(|s| s.kind == UnsafeOpKind::MutableStaticDefinition
                && s.detail == "static mut COUNTER"));
        assert!(op_kinds(function(&analysis, "bump")).contains(&UnsafeOpKind::MutableStaticAccess));
    }

    #[test]
    fn detects_extern_blocks_and_foreign_fns() {
        let (analysis, _dir) = analyze(&[(
            "lib.rs",
            "extern \"C\" {\n    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;\n}\n",
        )]);
        assert!(analysis
            .structural
            .iter()
            .any(|s| s.kind == UnsafeOpKind::ExternBlock));
        assert!(analysis
            .structural
            .iter()
            .any(|s| s.kind == UnsafeOpKind::ForeignFunction && s.detail.contains("socket")));
        let socket = function(&analysis, "socket");
        assert_eq!(socket.kind, FunctionKind::Extern);
        assert!(socket.is_unsafe_fn);
    }

    #[test]
    fn detects_unsafe_impls_and_traits() {
        let (analysis, _dir) = analyze(&[(
            "lib.rs",
            "struct Handle(*mut u8);\n\
             unsafe impl Send for Handle {}\n\
             unsafe impl Sync for Handle {}\n\
             trait Plain {}\n\
             unsafe impl Plain for Handle {}\n\
             unsafe trait Scary {}\n",
        )]);
        let kinds: Vec<_> = analysis.structural.iter().map(|s| s.kind).collect();
        for expected in [
            UnsafeOpKind::SendImpl,
            UnsafeOpKind::SyncImpl,
            UnsafeOpKind::UnsafeTraitImpl,
            UnsafeOpKind::UnsafeTrait,
        ] {
            assert!(kinds.contains(&expected), "missing {expected} in {kinds:?}");
        }
        let send = analysis
            .structural
            .iter()
            .find(|s| s.kind == UnsafeOpKind::SendImpl)
            .unwrap();
        assert_eq!(send.detail, "unsafe impl Send for Handle");
    }

    #[test]
    fn collects_call_sites_and_local_imports() {
        let (analysis, _dir) = analyze(&[(
            "lib.rs",
            "fn f() {\n\
             \x20   use crate::helpers::thing;\n\
             \x20   thing();\n\
             \x20   let s = String::new();\n\
             \x20   s.len();\n\
             \x20   self_method_receiver();\n\
             }\n\
             fn self_method_receiver() {}\n\
             mod helpers { pub fn thing() {} }\n\
             struct S;\n\
             impl S {\n\
             \x20   fn m(&self) {\n\
             \x20       self.helper();\n\
             \x20       Self::other();\n\
             \x20   }\n\
             \x20   fn helper(&self) {}\n\
             \x20   fn other() {}\n\
             }\n",
        )]);
        let f = function(&analysis, "f");
        assert_eq!(f.calls.len(), 4);
        assert!(
            matches!(&f.calls[0].callee, CalleeRef::Path { segments } if segments == &["thing"])
        );
        assert!(
            matches!(&f.calls[1].callee, CalleeRef::Path { segments } if segments == &["String", "new"])
        );
        assert!(
            matches!(&f.calls[2].callee, CalleeRef::Method { name, receiver_is_self: false } if name == "len")
        );
        assert!(
            matches!(&f.calls[3].callee, CalleeRef::Path { segments } if segments == &["self_method_receiver"])
        );
        assert_eq!(
            f.imports.exact["thing"],
            vec!["crate".to_owned(), "helpers".to_owned(), "thing".to_owned()]
        );

        let m = function(&analysis, "m");
        assert!(
            matches!(&m.calls[0].callee, CalleeRef::Method { name, receiver_is_self: true } if name == "helper")
        );
        assert!(
            matches!(&m.calls[1].callee, CalleeRef::Path { segments } if segments == &["Self", "other"])
        );
        assert_eq!(m.impl_self_ty, Some(vec!["S".to_owned()]));
    }

    #[test]
    fn locations_are_one_based() {
        let (analysis, _dir) = analyze(&[("lib.rs", "fn f() {\n    unsafe {}\n}\n")]);
        let f = function(&analysis, "f");
        assert_eq!(f.location.line, 1);
        let block = f
            .ops
            .iter()
            .find(|op| op.kind == UnsafeOpKind::UnsafeBlock)
            .unwrap();
        assert_eq!(block.location.line, 2);
        assert!(block.location.column >= 5);
        assert_eq!(block.location.file, "lib.rs");
    }
}
