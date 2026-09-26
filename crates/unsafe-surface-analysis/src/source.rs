//! Crate source loading: reading files and walking the module tree.
//!
//! The walker starts at the crate root (`src/lib.rs` / `src/main.rs`) and
//! follows `mod` declarations, handling `mod.rs` vs `name.rs` layouts,
//! inline modules and `#[path = "..."]` overrides. It defends against
//! hostile input with [`Limits`] (file size, file count, module depth) and
//! canonical-path cycle detection. Every problem becomes a
//! [`Diagnostic`]; the walker never aborts the whole crate for one bad
//! file.
//!
//! Files are read but never executed, and `#[cfg]`-disabled modules are
//! skipped via [`CfgEvaluator`]. Modules are emitted in post-order
//! (children after parents), which is deterministic; callers must not rely
//! on pre-order traversal.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use syn::Item;
use unsafe_surface_core::{Diagnostic, SourceLocation};

use crate::cfg_eval::{CfgEvaluator, CfgResult};
use crate::error::AnalysisError;
use crate::limits::Limits;

/// One parsed module of a crate.
#[derive(Debug)]
pub struct ParsedModule {
    /// Module path segments below the crate root (`[]` for the root).
    pub path: Vec<String>,
    /// Display path of the file (relative to the workspace root when the
    /// file is inside it, absolute otherwise).
    pub file_display: String,
    /// Original file path on disk.
    pub file_path: PathBuf,
    /// Raw source text (shared between modules of the same file; used for
    /// `SAFETY:` comment detection).
    pub text: Rc<str>,
    /// The module's own items (child modules included as [`syn::ItemMod`]).
    pub items: Vec<Item>,
}

/// A fully parsed crate.
#[derive(Debug)]
pub struct ParsedCrate {
    /// All modules, in deterministic post-order.
    pub modules: Vec<ParsedModule>,
    /// Non-fatal problems encountered while parsing.
    pub diagnostics: Vec<Diagnostic>,
    /// How many items were kept because their `cfg` evaluated to
    /// [`CfgResult::Unknown`] (over-approximation accounting).
    pub unknown_cfg_items: u64,
}

/// Context for parsing one crate.
pub struct ParseContext<'a> {
    /// `cfg` evaluator for this crate.
    pub cfg: CfgEvaluator<'a>,
    /// Resource limits.
    pub limits: &'a Limits,
    /// Root used to relativize display paths (usually the workspace root).
    pub display_root: Option<&'a Path>,
}

/// Parses a crate starting at `root_file`.
///
/// # Errors
///
/// Returns [`AnalysisError::CrateRootUnreadable`] only when the root file
/// itself cannot be read. All other problems are diagnostics.
pub fn parse_crate(
    root_file: &Path,
    context: &ParseContext<'_>,
) -> Result<ParsedCrate, AnalysisError> {
    let mut walker = Walker {
        context,
        modules: Vec::new(),
        diagnostics: Vec::new(),
        visited: HashSet::new(),
        files_parsed: 0,
        unknown_cfg_items: 0,
    };
    walker.load_module(root_file, Vec::new(), 0)?;
    Ok(ParsedCrate {
        modules: walker.modules,
        diagnostics: walker.diagnostics,
        unknown_cfg_items: walker.unknown_cfg_items,
    })
}

struct Walker<'a, 'b> {
    context: &'a ParseContext<'b>,
    modules: Vec<ParsedModule>,
    diagnostics: Vec<Diagnostic>,
    /// Canonical paths of already-loaded files (cycle and symlink-loop
    /// protection).
    visited: HashSet<PathBuf>,
    files_parsed: usize,
    unknown_cfg_items: u64,
}

/// Directory bases used to resolve child module files.
struct ModContext {
    /// Base for plain `mod name;` declarations.
    child_dir: PathBuf,
    /// Base for `#[path = "..."]` overrides.
    path_attr_dir: PathBuf,
}

/// The file currently being processed.
struct CurrentFile<'a> {
    /// Path on disk.
    path: &'a Path,
    /// Display path.
    display: &'a str,
    /// Shared source text.
    text: &'a Rc<str>,
}

impl Walker<'_, '_> {
    fn load_module(
        &mut self,
        file: &Path,
        module_path: Vec<String>,
        depth: usize,
    ) -> Result<(), AnalysisError> {
        let is_root = module_path.is_empty();
        if self.files_parsed >= self.context.limits.max_files_per_crate {
            self.diagnostics.push(Diagnostic::warning(format!(
                "per-crate file limit ({}) exceeded; remaining modules skipped",
                self.context.limits.max_files_per_crate
            )));
            return Ok(());
        }

        let canonical = match file.canonicalize() {
            Ok(path) => path,
            Err(e) if is_root => {
                return Err(AnalysisError::CrateRootUnreadable {
                    path: file.to_path_buf(),
                    message: e.to_string(),
                });
            }
            Err(e) => {
                self.diagnostics.push(Diagnostic::warning(format!(
                    "cannot resolve module file {}: {e}",
                    file.display()
                )));
                return Ok(());
            }
        };
        if !self.visited.insert(canonical) {
            // Re-visiting a file is not an error (diamond-shaped `#[path]`
            // sharing exists); silently keep the first occurrence.
            return Ok(());
        }
        // Count every file that is attempted: unreadable, oversized and
        // unparseable files must not escape the file limits.
        self.files_parsed += 1;

        let file_display = display_path(file, self.context.display_root);

        let metadata = match fs::metadata(file) {
            Ok(metadata) => metadata,
            Err(e) if is_root => {
                return Err(AnalysisError::CrateRootUnreadable {
                    path: file.to_path_buf(),
                    message: e.to_string(),
                });
            }
            Err(e) => {
                self.diagnostics.push(Diagnostic::warning(format!(
                    "cannot stat module file {file_display}: {e}"
                )));
                return Ok(());
            }
        };
        if metadata.len() > self.context.limits.max_file_bytes {
            self.diagnostics.push(Diagnostic::warning(format!(
                "file {file_display} exceeds the size limit ({} bytes); skipped",
                self.context.limits.max_file_bytes
            )));
            return Ok(());
        }

        let text = match fs::read_to_string(file) {
            Ok(text) => text,
            Err(e) if is_root => {
                return Err(AnalysisError::CrateRootUnreadable {
                    path: file.to_path_buf(),
                    message: e.to_string(),
                });
            }
            Err(e) => {
                self.diagnostics.push(Diagnostic::error(format!(
                    "cannot read {file_display}: {e}"
                )));
                return Ok(());
            }
        };

        let parsed = match syn::parse_file(&text) {
            Ok(parsed) => parsed,
            Err(e) => {
                let span = e.span().start();
                self.diagnostics.push(
                    Diagnostic::error(format!("syntax error in {file_display}: {e}")).at(
                        SourceLocation::new(
                            file_display,
                            u32::try_from(span.line).unwrap_or(u32::MAX),
                            u32::try_from(span.column + 1).unwrap_or(u32::MAX),
                        ),
                    ),
                );
                return Ok(());
            }
        };
        let text: Rc<str> = Rc::from(text.as_str());

        // Directory contexts for child module resolution. Rust uses two
        // different bases (verified against rustc 1.97):
        // * plain `mod name;` resolves against `child_dir`: the file's
        //   directory for crate roots and `mod.rs`, `<dir>/<file-stem>/`
        //   for other files;
        // * `#[path = "..."]` resolves against `path_attr_dir`: always the
        //   directory containing the current file.
        let parent = file.parent().map(Path::to_path_buf).unwrap_or_default();
        let is_container = is_root
            || file
                .file_name()
                .and_then(|n| n.to_str())
                .map(|name| name == "mod.rs")
                .unwrap_or(false);
        let child_dir = if is_container {
            parent.clone()
        } else {
            match file.file_stem().and_then(|s| s.to_str()) {
                Some(stem) => parent.join(stem),
                None => parent.clone(),
            }
        };
        let mod_context = ModContext {
            child_dir,
            path_attr_dir: parent,
        };

        let current = CurrentFile {
            path: file,
            display: &file_display,
            text: &text,
        };
        let items = self.process_items(parsed.items, &module_path, &mod_context, &current, depth);
        self.modules.push(ParsedModule {
            path: module_path,
            file_display,
            file_path: file.to_path_buf(),
            text,
            items,
        });
        Ok(())
    }

    /// Processes the items of one module: recurses into child modules and
    /// returns the items belonging to the module itself.
    fn process_items(
        &mut self,
        items: Vec<Item>,
        module_path: &[String],
        mod_context: &ModContext,
        current: &CurrentFile<'_>,
        depth: usize,
    ) -> Vec<Item> {
        let mut kept = Vec::new();
        for item in items {
            let cfg_result = self.context.cfg.evaluate_attrs(attrs_of(&item));
            if !cfg_result.keeps_item() {
                continue;
            }
            if cfg_result == CfgResult::Unknown {
                self.unknown_cfg_items += 1;
            }

            if let Item::Mod(item_mod) = &item {
                self.handle_mod(item_mod, module_path, mod_context, current, depth);
            }
            kept.push(item);
        }
        kept
    }

    fn handle_mod(
        &mut self,
        item_mod: &syn::ItemMod,
        module_path: &[String],
        mod_context: &ModContext,
        current: &CurrentFile<'_>,
        depth: usize,
    ) {
        let name = item_mod.ident.to_string();
        let mut child_path = module_path.to_vec();
        child_path.push(name.clone());

        // The depth limit is enforced here, the single recursion point,
        // so file modules *and* inline `mod name { ... }` blocks are
        // bounded: inline nesting recurses without ever touching a file.
        if depth + 1 > self.context.limits.max_module_depth {
            self.diagnostics.push(Diagnostic::warning(format!(
                "module depth limit ({}) exceeded at {}; subtree skipped",
                self.context.limits.max_module_depth, current.display
            )));
            return;
        }

        if let Some((_, items)) = &item_mod.content {
            // Inline module `mod name { ... }`: plain `mod` declarations
            // inside it resolve against `<context>/name/`; `#[path]` keeps
            // the enclosing file's base (documented approximation).
            let inline_context = ModContext {
                child_dir: mod_context.child_dir.join(&name),
                path_attr_dir: mod_context.path_attr_dir.clone(),
            };
            let kept = self.process_items(
                items.clone(),
                &child_path,
                &inline_context,
                current,
                depth + 1,
            );
            self.modules.push(ParsedModule {
                path: child_path,
                file_display: current.display.to_owned(),
                file_path: current.path.to_path_buf(),
                text: Rc::clone(current.text),
                items: kept,
            });
            return;
        }

        // `#[path = "..."]` overrides the default resolution. It is a
        // name-value attribute, not a list attribute.
        let override_path = item_mod
            .attrs
            .iter()
            .find(|a| a.path().is_ident("path"))
            .and_then(|a| match &a.meta {
                syn::Meta::NameValue(name_value) => match &name_value.value {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(lit),
                        ..
                    }) => Some(mod_context.path_attr_dir.join(lit.value())),
                    _ => None,
                },
                _ => None,
            });

        let candidates: Vec<PathBuf> = match override_path {
            Some(path) => vec![path],
            None => vec![
                mod_context.child_dir.join(format!("{name}.rs")),
                mod_context.child_dir.join(name.clone()).join("mod.rs"),
            ],
        };
        match candidates.iter().find(|c| c.is_file()) {
            Some(found) => {
                let found = found.clone();
                if let Err(error) = self.load_module(&found, child_path, depth + 1) {
                    self.diagnostics.push(Diagnostic::error(format!(
                        "failed to load module `{name}`: {error}"
                    )));
                }
            }
            None => {
                self.diagnostics.push(Diagnostic::warning(format!(
                    "module `{name}` declared in {} has no readable file \
                     (looked for {})",
                    current.display,
                    candidates
                        .iter()
                        .map(|c| c.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
    }
}

/// Attributes of an item (empty for item kinds that cannot carry `cfg`).
fn attrs_of(item: &Item) -> &[syn::Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

/// Display path relative to `root` when possible, with forward slashes.
fn display_path(file: &Path, root: Option<&Path>) -> String {
    match root.and_then(|root| file.strip_prefix(root).ok()) {
        Some(relative) => relative.to_string_lossy().replace('\\', "/"),
        None => file.to_string_lossy().replace('\\', "/"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use unsafe_surface_cargo::CfgValues;

    fn parse(files: &[(&str, &str)]) -> (ParsedCrate, tempfile::TempDir) {
        parse_with_limits(files, Limits::default())
    }

    fn parse_with_limits(
        files: &[(&str, &str)],
        limits: Limits,
    ) -> (ParsedCrate, tempfile::TempDir) {
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
        let context = ParseContext {
            cfg: CfgEvaluator::new(&values, &features),
            limits: &limits,
            display_root: Some(dir.path()),
        };
        let parsed = parse_crate(&root.unwrap(), &context).unwrap();
        (parsed, dir)
    }

    fn module_paths(parsed: &ParsedCrate) -> Vec<Vec<String>> {
        parsed.modules.iter().map(|m| m.path.clone()).collect()
    }

    #[test]
    fn walks_file_and_mod_rs_layouts() {
        let (parsed, _dir) = parse(&[
            ("lib.rs", "mod flat;\nmod nested;\nfn root_fn() {}"),
            ("flat.rs", "mod child;\nfn flat_fn() {}"),
            ("flat/child.rs", "fn child_fn() {}"),
            ("nested/mod.rs", "mod inner;\nfn nested_fn() {}"),
            ("nested/inner.rs", "fn inner_fn() {}"),
        ]);
        let paths = module_paths(&parsed);
        for expected in [
            vec![],
            vec!["flat"],
            vec!["flat", "child"],
            vec!["nested"],
            vec!["nested", "inner"],
        ] {
            let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
            assert!(
                paths.contains(&expected),
                "missing {expected:?} in {paths:?}"
            );
        }
        assert_eq!(parsed.diagnostics, vec![], "{:?}", parsed.diagnostics);
    }

    #[test]
    fn handles_inline_modules() {
        let (parsed, _dir) = parse(&[("lib.rs", "mod inline { pub fn f() {} }\nfn g() {}")]);
        let paths = module_paths(&parsed);
        assert!(paths.contains(&vec![]));
        assert!(paths.contains(&vec!["inline".to_string()]));
        let inline = parsed
            .modules
            .iter()
            .find(|m| m.path == vec!["inline".to_string()])
            .unwrap();
        assert_eq!(inline.file_display, "lib.rs");
    }

    #[test]
    fn handles_path_attribute() {
        let (parsed, _dir) = parse(&[
            ("lib.rs", "#[path = \"elsewhere.rs\"]\nmod weird;"),
            ("elsewhere.rs", "fn f() {}"),
        ]);
        let paths = module_paths(&parsed);
        assert!(paths.contains(&vec!["weird".to_string()]));
        assert!(parsed.diagnostics.is_empty());
    }

    #[test]
    fn cfg_disabled_modules_are_skipped() {
        let (parsed, _dir) = parse(&[
            ("lib.rs", "#[cfg(any())]\nmod gone;\nmod kept;"),
            ("gone.rs", "fn never() {}"),
            ("kept.rs", "fn always() {}"),
        ]);
        let paths = module_paths(&parsed);
        assert!(!paths.contains(&vec!["gone".to_string()]));
        assert!(paths.contains(&vec!["kept".to_string()]));
    }

    #[test]
    fn missing_module_file_is_a_warning_not_an_error() {
        let (parsed, _dir) = parse(&[("lib.rs", "mod ghost;\nfn f() {}")]);
        assert_eq!(parsed.diagnostics.len(), 1);
        assert!(parsed.diagnostics[0].message.contains("no readable file"));
    }

    #[test]
    fn syntax_error_is_a_diagnostic_not_an_error() {
        let (parsed, _dir) = parse(&[
            ("lib.rs", "mod broken;\nfn ok() {}"),
            ("broken.rs", "fn not valid rust ((("),
        ]);
        assert!(parsed
            .diagnostics
            .iter()
            .any(|d| d.message.contains("syntax error")));
        // The healthy root module is still analysed.
        assert!(module_paths(&parsed).contains(&vec![]));
    }

    #[test]
    fn cyclic_modules_terminate() {
        // `mod a` in lib.rs; a.rs declares `mod b` via #[path]; b.rs
        // declares a module pointing back at a.rs. `#[path]` in a
        // non-mod.rs file resolves against the file's own directory.
        let (parsed, _dir) = parse(&[
            ("lib.rs", "mod a;"),
            ("a.rs", "#[path = \"b.rs\"]\nmod b;"),
            ("b.rs", "#[path = \"a.rs\"]\nmod a_again;"),
        ]);
        let paths = module_paths(&parsed);
        assert!(paths.contains(&vec!["a".to_string()]));
        // a.rs was visited once; the cycle did not hang or duplicate.
        assert_eq!(
            paths
                .iter()
                .filter(|p| p.starts_with(&["a".to_string()]))
                .count(),
            2 // a and a::b
        );
    }

    #[test]
    fn oversized_files_are_skipped() {
        let limits = Limits {
            max_file_bytes: 64,
            ..Limits::default()
        };
        let big = "fn f() {}".repeat(100);
        let (parsed, _dir) = parse_with_limits(
            &[("lib.rs", "mod big;\nfn small() {}"), ("big.rs", &big)],
            limits,
        );
        assert!(parsed
            .diagnostics
            .iter()
            .any(|d| d.message.contains("size limit")));
        assert!(!module_paths(&parsed).contains(&vec!["big".to_string()]));
    }

    #[test]
    fn file_count_limit_is_enforced() {
        let limits = Limits {
            max_files_per_crate: 1,
            ..Limits::default()
        };
        let (parsed, _dir) = parse_with_limits(
            &[
                ("lib.rs", "mod a;\nmod b;"),
                ("a.rs", "fn a() {}"),
                ("b.rs", "fn b() {}"),
            ],
            limits,
        );
        assert!(parsed
            .diagnostics
            .iter()
            .any(|d| d.message.contains("file limit")));
    }

    #[test]
    fn file_count_limit_counts_unparseable_files() {
        // Files that fail to parse are still attempted work and must
        // count against the limit instead of being read without end.
        let mut files: Vec<(String, String)> = vec![(
            "lib.rs".to_owned(),
            (0..8).map(|i| format!("mod m{i};\n")).collect(),
        )];
        for i in 0..8 {
            files.push((format!("m{i}.rs"), "fn broken((".to_owned()));
        }
        let limits = Limits {
            max_files_per_crate: 3,
            ..Limits::default()
        };
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(name, content)| (name.as_str(), content.as_str()))
            .collect();
        let (parsed, _dir) = parse_with_limits(&borrowed, limits);
        let syntax_errors = parsed
            .diagnostics
            .iter()
            .filter(|d| d.message.contains("syntax error"))
            .count();
        assert_eq!(
            syntax_errors, 2,
            "only the remaining budget may be attempted: {:?}",
            parsed.diagnostics
        );
        assert!(parsed
            .diagnostics
            .iter()
            .any(|d| d.message.contains("file limit")));
    }

    #[test]
    fn inline_module_nesting_is_depth_limited() {
        // Inline modules recurse without touching any file; the depth
        // limit must stop hostile nesting.
        let mut src = String::new();
        for i in 0..20 {
            src.push_str(&format!("mod m{i} {{\n"));
        }
        src.push_str("fn deep() {}\n");
        for _ in 0..20 {
            src.push_str("}\n");
        }
        let limits = Limits {
            max_module_depth: 4,
            ..Limits::default()
        };
        let (parsed, _dir) = parse_with_limits(&[("lib.rs", src.as_str())], limits);
        assert!(
            parsed
                .diagnostics
                .iter()
                .any(|d| d.message.contains("module depth limit")),
            "expected a depth diagnostic: {:?}",
            parsed.diagnostics
        );
        assert!(
            !module_paths(&parsed).iter().any(|p| p.len() > 4),
            "modules beyond the limit must be skipped: {:?}",
            module_paths(&parsed)
        );
    }

    #[test]
    fn unreadable_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let values = CfgValues::new();
        let features = BTreeSet::new();
        let limits = Limits::default();
        let context = ParseContext {
            cfg: CfgEvaluator::new(&values, &features),
            limits: &limits,
            display_root: None,
        };
        let result = parse_crate(&dir.path().join("missing.rs"), &context);
        assert!(matches!(
            result,
            Err(crate::error::AnalysisError::CrateRootUnreadable { .. })
        ));
    }
}
