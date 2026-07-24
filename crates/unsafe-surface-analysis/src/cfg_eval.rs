//! Limited `#[cfg]` evaluation.
//!
//! Rust conditional compilation cannot be evaluated perfectly without the
//! full build environment (build scripts can emit arbitrary cfgs, features
//! interact across the graph). This module implements a conservative
//! evaluator:
//!
//! * Known keys (`feature`, `target_os`, `target_arch`, `target_family`,
//!   `target_pointer_width`, flags such as `unix`, …) are evaluated against
//!   `rustc --print cfg` output and the resolved feature set from Cargo.
//! * `test` always evaluates to **false**: the tool analyses shipped code,
//!   not test builds.
//! * Unknown predicates evaluate to [`CfgResult::Unknown`] and the item is
//!   **kept** (over-approximation — for an unsafe-code audit it is safer to
//!   analyse too much than too little) and counted in the diagnostics.
//!
//! `cfg_attr` is not evaluated; attributes it carries are ignored, which is
//! another deliberate over-approximation.

use std::collections::BTreeSet;

use syn::{Attribute, Expr};
use unsafe_surface_cargo::CfgValues;

/// Result of evaluating one `cfg` predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgResult {
    /// The predicate holds; the item is compiled in.
    Enabled,
    /// The predicate does not hold; the item is compiled out.
    Disabled,
    /// The predicate uses unknown keys; the item is kept anyway.
    Unknown,
}

impl CfgResult {
    /// Whether the item should be analysed.
    #[must_use]
    pub fn keeps_item(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Disabled, _) | (_, Self::Disabled) => Self::Disabled,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Enabled,
        }
    }

    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Enabled, _) | (_, Self::Enabled) => Self::Enabled,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Disabled,
        }
    }

    fn not(self) -> Self {
        match self {
            Self::Enabled => Self::Disabled,
            Self::Disabled => Self::Enabled,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// `cfg` names known to the Rust compiler. Used to distinguish "absent
/// because the predicate is false on this target" (`windows` on Linux)
/// from "unknown, emitted by a build script we never run" (kept as
/// [`CfgResult::Unknown`]).
const KNOWN_CFG_NAMES: &[&str] = &[
    "unix",
    "windows",
    "test",
    "doctest",
    "debug_assertions",
    "proc_macro",
    "panic",
    "relocation_model",
    "target_abi",
    "target_arch",
    "target_endian",
    "target_env",
    "target_family",
    "target_feature",
    "target_has_atomic",
    "target_os",
    "target_pointer_width",
    "target_thread_local",
    "target_vendor",
];

/// Evaluates `#[cfg]` attributes for one crate.
pub struct CfgEvaluator<'a> {
    /// Target cfg values from `rustc --print cfg`.
    values: &'a CfgValues,
    /// Enabled Cargo features of the crate being analysed.
    features: &'a BTreeSet<String>,
}

impl<'a> CfgEvaluator<'a> {
    /// Creates an evaluator for one crate.
    #[must_use]
    pub fn new(values: &'a CfgValues, features: &'a BTreeSet<String>) -> Self {
        Self { values, features }
    }

    /// Folds all `#[cfg(...)]` attributes on an item (logical AND).
    pub fn evaluate_attrs(&self, attrs: &[Attribute]) -> CfgResult {
        let mut result = CfgResult::Enabled;
        for attr in attrs {
            if !attr.path().is_ident("cfg") {
                continue;
            }
            let Ok(nested) = attr.parse_args::<Expr>() else {
                result = result.and(CfgResult::Unknown);
                continue;
            };
            result = result.and(self.evaluate_expr(&nested));
        }
        result
    }

    /// Evaluates a single `cfg` predicate expression.
    pub fn evaluate_expr(&self, expr: &Expr) -> CfgResult {
        match expr {
            // #[cfg(unix)]
            Expr::Path(path) => {
                let Some(ident) = path.path.get_ident() else {
                    return CfgResult::Unknown;
                };
                self.evaluate_flag(&ident.to_string())
            }
            // #[cfg(target_arch = "x86_64")] / #[cfg(feature = "tls")]
            Expr::Assign(assign) => {
                let key = match &*assign.left {
                    Expr::Path(path) => match path.path.get_ident() {
                        Some(ident) => ident.to_string(),
                        None => return CfgResult::Unknown,
                    },
                    _ => return CfgResult::Unknown,
                };
                let value = match &*assign.right {
                    Expr::Lit(lit) => match &lit.lit {
                        syn::Lit::Str(s) => s.value(),
                        _ => return CfgResult::Unknown,
                    },
                    _ => return CfgResult::Unknown,
                };
                self.evaluate_key_value(&key, &value)
            }
            // #[cfg(all(...))] / #[cfg(any(...))] / #[cfg(not(...))]
            Expr::Call(call) => {
                let name = match &*call.func {
                    Expr::Path(path) => match path.path.get_ident() {
                        Some(ident) => ident.to_string(),
                        None => return CfgResult::Unknown,
                    },
                    _ => return CfgResult::Unknown,
                };
                match name.as_str() {
                    "all" => call.args.iter().fold(CfgResult::Enabled, |acc, arg| {
                        acc.and(self.evaluate_expr(arg))
                    }),
                    "any" => call.args.iter().fold(CfgResult::Disabled, |acc, arg| {
                        acc.or(self.evaluate_expr(arg))
                    }),
                    "not" if call.args.len() == 1 => self.evaluate_expr(&call.args[0]).not(),
                    _ => CfgResult::Unknown,
                }
            }
            _ => CfgResult::Unknown,
        }
    }

    fn evaluate_flag(&self, key: &str) -> CfgResult {
        if key == "test" {
            return CfgResult::Disabled;
        }
        match self.values.get(key) {
            Some(entries) if entries.iter().any(|v| v.is_none()) => CfgResult::Enabled,
            Some(_) => CfgResult::Unknown,
            // Flag-style cfgs that exist in principle (`windows` on a Linux
            // host) are absent from `rustc --print cfg`; genuinely unknown
            // names (build-script cfgs like `has_feature_x`) must stay
            // Unknown so the item is kept (over-approximation).
            None if KNOWN_CFG_NAMES.contains(&key) => CfgResult::Disabled,
            None => CfgResult::Unknown,
        }
    }

    fn evaluate_key_value(&self, key: &str, value: &str) -> CfgResult {
        if key == "feature" {
            return if self.features.contains(value) {
                CfgResult::Enabled
            } else {
                CfgResult::Disabled
            };
        }
        if key == "test" {
            return CfgResult::Disabled;
        }
        match self.values.get(key) {
            Some(entries) if entries.iter().any(|v| v.as_deref() == Some(value)) => {
                CfgResult::Enabled
            }
            Some(_) => CfgResult::Disabled,
            None if KNOWN_CFG_NAMES.contains(&key) => CfgResult::Disabled,
            None => CfgResult::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unsafe_surface_cargo::CfgValues;

    fn values() -> CfgValues {
        let mut values = CfgValues::new();
        values.insert("unix".to_owned(), vec![None]);
        values.insert("target_arch".to_owned(), vec![Some("x86_64".to_owned())]);
        values.insert("target_os".to_owned(), vec![Some("linux".to_owned())]);
        values
    }

    fn features() -> BTreeSet<String> {
        ["tls".to_owned()].into_iter().collect()
    }

    fn parse_attr(src: &str) -> Attribute {
        // Parse `#[cfg(...)]` by embedding it on a dummy item.
        let file = syn::parse_file(&format!("{src}\nfn dummy() {{}}")).unwrap();
        let syn::Item::Fn(item) = &file.items[0] else {
            panic!("test attribute did not parse");
        };
        item.attrs[0].clone()
    }

    #[test]
    fn known_predicates() {
        let values = values();
        let features = features();
        let evaluator = CfgEvaluator::new(&values, &features);
        let cases = [
            ("#[cfg(unix)]", CfgResult::Enabled),
            ("#[cfg(windows)]", CfgResult::Disabled),
            ("#[cfg(target_arch = \"x86_64\")]", CfgResult::Enabled),
            ("#[cfg(target_arch = \"aarch64\")]", CfgResult::Disabled),
            ("#[cfg(feature = \"tls\")]", CfgResult::Enabled),
            ("#[cfg(feature = \"nope\")]", CfgResult::Disabled),
            ("#[cfg(test)]", CfgResult::Disabled),
            ("#[cfg(not(windows))]", CfgResult::Enabled),
            (
                "#[cfg(all(unix, target_os = \"linux\"))]",
                CfgResult::Enabled,
            ),
            ("#[cfg(any(windows, unix))]", CfgResult::Enabled),
            ("#[cfg(all(unix, windows))]", CfgResult::Disabled),
        ];
        for (src, expected) in cases {
            let attr = parse_attr(src);
            assert_eq!(evaluator.evaluate_attrs(&[attr]), expected, "{src}");
        }
    }

    #[test]
    fn unknown_predicates_keep_the_item() {
        let values = values();
        let features = features();
        let evaluator = CfgEvaluator::new(&values, &features);
        let attr = parse_attr("#[cfg(some_build_script_cfg)]");
        let result = evaluator.evaluate_attrs(&[attr]);
        assert_eq!(result, CfgResult::Unknown);
        assert!(result.keeps_item());
    }

    #[test]
    fn multiple_attrs_are_anded() {
        let values = values();
        let features = features();
        let evaluator = CfgEvaluator::new(&values, &features);
        let attrs = [parse_attr("#[cfg(unix)]"), parse_attr("#[cfg(windows)]")];
        assert_eq!(evaluator.evaluate_attrs(&attrs), CfgResult::Disabled);
    }

    #[test]
    fn meta_items_are_parsed_via_expr() {
        // Guards the `parse_args::<Expr>()` approach against cfg syntax.
        let values = values();
        let features = features();
        let evaluator = CfgEvaluator::new(&values, &features);
        let attr = parse_attr("#[cfg(not(any(windows, target_arch = \"wasm32\")))]");
        assert_eq!(evaluator.evaluate_attrs(&[attr]), CfgResult::Enabled);
    }
}
