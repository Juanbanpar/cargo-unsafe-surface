//! Call-graph related shared types.

use serde::{Deserialize, Serialize};

use crate::ids::{Confidence, ItemPath, SourceLocation};

/// What kind of callable item a graph node represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionKind {
    /// A free function (`fn f()` at module level).
    Free,
    /// An inherent or trait method; `self_ty` is the type name as written.
    Method {
        /// The `Self` type name of the enclosing impl block, as written in
        /// the source (generics stripped).
        self_ty: String,
    },
    /// A trait method with a default body.
    TraitMethod {
        /// Name of the trait.
        trait_name: String,
    },
    /// A foreign function declared in an `extern "..."` block.
    Extern,
}

/// How a call-graph edge was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// A path call resolved to a unique known item.
    Direct,
    /// A method call resolved by unique-name matching across all known
    /// impl blocks.
    InferredMethod,
}

impl EdgeKind {
    /// The confidence attached to edges of this kind.
    #[must_use]
    pub fn confidence(self) -> Confidence {
        match self {
            Self::Direct => Confidence::Confirmed,
            Self::InferredMethod => Confidence::Inferred,
        }
    }
}

/// Why a call site could not be resolved to a callee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum UnresolvedReason {
    /// No item with that name exists in the analysed sources.
    UnknownName,
    /// A method name matched several impl blocks; without type information
    /// the receiver cannot be disambiguated.
    AmbiguousMethod {
        /// How many candidate impls define a method with this name.
        candidates: usize,
    },
    /// Call through a `dyn Trait` object or a generic trait bound; the
    /// concrete target is only known at compile time.
    DynamicDispatch,
    /// Call through a function pointer or a closure value.
    FunctionPointer,
    /// The call is produced by a macro invocation whose expansion is not
    /// analysed.
    MacroExpansion,
    /// The callee belongs to `std`/`core`/`alloc`, whose sources are not
    /// analysed.
    StandardLibrary,
    /// The callee belongs to a dependency whose sources were not available
    /// (not downloaded or excluded from analysis).
    DependencySourceUnavailable {
        /// The dependency crate name.
        krate: String,
    },
    /// A construct the analyser deliberately does not model.
    UnsupportedConstruct,
}

impl UnresolvedReason {
    /// Short label for reports.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::UnknownName => "unknown name",
            Self::AmbiguousMethod { .. } => "ambiguous method",
            Self::DynamicDispatch => "dynamic dispatch",
            Self::FunctionPointer => "function pointer",
            Self::MacroExpansion => "macro expansion",
            Self::StandardLibrary => "standard library",
            Self::DependencySourceUnavailable { .. } => "dependency sources unavailable",
            Self::UnsupportedConstruct => "unsupported construct",
        }
    }
}

/// A call site that could not be resolved to a known callee.
///
/// Unresolved calls are part of the analysis *uncertainty*: they are never
/// treated as safe, and strict policy modes can fail on their presence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedCall {
    /// The function containing the call site.
    pub caller: ItemPath,
    /// The callee as written in the source.
    pub callee_text: String,
    /// Where the call occurs.
    pub location: SourceLocation,
    /// Why resolution failed.
    pub reason: UnresolvedReason,
}

/// One step in a reconstructed call path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathStep {
    /// The item at this step.
    pub item: ItemPath,
    /// The call site through which the *next* step is invoked (`None` for
    /// the last step).
    pub call_site: Option<SourceLocation>,
    /// Confidence of the edge leading to the *next* step.
    pub edge_confidence: Option<Confidence>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_confidence_mapping() {
        assert_eq!(EdgeKind::Direct.confidence(), Confidence::Confirmed);
        assert_eq!(EdgeKind::InferredMethod.confidence(), Confidence::Inferred);
    }

    #[test]
    fn unresolved_reason_labels_cover_all_variants() {
        let reasons = [
            UnresolvedReason::UnknownName,
            UnresolvedReason::AmbiguousMethod { candidates: 3 },
            UnresolvedReason::DynamicDispatch,
            UnresolvedReason::FunctionPointer,
            UnresolvedReason::MacroExpansion,
            UnresolvedReason::StandardLibrary,
            UnresolvedReason::DependencySourceUnavailable {
                krate: "dep".into(),
            },
            UnresolvedReason::UnsupportedConstruct,
        ];
        for reason in reasons {
            assert!(!reason.label().is_empty());
        }
    }

    #[test]
    fn unresolved_reason_serde_tagged() {
        let reason = UnresolvedReason::AmbiguousMethod { candidates: 2 };
        let json = serde_json::to_value(&reason).unwrap();
        assert_eq!(json["kind"], "ambiguous_method");
        assert_eq!(json["candidates"], 2);
    }
}
