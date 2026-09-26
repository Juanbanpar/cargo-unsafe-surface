//! Unsafe operation classification.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::{Confidence, SourceLocation};

/// The class of an unsafe or unsafe-adjacent operation.
///
/// Variants are ordered; the order is used for deterministic report output
/// and has no semantic meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsafeOpKind {
    /// An `unsafe { ... }` block.
    UnsafeBlock,
    /// Definition of an `unsafe fn`.
    UnsafeFn,
    /// A call to a function known to be `unsafe`.
    UnsafeFnCall,
    /// Definition of an `unsafe trait`.
    UnsafeTrait,
    /// An `unsafe impl Trait for Type` (other than `Send`/`Sync`).
    UnsafeTraitImpl,
    /// A manual `unsafe impl Send`.
    SendImpl,
    /// A manual `unsafe impl Sync`.
    SyncImpl,
    /// A foreign function declared inside an `extern "..."` block.
    ForeignFunction,
    /// An `extern "..."` block (with or without the 2024-edition `unsafe`).
    ExternBlock,
    /// A call to a foreign function (crosses the FFI boundary).
    FfiCall,
    /// A dereference expression inside an unsafe context, which may be a raw
    /// pointer dereference (see crate documentation for the heuristic).
    RawPointerDeref,
    /// `std::mem::transmute`, `transmute_copy` or an equivalent bit-cast.
    Transmute,
    /// `asm!`, `global_asm!` or `naked_asm!`.
    InlineAssembly,
    /// A field access on a value whose type is a known `union`.
    UnionFieldAccess,
    /// A reference to a known `static mut`.
    MutableStaticAccess,
    /// Definition of a `static mut`.
    MutableStaticDefinition,
    /// A use of `core::mem::MaybeUninit`.
    MaybeUninitUse,
    /// A call to an `*_unchecked` API.
    UncheckedCall,
}

impl UnsafeOpKind {
    /// Every operation kind.
    pub const ALL: &'static [Self] = &[
        Self::UnsafeBlock,
        Self::UnsafeFn,
        Self::UnsafeFnCall,
        Self::UnsafeTrait,
        Self::UnsafeTraitImpl,
        Self::SendImpl,
        Self::SyncImpl,
        Self::ForeignFunction,
        Self::ExternBlock,
        Self::FfiCall,
        Self::RawPointerDeref,
        Self::Transmute,
        Self::InlineAssembly,
        Self::UnionFieldAccess,
        Self::MutableStaticAccess,
        Self::MutableStaticDefinition,
        Self::MaybeUninitUse,
        Self::UncheckedCall,
    ];

    /// The stable snake_case identifier used in serialized reports and
    /// SARIF rule ids.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsafeBlock => "unsafe_block",
            Self::UnsafeFn => "unsafe_fn",
            Self::UnsafeFnCall => "unsafe_fn_call",
            Self::UnsafeTrait => "unsafe_trait",
            Self::UnsafeTraitImpl => "unsafe_trait_impl",
            Self::SendImpl => "send_impl",
            Self::SyncImpl => "sync_impl",
            Self::ForeignFunction => "foreign_function",
            Self::ExternBlock => "extern_block",
            Self::FfiCall => "ffi_call",
            Self::RawPointerDeref => "raw_pointer_deref",
            Self::Transmute => "transmute",
            Self::InlineAssembly => "inline_assembly",
            Self::UnionFieldAccess => "union_field_access",
            Self::MutableStaticAccess => "mutable_static_access",
            Self::MutableStaticDefinition => "mutable_static_definition",
            Self::MaybeUninitUse => "maybe_uninit_use",
            Self::UncheckedCall => "unchecked_call",
        }
    }

    /// Short human-readable label used in text reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::UnsafeBlock => "unsafe block",
            Self::UnsafeFn => "unsafe function",
            Self::UnsafeFnCall => "call to unsafe function",
            Self::UnsafeTrait => "unsafe trait",
            Self::UnsafeTraitImpl => "unsafe trait implementation",
            Self::SendImpl => "manual Send implementation",
            Self::SyncImpl => "manual Sync implementation",
            Self::ForeignFunction => "foreign function declaration",
            Self::ExternBlock => "extern block",
            Self::FfiCall => "FFI call",
            Self::RawPointerDeref => "raw pointer dereference",
            Self::Transmute => "transmute",
            Self::InlineAssembly => "inline assembly",
            Self::UnionFieldAccess => "union field access",
            Self::MutableStaticAccess => "mutable static access",
            Self::MutableStaticDefinition => "mutable static definition",
            Self::MaybeUninitUse => "MaybeUninit use",
            Self::UncheckedCall => "unchecked API call",
        }
    }
}

impl fmt::Display for UnsafeOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Whether a `SAFETY:` justification comment was found for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyJustification {
    /// A `// SAFETY: ...` comment (or a `# Safety` doc section on an
    /// `unsafe fn`) was found directly above the operation.
    Present,
    /// No justification comment was found.
    Absent,
}

impl SafetyJustification {
    /// Display label matching the text report.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }
}

/// A single unsafe or unsafe-adjacent operation found in a function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsafeOperation {
    /// The class of operation.
    pub kind: UnsafeOpKind,
    /// Where the operation occurs.
    pub location: SourceLocation,
    /// Confidence that the operation is what it was classified as.
    pub confidence: Confidence,
    /// Whether a safety justification comment was found.
    pub justification: SafetyJustification,
    /// Optional human-readable detail (e.g. the callee of an unsafe call,
    /// the name of the macro that expanded to assembly).
    pub detail: Option<String>,
}

impl UnsafeOperation {
    /// Creates a confirmed operation without detail text.
    #[must_use]
    pub fn new(kind: UnsafeOpKind, location: SourceLocation) -> Self {
        Self {
            kind,
            location,
            confidence: Confidence::Confirmed,
            justification: SafetyJustification::Absent,
            detail: None,
        }
    }

    /// Sets the confidence level.
    #[must_use]
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Sets the justification state.
    #[must_use]
    pub fn with_justification(mut self, justification: SafetyJustification) -> Self {
        self.justification = justification;
        self
    }

    /// Sets the detail text.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_covers_every_kind() {
        for kind in UnsafeOpKind::ALL {
            // The exhaustive match is the completeness guard: adding a
            // variant forces a new arm here (and in `as_str`).
            match kind {
                UnsafeOpKind::UnsafeBlock
                | UnsafeOpKind::UnsafeFn
                | UnsafeOpKind::UnsafeFnCall
                | UnsafeOpKind::UnsafeTrait
                | UnsafeOpKind::UnsafeTraitImpl
                | UnsafeOpKind::SendImpl
                | UnsafeOpKind::SyncImpl
                | UnsafeOpKind::ForeignFunction
                | UnsafeOpKind::ExternBlock
                | UnsafeOpKind::FfiCall
                | UnsafeOpKind::RawPointerDeref
                | UnsafeOpKind::Transmute
                | UnsafeOpKind::InlineAssembly
                | UnsafeOpKind::UnionFieldAccess
                | UnsafeOpKind::MutableStaticAccess
                | UnsafeOpKind::MutableStaticDefinition
                | UnsafeOpKind::MaybeUninitUse
                | UnsafeOpKind::UncheckedCall => {}
            }
            assert!(!kind.label().is_empty());
            assert!(!kind.as_str().is_empty());
            // `as_str` must agree with the serialized vocabulary.
            let json = serde_json::to_value(kind).unwrap();
            assert_eq!(json.as_str(), Some(kind.as_str()));
        }
    }

    #[test]
    fn builder_sets_fields() {
        let op = UnsafeOperation::new(UnsafeOpKind::Transmute, SourceLocation::new("a.rs", 3, 5))
            .with_confidence(Confidence::Inferred)
            .with_justification(SafetyJustification::Present)
            .with_detail("std::mem::transmute");
        assert_eq!(op.confidence, Confidence::Inferred);
        assert_eq!(op.justification, SafetyJustification::Present);
        assert_eq!(op.detail.as_deref(), Some("std::mem::transmute"));
        assert_eq!(op.location.to_string(), "a.rs:3:5");
    }

    #[test]
    fn serde_uses_snake_case() {
        let json = serde_json::to_string(&UnsafeOpKind::FfiCall).unwrap();
        assert_eq!(json, "\"ffi_call\"");
        let json = serde_json::to_string(&SafetyJustification::Present).unwrap();
        assert_eq!(json, "\"present\"");
    }
}
