//! Identity, location and provenance types.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Identifies an analysed package (a Cargo package, not just a crate name).
///
/// The version is `None` only when it could not be determined; equality and
/// ordering treat it as significant so two versions of the same registry
/// crate never collide in deterministic maps.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageId {
    /// Package name as written in `Cargo.toml` (may contain `-`).
    pub name: String,
    /// Resolved package version, if known.
    pub version: Option<String>,
    /// Where the package sources came from.
    pub origin: DependencyOrigin,
}

impl PackageId {
    /// Creates a new package identifier.
    #[must_use]
    pub fn new(name: impl Into<String>, version: Option<String>, origin: DependencyOrigin) -> Self {
        Self {
            name: name.into(),
            version,
            origin,
        }
    }

    /// The crate name used in Rust source paths (`-` replaced by `_`).
    #[must_use]
    pub fn crate_name(&self) -> String {
        self.name.replace('-', "_")
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(version) => write!(f, "{} {version}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

/// How a package entered the analysis.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum DependencyOrigin {
    /// A member of the analysed workspace.
    Workspace,
    /// A `path` dependency outside the workspace.
    Path,
    /// A crates.io (or alternative registry) dependency read from the local
    /// registry cache.
    Registry,
    /// A `git` dependency read from the local git checkout cache.
    Git,
    /// Origin could not be determined.
    #[default]
    Unknown,
}

/// A source position. Lines are 1-based, columns are 1-based (converted from
/// `proc-macro2`'s 0-based columns at parse time).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Display path of the file. Relative to the analysed workspace root
    /// when the file is inside it, otherwise the absolute path.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number.
    pub column: u32,
}

impl SourceLocation {
    /// Creates a new source location.
    #[must_use]
    pub fn new(file: impl Into<String>, line: u32, column: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column,
        }
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// A fully qualified path to an item, e.g. `server::network::run`.
///
/// The first component is always the crate name (`-` normalized to `_`), so
/// paths are unambiguous across a dependency graph with multiple versions of
/// the same crate is impossible; when that matters, [`PackageId`] disambigu-
/// ates at the finding level.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ItemPath {
    /// Crate name (`-` normalized to `_`).
    pub krate: String,
    /// Module and item segments after the crate name.
    pub segments: Vec<String>,
}

/// Error returned when parsing an [`ItemPath`] from a string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ItemPathError {
    /// The path was empty or contained empty segments.
    #[error("item path is empty or contains an empty segment")]
    Empty,
    /// The path contained characters that cannot appear in Rust identifiers
    /// or `::` separators.
    #[error("item path contains invalid characters: {0:?}")]
    InvalidCharacters(String),
}

impl ItemPath {
    /// Creates a new item path.
    #[must_use]
    pub fn new(krate: impl Into<String>, segments: Vec<String>) -> Self {
        Self {
            krate: krate.into(),
            segments,
        }
    }

    /// Parses `krate::segment::segment` into an [`ItemPath`].
    ///
    /// Only ASCII identifier characters, digits and `_` are accepted per
    /// segment; this keeps CLI-provided entry points free of terminal
    /// control characters.
    pub fn parse(input: &str) -> Result<Self, ItemPathError> {
        let trimmed = input.trim().trim_start_matches("::");
        if trimmed.is_empty() {
            return Err(ItemPathError::Empty);
        }
        let parts: Vec<&str> = trimmed.split("::").collect();
        for part in &parts {
            let valid =
                !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid {
                return Err(if part.is_empty() {
                    ItemPathError::Empty
                } else {
                    ItemPathError::InvalidCharacters((*part).to_owned())
                });
            }
        }
        let (krate, segments) = parts.split_first().ok_or(ItemPathError::Empty)?;
        Ok(Self {
            krate: (*krate).to_owned(),
            segments: segments.iter().map(|s| (*s).to_owned()).collect(),
        })
    }

    /// Returns the final segment (the item name), if any.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.segments.last().map(String::as_str)
    }
}

impl fmt::Display for ItemPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.krate)?;
        for segment in &self.segments {
            write!(f, "::{segment}")?;
        }
        Ok(())
    }
}

/// Confidence that a finding or graph edge reflects the real program.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Direct syntactic evidence (e.g. an `unsafe` block, a call whose target
    /// was resolved to a unique known item).
    #[default]
    Confirmed,
    /// Heuristic evidence (e.g. a method call resolved by unique name
    /// matching, a raw-pointer dereference inferred from an unsafe block).
    Inferred,
}

/// Severity of an analysis diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational; does not affect results.
    Info,
    /// Results may be incomplete (e.g. a file could not be parsed).
    Warning,
    /// Part of the analysis failed; results are definitely incomplete.
    Error,
}

/// Name and version of the tool that produced a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool name (`cargo-unsafe-surface`).
    pub name: String,
    /// Tool version.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_path_roundtrip() {
        let path = ItemPath::parse("server::network::run").unwrap();
        assert_eq!(path.krate, "server");
        assert_eq!(path.segments, vec!["network", "run"]);
        assert_eq!(path.to_string(), "server::network::run");
        assert_eq!(path.name(), Some("run"));
    }

    #[test]
    fn item_path_accepts_single_segment() {
        let path = ItemPath::parse("server").unwrap();
        assert!(path.segments.is_empty());
    }

    #[test]
    fn item_path_rejects_bad_input() {
        assert_eq!(ItemPath::parse(""), Err(ItemPathError::Empty));
        assert_eq!(ItemPath::parse("a::"), Err(ItemPathError::Empty));
        assert_eq!(ItemPath::parse("a::::b"), Err(ItemPathError::Empty));
        assert!(matches!(
            ItemPath::parse("a::b c"),
            Err(ItemPathError::InvalidCharacters(_))
        ));
        // Terminal control characters must be rejected.
        assert!(matches!(
            ItemPath::parse("a::\u{1b}[31m"),
            Err(ItemPathError::InvalidCharacters(_))
        ));
    }

    #[test]
    fn package_crate_name_normalization() {
        let pkg = PackageId::new("my-crate", Some("1.0.0".into()), DependencyOrigin::Path);
        assert_eq!(pkg.crate_name(), "my_crate");
        assert_eq!(pkg.to_string(), "my-crate 1.0.0");
    }

    #[test]
    fn confidence_ordering_is_stable() {
        assert!(Confidence::Confirmed < Confidence::Inferred);
    }
}
