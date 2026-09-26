//! Text, JSON and SARIF reporting for `cargo-unsafe-surface`.
//!
//! This crate is a pure formatting layer: it consumes the serializable
//! report model produced by the analysis layer and never inspects source
//! code or the call graph directly. All formats are deterministic.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod sanitize;
mod sarif;
mod text;

pub use error::ReportError;

use unsafe_surface_core::ReportModel;

/// Output formats supported by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text.
    Text,
    /// Machine-readable JSON (see `docs/json-schema.md`).
    Json,
    /// SARIF 2.1.0 for code-scanning systems.
    Sarif,
}

impl OutputFormat {
    /// Parses a format name (used by the CLI).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            _ => None,
        }
    }

    /// All format names, for help text.
    #[must_use]
    pub fn names() -> &'static [&'static str] {
        &["text", "json", "sarif"]
    }
}

/// Renders a report in the requested format.
///
/// # Errors
///
/// Returns [`ReportError`] when JSON or SARIF serialization fails
/// (pathological cases only; the text format cannot fail).
pub fn render(report: &ReportModel, format: OutputFormat) -> Result<String, ReportError> {
    match format {
        OutputFormat::Text => Ok(text::render_text(report)),
        OutputFormat::Json => Ok(serde_json::to_string_pretty(report)?),
        OutputFormat::Sarif => sarif::render_sarif(report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parsing() {
        assert_eq!(OutputFormat::parse("text"), Some(OutputFormat::Text));
        assert_eq!(OutputFormat::parse("json"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::parse("sarif"), Some(OutputFormat::Sarif));
        assert_eq!(OutputFormat::parse("yaml"), None);
    }
}
