//! Errors of the reporting layer.

/// Errors produced while rendering a report.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// JSON serialization failed.
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}
