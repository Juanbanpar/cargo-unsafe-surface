//! Detection of `SAFETY:` justification comments.
//!
//! The Rust community convention is to document every unsafe construct
//! with a `// SAFETY: ...` comment directly above it (and `unsafe fn`s
//! with a `# Safety` doc section). This module looks for such comments in
//! the raw source text, because `syn` discards non-doc comments.
//!
//! The scan walks upward from the construct, crossing comment lines,
//! attribute lines and blank lines (at most 16 lines), and reports
//! [`SafetyJustification::Present`] when a comment line starts with the
//! marker (after the comment prefix).

use unsafe_surface_core::SafetyJustification;

/// Maximum number of lines scanned upward from a construct.
const MAX_SCAN_LINES: usize = 16;

/// Whether a safety justification comment was found directly above the
/// construct starting at 1-based `line` in `text`.
#[must_use]
pub fn find_justification(text: &str, line: u32) -> SafetyJustification {
    let lines: Vec<&str> = text.lines().collect();
    if line == 0 || line as usize > lines.len() {
        return SafetyJustification::Absent;
    }
    let mut index = line as usize - 1; // index of the construct line
    let mut scanned = 0;
    while index > 0 && scanned < MAX_SCAN_LINES {
        index -= 1;
        scanned += 1;
        let trimmed = lines[index].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            // Blank lines and attributes do not break the association.
            continue;
        }
        if let Some(comment) = line_comment(trimmed) {
            if is_safety_marker(comment) {
                return SafetyJustification::Present;
            }
            continue;
        }
        // Any other line (code) ends the scan.
        break;
    }
    SafetyJustification::Absent
}

/// Extracts the comment payload of a `//`-style line (including doc
/// comments), or the content of a single-line `/* ... */` comment.
fn line_comment(trimmed: &str) -> Option<&str> {
    for prefix in ["///", "//!", "//"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return Some(rest.trim());
        }
    }
    if let Some(rest) = trimmed.strip_prefix("/*") {
        let rest = rest.strip_suffix("*/").unwrap_or(rest);
        return Some(rest.trim());
    }
    None
}

/// The community markers: `SAFETY:` comments and `# Safety` doc headings.
fn is_safety_marker(comment: &str) -> bool {
    let upper = comment.to_ascii_uppercase();
    upper.starts_with("SAFETY:") || upper.starts_with("# SAFETY")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_safety_comment_directly_above() {
        let text = "fn f() {\n    // SAFETY: pointer is valid\n    unsafe { *p };\n}\n";
        assert_eq!(find_justification(text, 3), SafetyJustification::Present);
    }

    #[test]
    fn detects_block_comment() {
        let text = "/* SAFETY: fine */\nunsafe { *p };\n";
        assert_eq!(find_justification(text, 2), SafetyJustification::Present);
    }

    #[test]
    fn detects_doc_safety_section() {
        let text = "/// Does things.\n///\n/// # Safety\n/// Caller ensures x.\nunsafe fn f() {}\n";
        assert_eq!(find_justification(text, 5), SafetyJustification::Present);
    }

    #[test]
    fn crosses_attributes_and_blank_lines() {
        let text = "// SAFETY: ok\n\n#[inline]\nunsafe fn f() {}\n";
        assert_eq!(find_justification(text, 4), SafetyJustification::Present);
    }

    #[test]
    fn code_between_comment_and_construct_breaks_association() {
        let text = "// SAFETY: unrelated\nlet x = 1;\nunsafe { *p };\n";
        assert_eq!(find_justification(text, 3), SafetyJustification::Absent);
    }

    #[test]
    fn no_comment_means_absent() {
        let text = "fn f() {\n    unsafe { *p };\n}\n";
        assert_eq!(find_justification(text, 2), SafetyJustification::Absent);
    }

    #[test]
    fn out_of_range_line_is_absent() {
        assert_eq!(find_justification("", 1), SafetyJustification::Absent);
        assert_eq!(find_justification("a\n", 0), SafetyJustification::Absent);
        assert_eq!(find_justification("a\n", 99), SafetyJustification::Absent);
    }

    #[test]
    fn marker_must_be_at_comment_start() {
        // "SAFETY:" buried in prose does not count; auditors search for the
        // marker at the start of the comment.
        let text = "// this is about SAFETY: nope\nunsafe { *p };\n";
        assert_eq!(find_justification(text, 2), SafetyJustification::Absent);
    }
}
