//! Sanitization of untrusted strings for terminal output.
//!
//! Identifiers, paths and messages in a report come from the analysed
//! repository and are therefore untrusted: a malicious crate could embed
//! ANSI escape sequences or control characters in identifiers (via
//! macro-generated names or unicode trickery) to forge report output or
//! attack terminal emulators. Every interpolated string passes through
//! [`sanitize`], which replaces control characters with `U+FFFD`.

/// Replaces ASCII and C1 control characters with the replacement
/// character, leaving printable text (including Unicode) intact.
pub(crate) fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_escape_sequences() {
        let malicious = "\u{1b}[31mred\u{1b}[0m";
        assert_eq!(sanitize(malicious), "\u{FFFD}[31mred\u{FFFD}[0m");
    }

    #[test]
    fn keeps_printable_unicode() {
        assert_eq!(sanitize("héllo wörld — ü"), "héllo wörld — ü");
    }

    #[test]
    fn strips_newlines_and_tabs() {
        // Newlines inside identifiers would let a finding forge extra
        // report lines.
        assert_eq!(sanitize("a\nb\tc"), "a\u{FFFD}b\u{FFFD}c");
    }
}
