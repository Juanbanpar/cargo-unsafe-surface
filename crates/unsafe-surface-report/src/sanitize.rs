//! Sanitization of untrusted strings for terminal output.
//!
//! Identifiers, paths and messages in a report come from the analysed
//! repository and are therefore untrusted: a malicious crate could embed
//! ANSI escape sequences, line separators or invisible Unicode controls
//! in identifiers (via macro-generated names or unicode trickery) to
//! forge report output, spoof its display or attack terminal emulators.
//! Every interpolated string passes through [`sanitize`], which replaces
//! dangerous characters with `U+FFFD`.

/// Replaces characters that could forge report structure or spoof its
/// display with the replacement character, leaving printable text
/// (including Unicode) intact.
///
/// This covers ASCII and C1 control characters, Unicode line and
/// paragraph separators — which line-oriented consumers read as line
/// breaks even though they are not control characters — and invisible
/// format characters: bidi controls that reorder or hide text and
/// zero-width marks that smuggle content past display and diffing.
pub(crate) fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| if is_dangerous(c) { '\u{FFFD}' } else { c })
        .collect()
}

fn is_dangerous(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Line and paragraph separators: not control characters, but
            // they break lines for many consumers.
            '\u{2028}' | '\u{2029}'
            // Bidi controls and the Arabic letter mark.
            | '\u{061C}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            // Zero-width marks (incl. LRM/RLM) and invisible formatting.
            | '\u{200B}'..='\u{200F}'
            | '\u{2060}'..='\u{2064}'
            | '\u{FEFF}'
        )
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

    #[test]
    fn strips_line_and_paragraph_separators() {
        // U+2028/U+2029 are line breaks for many consumers despite not
        // being control characters.
        assert_eq!(sanitize("a\u{2028}b\u{2029}c"), "a\u{FFFD}b\u{FFFD}c");
    }

    #[test]
    fn strips_bidi_and_zero_width_controls() {
        // Trojan-Source style spoofing and invisible smuggling.
        let malicious = "a\u{202E}b\u{200B}c\u{2066}d\u{FEFF}e\u{061C}";
        assert_eq!(
            sanitize(malicious),
            "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e\u{FFFD}"
        );
    }
}
