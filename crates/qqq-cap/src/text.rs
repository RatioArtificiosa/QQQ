// SPDX-License-Identifier: Apache-2.0

//! Single home for [`qqq_core::is_layout_forgery`], kept as a module so the
//! `qqq_cap::text::is_layout_forgery` path existing callers use keeps
//! working.
pub use qqq_core::text::{is_invisible_format, is_layout_forgery, utf16_surrogate_pair};

/// Escape a value for an operator-facing error message.
///
/// `{:?}` leaves U+2800 raw (Rust deems `So` printable), so a Debug echo
/// of a hostile identifier would show the reader the wrong name — the
/// exact spoof the refusal is warning about. This escapes every invisible
/// the validators refuse (plus controls, quotes, and backslashes) while
/// leaving ordinary text, including spaces and non-ASCII letters,
/// readable.
///
/// ```rust
/// use qqq_cap::text::escape_for_error;
///
/// assert_eq!(escape_for_error("acme"), "\"acme\"");
/// assert_eq!(escape_for_error("a\u{2800}b"), "\"a\\u{2800}b\"");
/// assert!(!escape_for_error("evil\u{200B}").contains('\u{200B}'));
/// ```
#[must_use]
pub fn escape_for_error(s: &str) -> String {
    // Debug first for its standard escapes, then patch the one hole:
    // a raw blank can only arrive here, never a literal `\u{2800}` text
    // (Debug backslash-escapes backslashes), so the replacement cannot
    // double-escape.
    format!("{s:?}").replace('\u{2800}', "\\u{2800}")
}

#[cfg(test)]
mod tests {
    /// `{:?}` is not a sanitizer: the one hole it leaves (U+2800) is
    /// patched, and everything else it escapes must stay escaped. Without
    /// this pin a future member outside `Debug`'s printable table renders
    /// raw in a refusal.
    #[test]
    fn error_escapes_show_no_invisibles() {
        for hostile in [
            "a\u{2800}b",
            "a\u{200B}b",
            "a\u{202E}b",
            "a\nb",
            "a\"b",
            "a\\b",
            "a\u{A0}b",
        ] {
            let escaped = super::escape_for_error(hostile);
            assert!(
                !escaped.chars().any(|c| c.is_control()
                    || super::is_layout_forgery(c)
                    || super::is_invisible_format(c)
                    || c == '\u{2800}'
                    || (c.is_whitespace() && c != ' ')),
                "{hostile:?} must escape invisibly: {escaped:?}"
            );
        }
        assert_eq!(super::escape_for_error("John Doe"), "\"John Doe\"");
    }
}
