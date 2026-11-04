// SPDX-License-Identifier: Apache-2.0

//! Text safety: invisible characters that forge layout without a newline.
//!
//! Line/paragraph separators (`U+2028`/`U+2029`) break lines in renderers that
//! honor them; bidirectional controls reorder the visible text. Neither is a
//! C0/C1 control, so `char::is_control` misses both -- and both are name-
//! and value-spoofing primitives, never legitimate in a validated field or a
//! rendered diagnostic. One home so validators and renderers cannot disagree
//! on what "safe to print" means.
//!
//! ```rust
//! use qqq_core::text::is_layout_forgery;
//!
//! assert!(is_layout_forgery('\u{2028}'));
//! assert!(!is_layout_forgery('a'));
//! ```
///
/// Whether one character is an invisible layout-forger: a line/paragraph
/// separator or a bidirectional control. Neither is a C0/C1 control, so
/// `char::is_control` misses both -- check this alongside that predicate,
/// never instead of it.
///
/// ```rust
/// use qqq_core::is_layout_forgery;
///
/// assert!(is_layout_forgery('\u{202e}'));
/// assert!(!is_layout_forgery('x'));
/// ```
#[must_use]
pub fn is_layout_forgery(c: char) -> bool {
    matches!(
        c,
        '\u{2028}'
            | '\u{2029}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Whether one character is an invisible format character that spoofs identifiers.
///
/// Zero-width spaces and joiners, the word joiner, the soft hyphen, the
/// Mongolian vowel separator, and variation selectors render as nothing (or
/// as a glyph that looks like nothing) in most renderings, so two identifiers
/// differing only in one of these display identically: `acme` and
/// `acme\u{200B}` are distinct keys that no reader can tell apart. Unlike
/// [`is_layout_forgery`], several members are legitimate in *content* — the
/// zero-width joiner builds emoji sequences, the non-joiner is correct
/// Persian orthography, variation selectors pick emoji presentation — so
/// renderers must NOT fold these (doing so would mangle legitimate guest
/// output). Only identifier validators refuse them, and value quoters treat
/// them as a quoting trigger while preserving the content inside quotes.
///
/// ```rust
/// use qqq_core::text::is_invisible_format;
///
/// assert!(is_invisible_format('\u{200B}'));
/// assert!(is_invisible_format('\u{200D}'));
/// assert!(!is_invisible_format('a'));
/// assert!(!is_invisible_format('\u{202E}'));
/// ```
#[must_use]
pub fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'
            | '\u{2064}'
            | '\u{FE00}'..='\u{FE0F}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every layout-forger is covered and nothing adjacent leaks in: the set
    /// is a closed list, so a member added to the predicate without a case
    /// here (or removed without deleting one) fails loudly.
    #[test]
    fn layout_forgery_covers_every_member_and_no_neighbours() {
        let members = [
            '\u{2028}', '\u{2029}', '\u{200E}', '\u{200F}', '\u{061C}', '\u{202A}', '\u{202B}',
            '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{FEFF}',
        ];
        assert_eq!(
            members.len(),
            15,
            "the set has 15 members; update both sides together"
        );
        for c in members {
            assert!(is_layout_forgery(c), "{c:?} must be a layout-forger");
        }
        for c in [
            'a', '\u{200B}', '\u{00A0}', '\u{0085}', '\u{007F}', '\u{071C}', '\u{2027}',
            '\u{202F}', '\u{206A}', '\u{2060}',
        ] {
            assert!(!is_layout_forgery(c), "{c:?} must not be a layout-forger");
        }
    }

    /// Every invisible format character is covered, and the two sets stay
    /// disjoint: a character must never be both folded by renderers and
    /// preserved by them, or surfaces disagree about what it is.
    #[test]
    fn invisible_format_covers_every_member_and_stays_disjoint() {
        let members = [
            '\u{00AD}', '\u{180E}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{2064}',
            '\u{FE00}', '\u{FE05}', '\u{FE0F}',
        ];
        for c in members {
            assert!(is_invisible_format(c), "{c:?} must be an invisible format");
            assert!(!is_layout_forgery(c), "{c:?} must be in exactly one set");
        }
        for c in ['a', '\u{202E}', '\u{2066}', '\u{00A0}', '\u{0085}'] {
            assert!(
                !is_invisible_format(c),
                "{c:?} must not be an invisible format"
            );
        }
    }
}
