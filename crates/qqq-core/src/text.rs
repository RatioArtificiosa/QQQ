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
//! Two sets, two treatments. [`is_layout_forgery`] reorders or breaks text:
//! every renderer folds it, because a forged line is a forged event.
//! [`is_invisible_format`] merely hides: identifier validators refuse it and
//! identifier renderers fold it, but content renderers (log messages, guest
//! output) preserve it — a zero-width joiner builds legitimate emoji, and
//! mangling content to police identifiers punishes the wrong layer.
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

/// Whether one character is an invisible character that spoofs identifiers.
///
/// Zero-width spaces and joiners, the word joiner, the soft hyphen, the
/// Mongolian vowel separator and free variation selectors, the combining
/// grapheme joiner, invisible function/times/separator/plus operators, tag
/// characters, and variation selectors render as nothing (or as a glyph that
/// looks like nothing) in most renderings, so two identifiers differing only
/// in one of these display identically: `acme` and `acme\u{200B}` are
/// distinct keys that no reader can tell apart. Unlike [`is_layout_forgery`],
/// several members are legitimate in *content* — the zero-width joiner builds
/// emoji sequences, the non-joiner is correct Persian orthography, variation
/// selectors pick emoji presentation — so renderers must NOT fold these
/// (doing so would mangle legitimate guest output). Only identifier
/// validators refuse them, and value quoters treat them as a quoting trigger
/// while preserving the content inside quotes.
///
/// The set is the assigned invisible code points of the format,
/// combining-mark, and default-ignorable classes — verified against the
/// Unicode Character Database (category `Cf`/`Mn`, non-control,
/// non-whitespace, zero-width in most renderings). Unassigned code points
/// are skipped (one that later assigns as visible must not be refused;
/// `2065` stays out even though it sits inside the `206x` block), and
/// visibly-rendering fillers (Hangul `115F`-`1160`, `3164`) are excluded
/// — they cannot spoof because they can be seen.
///
/// ```rust
/// use qqq_core::text::is_invisible_format;
///
/// assert!(is_invisible_format('\u{200B}'));
/// assert!(is_invisible_format('\u{200D}'));
/// assert!(is_invisible_format('\u{2062}'));
/// assert!(is_invisible_format('\u{0600}'));
/// assert!(!is_invisible_format('a'));
/// assert!(!is_invisible_format('\u{202E}'));
/// ```
#[must_use]
pub fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{0600}'..='\u{0605}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'
            | '\u{180B}'..='\u{180F}'
            | '\u{1BCA0}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'..='\u{2064}'
            | '\u{206A}'..='\u{206F}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
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
    /// preserved by them, or surfaces disagree about what it is. Ranges are
    /// iterated rather than sampled, so a hole in the middle of a range
    /// (the `2061`-`2063` class) fails instead of passing on endpoints.
    /// The count pins the whole list: adding a member to the predicate
    /// without extending this test fails, and so does shrinking either side.
    #[test]
    fn invisible_format_covers_every_member_and_stays_disjoint() {
        let singles = [
            '\u{00AD}',
            '\u{034F}',
            '\u{06DD}',
            '\u{070F}',
            '\u{08E2}',
            '\u{110BD}',
            '\u{110CD}',
            '\u{13430}',
            '\u{180F}',
            '\u{1BCA0}',
            '\u{E0001}',
        ];
        let ranges = [
            '\u{0600}'..='\u{0605}',
            '\u{0890}'..='\u{0891}',
            '\u{180B}'..='\u{180E}',
            '\u{1D173}'..='\u{1D17A}',
            '\u{200B}'..='\u{200D}',
            '\u{2060}'..='\u{2064}',
            '\u{206A}'..='\u{206F}',
            '\u{FE00}'..='\u{FE0F}',
            '\u{FFF9}'..='\u{FFFB}',
            '\u{E0020}'..='\u{E007F}',
            '\u{E0100}'..='\u{E01EF}',
        ];
        let mut count = 0u32;
        for c in singles.into_iter().chain(ranges.into_iter().flatten()) {
            count += 1;
            assert!(is_invisible_format(c), "{c:?} must be an invisible format");
            assert!(!is_layout_forgery(c), "{c:?} must be in exactly one set");
        }
        assert_eq!(
            count, 400,
            "the set has 400 members; update test and predicate together"
        );
        for c in [
            'a', '\u{202E}', '\u{2066}', '\u{00A0}', '\u{0085}', '\u{2065}', '\u{115F}',
            '\u{2000}', '\u{3000}',
        ] {
            assert!(
                !is_invisible_format(c),
                "{c:?} must not be an invisible format"
            );
        }
        // Visibly-rendering fillers are excluded: they cannot spoof because
        // they can be seen.
        for c in ['\u{115F}', '\u{1160}', '\u{3164}'] {
            assert!(
                !is_invisible_format(c),
                "{c:?} renders visibly, must stay out"
            );
        }
    }
}
