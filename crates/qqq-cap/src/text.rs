// SPDX-License-Identifier: Apache-2.0

//! Text safety: invisible characters that forge layout without a newline.
//!
//! Line/paragraph separators (`U+2028`/`U+2029`) break lines in renderers that
//! honor them; bidirectional controls reorder the visible text. Neither is a
//! C0/C1 control, so `char::is_control` misses both -- and both are name-
//! and value-spoofing primitives, never legitimate in a validated field or a
//! rendered diagnostic. One home so validators and renderers cannot disagree
//! on what "safe to print" means.
///
/// Whether one character is an invisible layout-forger: a line/paragraph
/// separator or a bidirectional control. Neither is a C0/C1 control, so
/// `char::is_control` misses both — check this alongside it, never instead
/// of it.
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
