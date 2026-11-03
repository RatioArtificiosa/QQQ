//! Structural-scan helpers for the allowlist tests.
//!
//! The audit and replay allowlist tests (`audit::tests`,
//! `ambient::tests`) scan the crate's own sources for call sites that must
//! name an allowlisted function. They share this projection (comments and
//! string contents blanked, byte-exact so spans index the original) and
//! the call-shape helpers below, so the three scanners cannot drift into
//! three dialects. Test-only: never compiled into the shipped binary.

/// Blanks string-literal contents and comments, preserving byte length
/// so spans cut from the projection index the original exactly (each
/// source byte becomes one output byte; newlines stay newlines so line
/// structure survives). Quotes stay; contents become spaces, so no needle
/// can match inside prose.
///
/// A single quote opens a char literal only in char shape (one char, an
/// escape, or a unicode escape, each closed by a quote); a lone quote is
/// a lifetime and is left alone. Raw and byte strings blank through
/// their closing delimiter, so a comment opener inside one cannot cut
/// the line and hide a registration.
// One function, not five: the projection is a single state machine over
// the source, and splitting it across items would scatter the
// string/comment/char/raw states it exists to keep consistent.
#[allow(
    clippy::too_many_lines,
    reason = "test-only structural scanner; one state machine reads clearer split apart"
)]
pub(crate) fn code_projection(text: &str) -> String {
    fn blanks(out: &mut String, byte_len: usize) {
        for _ in 0..byte_len {
            out.push(' ');
        }
    }
    // Blank a segment, preserving newlines: one space per byte otherwise.
    fn push_blanked(out: &mut String, s: &str) {
        for part in s.split_inclusive('\n') {
            if let Some(body) = part.strip_suffix('\n') {
                blanks(out, body.len());
                out.push('\n');
            } else {
                blanks(out, part.len());
            }
        }
    }
    // Blank a raw-string body through its closing delimiter.
    fn blank_raw_body<'a>(
        out: &mut String,
        mut rest: &'a str,
        closer: &str,
        hashes: usize,
    ) -> &'a str {
        loop {
            if rest.is_empty() {
                break;
            }
            if rest.starts_with(closer) {
                out.push('"');
                blanks(out, hashes);
                rest = &rest[1 + hashes..];
                break;
            }
            let c = rest.chars().next().expect("non-empty");
            push_blanked(out, &rest[..c.len_utf8()]);
            rest = &rest[c.len_utf8()..];
        }
        rest
    }
    // Raw or byte string at this position. Code context, so max-munch
    // already decided these lex as strings, not identifiers. Returns
    // the hash count and the text after the opening quote.
    fn raw_open(rest: &str) -> Option<(usize, &str)> {
        // `b` only starts a raw string as `br`: a bare `b"..."` is a
        // *cooked* byte string whose escapes stay live, and treating it
        // as raw mis-closes at an escaped quote and desyncs the rest of
        // the file.
        let s = match rest.strip_prefix('b') {
            Some(tail) if tail.starts_with('r') => tail,
            _ => rest,
        };
        let s = s.strip_prefix('r').unwrap_or(s);
        let hashes = s.chars().take_while(|c| *c == '#').count();
        s[hashes..].strip_prefix('"').map(|body| (hashes, body))
    }
    // Byte length of the char literal at the start of `rest` (which
    // starts with a quote), or `None` for a lifetime.
    fn char_len(rest: &str) -> Option<usize> {
        let tail = &rest[1..];
        if let Some(body) = tail.strip_prefix('\\') {
            if let Some(after_u) = body.strip_prefix("u{") {
                let i = after_u.find('}')?;
                if !after_u[i + 1..].starts_with('\'') {
                    return None;
                }
                return Some(1 + 1 + 2 + i + 2);
            }
            if body.len() >= 2 && body[1..].starts_with('\'') {
                return Some(4);
            }
            return None;
        }
        let c = tail.chars().next()?;
        if tail[c.len_utf8()..].starts_with('\'') {
            Some(1 + c.len_utf8() + 1)
        } else {
            None
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        if rest.starts_with('"') {
            out.push('"');
            rest = &rest[1..];
            while !rest.is_empty() {
                if rest.starts_with('\\') {
                    blanks(&mut out, 2);
                    rest = &rest[2..];
                } else if rest.starts_with('"') {
                    out.push('"');
                    rest = &rest[1..];
                    break;
                } else {
                    let c = rest.chars().next().expect("non-empty");
                    push_blanked(&mut out, &rest[..c.len_utf8()]);
                    rest = &rest[c.len_utf8()..];
                }
            }
        } else if rest.starts_with("//") {
            let end = rest.find('\n').unwrap_or(rest.len());
            blanks(&mut out, end);
            rest = &rest[end..];
        } else if rest.starts_with("/*") {
            let end = rest.find("*/").map_or(rest.len(), |i| i + 2);
            let (comment, tail) = rest.split_at(end);
            push_blanked(&mut out, comment);
            rest = tail;
        } else if let Some((hashes, body)) = raw_open(rest) {
            // `body` is a suffix of `rest`, so the opening length is
            // the difference; the quote itself is kept as the anchor.
            let open_len = rest.len() - body.len();
            blanks(&mut out, open_len - 1);
            out.push('"');
            rest = body;
            let closer: String = std::iter::once('"')
                .chain(std::iter::repeat_n('#', hashes))
                .collect();
            rest = blank_raw_body(&mut out, rest, &closer, hashes);
        } else if rest.starts_with('\'') {
            if let Some(len) = char_len(rest) {
                let len = len.min(rest.len());
                blanks(&mut out, len);
                rest = &rest[len..];
            } else {
                out.push('\'');
                rest = &rest[1..];
            }
        } else {
            let c = rest.chars().next().expect("non-empty");
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    out
}

/// Skip ASCII whitespace (and blanked comments, which are whitespace in
/// the projection) to the call's opening paren. Lets `a.record /**/ (`
/// match like `a.record(`; a name not followed by `(` is not a call.
/// Returns the paren's byte index (ASCII, so any offset works).
pub(crate) fn find_call_open(code: &str, mut i: usize) -> Option<usize> {
    let bytes = code.as_bytes();
    while let Some(&b) = bytes.get(i) {
        match b {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'(' => return Some(i),
            _ => return None,
        }
    }
    None
}

/// The identifier receiving a method or path call: the token ending
/// where the `.` or `::` before `name_start` begins. Empty when the name
/// is not a method/path call (the caller checks that first). Used to
/// attribute a call to its owner (`audit` vs `log`), so each allowlist
/// test excuses only the other test's forwarder.
pub(crate) fn receiver_of(code: &str, name_start: usize) -> &str {
    let mut before = code[..name_start].trim_end();
    if let Some(tail) = before.strip_suffix("::") {
        before = tail;
    } else if let Some(tail) = before.strip_suffix('.') {
        before = tail;
    } else {
        return "";
    }
    let before = before.trim_end();
    let mut len = 0usize;
    for c in before.chars().rev() {
        if c.is_ascii_alphanumeric() || c == '_' {
            len += c.len_utf8();
        } else {
            break;
        }
    }
    &before[before.len() - len..]
}

/// Top-level commas in a projected call span (strings and comments are
/// already blanked, so every comma counts). The audit shape check uses
/// arity rather than names: a `.record` with two or more top-level
/// commas is an audit-shaped call, whatever its identifiers are.
pub(crate) fn top_level_commas(projected_span: &str) -> usize {
    let mut depth = 0usize;
    let mut commas = 0usize;
    for c in projected_span.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 1 => commas += 1,
            _ => {}
        }
    }
    commas
}

/// Whether the span forwards the `function` parameter itself rather
/// than naming one: a bare `function` argument (bounded by delimiters, so
/// `dysfunction` and `my_function` do not match) or the commit path's
/// `row.function`. String contents are blanked in the projection, so a
/// `"function"` literal cannot smuggle through here. Test loops pass the
/// same-named loop variable over the allowlist itself, which is safe by
/// construction and shares the name.
pub(crate) fn is_forwarded_call(projected_span: &str) -> bool {
    if projected_span.contains("row.function") {
        return true;
    }
    let mut rest = projected_span;
    let word = "function";
    while let Some(i) = rest.find(word) {
        let before = rest[..i].chars().next_back();
        let after = rest[i + word.len()..].chars().next();
        let before_ok = matches!(before, None | Some('(' | ',' | ' ' | '\t' | '\n' | '\r'));
        let after_ok = matches!(after, None | Some(',' | ')' | ' ' | '\t' | '\n' | '\r'));
        if before_ok && after_ok {
            return true;
        }
        rest = &rest[i + 1..];
    }
    false
}

/// Whether the `name` at `start` opens a *method or path* call:
/// preceded by `.` or `::`, followed (after whitespace/comments, already
/// blanked) by `(`. Returns the paren's byte index. This is how
/// `a.record /**/ (` and UFCS `AuditHandle::record(h, ..)` scan like
/// `a.record(`; a bare `record` (free helper, definition, prose) never
/// qualifies.
pub(crate) fn is_method_call(code: &str, start: usize, name: &str) -> Option<usize> {
    let prev = code[..start].chars().next_back()?;
    if !matches!(prev, '.' | ':') {
        return None;
    }
    find_call_open(code, start + name.len())
}

/// Whether the `name` at `start` opens a *free-function* call: not part
/// of a longer identifier, not a `fn` definition, followed (after
/// whitespace/comments) by `(`. Returns the paren's byte index.
pub(crate) fn is_free_call(code: &str, start: usize, name: &str) -> Option<usize> {
    let before = &code[..start];
    if before
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    if before
        .split_whitespace()
        .next_back()
        .is_some_and(|w| w == "fn")
    {
        return None;
    }
    find_call_open(code, start + name.len())
}

/// The crate sources minus `#[cfg(test)]`-gated items, as a
/// (text, projection) pair with identical byte offsets.
///
/// The allowlist tests must see production code *wherever* it sits: inline
/// `#[cfg(test)]` helpers (like `ambient`'s clock helpers) hide every seam
/// below them from a split-at-first-test-gate scan. Runs on the projection
/// (comments and string contents blanked), so a `#[cfg(test)]` inside prose
/// cannot fake a gate and unbalanced braces inside strings cannot break the
/// item skip. Only the exact `#[cfg(test)]` spelling gates (the only
/// spelling in the tree). A truncated tail panics rather than silently
/// dropping the file and blinding the scanner.
pub(crate) fn strip_test_items(source: &str) -> (String, String) {
    let code = code_projection(source);
    assert_eq!(
        code.len(),
        source.len(),
        "projection must preserve byte length for aligned stripping"
    );
    // Cut ranges, computed in code space (blanks make every bracket real).
    // Slicing stays on the original `&str` cursors throughout: no byte
    // indexing, so multi-byte content elsewhere cannot misalign the spans.
    let mut cuts: Vec<(usize, usize)> = Vec::new();
    let mut at = 0;
    let gate = "#[cfg(test)]";
    while let Some(found) = code[at..].find(gate) {
        let gate_at = at + found;
        let mut rest = &code[gate_at + gate.len()..];
        // Skip whitespace and stacked attributes (`#[must_use]`, ...).
        loop {
            rest = rest.trim_start();
            if let Some(tail) = rest.strip_prefix('#') {
                let mut depth = 0usize;
                let mut taken = 0usize;
                for (n, c) in tail.char_indices() {
                    match c {
                        '[' => depth += 1,
                        ']' => {
                            depth -= 1;
                            if depth == 0 {
                                taken = n + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                assert!(taken > 0, "unterminated attribute after #[cfg(test)]");
                rest = &tail[taken..];
            } else {
                break;
            }
        }
        // Skip the item: to the matching close brace, or the semicolon for
        // body-less items.
        let mut depth = 0usize;
        let mut taken = None;
        for (n, c) in rest.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        taken = Some(n + 1);
                        break;
                    }
                }
                ';' if depth == 0 => {
                    taken = Some(n + 1);
                    break;
                }
                _ => {}
            }
        }
        let taken = taken.expect("unterminated #[cfg(test)] item");
        let cut_end = code.len() - rest.len() + taken;
        cuts.push((gate_at, cut_end));
        at = cut_end;
    }
    // Same byte ranges cut from both (projection preserves length).
    let mut text_out = String::with_capacity(source.len());
    let mut code_out = String::with_capacity(code.len());
    let mut prev = 0;
    for (start, end) in &cuts {
        text_out.push_str(&source[prev..*start]);
        code_out.push_str(&code[prev..*start]);
        prev = *end;
    }
    text_out.push_str(&source[prev..]);
    code_out.push_str(&code[prev..]);
    (text_out, code_out)
}
