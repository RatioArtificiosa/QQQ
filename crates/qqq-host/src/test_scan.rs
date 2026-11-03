// SPDX-License-Identifier: Apache-2.0

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
            // backslash-x-N-N: backslash, x, two hex digits, closing quote.
            if body.len() >= 4
                && body.starts_with('x')
                && body
                    .as_bytes()
                    .get(1..3)
                    .is_some_and(|w| w.iter().all(u8::is_ascii_hexdigit))
                && body[3..].starts_with('\'')
            {
                return Some(6);
            }
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
    // Bare `function` must be a whole top-level argument: the seam's
    // `audit.record(c, function, outcome)` and the test loops'
    // `stream.record(.., function, ..)`.
    if split_top_level(projected_span)
        .iter()
        .any(|arg| arg.trim() == "function")
    {
        return true;
    }
    // `row.function` as a whole token: the commit path re-records the
    // pending row's function. Word-bounded on both sides, so
    // `narrow.function` and `row.functionality` do not match.
    projected_span
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .any(|w| w == "row.function")
}

/// Split a projected call span at its top-level commas (depth 1 inside
/// the call's own parens). Strings and comments are already blanked, so
/// every comma counted is structural.
pub(crate) fn split_top_level(projected_span: &str) -> Vec<&str> {
    // Arguments only: the span starts at the callee name, so content
    // before the first paren is the head, not an argument. Trailing text
    // past the matching close paren is dropped the same way.
    let body = match projected_span.find('(') {
        Some(i) => &projected_span[i + 1..],
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in body.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    out.push(&body[start..i]);
                    break;
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                out.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out
}

/// Whether the `name` at `start` opens a *method or path* call:
/// preceded by `.` or `::`, followed (after whitespace/comments, already
/// blanked) by `(`. Returns the paren's byte index. This is how
/// `a.record /**/ (` and UFCS `AuditHandle::record(h, ..)` scan like
/// `a.record(`; a bare `record` (free helper, definition, prose) never
/// qualifies.
pub(crate) fn is_method_call(code: &str, start: usize, name: &str) -> Option<usize> {
    // Trailing whitespace skipped: `a .record(` and `A :: record(` are
    // valid Rust a spaced-out dot away from the canonical shape, and the
    // projection blanks comments, so `a /**/ .record(` matches too.
    let mut before = code[..start].trim_end();
    // A path separator with spaces (`A :: record`): strip one colon, then
    // whitespace, then require the second.
    if let Some(tail) = before.strip_suffix(':') {
        before = tail.trim_end();
        if !before.ends_with(':') {
            return None;
        }
    } else if !before.ends_with('.') {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_preserves_byte_length_over_hostile_input() {
        let src = "fn f() { let s = \"a\\\"b\u{2028}x\"; /* c // d */ let c = '\x41'; let r = r#\"e\"f\"#; }\n";
        let code = code_projection(src);
        assert_eq!(
            code.len(),
            src.len(),
            "every source byte must map to exactly one output byte"
        );
        assert_eq!(
            code.matches('\n').count(),
            src.matches('\n').count(),
            "newlines survive so line numbers stay aligned"
        );
    }

    #[test]
    fn projection_blanks_strings_and_comments_but_keeps_code() {
        let code = code_projection("a.record(\"name\"); // func_wrap(\"ghost\", x);\n");
        assert!(code.contains("a.record("), "code survives");
        assert!(!code.contains("ghost"), "line comments do not scan");
        assert!(!code.contains("name"), "string contents do not scan");
    }

    #[test]
    fn projection_tracks_block_comments_spanning_lines() {
        let code = code_projection("a(1);\n/* func_wrap(\"x\", y);\nstill comment */\nb(2);\n");
        assert!(code.contains("a(1);"), "code before survives");
        assert!(code.contains("b(2);"), "code after survives");
        assert!(!code.contains("func_wrap"), "block comment hidden");
    }

    #[test]
    fn projection_handles_raw_strings_char_literals_and_lifetimes() {
        // A `//` inside a raw string must not cut the line.
        let code = code_projection("a.func_wrap(\"x\"); let r = r#\"a // b\"#;\n");
        assert!(code.contains("a.func_wrap("), "code survives");
        // A char literal blanks to spaces; a lifetime stays.
        assert_eq!(code_projection("let c = 'x';\n"), "let c =    ;\n");
        assert_eq!(code_projection("let c = '\\x41';\n"), "let c =       ;\n");
        assert!(code_projection("let r = &\u{27}a str;\n").contains("&\u{27}a"));
        // Byte-exactness over multibyte content: one space per byte.
        let code = code_projection("\u{2028}\n");
        assert_eq!(code.len(), 4, "U+2028 is 3 bytes plus newline");
    }

    #[test]
    fn split_top_level_counts_structural_commas_only() {
        assert_eq!(split_top_level("record(a, b, c)"), vec!["a", " b", " c"]);
        assert_eq!(split_top_level("f(g(1, 2), h)").len(), 2);
        assert_eq!(
            top_level_commas("log.record(function, value)"),
            1,
            "the replay forwarder has one comma"
        );
        assert!(top_level_commas("self.record(\"sign\", key)") < 2);
    }

    #[test]
    fn is_forwarded_call_accepts_only_the_closed_set() {
        assert!(is_forwarded_call("record(c, function, outcome)"));
        assert!(is_forwarded_call("record(function, value)"));
        assert!(is_forwarded_call(
            "record(row.tenant, &c, row.function, row.outcome)"
        ));
        assert!(!is_forwarded_call("record(c, dysfunction, outcome)"));
        assert!(!is_forwarded_call("record(c, my_function, outcome)"));
        assert!(!is_forwarded_call("record(c, function2, outcome)"));
        assert!(!is_forwarded_call("record(c, evil, foo(function))"));
        assert!(!is_forwarded_call("record(narrow.function, outcome)"));
        assert!(!is_forwarded_call("record(row.functionality, outcome)"));
    }

    #[test]
    fn strip_test_items_removes_gated_code_but_keeps_production() {
        let src = "fn live() { require(a, b, \"x\"); }\n#[cfg(test)]\nfn dead() { require(a, b, \"y\"); }\nfn live2() {}\n";
        let (text, code) = strip_test_items(src);
        assert!(text.contains("live()"), "production kept");
        assert!(!text.contains("dead()"), "gated item stripped");
        assert!(!code.contains("\"y\""), "gated literal not scanned");
        assert_eq!(text.len(), code.len(), "aligned outputs");
    }
}
