// SPDX-License-Identifier: Apache-2.0

//! A minimal JSON writer, enough for the `json` benchmark's 1 KB object.
//!
//! # Why a writer and not a parser
//!
//! Nothing in this app accepts a JSON body. Orders arrive as form-encoded fields
//! (`orders::create`), which keeps the app off the parser-authoring path — a
//! hand-written JSON *parser* is a security surface, and this crate exists to be a
//! benchmark, not to be one more thing to audit. A writer has no such risk: it has
//! no input to get wrong.
//!
//! # Why the escaping is where the value is
//!
//! `string` is the only function that escapes, and it is the only one that can
//! produce an invalid document if it is wrong. Keeping that in one place means the
//! correctness argument is about twelve lines rather than about the module.

/// A JSON value that has already been rendered.
///
/// Newtype rather than `String` so a caller cannot concatenate a raw `String` into
/// a document without the name saying that is what happened.
pub struct Raw(String);

impl Raw {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Wrap an already-rendered document.
    ///
    /// Used where a document is assembled from pieces — the `template` workload's
    /// table, or a nested object — rather than by [`raw_object`].
    #[must_use]
    pub fn from_parts(s: String) -> Raw {
        Raw(s)
    }
}

/// Render one object from already-rendered pairs.
///
/// The `&[(&str, Raw)]` shape — rather than a `HashMap` — is deliberate: order is
/// caller-controlled and therefore stable, which `§10.5` requires. A `HashMap`
/// here would make the benchmark's payload differ run to run, and the `json`
/// benchmark is *about* that payload.
#[must_use]
pub fn raw_object(pairs: &[(&str, Raw)]) -> Raw {
    let mut out = String::with_capacity(64 + pairs.len() * 32);
    out.push('{');
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_escaped(&mut out, key);
        out.push(':');
        out.push_str(value.as_str());
    }
    out.push('}');
    Raw(out)
}

/// Render an object and answer with it, as `application/json`.
///
/// # Why this is a separate function from `raw_object`
///
/// Nested objects (`customer`, `shipping`) need the rendered document without a
/// response around it. Expressing `object` in terms of `raw_object` means the
/// escaping and the `Content-Type` are each decided once — a nested object cannot
/// drift from a top-level one because there is only one renderer.
#[must_use]
pub fn object(pairs: &[(&str, Raw)]) -> crate::exports_ih::incoming_handler::Response {
    let body = raw_object(pairs).0;
    let mut resp = crate::exports_ih::incoming_handler::Response {
        status: 200,
        headers: vec![],
        body: body.into_bytes(),
    };
    resp.headers.push(crate::root_http::Header {
        name: "Content-Type".to_owned(),
        value: b"application/json".to_vec(),
    });
    resp
}

/// Render a string value, with quotes.
#[must_use]
pub fn string(s: &str) -> Raw {
    let mut out = String::with_capacity(s.len() + 2);
    push_escaped(&mut out, s);
    Raw(out)
}

/// Render an unsigned number.
#[must_use]
pub fn number(n: u64) -> Raw {
    Raw(n.to_string())
}

/// Render an array of already-rendered values.
#[must_use]
pub fn array(items: &[Raw]) -> Raw {
    let mut out = String::with_capacity(2 + items.len() * 32);
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(item.as_str());
    }
    out.push(']');
    Raw(out)
}

/// Write `s` as a quoted JSON string.
///
/// # The rules implemented, and why each is not decoration
///
/// * `"` and `\` must be escaped or the document ends early.
/// * Every control character below `0x20` must be escaped. A raw newline inside a
///   string is **invalid JSON**, and `\u00XX` is the portable spelling.
/// * `\u007f` (DEL) is *valid* unescaped per RFC 8259 but is escaped anyway,
///   because it is a control character that a terminal renders as nothing, so an
///   unescaped one turns a log line into a puzzle.
///
/// `/` is deliberately **not** escaped. `\/` is legal but pointless outside a
/// `</script>` context, and paying two bytes for every slash in every benchmark
/// response would be a cost the `json` row would measure.
fn push_escaped(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str("\\u");
                out.push_str(&format!("{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(r: &crate::exports_ih::incoming_handler::Response) -> String {
        String::from_utf8(r.body.clone()).expect("the writer emits UTF-8")
    }

    #[test]
    fn an_object_is_rendered_in_the_order_given() {
        let r = object(&[("b", number(2)), ("a", number(1))]);
        assert_eq!(body(&r), r#"{"b":2,"a":1}"#);
    }

    #[test]
    fn strings_escape_everything_that_would_break_the_document() {
        assert_eq!(string("a\"b").as_str(), r#""a\"b""#);
        assert_eq!(string("a\\b").as_str(), r#""a\\b""#);
        assert_eq!(string("a\nb").as_str(), r#""a\nb""#);
        assert_eq!(string("a\rb").as_str(), r#""a\rb""#);
        assert_eq!(string("a\tb").as_str(), r#""a\tb""#);
        // A raw control character is invalid JSON, so it must not survive.
        assert_eq!(string("\u{01}").as_str(), r#""\u0001""#);
        assert_eq!(string("\u{1f}").as_str(), r#""\u001f""#);
        assert_eq!(string("\u{7f}").as_str(), r#""\u007f""#);
    }

    #[test]
    fn an_ordinary_string_is_not_touched() {
        // The control for the escaping above: if the escaper corrupted everything,
        // those assertions would still pass.
        assert_eq!(string("order-42").as_str(), r#""order-42""#);
        assert_eq!(string("café").as_str(), r#""café""#);
        assert_eq!(
            string("/orders/42").as_str(),
            r#""/orders/42""#,
            "a solidus is legal unescaped and escaping it would inflate every payload"
        );
    }

    #[test]
    fn a_control_character_in_a_key_is_escaped_too() {
        // The key goes through the same escaper; a key that broke the document
        // would be the same defect in a place easy to forget.
        let r = object(&[("k\n", number(1))]);
        assert_eq!(body(&r), r#"{"k\n":1}"#);
    }

    #[test]
    fn an_array_renders_with_commas_and_no_trailing_one() {
        assert_eq!(array(&[]).as_str(), "[]");
        assert_eq!(array(&[number(1)]).as_str(), "[1]");
        assert_eq!(array(&[number(1), string("x")]).as_str(), r#"[1,"x"]"#);
    }

    #[test]
    fn an_empty_object_is_valid() {
        assert_eq!(body(&object(&[])), "{}");
    }

    #[test]
    fn the_json_workload_payload_is_the_size_9_1_specifies() {
        // §9.1: "`json` — serialize 1 KB object". The benchmark is defined by the
        // payload's size, so a payload that drifted to 100 bytes would make the
        // row measure something else while still passing every test above.
        use crate::orders;
        let resp = orders::by_id("42");
        let len = resp.body.len();
        assert!(
            (700..=1400).contains(&len),
            "§9.1's json row is a 1 KB object; this payload is {len} bytes"
        );
    }
}
