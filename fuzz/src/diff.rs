// SPDX-License-Identifier: Apache-2.0

//! The differential classification for `I-07`, as pure functions.
//!
//! # Why this is a library module and not inline in the target
//!
//! The fuzz target (`fuzz_targets/http1_diff.rs`) can only run under
//! libFuzzer on nightly, which makes its logic untestable on stable and
//! un-runnable on platforms without a sanitizer runtime (Windows). The
//! classification — the part that decides "finding" versus "acceptable" —
//! is pure over bytes, so it lives here and is unit-tested here. The
//! target is then a thin loop over inputs. A classification bug caught by
//! these tests is a harness bug that would otherwise have silently
//! mislabelled a smuggling shape.

use qqq_serve::http1::{RequestHead, head_end, parse_head};

/// Reference header slots. Above QQQ's `MAX_HEADERS` (100) so a head QQQ
/// accepts always fits; heads the reference accepts past 100 fall in arm 3
/// (QQQ is stricter), never in a comparison.
pub const MAX_REF_HEADERS: usize = 128;

/// The classification of one head. Mirrors the four arms in the target's
/// documentation: agreement, QQQ-only acceptance, QQQ-strict refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Both accept and every compared field agrees.
    Agree,
    /// Both accept but a compared field disagrees: a smuggling shape until
    /// proven otherwise.
    Mismatch(&'static str),
    /// QQQ accepts, the reference rejects: a finding unless allow-listed.
    OursAccepts,
    /// QQQ rejects: acceptable, QQQ is the stricter parser.
    OursRejects,
}

/// Whether `head` is a documented intentional difference for arm 2.
///
/// Empty until a run names one: every entry needs the byte shape, the rule
/// that makes it intentional, and the observation that recorded it.
pub fn is_allowlisted_ours_accepts(_head: &[u8]) -> bool {
    false
}

/// The framing the reference headers describe: content length and chunked.
///
/// `None` means the reference side is unparseable here, which in arm 1
/// (QQQ accepted) is itself a divergence.
pub fn ref_framing(headers: &[httparse::Header<'_>]) -> Option<(Option<u64>, bool)> {
    let mut length: Option<u64> = None;
    let mut chunked = false;
    for h in headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            let text = std::str::from_utf8(h.value).ok()?;
            length = Some(text.trim().parse::<u64>().ok()?);
            // Multiple lengths: QQQ refuses duplicates, so arm 1 never has
            // two — but if it ever did, last-wins here would hide it. Fail
            // the comparison instead of guessing.
            if headers
                .iter()
                .filter(|x| x.name.eq_ignore_ascii_case("content-length"))
                .count()
                > 1
            {
                return None;
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            let text = std::str::from_utf8(h.value).ok()?;
            if text.trim().eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
    }
    Some((length, chunked))
}

/// Compare one head's two parses, naming the first disagreement.
pub fn compare_accepted(ours: &RequestHead, req: &httparse::Request<'_, '_>) -> Verdict {
    // Methods compare case-insensitively: `Method::parse` trims and
    // uppercases, so `get` and `GET` are one method to QQQ.
    let ref_method = req.method.unwrap_or("");
    if !ours.method.as_str().eq_ignore_ascii_case(ref_method) {
        return Verdict::Mismatch("method");
    }
    let ref_path = req.path.unwrap_or("");
    if ours.target != ref_path {
        return Verdict::Mismatch("target");
    }
    let ref_version = match req.version {
        Some(1) => "HTTP/1.1",
        Some(0) => "HTTP/1.0",
        _ => return Verdict::Mismatch("version"),
    };
    if ours.version.as_str() != ref_version {
        return Verdict::Mismatch("version");
    }
    if ours.headers.len() != req.headers.len() {
        return Verdict::Mismatch("header count");
    }
    for ((o_name, o_value), r) in ours.headers.iter().zip(req.headers.iter()) {
        if !o_name.eq_ignore_ascii_case(r.name) {
            return Verdict::Mismatch("header name");
        }
        // QQQ stores values trimmed; the reference returns raw spans, so
        // both sides trim before comparing (OWS is not significant).
        let r_value = String::from_utf8_lossy(r.value);
        if o_value.as_str() != r_value.trim() {
            return Verdict::Mismatch("header value");
        }
    }
    let (ref_length, ref_chunked) = match ref_framing(req.headers) {
        Some(f) => f,
        None => return Verdict::Mismatch("framing"),
    };
    if ours.content_length != ref_length || ours.chunked != ref_chunked {
        return Verdict::Mismatch("framing");
    }
    Verdict::Agree
}

/// Parse `data` with both parsers and classify the outcome.
pub fn classify(data: &[u8], max_input: usize) -> (Verdict, Vec<u8>) {
    if data.len() > max_input {
        return (Verdict::OursRejects, Vec::new());
    }
    let Some(end) = head_end(data) else {
        return (Verdict::OursRejects, Vec::new());
    };
    let head = &data[..end];
    let ours = parse_head(head).map(|(h, _)| h).ok();

    let mut buf = [httparse::EMPTY_HEADER; MAX_REF_HEADERS];
    let mut req = httparse::Request::new(&mut buf);
    let ref_accepts = matches!(req.parse(head), Ok(httparse::Status::Complete(_)));

    match (ours, ref_accepts) {
        (Some(o), true) => (compare_accepted(&o, &req), head.to_vec()),
        (Some(_), false) => {
            if is_allowlisted_ours_accepts(head) {
                (Verdict::Agree, head.to_vec())
            } else {
                (Verdict::OursAccepts, head.to_vec())
            }
        }
        (None, _) => (Verdict::OursRejects, Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_serve::http1::MAX_HEAD_BYTES;

    fn head(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn minimal_request_agrees() {
        let (v, _) = classify(&head("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), MAX_HEAD_BYTES);
        assert_eq!(v, Verdict::Agree);
    }

    #[test]
    fn lowercase_method_agrees_through_documented_normalisation() {
        let (v, _) = classify(&head("get / HTTP/1.1\r\nHost: x\r\n\r\n"), MAX_HEAD_BYTES);
        assert_eq!(v, Verdict::Agree);
    }

    #[test]
    fn obs_fold_is_ours_rejects() {
        let (v, _) = classify(
            &head("GET / HTTP/1.1\r\nHost: x\r\n folded: yes\r\n\r\n"),
            MAX_HEAD_BYTES,
        );
        assert_eq!(v, Verdict::OursRejects);
    }

    #[test]
    fn unknown_method_is_ours_rejects() {
        // `httparse` accepts any token method; QQQ knows nine. The strict
        // refusal is arm 3, never a finding.
        let (v, _) = classify(&head("FOO / HTTP/1.1\r\nHost: x\r\n\r\n"), MAX_HEAD_BYTES);
        assert_eq!(v, Verdict::OursRejects);
    }

    #[test]
    fn mutated_target_is_a_mismatch() {
        // The comparison must fire on a real field disagreement: parse a
        // head both accept, then compare a tampered copy against the same
        // reference parse.
        let raw = head("GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
        let (head_parsed, _) =
            parse_head(&raw).expect("fixture parses");
        let mut buf = [httparse::EMPTY_HEADER; MAX_REF_HEADERS];
        let mut req = httparse::Request::new(&mut buf);
        assert!(matches!(req.parse(&raw), Ok(httparse::Status::Complete(_))));
        let mut tampered = head_parsed;
        tampered.target = "/b".to_owned();
        assert_eq!(
            compare_accepted(&tampered, &req),
            Verdict::Mismatch("target")
        );
    }

    #[test]
    fn truncated_input_is_ours_rejects() {
        let (v, _) = classify(b"GET / HTTP/1.1\r\nHost: x\r\n", MAX_HEAD_BYTES);
        assert_eq!(v, Verdict::OursRejects);
    }
}
