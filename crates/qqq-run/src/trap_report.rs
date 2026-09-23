// SPDX-License-Identifier: Apache-2.0

//! Resolving a trap's backtrace to source lines, for a report that outlives the
//! engine that produced it.
//!
//! Implements Checklist `HOST-009`'s remaining half — *"structured trap reporting
//! with guest backtrace and DWARF source mapping when available"* — and is the
//! caller that makes `qqq_debug::resolve_frames` reachable. Without it the
//! resolver would be the `§O-045a` defect a third time: correct, tested, and
//! called by nothing.
//!
//! ## The two halves, and which was missing
//!
//! `Trap::from_wasmtime_error` reads `Wasmtime`'s own `WasmBacktrace`, which the
//! engine resolved in memory through the module's DWARF. That works **only while
//! the engine is alive**. The moment a trap becomes a `qqq_core::Error` — which is
//! what `qqqai run` returns, and what a JSON consumer sees — the frames are
//! flattened by [`qqq_host::Trap::to_error`] into `cause` strings of the form
//! `frame 3: handle+0x1a3`.
//!
//! Those strings are *lossy in exactly one way that matters*: a frame whose
//! `file`/`line` the engine could not resolve renders as `func+0x1a3`, and the
//! offset is the only thing in the string that can still be resolved — by the
//! source map extracted from the artifact, which does not need an engine.
//!
//! ## Why this parses the rendered frames
//!
//! It would be cleaner to carry the `Trap` itself to the CLI. That requires
//! changing `qqq_core::Error`, which is the error type for **every** crate and
//! every command; the frames would then ride along in the context of errors that
//! have nothing to do with traps.
//!
//! Parsing the `causes` instead keeps the change local and works on reports that
//! **already exist** — an error from a previous version, a log line, a report
//! pasted into an issue. The format is not incidental: it is produced by
//! `qqq_host::Trap::to_error` and pinned by tests on both sides.
//!
//! ## The rule
//!
//! > **An unmapped frame reports no location. It never reports a guessed one.**
//!
//! A frame the parser cannot understand is **dropped**, not rendered as junk, and
//! a frame the map does not cover keeps its offset. [`ResolvedBacktrace::explain`]
//! states which of the two happened, so a reader can tell "no debug info" from
//! "this report is in a format I do not recognise".

use qqq_core::Error;
use qqq_debug::{render_frames, resolve_frames, ReportedFrame, ResolveReport, SourceMap};

/// Extract a source map from an artifact, degrading to an empty map.
///
/// # Why this never fails
///
/// A project built without `debug = true` has no DWARF, and that is a legitimate
/// configuration rather than an error: `qqqai run` must still run it, and a trap
/// in it must still be reported. An artifact that cannot be read at all is the
/// same story from the caller's side — `execute` is about to report *that*
/// failure with a better message than this function could.
///
/// So the contract is: you get a map, and it may be empty. An empty map produces
/// frames that keep their offsets and an explanation naming the missing debug
/// info, which is the honest report. Refusing to run a release build because it
/// has no debug info would be a much worse outcome than an unresolved frame.
#[must_use]
pub fn source_map_for_artifact(path: &std::path::Path) -> SourceMap {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| qqq_debug::extract(&bytes).ok())
        .map_or_else(SourceMap::empty, |report| report.map)
}

/// A backtrace resolved against a source map, ready to render or serialize.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ResolvedBacktrace {
    /// The frames, in the order the trap reported them, outermost first.
    pub frames: Vec<ReportedFrame>,
    /// What the resolution pass did.
    pub report: ResolveReport,
    /// One sentence naming any gap, so an empty result is never silent.
    pub explanation: String,
}

impl ResolvedBacktrace {
    /// Whether there is anything to render.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// The frames as a terminal block.
    #[must_use]
    pub fn render(&self) -> String {
        render_frames(&self.frames)
    }
}

/// Extract frames from a rendered frame string, as `Trap::to_error` produces.
///
/// The accepted forms are exactly the ones [`qqq_host::WasmFrame`]'s `Display`
/// emits, optionally prefixed by `frame N: `:
///
/// | Input | Result |
/// |---|---|
/// | `frame 0: handle (src/handler.rs:42)` | `handle` at `src/handler.rs:42` |
/// | `frame 1: spin+0x1a3` | `spin` with `offset = 0x1a3`, no location |
/// | `frame 2: main` | `main`, no location, no offset |
/// | `some other cause text` | `None` — not a frame |
///
/// A leading `frame N: ` is stripped and **not** trusted for ordering: the
/// causes are read in order, and `N` is redundant with position. Trusting it
/// would let a mis-numbered report reorder a backtrace.
///
/// Returns `None` for anything that is not a frame, so a caller can filter a
/// mixed causes list without mis-reporting ordinary context as a frame.
#[must_use]
pub fn parse_frame(cause: &str) -> Option<ReportedFrame> {
    let text = cause.trim();

    // Strip the `frame N: ` prefix when present. `split_once` on the first `: `
    // is safe here because the prefix is digits only; a function path containing
    // `: ` cannot be mistaken for it.
    let text = match text.split_once(": ") {
        Some((prefix, rest)) if prefix.starts_with("frame ") => {
            let n = &prefix["frame ".len()..];
            // Digits only: `frame x: ` is not a frame marker, it is prose.
            if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            rest.trim()
        }
        _ => text,
    };

    if text.is_empty() {
        return None;
    }

    // Form 1: `func (file:line)`. The location is the last parenthesised group;
    // a function name may itself contain parentheses (Rust closures render as
    // `foo::{{closure}}`), so the *last* `(` is the delimiter, not the first.
    if text.ends_with(')') {
        if let Some(open) = text.rfind(" (") {
            let func = text[..open].trim();
            let inner = &text[open + 2..text.len() - 1];
            if !func.is_empty() {
                if let Some((file, line)) = split_location(inner) {
                    return Some(ReportedFrame {
                        module: None,
                        func: func.to_owned(),
                        // The engine resolved this, so no offset is reported --
                        // and inventing one would be a guess.
                        offset: None,
                        file: Some(file),
                        line: Some(line),
                    });
                }
            }
        }
    }

    // Form 2: `func+0xoffset`.
    if let Some((func, offset)) = text.rsplit_once("+0x") {
        if let Ok(offset) = u64::from_str_radix(offset, 16) {
            let func = func.trim();
            if !func.is_empty() {
                return Some(ReportedFrame {
                    module: None,
                    func: func.to_owned(),
                    offset: Some(offset),
                    file: None,
                    line: None,
                });
            }
        }
    }

    // Form 3: a bare function name.
    //
    // **Refused rather than accepted**, and this is the interesting case. A bare
    // name has no offset, so it cannot be resolved -- but it would also be
    // indistinguishable from ordinary context text, and accepting it would mean
    // every non-frame cause becomes a fake frame. The cost is that a real frame
    // with neither location nor offset is dropped; that frame carried no
    // information the report did not already have in its `detail` field.
    None
}

/// Split `file:line` (or `file:line:col`) from the inside of a `(...)` group.
///
/// Returns `None` when the text has no line number, because a file without a
/// line is not a location this crate is willing to report as one.
fn split_location(inner: &str) -> Option<(String, u32)> {
    let text = inner.trim();
    // Windows paths contain `C:\...`, so a naive split on the first `:` breaks.
    // The line is the final colon-separated field, and it must be numeric.
    let (head, tail) = text.rsplit_once(':')?;
    let tail = tail.trim();

    // `file:line:col` -- the column is the tail, and the line precedes it.
    if let Ok(maybe_col) = tail.parse::<u32>() {
        // Ambiguous only in that both fields are numeric; DWARF columns are
        // optional, so accept the reading that yields a valid line either way.
        if let Some((file, line)) = head.rsplit_once(':') {
            let line_trimmed = line.trim();
            if let Ok(line_num) = line_trimmed.parse::<u32>() {
                // Prefer `file:line:col` only when the file part is non-empty and
                // does not end in a bare drive letter.
                let file = file.trim();
                if !file.is_empty() && !file.ends_with(':') {
                    return Some((file.to_owned(), line_num));
                }
            }
        }
        // Fall through to `file:line` with `tail` as the line.
        let file = head.trim();
        if !file.is_empty() {
            return Some((file.to_owned(), maybe_col));
        }
        return None;
    }

    None
}

/// Pull every frame out of an error's rendered causes.
///
/// `qqq_host::Trap::to_error` attaches each frame as its own cause, so the
/// frames are the causes this recognises and everything else is skipped.
///
/// Reads the public `cause` field rather than a method: `qqq_core::Error` exposes
/// its parts, and an accessor would be a second name for the same thing.
#[must_use]
pub fn frames_from_error(err: &Error) -> Vec<ReportedFrame> {
    err.cause.iter().filter_map(|c| parse_frame(c)).collect()
}

/// Resolve an error's trap frames against a source map.
///
/// This is the whole `HOST-009` detached path in one call: take the error that
/// crossed a process boundary, take the map extracted from the artifact, and get
/// back frames a developer can open in an editor.
///
/// A map may be empty — a project built without `debug = true` — and the result
/// then reports every frame as unmapped rather than failing. That is the correct
/// outcome: the trap is still worth reporting, only the source lines are absent.
#[must_use]
pub fn resolve_error(err: &Error, map: &SourceMap) -> ResolvedBacktrace {
    let frames = frames_from_error(err);
    let (frames, report) = resolve_frames(&frames, map);
    let explanation = report.explain();
    ResolvedBacktrace {
        frames,
        report,
        explanation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_core::{Error, ErrorCode};
    use qqq_debug::source_map::LineEntry;
    use qqq_debug::{FrameLocation, SourceMap};

    fn entry(address: u64, file: &str, line: u32) -> LineEntry {
        LineEntry {
            address,
            location: FrameLocation {
                file: file.to_owned(),
                line,
                column: None,
            },
        }
    }

    fn map() -> SourceMap {
        SourceMap::from_entries(vec![
            entry(0x0000, "src/main.rs", 10),
            entry(0x0100, "src/handler.rs", 42),
        ])
    }

    // -- parsing, form by form ----------------------------------------------

    #[test]
    fn a_resolved_frame_is_parsed_with_its_location() {
        let f = parse_frame("frame 0: handle (src/handler.rs:42)").expect("parse");
        assert_eq!(f.func, "handle");
        assert_eq!(f.file.as_deref(), Some("src/handler.rs"));
        assert_eq!(f.line, Some(42));
        // No offset: the engine resolved this one, and inventing an offset would
        // be a guess that a later pass might act on.
        assert_eq!(f.offset, None);
        assert!(f.is_resolved());
    }

    #[test]
    fn an_unresolved_frame_keeps_its_offset() {
        let f = parse_frame("frame 1: spin+0x1a3").expect("parse");
        assert_eq!(f.func, "spin");
        assert_eq!(f.offset, Some(0x1a3));
        assert_eq!(f.file, None);
        assert!(!f.is_resolved());
    }

    #[test]
    fn a_frame_without_the_number_prefix_parses_too() {
        // `Trap::render` writes frames without `frame N: `, so both forms occur.
        let f = parse_frame("spin+0x1a3").expect("parse");
        assert_eq!(f.func, "spin");
        assert_eq!(f.offset, Some(0x1a3));
    }

    #[test]
    fn a_bare_name_is_not_treated_as_a_frame() {
        // The deliberate refusal: accepting bare names would turn every ordinary
        // cause into a fake frame.
        assert_eq!(parse_frame("frame 2: main"), None);
        assert_eq!(parse_frame("some other context"), None);
        assert_eq!(parse_frame(""), None);
        assert_eq!(parse_frame("   "), None);
    }

    #[test]
    fn a_non_numeric_frame_prefix_is_prose_not_a_marker() {
        assert_eq!(parse_frame("frame x: spin+0x1a3"), None);
        assert_eq!(parse_frame("frame : spin+0x1a3"), None);
    }

    // -- parsing, the awkward shapes ----------------------------------------

    #[test]
    fn a_function_name_containing_parentheses_keeps_them() {
        // Rust renders closures as `{{closure}}`; a first-`(` split would
        // truncate the name to `foo::` and lose it.
        let f = parse_frame("frame 0: foo::{{closure}} (src/a.rs:7)").expect("parse");
        assert_eq!(f.func, "foo::{{closure}}");
        assert_eq!(f.file.as_deref(), Some("src/a.rs"));
        assert_eq!(f.line, Some(7));
    }

    #[test]
    fn a_windows_path_survives_the_colon_split() {
        // `C:\src\a.rs:42` has two colons, and a first-colon split yields
        // `C` as the file -- a path no editor opens.
        let f = parse_frame("frame 0: handle (C:\\src\\a.rs:42)").expect("parse");
        assert_eq!(f.file.as_deref(), Some("C:\\src\\a.rs"));
        assert_eq!(f.line, Some(42));
    }

    #[test]
    fn a_column_is_dropped_but_the_line_is_kept() {
        // `ReportedFrame` has no column field, and the line must not be lost
        // just because a column was present.
        let f = parse_frame("frame 0: handle (src/a.rs:42:9)").expect("parse");
        assert_eq!(f.file.as_deref(), Some("src/a.rs"));
        assert_eq!(f.line, Some(42));
    }

    #[test]
    fn a_parenthesised_group_that_is_not_a_location_is_refused() {
        // `(inlined)` is not a location, and reporting the whole group as a file
        // would send a reader to a path that does not exist.
        assert_eq!(parse_frame("frame 0: handle (inlined)"), None);
    }

    #[test]
    fn a_malformed_offset_is_refused() {
        // Not hexadecimal: must not become offset 0 by a lenient parse, since
        // offset 0 resolves to the first line of the program and would report a
        // confident wrong location.
        assert_eq!(parse_frame("frame 0: spin+0xZZZ"), None);
        assert_eq!(parse_frame("frame 0: spin+0x"), None);
    }

    // -- the whole detached path --------------------------------------------

    #[test]
    fn an_error_with_unresolved_frames_resolves_against_a_map() {
        let err = Error::new(ErrorCode::GuestTrap, "the guest trapped")
            .with_cause("frame 0: handle+0x150")
            .with_cause("frame 1: main+0x10")
            .with_cause("trap-detail: unreachable");

        let resolved = resolve_error(&err, &map());
        assert_eq!(resolved.frames.len(), 2, "the detail line is not a frame");
        assert_eq!(resolved.frames[0].file.as_deref(), Some("src/handler.rs"));
        assert_eq!(resolved.frames[0].line, Some(42));
        assert_eq!(resolved.frames[1].file.as_deref(), Some("src/main.rs"));
        assert_eq!(resolved.report.resolved, 2);
        assert!(resolved.report.fully_resolved());
    }

    #[test]
    fn an_empty_map_reports_gaps_rather_than_inventing_locations() {
        let err = Error::new(ErrorCode::GuestTrap, "trapped").with_cause("frame 0: handle+0x150");
        let resolved = resolve_error(&err, &SourceMap::empty());
        assert_eq!(resolved.frames[0].file, None, "no map, no location");
        assert_eq!(resolved.report.unmapped, 1);
        assert!(resolved.explanation.contains("without debug info"));
    }

    /// An error that is not a trap has no frames, and that must be reported as
    /// "no backtrace" rather than as a resolution failure.
    #[test]
    fn an_error_with_no_frames_explains_itself() {
        let err = Error::new(ErrorCode::CapabilityDenied, "no");
        let resolved = resolve_error(&err, &map());
        assert!(resolved.is_empty());
        assert_eq!(resolved.explanation, "the trap carried no backtrace frames");
    }

    #[test]
    fn already_resolved_frames_are_not_re_resolved() {
        let err = Error::new(ErrorCode::GuestTrap, "trapped")
            .with_cause("frame 0: handle (engine/resolved.rs:7)");
        let resolved = resolve_error(&err, &map());
        assert_eq!(
            resolved.frames[0].file.as_deref(),
            Some("engine/resolved.rs")
        );
        assert_eq!(resolved.frames[0].line, Some(7));
        assert_eq!(resolved.report.already_resolved, 1);
        assert_eq!(resolved.report.resolved, 0);
    }

    // -- rendering -----------------------------------------------------------

    #[test]
    fn rendering_shows_the_resolved_location() {
        let err = Error::new(ErrorCode::GuestTrap, "trapped").with_cause("frame 0: handle+0x150");
        let resolved = resolve_error(&err, &map());
        let text = resolved.render();
        assert!(text.contains("handle (src/handler.rs:42)"), "{text}");
        assert!(
            !text.contains("+0x150"),
            "the offset is replaced by a line: {text}"
        );
    }

    // -- serde ---------------------------------------------------------------

    #[test]
    fn a_resolved_backtrace_serializes_for_json_output() {
        let err = Error::new(ErrorCode::GuestTrap, "trapped").with_cause("frame 0: handle+0x150");
        let resolved = resolve_error(&err, &map());
        let v = serde_json::to_value(&resolved).expect("serialize");
        assert_eq!(v["frames"][0]["func"], "handle");
        assert_eq!(v["frames"][0]["file"], "src/handler.rs");
        assert_eq!(v["frames"][0]["line"], 42);
        assert_eq!(v["report"]["resolved"], 1);
        assert!(v["explanation"].is_string());
    }
}
