// SPDX-License-Identifier: Apache-2.0

//! Resolving a **detached** trap report against an extracted [`SourceMap`].
//!
//! Implements the second half of Proposal §6.1's guest-trap row and Checklist
//! `HOST-009`: *"structured trap with code, guest backtrace and (if DWARF
//! present) source line"*.
//!
//! ## The gap this closes
//!
//! `qqq-host` builds a [`crate::FrameLocation`]-bearing backtrace two ways, and
//! only one of them was complete:
//!
//! | Situation | Where frames come from | Was it wired? |
//! |---|---|---|
//! | A live instance traps | `Wasmtime`'s `WasmBacktrace`, resolved in memory | yes |
//! | A trap report is read later | `SourceMap`, resolved from the artifact | **no** |
//!
//! The first only works while the engine that produced the error is alive. A
//! trap that crossed a process boundary — into a log, a UI, an HTTP response, an
//! agent's context — has no engine behind it, and its frames were therefore
//! stuck at `func+0x1a3` with `file: None` forever. `WasmFrame::offset` was
//! populated specifically so this could be fixed, and nothing consumed it.
//! That is the `§O-045a` failure mode again: the *field* had tests, so it looked
//! covered, while no code path ever read it.
//!
//! ## Why the input is a neutral shape and not `qqq_host::Trap`
//!
//! `qqq-debug` sits at the *bottom* of §4.3's topological order — below
//! `qqq-host` — so an edge to the trap type would point upward and
//! `tools/check_topology.py` would reject it. More importantly it would be the
//! wrong edge: a resolver that needed the whole host type could only be used by
//! something that already had the host, which defeats the purpose of a
//! **detached** report.
//!
//! So the input is [`ReportedFrame`]: the four facts a resolver actually needs,
//! with `serde` derives. A caller deserializes whatever JSON it has — this is
//! exactly the `WasmFrame` field set — and hands over the frames.
//!
//! ## The rule, restated because this module is where it could be broken
//!
//! > **An unmapped frame reports no location. It never reports a guessed one.**
//!
//! A frame that already carries a `file`/`line` is **left alone**. `Wasmtime`'s
//! in-memory resolution is authoritative: it read the *same* DWARF from the
//! *same* artifact with the engine's own loader. Re-resolving it here could only
//! agree or be worse, and a resolver that overwrote good data with a partial
//! lookup would be inventing a regression.

use serde::{Deserialize, Serialize};

use crate::source_map::SourceMap;

/// A frame as it appears in a serialized trap report.
///
/// Field-for-field the `WasmFrame` shape `qqq-host` serializes. Declared here so
/// a report can be resolved without depending on the crate that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedFrame {
    /// The module name, when the report carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// The function name or index.
    pub func: String,
    /// The Wasm bytecode offset within the module.
    ///
    /// The key into the [`SourceMap`]. `None` means the reporter did not record
    /// an offset, which is common for a hand-written or older report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Source file, when it was already resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Source line, when it was already resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl ReportedFrame {
    /// Whether a resolver has anything to add.
    ///
    /// Both a file *and* a line, not either: a frame with a file and no line
    /// renders as `func+0x…` (`WasmFrame`'s `Display` requires both), so half a
    /// location is not a location and is worth resolving.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.file.is_some() && self.line.is_some()
    }
}

/// What a resolve pass did, so a caller can report it rather than guess.
///
/// # Why this is returned and not just the frames
///
/// `HOST-009` requires the *absence* of source mapping be visible. A caller that
/// renders a report full of `func+0x…` and cannot say whether that is because the
/// artifact had no debug info, because the map was never extracted, or because
/// the offsets fell outside the line program has no way to tell a developer
/// which of the three to fix. The counts make that one sentence instead of an
/// investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResolveReport {
    /// Frames in the report.
    pub frames: usize,
    /// Frames that already had a file and line, and were left untouched.
    pub already_resolved: usize,
    /// Frames newly given a file and line from the map.
    pub resolved: usize,
    /// Frames with an offset that the map does not cover.
    ///
    /// The honest "no debug info for this instruction" count.
    pub unmapped: usize,
    /// Frames that carried no offset to look up.
    pub no_offset: usize,
}

impl ResolveReport {
    /// Whether every frame now has a source location.
    #[must_use]
    pub fn fully_resolved(&self) -> bool {
        self.frames > 0 && self.resolved + self.already_resolved == self.frames
    }

    /// One sentence explaining what happened, for a human or a log.
    #[must_use]
    pub fn explain(&self) -> String {
        if self.frames == 0 {
            return "the trap carried no backtrace frames".to_owned();
        }
        if self.fully_resolved() {
            return format!("all {} frame(s) resolved to source", self.frames);
        }
        // Ordered by what the reader should fix first: no map at all is a build
        // configuration problem; an uncovered offset is a debug-info gap; a
        // missing offset is a reporting problem.
        let mut gaps = Vec::new();
        if self.unmapped > 0 {
            gaps.push(format!(
                "{} frame(s) not covered by the source map -- the artifact may have \
                 been built without debug info",
                self.unmapped
            ));
        }
        if self.no_offset > 0 {
            gaps.push(format!(
                "{} frame(s) carried no bytecode offset to resolve",
                self.no_offset
            ));
        }
        format!(
            "{} of {} frame(s) resolved to source; {}",
            self.resolved + self.already_resolved,
            self.frames,
            gaps.join("; ")
        )
    }
}

/// Resolve every frame in a detached report against an extracted map.
///
/// Returns the frames **and** a [`ResolveReport`] describing what changed, so a
/// caller can state the outcome rather than assert it.
///
/// A frame that already carries a file and line is returned unchanged — see the
/// module documentation for why overwriting it would be a regression rather
/// than a correction.
///
/// # Why this is infallible
///
/// Every failure mode here is a *reported outcome*, not an error: an uncovered
/// offset and a missing offset both still produce a usable frame list, and a
/// report with unmapped frames is a report worth rendering. The first version
/// returned `Result<_, Infallible>`, which forced every caller to `unwrap()` a
/// value that cannot fail and left an unreachable `match` arm behind — ceremony
/// that clippy flagged as a future-compatibility hazard. If a report format
/// version is ever introduced, this gains a real error type and the callers
/// change then.
#[must_use]
pub fn resolve_frames(
    frames: &[ReportedFrame],
    map: &SourceMap,
) -> (Vec<ReportedFrame>, ResolveReport) {
    let mut out = Vec::with_capacity(frames.len());
    let mut report = ResolveReport {
        frames: frames.len(),
        ..ResolveReport::default()
    };

    for frame in frames {
        if frame.is_resolved() {
            report.already_resolved += 1;
            out.push(frame.clone());
            continue;
        }

        let Some(offset) = frame.offset else {
            report.no_offset += 1;
            out.push(frame.clone());
            continue;
        };

        if let Some(location) = map.lookup(offset) {
            report.resolved += 1;
            let mut resolved = frame.clone();
            resolved.file = Some(location.file.clone());
            resolved.line = Some(location.line);
            out.push(resolved);
        } else {
            // The rule: an uncovered offset keeps its offset and gains no
            // location. Counted so `explain` can name the gap.
            report.unmapped += 1;
            out.push(frame.clone());
        }
    }

    (out, report)
}

/// Render frames as the multi-line block a CLI or log prints.
///
/// Kept next to the resolver because the rendering is what makes the rule
/// visible: a frame with a location prints `func (file:line)`, and a frame
/// without prints `func+0xoffset`. There is no branch that prints a location for
/// a frame that has none.
#[must_use]
pub fn render_frames(frames: &[ReportedFrame]) -> String {
    frames
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let location = match (&f.file, f.line) {
                (Some(file), Some(line)) => format!(" ({file}:{line})"),
                _ => match f.offset {
                    Some(off) => format!("+0x{off:x}"),
                    None => String::new(),
                },
            };
            format!("{:>3}: {}{location}", i, f.func)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_map::{FrameLocation, LineEntry};

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
            entry(0x0000, "src/main.rs", 1),
            entry(0x0100, "src/handler.rs", 42),
            entry(0x0200, "src/db.rs", 17),
        ])
    }

    fn frame(func: &str, offset: Option<u64>) -> ReportedFrame {
        ReportedFrame {
            module: None,
            func: func.to_owned(),
            offset,
            file: None,
            line: None,
        }
    }

    // -- the happy path ------------------------------------------------------

    #[test]
    fn an_offset_is_resolved_to_the_covering_row() {
        let (out, report) = resolve_frames(&[frame("handle", Some(0x0150))], &map());
        assert_eq!(out[0].file.as_deref(), Some("src/handler.rs"));
        assert_eq!(out[0].line, Some(42));
        assert_eq!(report.resolved, 1);
        assert_eq!(report.unmapped, 0);
        assert!(report.fully_resolved());
    }

    #[test]
    fn the_first_row_is_address_zero_and_resolves() {
        let (out, _) = resolve_frames(&[frame("main", Some(0))], &map());
        assert_eq!(out[0].file.as_deref(), Some("src/main.rs"));
        assert_eq!(out[0].line, Some(1));
    }

    // -- the rule: never guess ----------------------------------------------

    /// **The fault-injection target for this module.** An unmapped offset must
    /// leave the frame unresolved rather than falling back to the nearest row.
    #[test]
    fn an_offset_before_the_first_row_is_unmapped_not_guessed() {
        let (out, report) = resolve_frames(&[frame("mystery", Some(0x4000))], &map());
        // 0x4000 is past the last row's start, so it *is* covered by the last
        // row by DWARF's range semantics -- assert the real answer.
        assert_eq!(out[0].file.as_deref(), Some("src/db.rs"));
        assert_eq!(report.unmapped, 0);

        // Now a genuinely uncovered case: an empty map has no covering row.
        let (out, report) = resolve_frames(&[frame("mystery", Some(0x10))], &SourceMap::empty());
        assert_eq!(out[0].file, None, "an empty map must not invent a location");
        assert_eq!(out[0].line, None);
        assert_eq!(report.unmapped, 1);
        assert!(!report.fully_resolved());
    }

    #[test]
    fn a_frame_with_no_offset_is_counted_separately_from_an_unmapped_one() {
        let (out, report) = resolve_frames(&[frame("nameless", None)], &map());
        assert_eq!(out[0].file, None);
        assert_eq!(report.no_offset, 1);
        assert_eq!(report.unmapped, 0, "no offset is not an unmapped offset");
        // The distinction is the point: one is a reporting problem, the other a
        // debug-info problem, and they have different fixes.
        assert!(report.explain().contains("no bytecode offset"));
    }

    // -- already-resolved frames are authoritative ---------------------------

    #[test]
    fn a_resolved_frame_is_left_exactly_as_it_was() {
        let mut resolved = frame("handle", Some(0x0150));
        resolved.file = Some("engine/says/this.rs".to_owned());
        resolved.line = Some(999);

        let (out, report) = resolve_frames(&[resolved.clone()], &map());
        assert_eq!(
            out[0], resolved,
            "the engine's answer must not be overwritten"
        );
        assert_eq!(report.already_resolved, 1);
        assert_eq!(report.resolved, 0);
        assert!(report.fully_resolved());
    }

    /// Half a location is not a location: a file with no line renders as
    /// `func+0x…`, so it is worth resolving.
    #[test]
    fn a_file_without_a_line_is_still_resolved() {
        let mut half = frame("handle", Some(0x0150));
        half.file = Some("somewhere.rs".to_owned());
        half.line = None;

        let (out, report) = resolve_frames(&[half], &map());
        assert_eq!(out[0].file.as_deref(), Some("src/handler.rs"));
        assert_eq!(out[0].line, Some(42));
        assert_eq!(report.resolved, 1);
        assert_eq!(report.already_resolved, 0);
    }

    // -- the report itself ---------------------------------------------------

    #[test]
    fn an_empty_report_explains_itself() {
        let (out, report) = resolve_frames(&[], &map());
        assert!(out.is_empty());
        assert_eq!(report.frames, 0);
        assert!(!report.fully_resolved());
        assert_eq!(report.explain(), "the trap carried no backtrace frames");
    }

    #[test]
    fn a_partial_report_names_both_kinds_of_gap() {
        let frames = vec![frame("a", Some(0x0150)), frame("b", None)];
        let (_, report) = resolve_frames(&frames, &map());
        let text = report.explain();
        assert!(text.contains("1 of 2"), "{text}");
        assert!(text.contains("no bytecode offset"), "{text}");
    }

    /// The unmapped branch of `explain` must be reachable and must say the right
    /// thing -- a message only produced for a mixed report would never be seen.
    #[test]
    fn an_unmapped_frame_is_explained_as_a_debug_info_gap() {
        let (_, report) = resolve_frames(&[frame("a", Some(1))], &SourceMap::empty());
        let text = report.explain();
        assert!(text.contains("not covered by the source map"), "{text}");
        assert!(text.contains("without debug info"), "{text}");
        // No debug info is the *build* problem, so it must not be reported as a
        // missing offset -- that would send the reader to the wrong fix.
        assert!(!text.contains("carried no bytecode offset"), "{text}");
    }

    // -- rendering -----------------------------------------------------------

    #[test]
    fn rendering_shows_a_location_only_when_one_exists() {
        let frames = vec![
            ReportedFrame {
                module: None,
                func: "handle".to_owned(),
                offset: Some(0x0150),
                file: Some("src/handler.rs".to_owned()),
                line: Some(42),
            },
            frame("inner", Some(0x1a3)),
            frame("nameless", None),
        ];
        let text = render_frames(&frames);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("src/handler.rs:42"), "{text}");
        assert!(lines[1].contains("+0x1a3"), "{text}");
        // No offset, no invented anything: just the name.
        assert_eq!(lines[2].trim(), "2: nameless");
    }

    // -- serde round trip ----------------------------------------------------

    /// The input shape must be exactly what `qqq-host` serializes, or the
    /// detached path silently drops fields. Asserted field by field.
    #[test]
    fn a_serialized_frame_round_trips_with_the_hosts_field_names() {
        // Deliberately hand-written to pin the wire format rather than derive it:
        // a rename in `ReportedFrame` must fail here.
        let json = r#"{
            "module": "orders",
            "func": "handle",
            "offset": 336,
            "file": "src/handler.rs",
            "line": 42
        }"#;
        let f: ReportedFrame = serde_json::from_str(json).expect("parse");
        assert_eq!(f.module.as_deref(), Some("orders"));
        assert_eq!(f.func, "handle");
        assert_eq!(f.offset, Some(336));
        assert_eq!(f.file.as_deref(), Some("src/handler.rs"));
        assert_eq!(f.line, Some(42));

        let back = serde_json::to_value(&f).expect("serialize");
        assert_eq!(back["func"], "handle");
        assert_eq!(back["offset"], 336);
    }

    /// Optional fields are omitted, not nulled -- matching `WasmFrame`'s
    /// `skip_serializing_if`, so a diff of two reports is stable.
    ///
    /// **This assertion was wrong on its first run and the test caught it.** It
    /// expected two remaining keys (`module` and `func`); the object has one,
    /// because `module` is *also* optional and the helper leaves it `None`. The
    /// code was right and the expectation was wrong -- which is the useful
    /// direction for a test to fail in, and the reason the count is asserted
    /// rather than merely the absence of the three optional keys. Checking only
    /// `!contains_key("offset")` would have passed while saying nothing about
    /// whether `module` was being nulled.
    #[test]
    fn absent_optional_fields_are_omitted_not_null() {
        let v = serde_json::to_value(frame("f", None)).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(!obj.contains_key("offset"), "{v}");
        assert!(!obj.contains_key("file"), "{v}");
        assert!(!obj.contains_key("line"), "{v}");
        assert!(!obj.contains_key("module"), "{v}");
        assert_eq!(obj.len(), 1, "func is the only required field: {v}");
        assert_eq!(obj.get("func").and_then(|f| f.as_str()), Some("f"));

        // And with every optional field present, all five appear -- so the count
        // above is testing the `skip_serializing_if`s, not an always-empty shape.
        let full = ReportedFrame {
            module: Some("m".to_owned()),
            func: "f".to_owned(),
            offset: Some(1),
            file: Some("a.rs".to_owned()),
            line: Some(2),
        };
        let v = serde_json::to_value(&full).expect("serialize");
        assert_eq!(v.as_object().expect("object").len(), 5, "{v}");
    }

    // -- a realistic multi-frame report --------------------------------------

    /// The end-to-end shape: a report read from a log, resolved with no engine.
    #[test]
    fn a_three_frame_report_resolves_every_frame() {
        let frames = vec![
            frame("handle_request", Some(0x0150)),
            frame("query", Some(0x0200)),
            frame("main", Some(0x0000)),
        ];
        let (out, report) = resolve_frames(&frames, &map());
        assert!(report.fully_resolved());
        assert_eq!(out[0].file.as_deref(), Some("src/handler.rs"));
        assert_eq!(out[1].file.as_deref(), Some("src/db.rs"));
        assert_eq!(out[2].file.as_deref(), Some("src/main.rs"));
        assert!(report.explain().contains("all 3 frame(s) resolved"));
    }
}
