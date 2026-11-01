// SPDX-License-Identifier: Apache-2.0

//! The source map: a sorted table from Wasm bytecode offset to source location.
//!
//! # Why a flat sorted table and not the DWARF tree
//!
//! A DWARF line program is a state machine whose output is a *sequence* of
//! (address, file, line, column) rows. Resolving an address is a binary search
//! over those rows, not a tree walk — so the tree is discarded once the rows are
//! extracted, and what remains is small enough to serialise, ship and diff.
//!
//! That matters because the map is a **product**: it travels with a trap report
//! to a log or an agent, and it may be extracted on one machine and consulted on
//! another. Keeping the DWARF would mean shipping the artifact.

use serde::{Deserialize, Deserializer, Serialize};

/// A resolved source location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrameLocation {
    /// The source file, as DWARF recorded it.
    ///
    /// **Not** joined to any root or made absolute. DWARF stores the path the
    /// compiler was given, which for a Cargo build is relative to the workspace
    /// root; rewriting it here would guess at a filesystem the reader may not
    /// share.
    pub file: String,
    /// The line number, 1-based. Zero is rejected at the boundary: DWARF line
    /// 0 means "unknown", and there is no unknown to represent here.
    pub line: u32,
    /// The column, when DWARF carries one.
    ///
    /// `None` rather than `0` when absent: a column of `0` is a valid-looking
    /// number that no editor accepts, and sources differ on whether the
    /// line program emits columns at all. Serialization agrees: a `Some(0)`
    /// is skipped exactly like `None`, so JSON never contains a `"column":0`
    /// that deserialization would normalize away.
    #[serde(default, skip_serializing_if = "column_is_absent")]
    pub column: Option<u32>,
}

/// Whether a column carries information: absent, or DWARF's `0` ("no column",
/// normalized to absent on the way in — see `FrameLocation`).
///
/// The signature is serde's, not a choice: `skip_serializing_if` passes the
/// field by reference, and `Option<u32>` is trivially copyable — hence the
/// two allows below, each-capable lints that cannot apply to a serde hook.
#[allow(
    clippy::ref_option,
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hook takes &Option<u32>"
)]
fn column_is_absent(column: &Option<u32>) -> bool {
    column.is_none_or(|c| c == 0)
}

impl<'de> Deserialize<'de> for FrameLocation {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            file: String,
            line: u32,
            #[serde(default)]
            column: Option<u32>,
        }
        let raw = Raw::deserialize(d)?;
        // DWARF line 0 means "unknown location". There is no unknown location
        // in this type, so a zero line is malformed input, not a defaultable
        // field — fail loudly at the trust boundary (a hand-written or
        // corrupted report) rather than rendering `file:0` as a real answer.
        if raw.line == 0 {
            return Err(serde::de::Error::custom(
                "FrameLocation.line must be >= 1 (DWARF line 0 means unknown)",
            ));
        }
        // An empty or whitespace-only path renders as `:42` — a location
        // shaped like an answer with no content. Reject it the way line 0 is
        // rejected: loudly, at the trust boundary. (A real file could in
        // theory be named `" "`, but DWARF resolving to it is absurd, and
        // denying is the safe direction.)
        if raw.file.trim().is_empty() {
            return Err(serde::de::Error::custom(
                "FrameLocation.file must not be empty",
            ));
        }
        // Column 0 is DWARF's "no column", same as a missing one.
        Ok(Self {
            file: raw.file,
            line: raw.line,
            column: raw.column.filter(|&c| c != 0),
        })
    }
}

impl std::fmt::Display for FrameLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.column {
            Some(c) => write!(f, "{}:{}:{}", self.file, self.line, c),
            None => write!(f, "{}:{}", self.file, self.line),
        }
    }
}

/// One row of the line program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineEntry {
    /// The Wasm bytecode offset this row begins at.
    pub address: u64,
    /// Where it maps to.
    pub location: FrameLocation,
}

/// One DWARF line-program sequence: a contiguous covered range.
///
/// A sequence starts at its first row's address and ends at the
/// `end_sequence` marker's address (exclusive). Rows from different sequences
/// may leave gaps — padding between functions, disjoint compilation units —
/// and an offset in such a gap belongs to no row. `SourceMap` records these
/// so `lookup` can deny gap offsets instead of attributing them to the
/// preceding row. Kept crate-private: construction goes through
/// `SourceMap::with_sequences`, which sorts them, and serialization stays a
/// plain pair.
///
/// Ranges from different compilation units may overlap (measured on a real
/// `wasm32-wasip2` build, whose units interleave). The lookup rule accounts
/// for that — see `lookup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct Sequence {
    start: u64,
    end: u64,
}

/// The offset-to-source table for one artifact.
///
/// `Debug` is implemented by hand below: a real artifact's map is thousands of
/// rows, and deriving it makes a failing assertion print all of them.
#[derive(Clone, PartialEq, Eq, Default, Serialize)]
pub struct SourceMap {
    /// The rows, **sorted by address** and with duplicates removed.
    ///
    /// Sorted because lookup is a binary search and because a `--json` diff of
    /// two runs must be byte-identical; DWARF's emission order is not guaranteed
    /// to be ascending across compilation units. The invariant is enforced by
    /// construction (`from_entries`) *and* by deserialization (hand-written
    /// below, routing through `from_entries`) — a shuffled or duplicate-laden
    /// JSON document cannot produce an unsorted table that would make
    /// `partition_point` return the wrong row.
    entries: Vec<LineEntry>,
    /// One past the highest address any row covers, when the extractor saw an
    /// end-of-sequence marker. Offsets at or past this bound are outside every
    /// range the line program described, so resolving them to the last row
    /// would be a guess. `None` when no end marker was observed (e.g. a
    /// hand-built map), in which case `lookup` keeps its range semantics.
    ///
    /// Skipped in JSON when absent, so a map written before bounds existed
    /// serializes exactly as before — and an old reader (without this field)
    /// still parses a new boundless document.
    #[serde(skip_serializing_if = "Option::is_none")]
    upper_bound: Option<u64>,
    /// The line program's sequences, sorted by start, disjoint.
    ///
    /// Empty for hand-built maps, which keep pure range semantics. Skipped in
    /// JSON when empty, so boundless maps serialize exactly as before.
    /// Forward-compatible by construction: a reader that predates this field
    /// ignores it (serde skips unknown fields) and keeps range semantics —
    /// a new document never breaks an old reader, it only resolves less.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sequences: Vec<Sequence>,
}

impl<'de> Deserialize<'de> for SourceMap {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            entries: Vec<LineEntry>,
            #[serde(default)]
            upper_bound: Option<u64>,
            #[serde(default)]
            sequences: Vec<Sequence>,
        }
        let raw = Raw::deserialize(d)?;
        let mut map = Self::from_entries(raw.entries);
        if let Some(upper) = raw.upper_bound {
            map = map.with_upper_bound(upper);
        }
        // Untrusted input: sort and dedup, but do not otherwise validate. A
        // gappy or overlapping document still deserializes; `lookup` treats
        // an offset as covered only while some covering range extends past
        // it, so the worst a hostile document does is deny more. Unstable:
        // pairs are plain data, and no equal-pair ordering survives the
        // dedup below.
        let mut sequences = raw.sequences;
        sequences.sort_unstable();
        sequences.dedup();
        // Derive the bound exactly as construction does: the document's own
        // `upper_bound` may predate (or understate) its sequences, and the
        // constructed and deserialized forms must agree.
        if let Some(tail) = sequences.iter().map(|s| s.end).max() {
            map.upper_bound = Some(map.upper_bound.map_or(tail, |b| b.max(tail)));
        }
        map.sequences = sequences;
        Ok(map)
    }
}

impl SourceMap {
    /// An empty map — the result of extracting from an artifact with no DWARF.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            upper_bound: None,
            sequences: Vec::new(),
        }
    }

    /// Build from unsorted rows.
    ///
    /// Sorts and deduplicates. A duplicate address keeps the **last** row
    /// supplied for that address: in a DWARF line program each row is the
    /// state starting at its address, so of two rows sharing one address the
    /// first covers an empty range and the second is the mapping in force.
    /// Keeping the first would attribute the address to a range of length
    /// zero — a confident-wrong location for code the compiler did emit rows
    /// for. (`BTreeMap` insertion both sorts by address and overwrites, so
    /// the last row wins and the table stays sorted either way.)
    #[must_use]
    pub fn from_entries(entries: Vec<LineEntry>) -> Self {
        let mut by_address = std::collections::BTreeMap::new();
        for e in entries {
            by_address.insert(e.address, e.location);
        }
        let entries = by_address
            .into_iter()
            .map(|(address, location)| LineEntry { address, location })
            .collect();
        Self {
            entries,
            upper_bound: None,
            sequences: Vec::new(),
        }
    }

    /// How many rows the map holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The rows, in address order.
    #[must_use]
    pub fn entries(&self) -> &[LineEntry] {
        &self.entries
    }

    /// One past the highest address any row covers, if an end-of-sequence
    /// marker was observed during extraction. `None` means unbounded: the map
    /// was built without end information (e.g. by hand), and `lookup` keeps
    /// its range semantics instead of guessing a bound.
    ///
    /// ```
    /// # use qqq_debug::source_map::{FrameLocation, LineEntry, SourceMap};
    /// # let map = SourceMap::from_entries(vec![LineEntry {
    /// #     address: 0,
    /// #     location: FrameLocation { file: "a.rs".into(), line: 1, column: None },
    /// # }]);
    /// assert_eq!(map.upper_bound(), None);
    /// assert_eq!(map.with_upper_bound(0x40).upper_bound(), Some(0x40));
    /// ```
    #[must_use]
    pub fn upper_bound(&self) -> Option<u64> {
        self.upper_bound
    }

    /// Attach the exclusive upper bound of the covered range.
    ///
    /// The bound is the largest end-of-sequence address the extractor saw:
    /// every row's range ends at the next row's start or at this bound, so an
    /// offset at or past it is outside the artifact and must not resolve.
    ///
    /// Over-narrowing is the safe direction: a bound below some rows only
    /// denies more, and a caller may intend exactly that (narrowing the
    /// resolvable prefix of a hand-built map). No validation is performed
    /// for the same reason: every exclusive bound is a coherent
    /// configuration, so an assertion could only reject valid uses — the
    /// exclusivity is pinned by tests instead (see the doctest and
    /// `past_the_recorded_bound_is_unmapped_not_guessed`).
    ///
    /// ```
    /// # use qqq_debug::source_map::{FrameLocation, LineEntry, SourceMap};
    /// # use qqq_debug::{ReportedFrame, resolve_frames};
    /// # let map = SourceMap::from_entries(vec![LineEntry {
    /// #     address: 0x10,
    /// #     location: FrameLocation { file: "a.rs".into(), line: 5, column: None },
    /// # }]).with_upper_bound(0x20);
    /// # let frame = ReportedFrame {
    /// #     module: None, func: "f".into(), offset: Some(0x20),
    /// #     file: None, line: None,
    /// # };
    /// // The bound is exclusive: `0x20` is outside, `0x1f` is inside.
    /// let (out, report) = resolve_frames(&[frame.clone()], &map);
    /// assert_eq!(out[0].file, None);
    /// let (out, _) = resolve_frames(&[ReportedFrame { offset: Some(0x1f), ..frame }], &map);
    /// assert_eq!(out[0].file.as_deref(), Some("a.rs"));
    /// ```
    #[must_use]
    pub fn with_upper_bound(mut self, upper_bound: u64) -> Self {
        self.upper_bound = Some(upper_bound);
        self
    }

    /// Attach the line program's sequences — the contiguous covered ranges.
    ///
    /// `lookup` treats an offset as covered only while some recorded sequence
    /// starting at or before the candidate row still extends past it, so an
    /// offset past every covering range denies instead of attributing to the
    /// preceding row. Ranges from different units may overlap; the rule takes
    /// the furthest covering tail, so overlap fails open toward legacy range
    /// semantics and only certain gaps deny. Maps without sequences
    /// (hand-built, or deserialized from a document that predates them) keep
    /// pure range semantics.
    ///
    /// The bound follows the data: the furthest sequence tail becomes the
    /// upper bound when it extends past any bound already set, so the scalar
    /// gate and the sequence gate cannot disagree about where the artifact
    /// ends.
    ///
    /// ```
    /// # use qqq_debug::source_map::{LineEntry, FrameLocation, SourceMap};
    /// # let map = SourceMap::from_entries(vec![
    /// #     LineEntry { address: 0x00, location: FrameLocation { file: "a.rs".into(), line: 1, column: None } },
    /// #     LineEntry { address: 0x20, location: FrameLocation { file: "b.rs".into(), line: 2, column: None } },
    /// # ]);
    /// let map = map.with_sequences(vec![(0x00, 0x10), (0x20, 0x30)]);
    /// assert_eq!(map.upper_bound(), Some(0x30));
    /// assert!(map.lookup(0x18).is_none());
    /// assert_eq!(map.lookup(0x28).unwrap().line, 2);
    /// ```
    #[must_use]
    pub fn with_sequences(mut self, sequences: Vec<(u64, u64)>) -> Self {
        let mut seqs: Vec<Sequence> = sequences
            .into_iter()
            .map(|(start, end)| Sequence { start, end })
            .collect();
        // Unstable: sequences are plain data, and no equal-range ordering
        // survives the dedup below.
        seqs.sort_unstable();
        seqs.dedup();
        // No disjointness assertion: ranges from different compilation units
        // overlap in real artifacts (measured). Sorting is the only invariant
        // `lookup` needs; overlap is handled by taking the furthest tail.
        // Duplicates collapse: identical ranges union idempotently.
        if let Some(tail) = seqs.iter().map(|s| s.end).max() {
            self.upper_bound = Some(self.upper_bound.map_or(tail, |b| b.max(tail)));
        }
        self.sequences = seqs;
        self
    }

    /// Resolve a Wasm bytecode offset to a source location.
    ///
    /// Returns the entry whose address range contains `offset` — that is, the
    /// last row whose `address` is `<= offset`, provided the offset is not
    /// past every covering line-program sequence. A line program describes
    /// ranges, not points, so the nearest preceding row is the correct answer
    /// rather than an approximation — but only while inside a range the
    /// program described. An offset past every sequence covering the
    /// candidate row (padding between functions, disjoint compilation units)
    /// belongs to no row and resolves to nothing, rather than to the
    /// preceding row's function.
    ///
    /// Ranges from different units may overlap; the rule takes the furthest
    /// covering tail, so overlap fails open toward range semantics. Maps that
    /// carry no sequence information (built by hand, or deserialized from a
    /// document that predates sequences) keep pure range semantics: any
    /// offset at or past a row resolves to it.
    ///
    /// Overlapping ranges fail open by design, and this is documented as the
    /// sole exception to the crate's "never guess" rule: without per-row
    /// sequence provenance either range may own the row, so coverage wins
    /// over denial. This is ambiguous DWARF, not absent DWARF — the map still
    /// denies what is certainly outside every covering range, and per-module
    /// maps (tracked when a stable module identity exists) would close even
    /// this. The extractor always
    /// records sequences, so the stricter gate applies exactly where the data
    /// supports it.
    ///
    /// `None` means **the offset is not covered by any row**, which is a real
    /// answer: an artifact built without debug info, or an offset inside a
    /// function the compiler emitted no rows for.
    ///
    /// # What `None` must never become
    ///
    /// A caller must not substitute the nearest entry it *can* find, or the
    /// first entry, or a placeholder path. An unmapped frame says "no debug
    /// info"; a guessed one says "the bug is here" and is wrong. See the crate
    /// documentation for why that distinction is load-bearing.
    #[must_use]
    pub fn lookup(&self, offset: u64) -> Option<&FrameLocation> {
        // The bound is part of the map: every consumer gets the gate, not
        // just `resolve_frames`. A map that records where its artifact ends
        // must not resolve past it through any path.
        if self.upper_bound.is_some_and(|bound| offset >= bound) {
            return None;
        }
        // `partition_point` gives the count of entries with address <= offset,
        // so the answer is the one before it. Written this way rather than with
        // a hand-rolled binary search because the off-by-one is the entire
        // difficulty and the standard library already got it right.
        //
        // Binary over rows, then a prefix scan over sequences (sorted by
        // start): sequence counts stay in the dozens per artifact, so the
        // scan is noise next to the search.
        let idx = self.entries.partition_point(|e| e.address <= offset);
        if idx == 0 {
            // Every row starts after this offset. An offset before the first
            // row is genuinely unmapped — DWARF's first row is often address 0,
            // but not always.
            return None;
        }
        let entry = self.entries.get(idx - 1)?;
        if self.sequences.is_empty() {
            // No sequence information: pure range semantics (hand-built maps).
            return Some(&entry.location);
        }
        // The furthest tail over sequences starting at or before the
        // candidate row. Sorted by start, so everything past the first
        // later-starting range is irrelevant. Deny only past *every*
        // covering range (a certain gap); overlapping ranges fail open
        // toward range semantics, because either range may own the row.
        let mut tail: Option<u64> = None;
        for seq in &self.sequences {
            if seq.start > entry.address {
                break;
            }
            tail = Some(tail.map_or(seq.end, |t: u64| t.max(seq.end)));
        }
        if tail.is_some_and(|end| offset >= end) {
            return None;
        }
        Some(&entry.location)
    }

    /// Resolve, and report whether the offset fell inside the last row's range.
    ///
    /// DWARF line programs end with a row marking the end of the sequence, so a
    /// plain `lookup` past the final instruction still finds the last row. That
    /// is correct for an address inside the covering range and misleading past
    /// it, and the difference matters when reporting an offset that was
    /// computed rather than observed.
    ///
    /// The bound is **exclusive**: an offset equal to `upper_bound` is already
    /// outside the covered range and resolves to nothing. Prefer
    /// [`SourceMap::upper_bound`] with a map built by the extractor, which
    /// records the bound from the line program's own end markers; use this
    /// explicit-bound form only when the caller computed a tighter limit.
    #[must_use]
    pub fn lookup_bounded(&self, offset: u64, upper_bound: u64) -> Option<&FrameLocation> {
        if offset >= upper_bound {
            return None;
        }
        self.lookup(offset)
    }
}

impl std::fmt::Debug for SourceMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Prints the shape, not the table: a map for a real artifact is
        // thousands of rows, and debug-printing them all is how a test failure
        // becomes unreadable.
        f.debug_struct("SourceMap")
            .field("entries", &self.entries.len())
            .field("upper_bound", &self.upper_bound)
            .field("sequences", &self.sequences.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            entry(0x00, "src/a.rs", 1),
            entry(0x10, "src/a.rs", 5),
            entry(0x20, "src/b.rs", 12),
        ])
    }

    #[test]
    fn an_empty_map_resolves_nothing() {
        let m = SourceMap::empty();
        assert!(m.is_empty());
        assert_eq!(m.lookup(0), None);
        assert_eq!(m.lookup(0x1000), None);
    }

    /// An exact address resolves to its own row.
    #[test]
    fn an_exact_address_resolves() {
        let m = map();
        assert_eq!(m.lookup(0x10).unwrap().file, "src/a.rs");
        assert_eq!(m.lookup(0x10).unwrap().line, 5);
    }

    /// An offset **between** rows resolves to the row that covers it.
    ///
    /// A line program describes ranges, so the row at the start of the range is
    /// the answer. This is the property that makes lookup a search rather than
    /// an equality test.
    #[test]
    fn an_offset_inside_a_range_resolves_to_its_start() {
        let m = map();
        // 0x18 is inside the range that begins at 0x10.
        assert_eq!(m.lookup(0x18).unwrap().line, 5);
        assert_eq!(m.lookup(0x18).unwrap().file, "src/a.rs");
        // 0x1f is still inside it; 0x20 starts the next.
        assert_eq!(m.lookup(0x1f).unwrap().line, 5);
        assert_eq!(m.lookup(0x20).unwrap().line, 12);
    }

    /// An offset **before the first row** resolves to nothing.
    ///
    /// The dangerous default would be to return the first entry, which is a
    /// plausible-looking answer for an offset that is not covered at all — the
    /// `§O-038b` failure mode.
    #[test]
    fn an_offset_before_the_first_row_is_unmapped() {
        let m = SourceMap::from_entries(vec![entry(0x100, "src/a.rs", 1)]);
        assert_eq!(
            m.lookup(0x00),
            None,
            "an uncovered offset must not be attributed to the first row"
        );
        assert_eq!(m.lookup(0x99), None);
        assert_eq!(m.lookup(0x100).unwrap().line, 1);
    }

    /// Past the last row, plain `lookup` still answers — which is why
    /// `lookup_bounded` exists.
    #[test]
    fn lookup_past_the_end_still_finds_the_last_row() {
        let m = map();
        assert_eq!(m.lookup(u64::MAX).unwrap().file, "src/b.rs");
        // But a caller with an upper bound is told the offset is outside.
        assert_eq!(m.lookup_bounded(u64::MAX, 0x30), None);
        assert_eq!(m.lookup_bounded(0x25, 0x30).unwrap().file, "src/b.rs");
    }

    // -- ordering and determinism -------------------------------------------

    /// Rows are sorted regardless of the order they arrive in.
    ///
    /// DWARF emission order is not guaranteed ascending across compilation
    /// units, so a map built from an artifact can arrive shuffled. An unsorted
    /// table would make `lookup` return whichever row the binary search happened
    /// to land on — a wrong answer that varies with the compiler's linking
    /// order.
    #[test]
    fn entries_are_sorted_on_construction() {
        let shuffled = SourceMap::from_entries(vec![
            entry(0x20, "src/b.rs", 12),
            entry(0x00, "src/a.rs", 1),
            entry(0x10, "src/a.rs", 5),
        ]);
        let ordered: Vec<u64> = shuffled.entries().iter().map(|e| e.address).collect();
        assert_eq!(ordered, vec![0x00, 0x10, 0x20]);
    }

    /// Two maps built from the same rows in different orders are equal.
    ///
    /// This is the determinism property the `--json` diff depends on.
    #[test]
    fn construction_is_order_independent() {
        let a = SourceMap::from_entries(vec![entry(0x10, "x.rs", 2), entry(0x00, "x.rs", 1)]);
        let b = SourceMap::from_entries(vec![entry(0x00, "x.rs", 1), entry(0x10, "x.rs", 2)]);
        assert_eq!(a, b);
    }

    /// A duplicate address keeps the **last** row supplied for it.
    ///
    /// Each line-program row is the mapping state starting at its address, so
    /// of two rows sharing one address the first covers an empty range and the
    /// second is the mapping in force (this is what `addr2line` resolves too).
    /// Keeping the first would attribute the address to a zero-length range.
    #[test]
    fn a_duplicate_address_keeps_the_last_row() {
        let m = SourceMap::from_entries(vec![
            entry(0x10, "first.rs", 1),
            entry(0x10, "second.rs", 2),
        ]);
        assert_eq!(m.len(), 1);
        assert_eq!(m.lookup(0x10).unwrap().file, "second.rs");
        assert_eq!(m.lookup(0x10).unwrap().line, 2);
    }

    // -- the location type ---------------------------------------------------

    #[test]
    fn a_location_renders_with_and_without_a_column() {
        let with = FrameLocation {
            file: "src/a.rs".to_owned(),
            line: 5,
            column: Some(3),
        };
        assert_eq!(with.to_string(), "src/a.rs:5:3");

        let without = FrameLocation {
            file: "src/a.rs".to_owned(),
            line: 5,
            column: None,
        };
        assert_eq!(without.to_string(), "src/a.rs:5");
    }

    /// A missing column serialises as absent, not as zero.
    ///
    /// A column of `0` is a valid-looking number that no editor accepts, and a
    /// reader would treat it as real.
    #[test]
    fn a_missing_column_is_absent_in_json() {
        let loc = FrameLocation {
            file: "a.rs".to_owned(),
            line: 1,
            column: None,
        };
        let json = serde_json::to_string(&loc).unwrap();
        assert!(!json.contains("column"), "{json}");
        assert!(json.contains("\"line\":1"), "{json}");
    }

    #[test]
    fn a_map_round_trips_through_json() {
        let m = map();
        let json = serde_json::to_string(&m).unwrap();
        let back: SourceMap = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    /// A shuffled or duplicate-laden document still deserializes to a sorted,
    /// deduplicated map — the invariant lives in construction, not in the
    /// bytes on the wire. A map extracted on one machine is consulted on
    /// another, so the deserializer must enforce what `from_entries` enforces.
    #[test]
    fn deserialization_enforces_the_sort_and_dedup_invariant() {
        let json = r#"{"entries": [
            {"address": 32, "location": {"file": "src/b.rs", "line": 12}},
            {"address": 0, "location": {"file": "src/a.rs", "line": 1}},
            {"address": 16, "location": {"file": "src/a.rs", "line": 5}},
            {"address": 16, "location": {"file": "src/evil.rs", "line": 99}}
        ]}"#;
        let back: SourceMap = serde_json::from_str(json).unwrap();
        // Sorted ...
        let addrs: Vec<u64> = back.entries().iter().map(|e| e.address).collect();
        assert_eq!(addrs, vec![0x00, 0x10, 0x20]);
        // ... and the duplicate resolves to the LAST row, per range semantics.
        assert_eq!(back.lookup(0x10).unwrap().file, "src/evil.rs");
        assert_eq!(back.lookup(0x10).unwrap().line, 99);
        // ... which is exactly what `from_entries` builds from the same rows.
        let rebuilt = SourceMap::from_entries(vec![
            entry(0x20, "src/b.rs", 12),
            entry(0x00, "src/a.rs", 1),
            entry(0x10, "src/a.rs", 5),
            entry(0x10, "src/evil.rs", 99),
        ]);
        assert_eq!(back, rebuilt);
    }

    /// A hand-written map carries its bound with it, and an old document
    /// without one still parses — the bound is a refinement, not a format
    /// break.
    #[test]
    fn an_upper_bound_round_trips_and_defaults_to_none() {
        let m = map().with_upper_bound(0x40);
        let json = serde_json::to_string(&m).unwrap();
        let back: SourceMap = serde_json::from_str(&json).unwrap();
        assert_eq!(back.upper_bound(), Some(0x40));
        assert_eq!(back, m);

        let legacy = r#"{"entries": []}"#;
        let back: SourceMap = serde_json::from_str(legacy).unwrap();
        assert_eq!(back.upper_bound(), None);
    }

    /// A gap between sequences denies: the offset belongs to no row, so
    /// resolving it to the preceding row would name the wrong function.
    ///
    /// Two sequences, `[0x00, 0x10)` and `[0x20, 0x30)`: `0x18` sits in the
    /// gap. A range-only lookup would return the `0x00` row; the sequence
    /// gate returns nothing.
    #[test]
    fn an_offset_in_a_sequence_gap_is_unmapped() {
        let m =
            SourceMap::from_entries(vec![entry(0x00, "src/a.rs", 1), entry(0x20, "src/b.rs", 2)])
                .with_sequences(vec![(0x00, 0x10), (0x20, 0x30)]);
        assert_eq!(m.lookup(0x08).unwrap().line, 1);
        assert_eq!(
            m.lookup(0x18),
            None,
            "a gap offset must not be attributed to the preceding row"
        );
        assert_eq!(m.lookup(0x28).unwrap().line, 2);
        // The tail follows the furthest sequence.
        assert_eq!(m.upper_bound(), Some(0x30));
        assert_eq!(m.lookup(0x30), None);
    }

    /// Sequences sort on the way in, so construction order never matters —
    /// the same determinism property the rows themselves carry.
    #[test]
    fn sequences_are_sorted_on_construction() {
        let m = SourceMap::from_entries(vec![entry(0x00, "src/a.rs", 1)])
            .with_sequences(vec![(0x20, 0x30), (0x00, 0x10)]);
        assert_eq!(m.lookup(0x08).unwrap().line, 1);
        assert_eq!(m.lookup(0x18), None);
    }

    /// Overlapping sequences fail open toward coverage: the rule takes the
    /// furthest covering tail, so only an offset past *every* covering range
    /// denies. Ranges from different compilation units interleave in real
    /// artifacts — denying on the first ending range would deny real code.
    #[test]
    fn overlapping_sequences_fail_open_toward_coverage() {
        let m = SourceMap::from_entries(vec![
            entry(0x00, "src/a.rs", 1),
            entry(0x08, "src/b.rs", 2),
            entry(0x20, "src/c.rs", 3),
        ])
        .with_sequences(vec![(0x00, 0x10), (0x08, 0x30)]);
        // 0x18 is past the first range but inside the second: covered.
        assert_eq!(m.lookup(0x18).unwrap().line, 2);
        // 0x28 is inside the second range: covered by the 0x20 row.
        assert_eq!(m.lookup(0x28).unwrap().line, 3);
        // Past every covering tail: denied.
        assert_eq!(m.lookup(0x30), None);
        // The bound is the furthest tail, not the last-starting range's.
        assert_eq!(m.upper_bound(), Some(0x30));
    }

    /// An empty file name is rejected at the boundary, like a zero line: it
    /// renders as `:42` — a location shaped like an answer with no content.
    #[test]
    fn an_empty_file_is_rejected_at_the_boundary() {
        let json = r#"{"file": "", "line": 1}"#;
        assert!(
            serde_json::from_str::<FrameLocation>(json).is_err(),
            "an empty file must not deserialize"
        );
    }

    /// The bound gates `lookup` itself, not just `resolve_frames`: a caller
    /// holding a bounded map must not resolve past it through any path.
    #[test]
    fn a_bounded_map_denies_direct_lookup_past_the_bound() {
        let m = map().with_upper_bound(0x30);
        assert_eq!(m.lookup(0x2f).unwrap().file, "src/b.rs");
        assert_eq!(
            m.lookup(0x30),
            None,
            "the exclusive bound denies direct lookup too"
        );
        assert_eq!(m.lookup(u64::MAX), None);
    }

    /// Deserialization derives the bound exactly as construction does: a
    /// document whose `upper_bound` understates its sequences still resolves
    /// to the furthest tail.
    #[test]
    fn deserialization_derives_the_bound_from_sequences() {
        let json = r#"{"entries": [
            {"address": 0, "location": {"file": "a.rs", "line": 1}}
        ], "upper_bound": 16, "sequences": [{"start": 0, "end": 48}]}"#;
        let back: SourceMap = serde_json::from_str(json).unwrap();
        assert_eq!(back.upper_bound(), Some(48));
        assert_eq!(
            back,
            SourceMap::from_entries(vec![entry(0x00, "a.rs", 1)])
                .with_upper_bound(16)
                .with_sequences(vec![(0x00, 0x30)]),
            "deserialized and constructed forms must agree"
        );
    }

    /// A `Some(0)` column never reaches JSON: it serializes as absent, so a
    /// round trip cannot produce the `"column":0` that deserialization would
    /// normalize away.
    #[test]
    fn a_zero_column_is_absent_in_json() {
        let loc = FrameLocation {
            file: "a.rs".to_owned(),
            line: 1,
            column: Some(0),
        };
        let json = serde_json::to_string(&loc).unwrap();
        assert!(!json.contains("column"), "{json}");
    }

    /// DWARF line 0 means "unknown location". There is no unknown location in
    /// this type, so a zero line is malformed input — fail loudly at the
    /// trust boundary rather than rendering `file:0` as a real answer.
    #[test]
    fn a_zero_line_is_rejected_at_the_boundary() {
        let json = r#"{"file": "a.rs", "line": 0}"#;
        assert!(
            serde_json::from_str::<FrameLocation>(json).is_err(),
            "line 0 must not deserialize"
        );
    }

    /// Column 0 is DWARF's "no column", normalized to absent on the way in —
    /// matching how `extract` already maps `LeftEdge` to `None`.
    #[test]
    fn a_zero_column_normalizes_to_absent() {
        let json = r#"{"file": "a.rs", "line": 1, "column": 0}"#;
        let loc: FrameLocation = serde_json::from_str(json).unwrap();
        assert_eq!(loc.column, None);
    }
}
