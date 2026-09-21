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

use serde::{Deserialize, Serialize};

/// A resolved source location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameLocation {
    /// The source file, as DWARF recorded it.
    ///
    /// **Not** joined to any root or made absolute. DWARF stores the path the
    /// compiler was given, which for a Cargo build is relative to the workspace
    /// root; rewriting it here would guess at a filesystem the reader may not
    /// share.
    pub file: String,
    /// The line number, 1-based.
    pub line: u32,
    /// The column, when DWARF carries one.
    ///
    /// `None` rather than `0` when absent: a column of `0` is a valid-looking
    /// number that no editor will accept, and sources differ on whether the
    /// line program emits columns at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
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

/// The offset-to-source table for one artifact.
///
/// `Debug` is implemented by hand below: a real artifact's map is thousands of
/// rows, and deriving it makes a failing assertion print all of them.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SourceMap {
    /// The rows, **sorted by address** and with duplicates removed.
    ///
    /// Sorted because lookup is a binary search and because a `--json` diff of
    /// two runs must be byte-identical; DWARF's emission order is not guaranteed
    /// to be ascending across compilation units.
    entries: Vec<LineEntry>,
}

impl SourceMap {
    /// An empty map — the result of extracting from an artifact with no DWARF.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Build from unsorted rows.
    ///
    /// Sorts and deduplicates. A duplicate address keeps the **first** row for
    /// that address after a stable sort, which preserves the line program's own
    /// preference: when two rows share an address, DWARF's later row is the one
    /// that "ends" the previous range, and the earlier one is the intended
    /// mapping.
    #[must_use]
    pub fn from_entries(mut entries: Vec<LineEntry>) -> Self {
        entries.sort_by_key(|e| e.address);
        entries.dedup_by_key(|e| e.address);
        Self { entries }
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

    /// Resolve a Wasm bytecode offset to a source location.
    ///
    /// Returns the entry whose address range contains `offset` — that is, the
    /// last row whose `address` is `<= offset`. A line program describes ranges,
    /// not points, so the nearest preceding row is the correct answer rather
    /// than an approximation.
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
        // `partition_point` gives the count of entries with address <= offset,
        // so the answer is the one before it. Written this way rather than with
        // a hand-rolled binary search because the off-by-one is the entire
        // difficulty and the standard library already got it right.
        let idx = self.entries.partition_point(|e| e.address <= offset);
        if idx == 0 {
            // Every row starts after this offset. An offset before the first
            // row is genuinely unmapped — DWARF's first row is often address 0,
            // but not always.
            return None;
        }
        self.entries.get(idx - 1).map(|e| &e.location)
    }

    /// Resolve, and report whether the offset fell inside the last row's range.
    ///
    /// DWARF line programs end with a row marking the end of the sequence, so a
    /// `lookup` past the final instruction still finds the last row. That is
    /// correct for an address inside the covering range and misleading past it,
    /// and the difference matters when reporting an offset that was computed
    /// rather than observed.
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

    /// A duplicate address keeps the first row supplied for it.
    #[test]
    fn a_duplicate_address_keeps_the_first_row() {
        let m = SourceMap::from_entries(vec![
            entry(0x10, "first.rs", 1),
            entry(0x10, "second.rs", 2),
        ]);
        assert_eq!(m.len(), 1);
        assert_eq!(m.lookup(0x10).unwrap().file, "first.rs");
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
}
