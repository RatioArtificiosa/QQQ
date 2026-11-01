// SPDX-License-Identifier: Apache-2.0

//! Extracting a [`SourceMap`] from a Wasm component's DWARF sections.
//!
//! # Where the DWARF lives
//!
//! A Rust `wasm32-wasip2` build puts DWARF in **custom sections** of the Wasm
//! module, named `.debug_info`, `.debug_line`, `.debug_abbrev`, `.debug_str` and
//! so on — the same names as an ELF or Mach-O object, carried in the section-name
//! field of a custom section.
//!
//! So extraction is two steps: read the Wasm section table to find those
//! payloads, then hand them to gimli's line-program reader. Neither step
//! needs an engine, which is the whole point: the map can be extracted from a
//! `.wasm` on disk, from a `.cwasm`'s source artifact, or in a build step, long
//! before and long after any instance exists.
//!
//! # Why `wasmparser` is not a dependency
//!
//! The section table is a flat sequence of `(id, size, payload)` with a varint
//! length. Reading it is about forty lines, and `wasmparser` would add a large
//! dependency to a crate whose whole job is a lookup table. The parsing here is
//! correspondingly narrow: it finds custom sections and stops. It does not
//! validate the module — an artifact that is not valid Wasm is caught by
//! `qqq-host` when it compiles, and reporting that here would duplicate the check
//! with a worse error.

use std::collections::BTreeMap;

use qqq_core::{Error, ErrorCode, Result};

use crate::source_map::{FrameLocation, LineEntry, SourceMap};

/// The outcome of an extraction attempt, for reporting.
///
/// # Why this is a struct rather than an `Option<SourceMap>`
///
/// "No debug info" is a **normal** result and needs to be distinguishable from
/// "extraction failed" without a caller inspecting an error. And when debug info
/// *is* present, the number of sections found and rows extracted is what tells a
/// user whether they built with the right profile — `debug = true` in a release
/// profile is the usual reason a trap has no line numbers, and `0 rows from 11
/// sections` says so at a glance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionReport {
    /// The map, empty when the artifact carries no usable debug info.
    pub map: SourceMap,
    /// DWARF sections found in the artifact, by name.
    pub sections_found: Vec<String>,
    /// Rows read from the line program.
    pub rows: usize,
    /// Whether the artifact is a Wasm module at all.
    pub is_wasm: bool,
}

impl ExtractionReport {
    /// Whether the artifact carried DWARF.
    #[must_use]
    pub fn has_debug_info(&self) -> bool {
        // Gated on `.debug_info` *and* a non-empty map, not on any `.debug_*`
        // section: a stray `.debug_str` with no compilation units is not debug
        // info, and a line program that produced no rows maps nothing. Either
        // shape previously reported `true` and sent the reader to the wrong
        // fix.
        self.sections_found.iter().any(|n| n == ".debug_info") && !self.map.is_empty()
    }

    /// A one-line explanation of the result, for a human or an agent.
    ///
    /// Written to answer the question a user actually has — *why does my trap
    /// have no line number?* — rather than to report a status code.
    #[must_use]
    pub fn explain(&self) -> String {
        if !self.is_wasm {
            return "the artifact is not a WebAssembly module".to_owned();
        }
        // The specific case first: `.debug_info` present but rowless. Checking
        // the general case first made this branch dead — `has_debug_info` is
        // false for an empty map, so a rowless artifact reported "no DWARF
        // sections" and the rowless message was unreachable.
        if self.rows == 0 && self.sections_found.iter().any(|n| n == ".debug_info") {
            return format!(
                "{} DWARF section kind(s) found but the line program produced no rows; \
                 no address in the artifact maps to a source location",
                self.sections_found.len()
            );
        }
        if !self.has_debug_info() {
            return "the artifact carries no DWARF sections; build with debug info \
                    (`[profile.release] debug = true`) to get source locations"
                .to_owned();
        }
        format!(
            "{} row(s) from {} DWARF section kind(s)",
            self.rows,
            self.sections_found.len()
        )
    }
}

/// The Wasm magic and the component encoding both start with this.
const WASM_MAGIC: &[u8; 4] = b"\0asm";

/// The layer field of a component preamble: `1` means component, `0` means
/// core module.
///
/// The preamble after the magic is version (2 bytes) then layer (2 bytes),
/// little-endian. A core module's 4-byte version (`01 00 00 00`) reads as
/// version `1`, layer `0` under the same split; a component reads as version
/// `0x000d`, layer `1`. Section id `1` means a different thing under each
/// layer, which is why this constant exists — see `collect_sections`.
const COMPONENT_LAYER: u16 = 1;

/// Read the layer field of a Wasm preamble.
///
/// `None` when the input is shorter than a preamble. Callers check the magic
/// first; this only splits what follows it.
fn layer_of(bytes: &[u8]) -> Option<u16> {
    let layer = bytes.get(6..8)?;
    // Two bytes, little-endian. The range bound above guarantees the length;
    // the conversion states it rather than subscripting it.
    let pair: [u8; 2] = layer.try_into().ok()?;
    Some(u16::from_le_bytes(pair))
}

/// Extract a source map from a Wasm artifact.
///
/// # Errors
///
/// A `QQQ-1006` (`DebugInfoInvalid`) error only when the artifact **is**
/// Wasm and its DWARF is malformed. An artifact that is not Wasm, or that is
/// Wasm with no debug info, is a successful extraction with an empty map —
/// see [`ExtractionReport`].
pub fn extract(bytes: &[u8]) -> Result<ExtractionReport> {
    if !bytes.starts_with(WASM_MAGIC) {
        return Ok(ExtractionReport {
            map: SourceMap::empty(),
            sections_found: Vec::new(),
            rows: 0,
            is_wasm: false,
        });
    }

    let modules = parse_custom_sections(bytes);

    // The distinct DWARF section kinds found, across every nested module: two
    // core modules may each carry a `.debug_line`, and both are real sections
    // (the rows merge per-module below, so the count names kinds, not blobs).
    // Unstable: names are plain data with no order to preserve.
    let mut names: Vec<String> = modules.iter().flat_map(|m| m.keys().cloned()).collect();
    names.sort_unstable();
    names.dedup();
    if modules.is_empty() {
        return Ok(ExtractionReport {
            map: SourceMap::empty(),
            sections_found: Vec::new(),
            rows: 0,
            is_wasm: true,
        });
    }

    // Each module's sections are a separate section table with their own
    // headers: concatenating two `.debug_line` payloads would parse neither.
    // So the line program runs once per module and the rows merge after —
    // through `merge_module_rows`, which refuses an ambiguous merge rather
    // than silently dropping one module's rows.
    let mut per_module = Vec::with_capacity(modules.len());
    for module in &modules {
        per_module.push(read_line_program(module)?);
    }
    let (entries, sequences) = merge_module_rows(per_module)?;
    let map = SourceMap::from_entries(entries).with_sequences(sequences);
    let rows = map.len();

    Ok(ExtractionReport {
        map,
        sections_found: names,
        rows,
        is_wasm: true,
    })
}

/// One module's line-program output: its rows plus its covered sequences.
///
/// A named alias rather than a nested tuple: the shape threads through
/// `read_line_program`, `merge_module_rows` and `extract`, and the nesting
/// reads as noise at every site without it.
type ModuleLineProgram = (Vec<LineEntry>, Vec<(u64, u64)>);

/// Merge per-module line-program output into one table.
///
/// Rows concatenate and sequences union: modules that describe disjoint
/// address ranges compose cleanly. But every core module's code addresses
/// start at 0, so two DWARF-bearing modules will overlap — and at an
/// overlapping address with *different* locations no merge is honest: one
/// module's rows would silently displace the other's, and a frame would
/// resolve to the wrong module's file and line. That is the blob-overwrite
/// defect one level up, so it errors (`DebugInfoInvalid`) instead of
/// guessing. Identical rows at the same address (the same code linked twice)
/// merge cleanly; the later dedup in `from_entries` collapses them.
///
/// Rationale for erroring rather than resolving per-module: matching a
/// `ReportedFrame.module` (a Wasmtime module name) to a DWARF module (a
/// compilation directory and unit name) has no stable mapping, so
/// module-aware resolution would itself be a guess. When multi-module DWARF
/// actually appears, the fix is per-module maps keyed by something both
/// sides name — until then, a loud error beats a confident wrong answer.
///
/// # Errors
///
/// `DebugInfoInvalid` when two modules map the same address to different
/// locations.
fn merge_module_rows(per_module: Vec<ModuleLineProgram>) -> Result<ModuleLineProgram> {
    let mut entries = Vec::new();
    let mut sequences = Vec::new();
    // The addresses already taken, with the module index that claimed them
    // and the location they map to: within one module the last row wins
    // (DWARF range semantics — see `SourceMap::from_entries`), while across
    // modules the same address must agree.
    let mut seen: BTreeMap<u64, (usize, FrameLocation)> = BTreeMap::new();
    for (module_idx, (module_entries, module_sequences)) in per_module.into_iter().enumerate() {
        // Dedup within the module first, last-wins: duplicate addresses in
        // one line program are routine (overlapping compilation units), and
        // only the effective mapping may conflict with another module.
        let mut local: BTreeMap<u64, FrameLocation> = BTreeMap::new();
        for row in module_entries {
            local.insert(row.address, row.location);
        }
        for (address, location) in local {
            if let Some((first_idx, first)) = seen.get(&address) {
                // Compared on the observable identity — file and line — not
                // the whole row: `resolve_frames` drops columns (the wire
                // shape has no room for one), so two modules differing only
                // in column resolve identically and must not error. (The
                // first index always differs here: `local` deduped the
                // module, so any hit comes from an earlier module.)
                debug_assert_ne!(
                    *first_idx, module_idx,
                    "intra-module duplicates never reach the cross-module check"
                );
                let same_place = first.file == location.file && first.line == location.line;
                if !same_place {
                    return Err(Error::new(
                        ErrorCode::DebugInfoInvalid,
                        "two core modules map the same bytecode offset to different \
                         source locations; no unambiguous source map exists",
                    )
                    .with_remediation(
                        "rebuild with `[profile.release] debug = true`; if the failure \
                         persists, the toolchain emitted overlapping DWARF for two \
                         core modules — see https://qqq.codes/errors/QQQ-1006",
                    )
                    .with_context("offset", format!("{address:#x}"))
                    .with_context("first", format!("{}:{}", first.file, first.line))
                    .with_context("second", format!("{}:{}", location.file, location.line)));
                }
                continue;
            }
            seen.insert(address, (module_idx, location.clone()));
            entries.push(LineEntry { address, location });
        }
        sequences.extend(module_sequences);
    }
    // Identical ranges from identical modules union idempotently; the sort
    // matches `with_sequences`, which enforces the same rule for hand-built
    // maps and deserialized documents. Unstable: pairs are plain data, and
    // no equal-pair ordering is observable after the dedup below.
    sequences.sort_unstable();
    sequences.dedup();
    Ok((entries, sequences))
}

/// Read a little-endian LEB128 unsigned integer.
///
/// Returns the value and the number of bytes consumed. Refuses a run longer than
/// five bytes, which is the encoding's own maximum for a `u32` and therefore the
/// point past which the input is not a valid length — and refuses a value above
/// `u32::MAX`, because every consumer here is a section size or name length and
/// a wider value can only come from a corrupt table.
fn read_uleb(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if i >= 5 {
            return None;
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            // Five septets carry 35 bits; the fifth byte's top three bits must
            // be zero or the value does not fit the `u32` this encoding tops
            // out at. Without this, a crafted length passes here and fails
            // pages later as an out-of-bounds slice — a confusing error for a
            // kind of input that is never valid.
            return u32::try_from(result).ok().map(|v| (u64::from(v), i + 1));
        }
        shift += 7;
    }
    None
}

/// Walk the section table and collect every `.debug_*` custom section.
///
/// Returns one map **per module level**: the outer component's own custom
/// sections, then one map for each nested module that carries any. A second
/// core module's `.debug_line` must not overwrite the first's — an earlier
/// version collected into a single `BTreeMap<String, Vec<u8>>` keyed by
/// section name, so whichever module was walked last won and the other's rows
/// vanished without a word.
///
/// Only `.debug_*` sections are collected. Compressed `.zdebug_*` sections
/// are not: no supported toolchain emits them for Wasm targets, and reading
/// them would need decompression in the section loader. If one ever appears,
/// extraction reports no usable DWARF for that module (honest) rather than
/// misreading it.
///
/// Infallible: a truncated or malformed table yields whatever was readable
/// before the damage, and an artifact with no debug info yields an empty
/// vector. Both are normal results — see [`extract`] for why neither is an
/// error.
///
/// # Components nest their core module
///
/// Measured on a real `qqqai build` artifact: the DWARF sections are **not** at
/// the top level. `qqqai build` emits a *component* (layer 1), and a component
/// wraps one or more *core modules* (layer 0) — the DWARF lives inside the core
/// module's own section table, one level down.
///
/// An earlier version of this function only walked the outer table, found a
/// section id of `1` (a module wrapper) and no custom sections at all, and
/// reported `the artifact carries no DWARF sections` for an artifact that
/// `wasm-tools objdump` showed to be 265 KB of debug info. The parser was not
/// wrong about what it read; it was reading the wrong table.
///
/// So: if the outer artifact is a component, descend into its nested modules and
/// collect from those. The recursion is bounded by `MAX_NESTING`, because the
/// input is untrusted and a self-referential encoding must not be able to drive
/// unbounded work.
fn parse_custom_sections(bytes: &[u8]) -> Vec<BTreeMap<String, Vec<u8>>> {
    let mut modules = Vec::new();
    collect_sections(bytes, &mut modules, 0);
    modules
}

/// How deep the module nesting is followed.
///
/// A component wrapping a module is the real case. The limit exists so a
/// malformed artifact cannot make this recurse without bound; two levels is
/// everything a valid Component Model encoding produces today.
const MAX_NESTING: u8 = 4;

/// Collect `.debug_*` custom sections from `bytes`, descending into nested
/// modules.
///
/// One map per module level is appended to `out`: nested levels collected
/// during the walk come first, the current level's own map last — order is
/// irrelevant, the caller merges every map. Levels with no DWARF contribute
/// nothing.
fn collect_sections(bytes: &[u8], out: &mut Vec<BTreeMap<String, Vec<u8>>>, depth: u8) {
    if depth > MAX_NESTING || !bytes.starts_with(WASM_MAGIC) || bytes.len() < 8 {
        return;
    }

    // Section id `1` is a **nested core module** in a component — and the
    // **Type section** in a core module. Descending unconditionally recursed
    // into a core module's Type section (caught only by the magic check on
    // whatever bytes happened to be there) and could skip a real nested
    // module if that check ever failed closed. The layer field disambiguates:
    // only a component's id-`1` (and id-`4`, a nested component) wraps bytes
    // with their own section table.
    let is_component = layer_of(bytes) == Some(COMPONENT_LAYER);

    // Magic (4) + version (2) + layer (2).
    let mut here = BTreeMap::new();
    let mut pos = 8usize;
    while pos < bytes.len() {
        // Truncation ends the scan (`break`), it does not discard the level:
        // whatever was readable before the damage is still collected below.
        // The loop guard bounds `pos`, so the first arm is unreachable
        // structure that terminates the scan instead of panicking it.
        let Some(&id) = bytes.get(pos) else { break };
        pos += 1;

        let Some((size, n)) = read_uleb(bytes.get(pos..).unwrap_or(&[])) else {
            break;
        };
        pos += n;

        let Ok(size) = usize::try_from(size) else {
            break;
        };
        let Some(end) = pos.checked_add(size) else {
            break;
        };
        let Some(payload) = bytes.get(pos..end) else {
            break;
        };

        match id {
            // Custom section: a name (varint length + bytes) then the content.
            0 => {
                if let Some((name, content)) = split_custom_section(payload)
                    && name.starts_with(".debug_")
                {
                    // Same name twice at one level is malformed input (a valid
                    // module has one section per name); the last wins,
                    // deterministically, matching the row-dedup rule.
                    here.insert(name.to_owned(), content.to_vec());
                }
            }
            // A nested module (id 1) or nested component (id 4) inside a
            // **component** carries its own section table, which is where the
            // DWARF lives. This is the case that made the difference between
            // "no debug info" and 46 KB of line program.
            1 | 4 if is_component => {
                // The payload is the nested module's bytes with its own header,
                // so recurse on it directly.
                collect_sections(payload, out, depth + 1);
            }
            _ => {}
        }

        pos = end;
    }

    if !here.is_empty() {
        out.push(here);
    }
}

/// Split a custom section payload into its name and content.
fn split_custom_section(payload: &[u8]) -> Option<(&str, &[u8])> {
    let (name_len, n) = read_uleb(payload)?;
    let name_len = usize::try_from(name_len).ok()?;
    let name_end = n.checked_add(name_len)?;
    let name = std::str::from_utf8(payload.get(n..name_end)?).ok()?;
    Some((name, payload.get(name_end..)?))
}

/// Run the DWARF line program and collect its rows.
///
/// Returns the rows plus the line program's sequences — the contiguous covered
/// ranges as `(start, end)` pairs, where `end` is the `end_sequence` address
/// (one past the last covered address). The caller records them on the map so
/// offsets in inter-sequence gaps deny instead of attributing to the
/// preceding row, and the map derives its upper bound as the furthest tail.
///
/// # Why this walks units rather than calling `addr2line`
///
/// `addr2line`'s `Context` resolves *one probe at a time*, which is a lookup API.
/// This needs the **whole table**, because the map is extracted once and
/// consulted many times, possibly on another machine. Iterating units and their
/// line programs directly produces the table; `Context` would require already
/// knowing every offset worth asking about.
///
/// The cost is that function names are not resolved here — a frame's `func` comes
/// from Wasmtime's own frame info at trap time, which is where it is free.
fn read_line_program(sections: &BTreeMap<String, Vec<u8>>) -> Result<ModuleLineProgram> {
    let load = |id: gimli::SectionId| -> std::result::Result<
        gimli::EndianSlice<'_, gimli::LittleEndian>,
        gimli::Error,
    > {
        let name = id.name();
        // A missing section is an empty slice, not an error: a build with only
        // `.debug_line` and `.debug_abbrev` is valid and common.
        let data: &[u8] = sections.get(name).map_or(&[], Vec::as_slice);
        Ok(gimli::EndianSlice::new(data, gimli::LittleEndian))
    };

    let dwarf = gimli::Dwarf::load(load).map_err(|e| {
        Error::new(
            ErrorCode::DebugInfoInvalid,
            "the artifact's DWARF sections could not be parsed",
        )
        .with_cause(e.to_string())
        .with_remediation(
            "rebuild with `[profile.release] debug = true`; if the failure persists, \
             the toolchain emitted malformed DWARF — see https://qqq.codes/errors/QQQ-1006",
        )
    })?;

    let mut entries = Vec::new();
    // The covered ranges, as `(start, end)` pairs: `start` is the first row's
    // address since the previous end marker, `end` the marker's own address
    // (exclusive). Recorded so gap offsets deny instead of attributing to the
    // preceding row. A program with no end marker yields no sequences, and
    // the map keeps legacy range semantics for it.
    let mut sequences = Vec::new();
    let mut units = dwarf.units();

    // The unit index travels in error context: a corrupt `--debug`-built
    // artifact can carry dozens of units, and "unit 7 failed" beats
    // re-parsing the artifact to find which one.
    let mut unit_idx = 0usize;
    while let Some(header) = units.next().map_err(|e| {
        Error::new(
            ErrorCode::DebugInfoInvalid,
            "the artifact's DWARF unit headers could not be read",
        )
        .with_cause(e.to_string())
        .with_remediation(
            "rebuild with `[profile.release] debug = true`; if the failure persists, \
             the toolchain emitted malformed DWARF — see https://qqq.codes/errors/QQQ-1006",
        )
        .with_context("unit", unit_idx.to_string())
    })? {
        let unit = dwarf.unit(header).map_err(|e| {
            Error::new(
                ErrorCode::DebugInfoInvalid,
                "a DWARF compilation unit could not be read",
            )
            .with_cause(e.to_string())
            .with_remediation(
                "rebuild with `[profile.release] debug = true`; if the failure persists, \
                 the toolchain emitted malformed DWARF — see https://qqq.codes/errors/QQQ-1006",
            )
            .with_context("unit", unit_idx.to_string())
        })?;
        // Captured before the increment below: the rows error reports the
        // unit it was reading, not the next one.
        let cur_unit = unit_idx;
        unit_idx += 1;

        let Some(program) = unit.line_program.clone() else {
            continue;
        };

        // Per compilation unit, not per artifact: a unit without a trailing
        // end marker must not lend its start to the next unit's sequence,
        // which would record a cross-unit range covering the gap between
        // them. (Real units always end; this is one line against a corrupt
        // or truncated program extending coverage it never described.)
        let mut seq_start: Option<u64> = None;

        let mut rows = program.rows();
        while let Some((header, row)) = rows.next_row().map_err(|e| {
            Error::new(
                ErrorCode::DebugInfoInvalid,
                "the artifact's DWARF line program could not be read",
            )
            .with_cause(e.to_string())
            .with_remediation(
                "rebuild with `[profile.release] debug = true`; if the failure persists, \
                 the toolchain emitted malformed DWARF — see https://qqq.codes/errors/QQQ-1006",
            )
            .with_context("unit", cur_unit.to_string())
        })? {
            // The row that marks the end of a sequence has no real location;
            // `end_sequence` is DWARF's own way of saying "the range stops
            // here". Its address is one past the last covered address, so the
            // range from the sequence's first row to here is recorded as
            // covered — and anything past it, short of the next sequence,
            // is a gap that must deny rather than attribute to the last row.
            if row.end_sequence() {
                if let Some(start) = seq_start.take() {
                    sequences.push((start, row.address()));
                }
                continue;
            }

            if seq_start.is_none() {
                seq_start = Some(row.address());
            }

            let Some(file) = resolve_file(&dwarf, &unit, header, row.file_index()) else {
                continue;
            };

            // `line` is `Option<NonZeroU64>`: DWARF treats line 0 as "unknown",
            // and the type makes that unrepresentable. Skipping it is correct —
            // a reported line of 1 would be a guess.
            let Some(line) = row.line() else {
                continue;
            };
            let Ok(line) = u32::try_from(line.get()) else {
                continue;
            };

            // Column 0 is DWARF's "no column", and the type keeps it distinct
            // from an absent column.
            let column = match row.column() {
                gimli::ColumnType::Column(c) => u32::try_from(c.get()).ok(),
                gimli::ColumnType::LeftEdge => None,
            };

            entries.push(LineEntry {
                // This is the property that makes the whole crate small: for a
                // Wasm target, the line program's address *is* the bytecode
                // offset that a Wasmtime frame reports.
                address: row.address(),
                location: FrameLocation { file, line, column },
            });
        }
    }

    Ok((entries, sequences))
}

/// Resolve a row's file index to a path.
///
/// DWARF can store the path directly, as an index into `debug_line_str` or
/// `debug_str`, or as a file name with a directory-table index — resolved
/// below against the line program header's include directories, which
/// `FileEntry::directory` folds together with the compilation directory
/// (`DW_AT_comp_dir`: index 0 in DWARF v4 and earlier; a separate header
/// field from the include table in v5). A bare `lib.rs` without this join
/// collides across directories, which is why the join lives here.
///
/// A name that will not resolve is skipped (no location is better than a
/// fabricated one), but an *unresolvable directory* falls back to the bare
/// name: the file was found, only its directory was not, and dropping the
/// row would lose a real location for want of a prefix.
fn resolve_file<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    header: &gimli::LineProgramHeader<R>,
    index: u64,
) -> Option<String> {
    let file = header.file(index)?;
    // `path_name()` returns an `AttributeValue`; `attr_string` resolves it
    // against `debug_line_str`/`debug_str`, which is the whole reason this is
    // not an inline match at the call site.
    let name = dwarf.attr_string(unit, file.path_name()).ok()?;
    // The trait form is fallible (other readers can fail where `EndianSlice`
    // cannot); an unstringifiable name skips the row rather than poisoning
    // the table.
    let name = name.to_string_lossy().ok()?.into_owned();
    // An empty or whitespace-only name renders as `:42` — a location shaped
    // like an answer with no content, and one the JSON boundary would reject
    // on round-trip. No row is better.
    if name.trim().is_empty() {
        return None;
    }
    // The directory table (DWARF §6.2.4): `FileEntry::directory` folds the
    // index together with the compilation directory, so there is no separate
    // version switch here — the version handling lives in gimli, where the
    // header encoding is known. Absent or unresolvable means the file stands
    // alone: today's behavior, kept as the graceful fallback.
    let Some(dir_attr) = file.directory(header) else {
        return Some(name);
    };
    let Ok(dir) = dwarf.attr_string(unit, dir_attr) else {
        return Some(name);
    };
    let Ok(dir) = dir.to_string_lossy() else {
        return Some(name);
    };
    Some(join_dir(&dir, &name))
}

/// Join a DWARF directory entry and file name into the recorded path.
///
/// Pure string surgery, no filesystem access: the result stays relative when
/// the inputs are relative, because resolving it against *this* machine's
/// filesystem would guess at a tree the reader may not share (see the
/// `FrameLocation::file` docs). A file name that is already absolute wins; an
/// empty directory contributes nothing.
fn join_dir(dir: &str, file: &str) -> String {
    // A drive-letter prefix (`C:`) or a leading slash — or backslash — is
    // absolute: a leading slash is absolute everywhere DWARF toolchains write
    // paths, and a lone leading backslash is a rooted Windows path.
    let file_is_absolute =
        file.starts_with('/') || file.starts_with('\\') || file.get(1..2) == Some(":");
    if dir.is_empty() || file_is_absolute {
        return file.to_owned();
    }
    // Join with the directory's own separator: mixing `C:\foo` with `/`
    // produces a path no Windows API normalizes back.
    if dir.ends_with(['/', '\\']) {
        return format!("{dir}{file}");
    }
    let sep = if dir.contains('\\') { '\\' } else { '/' };
    format!("{dir}{sep}{file}")
}

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest thing that starts like Wasm: magic, version, layer.
    fn empty_wasm() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(WASM_MAGIC);
        v.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]);
        v
    }

    #[test]
    fn a_non_wasm_artifact_extracts_nothing_and_says_so() {
        let report = extract(b"this is not webassembly").expect("must not error");
        assert!(!report.is_wasm);
        assert!(report.map.is_empty());
        assert!(report.explain().contains("not a WebAssembly module"));
    }

    #[test]
    fn an_empty_wasm_artifact_has_no_debug_info() {
        let report = extract(&empty_wasm()).expect("must not error");
        assert!(report.is_wasm);
        assert!(!report.has_debug_info());
        assert!(report.map.is_empty());
    }

    /// The explanation must name the fix, not just the absence.
    ///
    /// A user seeing "no source location" needs to know it is a build setting.
    #[test]
    fn the_no_debug_info_explanation_names_the_build_setting() {
        let report = extract(&empty_wasm()).unwrap();
        assert!(
            report.explain().contains("debug = true"),
            "the explanation must name the fix: {}",
            report.explain()
        );
    }

    #[test]
    fn an_unsupported_build_artifact_reports_empty() {
        // A real `.wasm`-shaped header but truncated section table.
        let mut v = empty_wasm();
        v.push(0x00); // custom section id, then nothing
        let report = extract(&v).expect("must not error on a truncated table");
        assert!(report.is_wasm);
        assert!(report.map.is_empty());
    }

    /// A truncated section table keeps whatever was readable: one valid
    /// section followed by garbage still yields the first section's blob.
    ///
    /// The collection loop `break`s on truncation instead of returning, and
    /// the level is pushed after the loop — this test pins that the readable
    /// prefix actually survives, which a no-DWARF fixture cannot prove.
    #[test]
    fn a_truncated_table_keeps_the_readable_prefix() {
        let mut section = vec![0x00];
        let name = b".debug_line";
        let mut body = Vec::new();
        body.push(u8::try_from(name.len()).unwrap());
        body.extend_from_slice(name);
        body.extend_from_slice(b"\xAA");
        section.push(u8::try_from(body.len()).unwrap());
        section.extend_from_slice(&body);

        let mut wasm = empty_wasm();
        wasm.extend_from_slice(&section);
        // A second section header promising 200 bytes, then nothing.
        wasm.push(0x00);
        wasm.push(0xC8);

        let sections = parse_custom_sections(&wasm);
        assert_eq!(
            sections.len(),
            1,
            "the readable prefix must survive truncation: {sections:?}"
        );
        assert_eq!(sections[0][".debug_line"], b"\xAA".to_vec());
    }

    // -- LEB128 ------------------------------------------------------------

    #[test]
    fn uleb128_decodes_single_bytes() {
        assert_eq!(read_uleb(&[0x00]), Some((0, 1)));
        assert_eq!(read_uleb(&[0x7f]), Some((127, 1)));
    }

    #[test]
    fn uleb128_decodes_multi_bytes() {
        // 128 = 0x80 0x01
        assert_eq!(read_uleb(&[0x80, 0x01]), Some((128, 2)));
        // 624485 = 0xE5 0x8E 0x26
        assert_eq!(read_uleb(&[0xE5, 0x8E, 0x26]), Some((624_485, 3)));
    }

    /// An unterminated run is refused rather than returning a partial value.
    #[test]
    fn an_unterminated_uleb_is_refused() {
        assert_eq!(read_uleb(&[0x80, 0x80]), None);
        assert_eq!(read_uleb(&[]), None);
    }

    /// A run longer than five bytes is refused.
    ///
    /// Five bytes is the encoding's maximum for a `u32`, so a longer run is not
    /// a length — continuing would shift past 64 bits and wrap.
    #[test]
    fn an_overlong_uleb_is_refused() {
        assert_eq!(read_uleb(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]), None);
    }

    // -- section walking ---------------------------------------------------

    /// A custom section is found by name, and its payload is its content.
    #[test]
    fn a_custom_section_is_found_with_its_payload() {
        let mut wasm = empty_wasm();
        let name = b".debug_line";
        let payload = b"\xDE\xAD\xBE\xEF";
        let mut body = Vec::new();
        body.push(u8::try_from(name.len()).unwrap());
        body.extend_from_slice(name);
        body.extend_from_slice(payload);

        wasm.push(0x00); // custom section
        wasm.push(u8::try_from(body.len()).unwrap());
        wasm.extend_from_slice(&body);

        let sections = parse_custom_sections(&wasm);
        assert_eq!(sections.len(), 1, "one module level: {sections:?}");
        assert_eq!(sections[0][".debug_line"], payload.to_vec());
    }

    /// A non-DWARF custom section is ignored.
    ///
    /// Every Rust component carries a `name` custom section and usually
    /// `producers`; collecting those would make `has_debug_info` always true.
    #[test]
    fn a_non_dwarf_custom_section_is_ignored() {
        let mut wasm = empty_wasm();
        let name = b"producers";
        let mut body = Vec::new();
        body.push(u8::try_from(name.len()).unwrap());
        body.extend_from_slice(name);
        body.extend_from_slice(b"some metadata");

        wasm.push(0x00);
        wasm.push(u8::try_from(body.len()).unwrap());
        wasm.extend_from_slice(&body);

        let sections = parse_custom_sections(&wasm);
        assert!(
            sections.is_empty(),
            "a `producers` section is not debug info: {sections:?}"
        );
    }

    /// A custom section inside a **nested core module** is found.
    ///
    /// The regression test for the defect that made this feature report "no
    /// DWARF" for a 265 KB artifact full of it.
    ///
    /// A component (layer 1) wraps core modules (layer 0) in section id `1`, and
    /// the DWARF lives in the *inner* module's own section table. A parser that
    /// walked only the outer table found a module wrapper and no custom sections
    /// — correct about what it read, reading the wrong table.
    #[test]
    fn a_custom_section_inside_a_nested_module_is_found() {
        // Inner module: a core module with one DWARF custom section.
        let mut inner = Vec::new();
        inner.extend_from_slice(WASM_MAGIC);
        inner.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // layer 0 = core
        let name = b".debug_line";
        let payload = b"\xAA\xBB";
        let mut body = Vec::new();
        body.push(u8::try_from(name.len()).unwrap());
        body.extend_from_slice(name);
        body.extend_from_slice(payload);
        inner.push(0x00);
        inner.push(u8::try_from(body.len()).unwrap());
        inner.extend_from_slice(&body);

        // Outer component: section id 1, carrying the inner module.
        let mut outer = Vec::new();
        outer.extend_from_slice(WASM_MAGIC);
        outer.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]); // layer 1 = component
        outer.push(0x01); // nested module
        outer.push(u8::try_from(inner.len()).unwrap());
        outer.extend_from_slice(&inner);

        let sections = parse_custom_sections(&outer);
        assert_eq!(
            sections.len(),
            1,
            "the nested module's DWARF must be found: {sections:?}"
        );
        assert_eq!(sections[0][".debug_line"], payload.to_vec());
    }

    /// Two nested modules keep **both** DWARF blobs.
    ///
    /// The regression test for silent multi-module loss: collecting into a
    /// single name-keyed map let the second module's `.debug_line` overwrite
    /// the first's, and the first module's rows vanished without a word.
    #[test]
    fn two_nested_modules_keep_both_blobs() {
        fn core_module_with(payload: &[u8]) -> Vec<u8> {
            let mut inner = Vec::new();
            inner.extend_from_slice(WASM_MAGIC);
            inner.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // layer 0
            let name = b".debug_line";
            let mut body = Vec::new();
            body.push(u8::try_from(name.len()).unwrap());
            body.extend_from_slice(name);
            body.extend_from_slice(payload);
            inner.push(0x00);
            inner.push(u8::try_from(body.len()).unwrap());
            inner.extend_from_slice(&body);
            inner
        }

        let first = core_module_with(b"\xAA");
        let second = core_module_with(b"\xBB");
        let mut outer = Vec::new();
        outer.extend_from_slice(WASM_MAGIC);
        outer.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]); // layer 1
        for module in [&first, &second] {
            outer.push(0x01);
            outer.push(u8::try_from(module.len()).unwrap());
            outer.extend_from_slice(module);
        }

        let sections = parse_custom_sections(&outer);
        assert_eq!(sections.len(), 2, "both modules' blobs: {sections:?}");
        let mut payloads: Vec<Vec<u8>> =
            sections.iter().map(|m| m[".debug_line"].clone()).collect();
        payloads.sort();
        assert_eq!(payloads, vec![b"\xAA".to_vec(), b"\xBB".to_vec()]);
    }

    /// A core module's id-`1` section is its Type section, not a nested
    /// module — and must not be descended into.
    ///
    /// The payload below starts with the Wasm magic on purpose: the old code
    /// descended into *every* id-`1` section and relied on the magic check to
    /// save it, so a Type section whose bytes happened to start with the magic
    /// would have its contents misread as a section table. The layer gate
    /// closes that: a layer-0 artifact has no nested modules to descend into.
    #[test]
    fn a_type_section_in_a_core_module_is_not_descended_into() {
        // A fake "nested module": magic, then a DWARF custom section.
        let mut nested = Vec::new();
        nested.extend_from_slice(WASM_MAGIC);
        nested.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let name = b".debug_info";
        let mut body = Vec::new();
        body.push(u8::try_from(name.len()).unwrap());
        body.extend_from_slice(name);
        body.push(0x00);
        nested.push(0x00);
        nested.push(u8::try_from(body.len()).unwrap());
        nested.extend_from_slice(&body);

        // ...placed as section id 1 of a CORE module, where id 1 is the Type
        // section and the payload is type definitions, not a module.
        let mut core = Vec::new();
        core.extend_from_slice(WASM_MAGIC);
        core.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // layer 0 = core
        core.push(0x01);
        core.push(u8::try_from(nested.len()).unwrap());
        core.extend_from_slice(&nested);

        let sections = parse_custom_sections(&core);
        assert!(
            sections.is_empty(),
            "a core module's Type section is not a module: {sections:?}"
        );
    }

    /// A nested **component** (id `4`) is descended into.
    ///
    /// Components nest: a component may wrap a component that wraps the core
    /// module carrying the DWARF. Only the component layer's id-`1` and id-`4`
    /// sections wrap a section table; both must be followed.
    #[test]
    fn a_nested_component_is_descended_into() {
        let mut inner = Vec::new();
        inner.extend_from_slice(WASM_MAGIC);
        inner.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // layer 0
        let name = b".debug_line";
        let payload = b"\xCC";
        let mut body = Vec::new();
        body.push(u8::try_from(name.len()).unwrap());
        body.extend_from_slice(name);
        body.extend_from_slice(payload);
        inner.push(0x00);
        inner.push(u8::try_from(body.len()).unwrap());
        inner.extend_from_slice(&body);

        // Nested component: layer 1, wrapping the core module as id 1.
        let mut nested_component = Vec::new();
        nested_component.extend_from_slice(WASM_MAGIC);
        nested_component.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]);
        nested_component.push(0x01);
        nested_component.push(u8::try_from(inner.len()).unwrap());
        nested_component.extend_from_slice(&inner);

        // Outer component: the nested component rides as id 4.
        let mut outer = Vec::new();
        outer.extend_from_slice(WASM_MAGIC);
        outer.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]);
        outer.push(0x04);
        outer.push(u8::try_from(nested_component.len()).unwrap());
        outer.extend_from_slice(&nested_component);

        let sections = parse_custom_sections(&outer);
        assert_eq!(sections.len(), 1, "id-4 descent: {sections:?}");
        assert_eq!(sections[0][".debug_line"], payload.to_vec());
    }

    /// Nesting is bounded, so a malformed artifact cannot drive unbounded work.
    #[test]
    fn nesting_is_bounded() {
        // Six levels of module wrapping: deeper than the limit.
        let mut bytes = empty_wasm();
        for _ in 0..6 {
            let mut outer = empty_wasm();
            outer.push(0x01);
            outer.push(u8::try_from(bytes.len()).unwrap());
            outer.extend_from_slice(&bytes);
            bytes = outer;
        }
        // Must terminate and return, not recurse forever. The assertion is that
        // this line is reached at all — a stack overflow would abort the test
        // rather than fail it, which is a louder signal than any assertion.
        //
        // The input carries no DWARF, so the result is an empty map; asserting
        // on emptiness as well as on termination would be asserting a property
        // of the fixture rather than of the bound.
        let sections = parse_custom_sections(&bytes);
        assert!(
            sections.is_empty(),
            "the fixture has no DWARF, so nothing should be collected"
        );
    }

    /// The bound gates collection: DWARF within the limit is found, DWARF
    /// past it is not.
    ///
    /// The test above only proves termination (its fixture has no DWARF, so
    /// emptiness cannot distinguish "bounded" from "never descends"). This
    /// one puts a real section at a reachable depth and at an unreachable
    /// one, pinning both sides of `MAX_NESTING`.
    #[test]
    fn nesting_depth_gates_collection() {
        fn debug_core() -> Vec<u8> {
            let mut inner = Vec::new();
            inner.extend_from_slice(WASM_MAGIC);
            inner.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
            let name = b".debug_line";
            let mut body = Vec::new();
            body.push(u8::try_from(name.len()).unwrap());
            body.extend_from_slice(name);
            body.push(0xAA);
            inner.push(0x00);
            inner.push(u8::try_from(body.len()).unwrap());
            inner.extend_from_slice(&body);
            inner
        }
        fn wrap_component(bytes: &[u8]) -> Vec<u8> {
            let mut outer = Vec::new();
            outer.extend_from_slice(WASM_MAGIC);
            outer.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]);
            outer.push(0x01);
            outer.push(u8::try_from(bytes.len()).unwrap());
            outer.extend_from_slice(bytes);
            outer
        }

        let mut shallow = debug_core();
        for _ in 0..3 {
            shallow = wrap_component(&shallow);
        }
        assert_eq!(
            parse_custom_sections(&shallow).len(),
            1,
            "DWARF three levels down is within the bound"
        );

        let mut deep = debug_core();
        for _ in 0..6 {
            deep = wrap_component(&deep);
        }
        assert!(
            parse_custom_sections(&deep).is_empty(),
            "DWARF six levels down exceeds the bound"
        );
    }

    /// Several DWARF sections are collected together.
    #[test]
    fn several_debug_sections_are_collected() {
        let mut wasm = empty_wasm();
        for name in [".debug_info", ".debug_abbrev", ".debug_line"] {
            let mut body = Vec::new();
            body.push(u8::try_from(name.len()).unwrap());
            body.extend_from_slice(name.as_bytes());
            body.push(0x00); // one byte of content

            wasm.push(0x00);
            wasm.push(u8::try_from(body.len()).unwrap());
            wasm.extend_from_slice(&body);
        }

        let sections = parse_custom_sections(&wasm);
        assert_eq!(sections.len(), 1, "one module level: {sections:?}");
        let level = &sections[0];
        assert_eq!(level.len(), 3);
        assert!(level.contains_key(".debug_info"));
        assert!(level.contains_key(".debug_line"));
    }

    // -- path joining ------------------------------------------------------

    /// An empty directory contributes nothing.
    #[test]
    fn join_dir_with_an_empty_directory_keeps_the_file() {
        assert_eq!(join_dir("", "lib.rs"), "lib.rs");
    }

    /// A relative pair joins with one slash.
    #[test]
    fn join_dir_joins_a_relative_pair() {
        assert_eq!(join_dir("src", "lib.rs"), "src/lib.rs");
        assert_eq!(join_dir("src/", "lib.rs"), "src/lib.rs");
    }

    /// An absolute file wins over any directory.
    #[test]
    fn join_dir_leaves_absolute_files_alone() {
        assert_eq!(join_dir("src", "/abs/lib.rs"), "/abs/lib.rs");
        assert_eq!(join_dir("src", "C:/work/lib.rs"), "C:/work/lib.rs");
        assert_eq!(join_dir("src", "\\rooted\\lib.rs"), "\\rooted\\lib.rs");
    }

    /// The directory's own separator wins: `C:\foo` + `bar` joins with a
    /// backslash, not a mixed `C:\foo/bar` no Windows API normalizes back.
    /// Trailing separators of either kind are honored as-is.
    #[test]
    fn join_dir_keeps_the_directory_separator() {
        assert_eq!(join_dir("C:\\foo", "bar.rs"), "C:\\foo\\bar.rs");
        assert_eq!(join_dir("C:\\foo\\", "bar.rs"), "C:\\foo\\bar.rs");
        assert_eq!(join_dir("src", "bar.rs"), "src/bar.rs");
    }

    /// A value above `u32::MAX` is refused: the fifth LEB byte's top bits.
    #[test]
    fn a_uleb_above_u32_max_is_refused() {
        // 0xFFFF_FFFF: the largest encodable `u32`.
        assert_eq!(
            read_uleb(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
            Some((u64::from(u32::MAX), 5))
        );
        // 0x1_0000_0000: one past it.
        assert_eq!(read_uleb(&[0x80, 0x80, 0x80, 0x80, 0x10]), None);
    }

    /// The preamble layer splits components from core modules.
    #[test]
    fn layer_of_splits_component_from_core() {
        let mut component = Vec::new();
        component.extend_from_slice(WASM_MAGIC);
        component.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]);
        assert_eq!(layer_of(&component), Some(COMPONENT_LAYER));

        let mut core = Vec::new();
        core.extend_from_slice(WASM_MAGIC);
        core.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(layer_of(&core), Some(0));

        assert_eq!(layer_of(b"\0as"), None);
    }

    // -- merge seam (H1) -----------------------------------------------------

    fn row(address: u64, file: &str, line: u32) -> LineEntry {
        LineEntry {
            address,
            location: FrameLocation {
                file: file.to_owned(),
                line,
                column: None,
            },
        }
    }

    /// Identical rows from two modules merge cleanly: same address, same
    /// location (the same code linked twice) is agreement, not ambiguity.
    /// The sequences union idempotently: one pair, not two copies.
    #[test]
    fn identical_rows_from_two_modules_merge() {
        let one = vec![row(0x10, "a.rs", 1)];
        let two = vec![row(0x10, "a.rs", 1)];
        let (entries, sequences) =
            merge_module_rows(vec![(one, vec![(0x10, 0x20)]), (two, vec![(0x10, 0x20)])])
                .expect("identical rows must merge");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].location.file, "a.rs");
        assert_eq!(sequences, vec![(0x10, 0x20)]);
    }

    /// The same address mapping to *different* locations is ambiguous: one
    /// module's rows would silently displace the other's, so the merge
    /// errors instead of guessing.
    #[test]
    fn conflicting_rows_from_two_modules_error() {
        let one = vec![row(0x10, "a.rs", 1)];
        let two = vec![row(0x10, "b.rs", 2)];
        let err = merge_module_rows(vec![(one, vec![(0x10, 0x20)]), (two, vec![(0x10, 0x30)])])
            .expect_err("conflicting rows must not merge silently");
        assert_eq!(
            err.code,
            ErrorCode::DebugInfoInvalid,
            "ambiguity is a debug-info defect, not a manifest one: {err:?}"
        );
    }

    /// Disjoint modules compose: rows concatenate, sequences union.
    #[test]
    fn disjoint_modules_merge_with_unioned_sequences() {
        let one = vec![row(0x10, "a.rs", 1)];
        let two = vec![row(0x100, "b.rs", 2)];
        let (entries, sequences) =
            merge_module_rows(vec![(one, vec![(0x10, 0x20)]), (two, vec![(0x100, 0x200)])])
                .expect("disjoint modules must merge");
        assert_eq!(entries.len(), 2);
        assert_eq!(sequences, vec![(0x10, 0x20), (0x100, 0x200)]);
    }

    /// A column-only difference is not a conflict: resolution drops columns,
    /// so the same file and line from two modules resolve identically.
    #[test]
    fn column_only_differences_merge() {
        fn row_at(address: u64, column: Option<u32>) -> LineEntry {
            LineEntry {
                address,
                location: FrameLocation {
                    file: "a.rs".to_owned(),
                    line: 1,
                    column,
                },
            }
        }
        let one = vec![row_at(0x10, Some(3))];
        let two = vec![row_at(0x10, None)];
        let (entries, _) = merge_module_rows(vec![(one, vec![]), (two, vec![])])
            .expect("column-only differences must merge");
        assert_eq!(entries.len(), 1);
    }

    /// Within one module the last row wins *before* the cross-module check:
    /// duplicates in a single line program are routine, and only the
    /// effective mapping may conflict with another module.
    ///
    /// The first case agrees with the second module's effective row; the
    /// second case matches only the stale (overwritten) row and must error.
    /// A merge that compared incrementally — first row seen wins — would get
    /// both backwards, and the existing one-row-per-module tests would still
    /// pass, which is why this test exists.
    #[test]
    fn intra_module_last_wins_before_cross_module_check() {
        let a = vec![row(0x10, "a.rs", 1), row(0x10, "a.rs", 2)];
        let b = vec![row(0x10, "a.rs", 2)];
        assert!(
            merge_module_rows(vec![(a, vec![]), (b, vec![])]).is_ok(),
            "agreement with the effective row must merge"
        );

        let a2 = vec![row(0x10, "a.rs", 1), row(0x10, "a.rs", 2)];
        let c = vec![row(0x10, "a.rs", 1)];
        assert!(
            merge_module_rows(vec![(a2, vec![]), (c, vec![])]).is_err(),
            "agreement with only the stale row must error"
        );
    }

    // -- error paths (H5, M2) --------------------------------------------------

    /// Malformed DWARF errors with `DebugInfoInvalid`, not a manifest code.
    ///
    /// A truncated `.debug_info` section parses as a unit header and then
    /// runs out of bytes — the exact shape a corrupt toolchain output takes.
    #[test]
    fn malformed_dwarf_errors_with_debug_info_invalid() {
        // A component wrapping a core module with a truncated `.debug_info`:
        // a unit length promising 8 bytes, then nothing.
        let mut inner = Vec::new();
        inner.extend_from_slice(WASM_MAGIC);
        inner.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let name = b".debug_info";
        let mut body = Vec::new();
        body.push(u8::try_from(name.len()).unwrap());
        body.extend_from_slice(name);
        body.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
        inner.push(0x00);
        inner.push(u8::try_from(body.len()).unwrap());
        inner.extend_from_slice(&body);

        let mut outer = Vec::new();
        outer.extend_from_slice(WASM_MAGIC);
        outer.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]);
        outer.push(0x01);
        outer.push(u8::try_from(inner.len()).unwrap());
        outer.extend_from_slice(&inner);

        let err = extract(&outer).expect_err("truncated DWARF must error");
        assert_eq!(
            err.code,
            ErrorCode::DebugInfoInvalid,
            "a corrupt line program is a debug-info defect: {err:?}"
        );
    }

    /// `.debug_info` present but rowless reports the rowless case — not "no
    /// DWARF sections". The general branch used to run first and made this
    /// message dead code.
    #[test]
    fn a_rowless_artifact_with_debug_info_says_so() {
        let report = ExtractionReport {
            map: SourceMap::empty(),
            sections_found: vec![".debug_info".to_owned(), ".debug_line".to_owned()],
            rows: 0,
            is_wasm: true,
        };
        assert!(
            !report.has_debug_info(),
            "an empty map is not debug info, even with sections present"
        );
        let text = report.explain();
        assert!(
            text.contains("produced no rows"),
            "the rowless case needs its own message: {text}"
        );
    }
}
