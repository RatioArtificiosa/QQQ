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
//! payloads, then hand them to `addr2line` as a section loader. Neither step
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
    /// Whether the artifact carried DWARF at all.
    #[must_use]
    pub fn has_debug_info(&self) -> bool {
        !self.sections_found.is_empty()
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
        if !self.has_debug_info() {
            return "the artifact carries no DWARF sections; build with debug info \
                    (`[profile.release] debug = true`) to get source locations"
                .to_owned();
        }
        if self.rows == 0 {
            return format!(
                "{} DWARF section(s) found but the line program produced no rows; \
                 the debug info may be for a different compilation unit",
                self.sections_found.len()
            );
        }
        format!(
            "{} row(s) from {} DWARF section(s)",
            self.rows,
            self.sections_found.len()
        )
    }
}

/// The Wasm magic and the component encoding both start with this.
const WASM_MAGIC: &[u8; 4] = b"\0asm";

/// Extract a source map from a Wasm artifact.
///
/// # Errors
///
/// A `QQQ-2002` error only when the artifact **is** Wasm and its DWARF is
/// malformed. An artifact that is not Wasm, or that is Wasm with no debug info,
/// is a successful extraction with an empty map — see [`ExtractionReport`].
pub fn extract(bytes: &[u8]) -> Result<ExtractionReport> {
    if !bytes.starts_with(WASM_MAGIC) {
        return Ok(ExtractionReport {
            map: SourceMap::empty(),
            sections_found: Vec::new(),
            rows: 0,
            is_wasm: false,
        });
    }

    let sections = parse_custom_sections(bytes);

    let names: Vec<String> = sections.keys().cloned().collect();
    if names.is_empty() {
        return Ok(ExtractionReport {
            map: SourceMap::empty(),
            sections_found: Vec::new(),
            rows: 0,
            is_wasm: true,
        });
    }

    let entries = read_line_program(&sections)?;
    let rows = entries.len();

    Ok(ExtractionReport {
        map: SourceMap::from_entries(entries),
        sections_found: names,
        rows,
        is_wasm: true,
    })
}

/// Read a little-endian LEB128 unsigned integer.
///
/// Returns the value and the number of bytes consumed. Refuses a run longer than
/// five bytes, which is the encoding's own maximum for a `u32` and therefore the
/// point past which the input is not a valid length.
fn read_uleb(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if i >= 5 {
            return None;
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

/// Walk the section table and collect every `.debug_*` custom section.
///
/// Infallible: a truncated or malformed table yields whatever was readable
/// before the damage, and an artifact with no debug info yields an empty map.
/// Both are normal results — see [`extract`] for why neither is an error.
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
fn parse_custom_sections(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut sections = BTreeMap::new();
    collect_sections(bytes, &mut sections, 0);
    sections
}

/// How deep the module nesting is followed.
///
/// A component wrapping a module is the real case. The limit exists so a
/// malformed artifact cannot make this recurse without bound; two levels is
/// everything a valid Component Model encoding produces today.
const MAX_NESTING: u8 = 4;

/// Collect `.debug_*` custom sections from `bytes`, descending into nested
/// modules.
fn collect_sections(bytes: &[u8], out: &mut BTreeMap<String, Vec<u8>>, depth: u8) {
    if depth > MAX_NESTING || !bytes.starts_with(WASM_MAGIC) {
        return;
    }

    // Magic (4) + version (2) + layer (2).
    let mut pos = 8usize;
    while pos < bytes.len() {
        let Some(&id) = bytes.get(pos) else { return };
        pos += 1;

        let Some((size, n)) = read_uleb(&bytes[pos..]) else {
            return;
        };
        pos += n;

        let Ok(size) = usize::try_from(size) else {
            return;
        };
        let Some(end) = pos.checked_add(size) else {
            return;
        };
        let Some(payload) = bytes.get(pos..end) else {
            return;
        };

        match id {
            // Custom section: a name (varint length + bytes) then the content.
            0 => {
                if let Some((name, content)) = split_custom_section(payload) {
                    if name.starts_with(".debug_") {
                        out.insert(name.to_owned(), content.to_vec());
                    }
                }
            }
            // Section id 1 in a component is a **nested core module**, whose own
            // section table is where the DWARF lives. This is the case that made
            // the difference between "no debug info" and 46 KB of line program.
            1 => {
                // The payload is the nested module's bytes with its own header,
                // so recurse on it directly.
                collect_sections(payload, out, depth + 1);
            }
            _ => {}
        }

        pos = end;
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
fn read_line_program(sections: &BTreeMap<String, Vec<u8>>) -> Result<Vec<LineEntry>> {
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
            ErrorCode::ManifestSchemaViolation,
            "the artifact's DWARF sections could not be parsed",
        )
        .with_cause(e.to_string())
    })?;

    let mut entries = Vec::new();
    let mut units = dwarf.units();

    while let Some(header) = units.next().map_err(|e| {
        Error::new(
            ErrorCode::ManifestSchemaViolation,
            "the artifact's DWARF unit headers could not be read",
        )
        .with_cause(e.to_string())
    })? {
        let unit = dwarf.unit(header).map_err(|e| {
            Error::new(
                ErrorCode::ManifestSchemaViolation,
                "a DWARF compilation unit could not be read",
            )
            .with_cause(e.to_string())
        })?;

        let Some(program) = unit.line_program.clone() else {
            continue;
        };

        let mut rows = program.rows();
        while let Some((header, row)) = rows.next_row().map_err(|e| {
            Error::new(
                ErrorCode::ManifestSchemaViolation,
                "the artifact's DWARF line program could not be read",
            )
            .with_cause(e.to_string())
        })? {
            // The row that marks the end of a sequence has no real location;
            // `end_sequence` is DWARF's own way of saying "the range stops
            // here", so it is skipped rather than attributed a file and line.
            if row.end_sequence() {
                continue;
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
                location: FrameLocation {
                    file: file.to_string_lossy().into_owned(),
                    line,
                    column,
                },
            });
        }
    }

    Ok(entries)
}

/// Resolve a row's file index to a path.
///
/// DWARF can store the path directly, as an index into `debug_line_str` or
/// `debug_str`, or as a relative path against the compilation directory —
/// `attr_string` handles all four, which is why the file resolution is spread
/// across these few lines rather than inlined.
fn resolve_file<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    header: &gimli::LineProgramHeader<R>,
    index: u64,
) -> Option<R> {
    let file = header.file(index)?;
    // `path_name()` returns an `AttributeValue`; `attr_string` resolves it
    // against `debug_line_str`/`debug_str` and the compilation directory, which
    // is the whole reason this is not an inline match at the call site.
    dwarf.attr_string(unit, file.path_name()).ok()
}

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
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[".debug_line"], payload.to_vec());
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
        assert_eq!(sections[".debug_line"], payload.to_vec());
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
        assert_eq!(sections.len(), 3);
        assert!(sections.contains_key(".debug_info"));
        assert!(sections.contains_key(".debug_line"));
    }
}
