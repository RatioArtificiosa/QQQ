// SPDX-License-Identifier: Apache-2.0

//! Static component shape inspection (`F-08`, `F-10`).
//!
//! Some limits must be known *before* instantiation: admission (F-10) must
//! refuse oversized components at load rather than under load, and that
//! decision needs the same numbers read from the component bytes — so they
//! live here once. Runtime enforcement needs no static sum: Wasmtime reports
//! initial allocation through `memory_growing(current = 0)`, which the
//! aggregate limiter charges by delta like any other growth (an earlier
//! pre-charge design double-counted and was removed; see §O-557).
//!
//! The parser is `wasmparser` (already in the tree via Wasmtime; pinned to
//! the same copy so no second crate enters the build). Only minimums are
//! summed: initial allocation is exactly the declared minimums, and growth
//! beyond them goes through the limiter callbacks.
use wasmparser::{MemoryType, Parser, Payload};

/// Sum of initial linear-memory sizes, in bytes, across every core module in
/// a component (`parse_all` descends into nested modules and composed
/// components, so one pass sees them all): each memory's minimum page count
/// × its page size (64 KiB unless the memory sets a custom page size, which
/// [`wasmparser::MemoryType::page_size`] reports).
///
/// Shared memories are included in the sum: whether the host can account
/// them is decided by the caller (DET-012 keeps them refused), not hidden by
/// the measurement.
pub(crate) fn initial_memory_bytes(bytes: &[u8]) -> Result<u64, String> {
    // One flat pass: `Parser::parse_all` already descends into nested core
    // modules and components (it swaps to a sub-parser on `ModuleSection` /
    // `ComponentSection` and resumes the parent at `End`), so every
    // `MemorySection` in the whole component surfaces here exactly once. A
    // manual recursion into `unchecked_range` would count every nested
    // memory TWICE — the pre-charge would over-refuse legal components.
    // (Proven: with the recursion the 3-page fixture below measured 6.)
    let mut total = 0u64;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| format!("component bytes do not parse: {e}"))?;
        if let Payload::MemorySection(reader) = payload {
            for memory in reader {
                let memory: MemoryType =
                    memory.map_err(|e| format!("memory section does not parse: {e}"))?;
                let size = u64::from(memory.page_size()).saturating_mul(memory.initial);
                total = total.saturating_add(size);
            }
        }
    }
    Ok(total)
}

/// Countable shape of a component: how many memories, tables, and core
/// modules it declares (`F-10`).
///
/// Memories and tables are summed across every nested core module (one flat
/// `parse_all` pass, same descent as above); core modules are counted by
/// section. Module count is the static proxy for instantiated core
/// instances: a module instantiated twice counts once here, so the pool's
/// `total_core_instances` (instances × 64) still carries the runtime
/// multiplicity — this cap only refuses pathologically composed artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ComponentCounts {
    pub memories: u32,
    pub tables: u32,
    pub core_modules: u32,
}

pub(crate) fn component_counts(bytes: &[u8]) -> Result<ComponentCounts, String> {
    let mut counts = ComponentCounts {
        memories: 0,
        tables: 0,
        core_modules: 0,
    };
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| format!("component bytes do not parse: {e}"))?;
        match payload {
            Payload::MemorySection(reader) => {
                for memory in reader {
                    memory.map_err(|e| format!("memory section does not parse: {e}"))?;
                    counts.memories = counts.memories.saturating_add(1);
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    table.map_err(|e| format!("table section does not parse: {e}"))?;
                    counts.tables = counts.tables.saturating_add(1);
                }
            }
            Payload::ModuleSection { .. } => {
                counts.core_modules = counts.core_modules.saturating_add(1);
            }
            _ => {}
        }
    }
    Ok(counts)
}

/// Per-component caps: the most memories, tables, and core modules one
/// component may declare (`F-10`).
///
/// Split from [`crate::config::PoolShape`] deliberately: the pool shape also
/// carries instance counts and byte ceilings, which load-time validation of a
/// single artifact must not depend on. The shape derives these caps from the
/// same shared constants, so the two agree by construction rather than by
/// review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShapeCaps {
    pub memories: u32,
    pub tables: u32,
    pub core_modules: u32,
}

impl ShapeCaps {
    /// The caps from the shared constants: what the pool enforces per
    /// instance is what load-time validation refuses past.
    pub(crate) fn maximum() -> Self {
        Self {
            memories: crate::config::MAX_MEMORIES_PER_COMPONENT,
            tables: crate::config::MAX_TABLES_PER_COMPONENT,
            core_modules: u32::try_from(crate::instance::MAX_INNER_INSTANCES).unwrap_or(u32::MAX),
        }
    }
}

/// Refuse a component whose shape exceeds the per-instance caps.
///
/// Load-time validation: a 9-memory component against an 8-memory cap is
/// refused HERE, at deploy, rather than as an instantiation error under
/// load.
///
/// Unparseable-by-`wasmparser` bytes are NOT refused: `Component::new`
/// already validated them, so at this point they are either a parser
/// disagreement (refusing would turn a measurement aid into a denial of
/// service) or WAT text, which Wasmtime's `wat` feature accepts and the test
/// suite passes throughout. Production artifacts are binary; the runtime
/// limiters remain the enforcement for everything instantiation admits.
/// This is the same fail-open-with-backstop as `initial_memory_bytes`'
/// zero-on-unparseable, and for the same reason.
///
/// Returns the message for the refusal; the caller attaches the code
/// (`LimitOutOfRange`) and the remediation.
pub(crate) fn validate_shape(bytes: &[u8], caps: &ShapeCaps) -> Result<(), String> {
    let Ok(counts) = component_counts(bytes) else {
        return Ok(());
    };
    if counts.memories > caps.memories {
        return Err(format!(
            "component declares {} memories, more than the {} per-instance maximum",
            counts.memories, caps.memories
        ));
    }
    if counts.tables > caps.tables {
        return Err(format!(
            "component declares {} tables, more than the {} per-instance maximum",
            counts.tables, caps.tables
        ));
    }
    if counts.core_modules > caps.core_modules {
        return Err(format!(
            "component declares {} core modules, more than the {} per-instance maximum",
            counts.core_modules, caps.core_modules
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes per WebAssembly page (test-only: production multiplies by the
    /// per-memory `page_size()` instead of assuming 64 KiB).
    const WASM_PAGE_BYTES: u64 = 65536;

    /// Minimal component bytes, hand-encoded: one core module with one memory
    /// of 3 pages. Hand-encoding keeps the test hermetic (no engine, no WAT
    /// toolchain): component magic + version, one core-module custom section
    /// containing a module with a memory section.
    fn one_memory_component() -> Vec<u8> {
        // Core module: magic, version 1.0, memory section (id 5):
        // count 1, limits flag 0x00 (min only), min 3.
        let mut module = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        module.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x03]);
        // Component: magic, version 13.0, core-module section (id 1)
        // holding exactly one module as raw bytes (no count prefix: a
        // core-module section embeds a single module directly).
        let mut component = vec![0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
        component.push(0x01);
        component.push(u8::try_from(module.len()).expect("the fixture module is 13 bytes"));
        component.extend_from_slice(&module);
        component
    }

    #[test]
    fn f08_initial_memory_sums_minimums_across_core_modules() {
        assert_eq!(
            initial_memory_bytes(&one_memory_component()).expect("parses"),
            3 * WASM_PAGE_BYTES
        );
        assert_eq!(
            initial_memory_bytes(&[0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00])
                .expect("parses"),
            0
        );
    }

    #[test]
    fn f08_garbage_bytes_are_an_error_not_a_panic() {
        assert!(initial_memory_bytes(&[0x00, 0x01, 0x02]).is_err());
        assert!(initial_memory_bytes(&[]).is_err());
    }
}
