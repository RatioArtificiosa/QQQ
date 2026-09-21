// SPDX-License-Identifier: Apache-2.0

//! The trap taxonomy — mapping engine failures to stable `QQQ-3xxx` codes.
//!
//! Proposal §6.1 requires that a guest failure never takes down the host, and
//! that each failure class is reported with a **stable code**, a structured
//! backtrace, and a behaviour the caller can act on.
//!
//! # The precise mapping
//!
//! | Condition | Code | Retryable | Instance reusable? |
//! |---|---|---|---|
//! | Memory limit exceeded | `QQQ-3001` | no | **no** — discard |
//! | Fuel exhausted | `QQQ-3002` | no | **no** — discard |
//! | Epoch deadline exceeded | `QQQ-3003` | no | **no** — discard |
//! | Invalid resource handle | `QQQ-3005` | no | **no** — discard |
//! | Guest panic (`unreachable` from a panic path) | `QQQ-3006` | no | **no** — discard |
//! | Anything else | `QQQ-3004` | no | **no** — discard |
//!
//! # Why every trap discards the instance
//!
//! A trapped instance has been interrupted mid-execution. Its linear memory may
//! hold partially-written state, its resource handles may be half-closed, and
//! its fuel accounting is spent. Returning it to the pool would hand the next
//! request a contaminated context — which is exactly the kind of cross-request
//! leak the capability model exists to prevent. **Every trap discards.**
//!
//! # Why traps are never retryable
//!
//! The same input traps the same way. [`qqq_core::ErrorClass::is_retryable`]
//! returns `false` for the `Trap` class for this reason. A caller that retries
//! a trapped guest with identical input is burning budget; a caller retrying
//! with *different* input is making a product decision, not a retry.
//!
//! See Proposal §6.1, §10.5 and Checklist `HOST-008`, `HOST-009`, `HOST-010`.

use std::fmt;

use qqq_core::{Error, ErrorCode};

/// Classifies a raw engine failure into the stable taxonomy.
///
/// Kept as a free function on `&str` rather than on Wasmtime's error type so
/// the mapping is **testable without a real engine**, and so a Wasmtime upgrade
/// that changes the error type does not force a rewrite of the taxonomy.
///
/// # Why string matching
///
/// Wasmtime's error type is not exhaustively matchable across versions — it is
/// a boxed trait object whose variants are not part of its stability contract.
/// Matching on the *message* is therefore the only option, which makes this
/// function a genuine compatibility surface: **the tests pin the exact
/// strings**, so a Wasmtime upgrade that changes one fails CI rather than
/// silently misclassifying a trap.
///
/// # Ordering is load-bearing
///
/// Signatures are checked most-specific first. In particular:
///
/// * **Fuel** is checked before memory, because Wasmtime's fuel message can
///   mention memory in its backtrace.
/// * **Out-of-bounds is checked before the memory-limit heuristic.** These are
///   different failures: `out of bounds memory access` is a **guest bug** (a
///   buffer overrun), while `memory limit exceeded` means the guest asked for
///   more than it was allowed. Conflating them would send a developer hunting
///   for a limit to raise when the real fix is a code change.
/// * **Bare `interrupt`** maps to the epoch deadline: it is the message
///   Wasmtime emits when epoch preemption fires, and it does not contain the
///   word "epoch".
#[must_use]
pub fn classify_trap(detail: &str) -> ErrorCode {
    let d = detail.to_ascii_lowercase();

    // -- Fuel (most specific; its backtrace may mention anything) --------
    if d.contains("fuel") {
        return ErrorCode::FuelExhausted;
    }

    // -- Epoch preemption ------------------------------------------------
    // "wasm trap: interrupt" is the actual message Wasmtime emits for epoch
    // preemption, and it does NOT contain "epoch".
    if d.contains("epoch") && (d.contains("deadline") || d.contains("interrupt")) {
        return ErrorCode::EpochDeadlineExceeded;
    }
    if d.contains("trap: interrupt") {
        return ErrorCode::EpochDeadlineExceeded;
    }

    // -- Guest memory bugs (checked BEFORE the limit heuristics) ---------
    // A genuine overrun is a code defect, not a limit that needs raising.
    if d.contains("out of bounds") || d.contains("out-of-bounds") {
        return ErrorCode::GuestOutOfBounds;
    }

    // -- Limit violations -------------------------------------------------
    if d.contains("memory")
        && (d.contains("limit")
            || d.contains("exceed")
            || d.contains("grow")
            || d.contains("minimum size"))
    {
        return ErrorCode::MemoryLimitExceeded;
    }

    // -- Resource handles -------------------------------------------------
    if d.contains("resource")
        && (d.contains("handle") || d.contains("table") || d.contains("closed"))
    {
        return ErrorCode::InvalidResourceHandle;
    }

    // -- Guest panic ------------------------------------------------------
    // A Rust panic in a Wasm guest compiles to `unreachable`.
    if d.contains("unreachable") || d.contains("panic") {
        return ErrorCode::GuestPanic;
    }

    ErrorCode::GuestTrap
}

/// A guest failure, with everything needed to diagnose it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Trap {
    /// The stable code.
    pub code: ErrorCode,
    /// A single human sentence describing what happened.
    pub message: String,
    /// The raw engine detail. **Unstable** — for debugging, never for parsing.
    pub detail: String,
    /// Wasm frames, outermost first, when the engine supplied them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backtrace: Vec<WasmFrame>,
    /// Peak memory observed for this instance, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_peak_bytes: Option<u64>,
    /// Fuel consumed before the trap, when metering is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel_consumed: Option<u64>,
}

/// One frame of a guest backtrace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WasmFrame {
    /// The module name, when the engine resolved one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// The function name or index.
    pub func: String,
    /// The Wasm bytecode offset within the function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Source file, when DWARF debug info is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Source line, when DWARF debug info is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl fmt::Display for WasmFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `func (file:line)` when debug info is available, `func+offset` when
        // it is not. Both are useful; inventing a fake line number is not.
        match (&self.file, self.line) {
            (Some(file), Some(line)) => write!(f, "{} ({file}:{line})", self.func),
            _ => match self.offset {
                Some(off) => write!(f, "{}+0x{off:x}", self.func),
                None => f.write_str(&self.func),
            },
        }
    }
}

/// Convert one `Wasmtime` frame into QQQ's own.
///
/// # Why the function name is taken from `func_name` and not from a symbol
///
/// `Wasmtime` offers two names for a frame: `func_name`, from the module's name
/// section, and the DWARF symbols' names. The name section is present in every
/// build and needs no debug info; the DWARF symbol name is mangled, so it would
/// have to be demangled to be readable — and demangling is a heuristic that
/// occasionally returns something wrong.
///
/// So: the name section for the name, DWARF for the location. That split means a
/// frame is *named* even in an artifact built without `debug = true`, which is
/// the common case, and it keeps this function free of a demangler.
fn frame_from(info: &wasmtime::FrameInfo) -> WasmFrame {
    // `symbols()` is the DWARF-derived list; the first entry is the innermost
    // symbol at this instruction. It is empty when the module was compiled
    // without `debug_info`, which is the default — see `EngineConfig`.
    let symbol = info.symbols().first();

    WasmFrame {
        // The module's own name, when it has one. `Module::name()` reads the
        // name custom section and returns `None` for a stripped module.
        module: info.module().name().map(str::to_owned),
        func: info
            .func_name()
            .map_or_else(|| format!("func[{}]", info.func_index()), str::to_owned),
        // The instruction's offset within the module. This is what
        // `qqq_debug::SourceMap` is keyed on, so a detached report can be
        // resolved without the engine.
        offset: info.module_offset().map(|o| o as u64),
        file: symbol.and_then(|s| s.file().map(str::to_owned)),
        line: symbol.and_then(wasmtime::FrameSymbol::line),
    }
}

impl Trap {
    /// Build a trap from a raw engine error.
    #[must_use]
    pub fn from_engine_error(detail: &str) -> Self {
        let code = classify_trap(detail);
        Self {
            code,
            message: human_message(code).to_owned(),
            detail: detail.to_owned(),
            backtrace: Vec::new(),
            memory_peak_bytes: None,
            fuel_consumed: None,
        }
    }

    /// Build a trap from a real engine error, **keeping its frames**.
    ///
    /// # Why this exists next to [`from_engine_error`]
    ///
    /// `from_engine_error` takes a formatted string, which is what the caller
    /// has after `format!("{e:#}")` — and a formatted string has already lost
    /// the structured backtrace. `Instance::run` used it for that reason, so
    /// every real trap carried an **empty** `backtrace` while the field, the
    /// type and `with_backtrace` all existed. The gap was invisible because
    /// `with_backtrace` had tests: they built frames by hand and asserted on
    /// them, which proves the field can hold frames and nothing about whether
    /// anything ever puts them there (`§O-045a`).
    ///
    /// This constructor reads `Wasmtime`'s own backtrace, which is where the
    /// frames are free: the engine already walked them to produce the error, and
    /// with `debug_info` enabled it has resolved each one to a source file and
    /// line through the module's DWARF.
    ///
    /// # The two mechanisms, and when each applies
    ///
    /// | Situation | Source of frames |
    /// |---|---|
    /// | A live instance trapped | this function — `Wasmtime`'s frames, resolved in memory |
    /// | A trap report read later, with no engine | `qqq_debug::SourceMap`, extracted from the artifact |
    ///
    /// Both are needed and neither replaces the other. `Wasmtime` cannot resolve a
    /// frame after the engine is gone — that is the whole reason `qqq-debug`
    /// exists — and `qqq-debug` cannot name a *function*, which `Wasmtime` knows
    /// from the module's name section without any DWARF at all.
    #[must_use]
    pub fn from_wasmtime_error(err: &wasmtime::Error) -> Self {
        let mut trap = Self::from_engine_error(&format!("{err:#}"));

        let frames: Vec<WasmFrame> = err
            .downcast_ref::<wasmtime::WasmBacktrace>()
            .map(|bt| bt.frames().iter().map(frame_from).collect())
            .unwrap_or_default();

        if !frames.is_empty() {
            trap.backtrace = frames;
        }
        trap
    }

    /// Attach a parsed backtrace.
    #[must_use]
    pub fn with_backtrace(mut self, frames: Vec<WasmFrame>) -> Self {
        self.backtrace = frames;
        self
    }
    /// Attach the peak memory observed.
    #[must_use]
    pub fn with_memory_peak(mut self, bytes: u64) -> Self {
        self.memory_peak_bytes = Some(bytes);
        self
    }

    /// Attach the fuel consumed before the trap.
    #[must_use]
    pub fn with_fuel_consumed(mut self, fuel: u64) -> Self {
        self.fuel_consumed = Some(fuel);
        self
    }

    /// Whether the instance must be discarded rather than returned to the pool.
    ///
    /// Always `true` — see the module docs. It exists as a method so the
    /// decision is named and greppable at every call site, rather than being an
    /// implicit convention that a future contributor might not know.
    #[must_use]
    pub const fn must_discard_instance(&self) -> bool {
        true
    }

    /// Convert to the shared error type with a remediation.
    #[must_use]
    pub fn to_error(&self) -> Error {
        let mut e = Error::new(self.code, self.message.clone())
            .with_context("trap-detail", self.detail.clone());

        if let Some(peak) = self.memory_peak_bytes {
            e = e.with_context("memory-peak", format_bytes(peak));
        }
        if let Some(fuel) = self.fuel_consumed {
            e = e.with_context("fuel-consumed", fuel.to_string());
        }
        for (i, f) in self.backtrace.iter().enumerate() {
            e = e.with_cause(format!("frame {i}: {f}"));
        }

        e.with_remediation(remediation_for(self.code).to_owned())
    }

    /// Render for a terminal.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "{}  {}", self.code.id(), self.message);
        let _ = writeln!(out, "  detail: {}", self.detail);
        if let Some(p) = self.memory_peak_bytes {
            let _ = writeln!(out, "  memory peak: {}", format_bytes(p));
        }
        if let Some(f) = self.fuel_consumed {
            let _ = writeln!(out, "  fuel consumed: {f}");
        }
        if !self.backtrace.is_empty() {
            let _ = writeln!(out, "  backtrace:");
            for f in &self.backtrace {
                let _ = writeln!(out, "    {f}");
            }
        }
        let _ = writeln!(out, "\n  → {}", remediation_for(self.code));
        out
    }
}

/// The canonical one-sentence message for a trap code.
#[must_use]
pub const fn human_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::MemoryLimitExceeded => "the guest exceeded its declared memory limit",
        ErrorCode::FuelExhausted => "the guest exhausted its instruction budget",
        ErrorCode::EpochDeadlineExceeded => "the guest exceeded its wall-clock deadline",
        ErrorCode::InvalidResourceHandle => "the guest used an invalid or closed resource handle",
        ErrorCode::GuestPanic => "the guest panicked",
        ErrorCode::GuestOutOfBounds => "the guest accessed memory outside its linear memory",
        _ => "the guest trapped",
    }
}

/// The actionable fix for a trap code.
#[must_use]
pub const fn remediation_for(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::MemoryLimitExceeded => {
            "raise `limits.memory` in qqq.toml, or fix the leak — the peak is reported above"
        }
        ErrorCode::FuelExhausted => "raise `limits.fuel` in qqq.toml, or optimise the hot path",
        ErrorCode::EpochDeadlineExceeded => {
            "raise `limits.epoch_deadline_ms`; a guest that repeatedly hits this is usually \
             blocked on I/O it was not granted"
        }
        ErrorCode::InvalidResourceHandle => {
            "this is a guest bug; check handle lifetimes against the interface contract"
        }
        ErrorCode::GuestPanic => {
            "build with debug info (`qqqai build --debug`) for source-mapped frames"
        }
        ErrorCode::GuestOutOfBounds => {
            "this is a guest bug, not a limit to raise — fix the indexing or pointer arithmetic"
        }
        _ => "run with `--debug` for source-mapped frames",
    }
}

/// Format a byte count for a human, without pulling in a dependency.
///
/// # Precision note
///
/// The conversion to `f64` is deliberate and safe here. A byte count is
/// displayed with one decimal place, so any `u64` large enough to lose
/// precision in an `f64` mantissa (above 2^53 bytes, i.e. 8 PiB) would be
/// rendered identically at that precision anyway. The alternative — integer
/// arithmetic with manual rounding — is more code for no observable gain.
/// The cast is annotated rather than allowed crate-wide so this reasoning
/// stays local to the one place it applies.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    /// Convert for display, with the precision rationale above.
    #[allow(clippy::cast_precision_loss)]
    fn as_f64(v: u64) -> f64 {
        v as f64
    }

    if bytes >= GIB {
        format!("{:.1} GiB", as_f64(bytes) / as_f64(GIB))
    } else if bytes >= MIB {
        format!("{:.1} MiB", as_f64(bytes) / as_f64(MIB))
    } else if bytes >= KIB {
        format!("{:.1} KiB", as_f64(bytes) / as_f64(KIB))
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// These strings are pinned deliberately. They are the compatibility
    /// surface with Wasmtime: if an upgrade changes them, CI fails here rather
    /// than silently misclassifying a trap in production.
    #[test]
    fn wasmtime_fuel_message_classifies_as_fuel() {
        let detail = "error while executing at wasm backtrace:\n\
                      0: 0x1234 - <unknown>!spin\n\
                      Caused by:\n    all fuel consumed by WebAssembly";
        assert_eq!(classify_trap(detail), ErrorCode::FuelExhausted);
    }

    #[test]
    fn wasmtime_memory_limit_message_classifies_as_memory_limit() {
        for detail in [
            "memory minimum size of 2 pages exceeds memory limits",
            "failed to grow memory: resource limit exceeded",
            "cannot allocate memory: limit exceeded",
        ] {
            assert_eq!(
                classify_trap(detail),
                ErrorCode::MemoryLimitExceeded,
                "failed to classify: {detail}"
            );
        }
    }

    /// A genuine overrun is a **guest bug**, not a limit to raise. Conflating
    /// the two would send a developer hunting for a limit when the real fix is
    /// a code change — so this distinction is asserted explicitly.
    #[test]
    fn out_of_bounds_is_a_guest_bug_not_a_limit_violation() {
        for detail in [
            "wasm trap: out of bounds memory access",
            "out-of-bounds memory access at offset 0x1000",
        ] {
            assert_eq!(
                classify_trap(detail),
                ErrorCode::GuestOutOfBounds,
                "failed to classify: {detail}"
            );
        }
        // And the remediation must say so.
        let r = remediation_for(ErrorCode::GuestOutOfBounds);
        assert!(
            r.contains("not a limit to raise"),
            "the fix must steer away from raising a limit: {r}"
        );
    }

    #[test]
    fn wasmtime_epoch_message_classifies_as_deadline() {
        for detail in [
            "epoch deadline reached during execution",
            // The actual message Wasmtime emits for epoch preemption. It does
            // NOT contain the word "epoch", which is why the check has a
            // dedicated arm for it.
            "wasm trap: interrupt",
        ] {
            assert_eq!(
                classify_trap(detail),
                ErrorCode::EpochDeadlineExceeded,
                "failed to classify: {detail}"
            );
        }
    }

    #[test]
    fn wasmtime_unreachable_classifies_as_guest_panic() {
        assert_eq!(
            classify_trap("wasm trap: wasm `unreachable` instruction executed"),
            ErrorCode::GuestPanic
        );
        assert_eq!(
            classify_trap("panicked at src/lib.rs:42: assertion failed"),
            ErrorCode::GuestPanic
        );
    }

    #[test]
    fn unknown_details_fall_back_to_generic_trap() {
        assert_eq!(
            classify_trap("something entirely unexpected"),
            ErrorCode::GuestTrap
        );
        assert_eq!(classify_trap(""), ErrorCode::GuestTrap);
    }

    /// Ordering matters: fuel must win over a message that also mentions
    /// memory, or the wrong code reaches the caller.
    #[test]
    fn classification_prefers_the_most_specific_signature() {
        let both = "all fuel consumed; memory limit also mentioned";
        assert_eq!(classify_trap(both), ErrorCode::FuelExhausted);
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert_eq!(classify_trap("ALL FUEL CONSUMED"), ErrorCode::FuelExhausted);
        assert_eq!(
            classify_trap("Epoch DEADLINE reached"),
            ErrorCode::EpochDeadlineExceeded
        );
    }

    /// Every trap must discard its instance. This is a security property, not
    /// a performance one: a trapped instance may hold half-written state.
    #[test]
    fn every_trap_discards_the_instance() {
        for code in [
            ErrorCode::MemoryLimitExceeded,
            ErrorCode::FuelExhausted,
            ErrorCode::EpochDeadlineExceeded,
            ErrorCode::GuestTrap,
            ErrorCode::GuestPanic,
            ErrorCode::GuestOutOfBounds,
            ErrorCode::InvalidResourceHandle,
        ] {
            let t = Trap {
                code,
                message: human_message(code).to_owned(),
                detail: String::new(),
                backtrace: Vec::new(),
                memory_peak_bytes: None,
                fuel_consumed: None,
            };
            assert!(
                t.must_discard_instance(),
                "{code} must discard the instance"
            );
            assert!(!t.to_error().is_retryable(), "{code} must not be retryable");
        }
    }

    #[test]
    fn every_trap_code_has_a_message_and_a_remediation() {
        for code in [
            ErrorCode::MemoryLimitExceeded,
            ErrorCode::FuelExhausted,
            ErrorCode::EpochDeadlineExceeded,
            ErrorCode::GuestTrap,
            ErrorCode::GuestPanic,
            ErrorCode::GuestOutOfBounds,
            ErrorCode::InvalidResourceHandle,
        ] {
            assert!(!human_message(code).is_empty(), "{code} needs a message");
            assert!(
                !remediation_for(code).is_empty(),
                "{code} needs a remediation"
            );
            let t = Trap {
                code,
                message: human_message(code).to_owned(),
                detail: "detail".to_owned(),
                backtrace: Vec::new(),
                memory_peak_bytes: None,
                fuel_consumed: None,
            };
            let e = t.to_error();
            assert_eq!(e.code, code);
            assert!(e.remediation.is_some());
            assert!(e.render().contains(&code.id()));
        }
    }

    #[test]
    fn error_context_carries_the_diagnostics() {
        let t = Trap::from_engine_error("all fuel consumed by WebAssembly")
            .with_fuel_consumed(50_000_000)
            .with_memory_peak(2 * 1024 * 1024)
            .with_backtrace(vec![WasmFrame {
                module: Some("app".to_owned()),
                func: "handle_request".to_owned(),
                offset: Some(0x1a2b),
                file: Some("src/lib.rs".to_owned()),
                line: Some(42),
            }]);
        let e = t.to_error();
        assert_eq!(e.code, ErrorCode::FuelExhausted);
        assert!(e.context.iter().any(|(k, _)| k == "fuel-consumed"));
        assert!(e
            .context
            .iter()
            .any(|(k, v)| k == "memory-peak" && v.contains("MiB")));
        assert!(
            e.cause.iter().any(|c| c.contains("handle_request")),
            "the backtrace must reach the error: {:?}",
            e.cause
        );
        // Source-mapped frames include the location.
        assert!(e.cause.iter().any(|c| c.contains("src/lib.rs:42")));
    }

    #[test]
    fn frame_display_uses_source_when_available() {
        let mapped = WasmFrame {
            module: None,
            func: "f".to_owned(),
            offset: Some(0x10),
            file: Some("a.rs".to_owned()),
            line: Some(7),
        };
        assert_eq!(mapped.to_string(), "f (a.rs:7)");

        let unmapped = WasmFrame {
            module: None,
            func: "f".to_owned(),
            offset: Some(0x10),
            file: None,
            line: None,
        };
        assert_eq!(unmapped.to_string(), "f+0x10");

        let bare = WasmFrame {
            module: None,
            func: "f".to_owned(),
            offset: None,
            file: None,
            line: None,
        };
        assert_eq!(bare.to_string(), "f");
    }

    #[test]
    fn byte_formatting_is_readable() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.0 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn trap_serializes_for_the_audit_stream() {
        let t = Trap::from_engine_error("all fuel consumed")
            .with_fuel_consumed(1)
            .with_backtrace(vec![WasmFrame {
                module: None,
                func: "main".to_owned(),
                offset: None,
                file: None,
                line: None,
            }]);
        let j = serde_json::to_value(&t).unwrap();
        assert_eq!(j["code"], "QQQ-3002");
        assert_eq!(j["fuel_consumed"], 1);
        assert_eq!(j["backtrace"][0]["func"], "main");
        // Round-trips: an agent can consume and re-emit it.
        let back: Trap = serde_json::from_value(j).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn render_includes_the_fix() {
        let t = Trap::from_engine_error("memory limit exceeded");
        let out = t.render();
        assert!(out.contains("QQQ-3001"));
        assert!(out.contains("→"), "must show the fix: {out}");
        assert!(out.contains("limits.memory"));
    }
}
