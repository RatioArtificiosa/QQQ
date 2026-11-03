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
//! | Guest out of bounds (buffer overrun, not a limit) | `QQQ-3007` | no | **no** — discard |
//! | Contained host panic (host bug, never the guest's fault) | `QQQ-6007` | no | **no** — discard |
//! | Host allocation failure (host OOM, not guest usage) | `QQQ-6005` | yes | **no** — discard |
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
    // Bound the matching work: the checks below scan the whole text several
    // times over, and a megabyte backtrace tail carries no new signal kinds.
    // The engine puts the cause first and `frame_message` keeps only each
    // frame's engine-message suffix, so cutting past 64 KiB cannot hide a
    // signal the pinned fixtures (8 KiB in) establish. Cut on a character
    // boundary, like `truncate_detail` below.
    let mut cap = detail.len().min(64 * 1024);
    while !detail.is_char_boundary(cap) {
        cap -= 1;
    }
    let detail = &detail[..cap];
    // Backtrace frame names are guest-controlled (module and function names),
    // so a frame contributes only its engine-message suffix to matching: a
    // guest naming a function "all fuel consumed" must not reclassify its own
    // trap, forge a fuel metric, or trip the fuel remediation. Stripping the
    // whole frame line is wrong in the other direction — this engine version
    // embeds genuine signals in the frame line itself
    // (`0: 0x2d - m!f: wasm trap: all fuel consumed`) — so the prefix (index,
    // address, names) is cut and the trailing engine message is kept. The
    // `Caused by:` chain is engine diagnostics, never guest names, and is
    // kept whole, which is why the pinned fuel fixture (signal on the fourth
    // line) still classifies.
    let d: String = detail
        .lines()
        .map(frame_message)
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();

    // -- Fuel (most specific; its backtrace may mention anything) --------
    // Anchored to consumption/exhaustion wording, not the bare word: a bare
    // `contains("fuel")` matches `refuel` and any guest-echoed text, and the
    // engine's own signals all name consuming or exhausting the budget.
    if d.contains("fuel")
        && (d.contains("consum")
            || d.contains("exhaust")
            || d.contains("out of")
            || d.contains("limit"))
    {
        return ErrorCode::FuelExhausted;
    }

    // -- Host allocation failure -------------------------------------------
    // The engine could not allocate host memory (not guest linear memory,
    // which is `MemoryLimitExceeded` above). Reporting that as a guest trap
    // would send an operator to `--debug` a guest for a host-side OOM, so it
    // maps to the retryable host-resource code instead.
    if d.contains("out of memory")
        || d.contains("failed to allocate")
        || d.contains("allocation failed")
    {
        return ErrorCode::HostResourceExhausted;
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

    // -- Contained host panic (checked BEFORE the guest-panic heuristic) --
    // [`crate::guard::guard`] turns a panicking host function into a trap
    // whose message names the function and its containment. It contains the
    // word "panic", so without this arm it would classify as `GuestPanic` —
    // sending an operator to inspect the guest for a host defect, and
    // counting a host bug on the guest-panic metric. The marker is the whole
    // sentence the guard writes, not one word, so a guest that happens to
    // trap with "host function" in its own message still falls through to
    // the guest classes below.
    if d.contains("host function") && d.contains("the host contained it") {
        return ErrorCode::HostPanicContained;
    }

    // -- Guest panic ------------------------------------------------------
    // A Rust panic in a Wasm guest compiles to `unreachable`.
    if d.contains("unreachable") || d.contains("panic") {
        return ErrorCode::GuestPanic;
    }

    ErrorCode::GuestTrap
}

/// The engine-message suffix of a `format!("{err:#}")` line.
///
/// A Wasm backtrace frame looks like
/// `0: 0x2d - m!<wasm function 0>: wasm trap: all fuel consumed`: a decimal
/// index, a hex address, guest-controlled module/function names, then the
/// engine's own message after the first `": "` past the address. Everything else — the
/// engine's message lines and its `Caused by:` chain — is returned whole.
/// An unrecognized shape is also returned whole: dropping text the matcher
/// does not understand would turn a future Wasmtime format change into silent
/// misclassification, while keeping it preserves the old behaviour exactly.
///
/// The split takes the *first* `": "` after the address, because the engine's
/// own messages contain one (`"wasm trap: interrupt"`): splitting at the last
/// would truncate genuine signals to their tail (`"interrupt"`), which matches
/// nothing. A guest name containing `": "` can therefore smuggle a signal word
/// into the suffix — that shape is exotic (no toolchain emits it), and the
/// alternative of dropping the suffix loses genuine signals outright.
#[must_use]
fn frame_message(line: &str) -> &str {
    let Some((index, rest)) = line.trim_start().split_once(':') else {
        return line;
    };
    if index.trim().is_empty()
        || !index.trim().chars().all(|c| c.is_ascii_digit())
        || !rest.trim_start().starts_with("0x")
    {
        return line;
    }
    let Some((_, after_addr)) = rest.split_once(" - ") else {
        return line;
    };
    match after_addr.split_once(": ") {
        Some((_, message)) => message,
        None => "",
    }
}

/// The first classifiable message in an error chain, outermost first.
///
/// A chain of pure traps yields the top message, preserving the old
/// behaviour for errors with no engine signal anywhere in them.
#[must_use]
fn first_signal_in_chain(err: &wasmtime::Error) -> String {
    let mut top = String::new();
    for (depth, cause) in err.chain().enumerate() {
        let message = cause.to_string();
        if depth == 0 {
            top.clone_from(&message);
        }
        if classify_trap(&message) != ErrorCode::GuestTrap {
            return message;
        }
    }
    top
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
/// Cap a guest-influenced string kept in a stored record.
///
/// Module and function names come from the guest name section and file
/// paths from its DWARF: without a bound, one identifier prices unbounded
/// host memory across up to 64 kept frames. Offsets and line numbers are
/// integers, so capping names loses nothing the debugger keys on.
fn capped_name(s: &str, max_chars: usize) -> String {
    if s.len() <= max_chars {
        s.to_owned()
    } else {
        s.chars().take(max_chars).collect()
    }
}

fn frame_from(info: &wasmtime::FrameInfo) -> WasmFrame {
    // `symbols()` is the DWARF-derived list; the first entry is the innermost
    // symbol at this instruction. It is empty when the module was compiled
    // without `debug_info`, which is the default — see `EngineConfig`.
    let symbol = info.symbols().first();

    WasmFrame {
        // The module's own name, when it has one. `Module::name()` reads the
        // name custom section and returns `None` for a stripped module.
        module: info.module().name().map(|n| capped_name(n, 256)),
        func: info.func_name().map_or_else(
            || format!("func[{}]", info.func_index()),
            |n| capped_name(n, 256),
        ),
        // The instruction's offset within the module. This is what
        // `qqq_debug::SourceMap` is keyed on, so a detached report can be
        // resolved without the engine.
        offset: info.module_offset().map(|o| o as u64),
        file: symbol.and_then(|s| s.file().map(|f| capped_name(f, 512))),
        line: symbol.and_then(wasmtime::FrameSymbol::line),
    }
}

/// The most engine detail one trap keeps, in bytes.
///
/// Backtrace frames carry guest-controlled module and function names, so an
/// unbounded `detail` is an unbounded host allocation priced at one guest
/// identifier. Only what is *stored* (and rendered, and exported) is cut —
/// classification reads the 64 KiB head, and triage keeps the head, where the
/// engine puts the cause.
pub const MAX_TRAP_DETAIL_BYTES: usize = 4 * 1024;

fn truncate_detail(detail: &str) -> String {
    if detail.len() <= MAX_TRAP_DETAIL_BYTES {
        return detail.to_owned();
    }
    // Cut on a character boundary and mark it: a silent cut would read as a
    // complete record.
    let mut end = MAX_TRAP_DETAIL_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &detail[..end])
}

impl Trap {
    /// Build a trap from a raw engine error.
    #[must_use]
    pub fn from_engine_error(detail: &str) -> Self {
        let code = classify_trap(detail);
        Self {
            code,
            message: human_message(code).to_owned(),
            // Classified whole, stored cut: frame names are
            // guest-controlled, so the stored (rendered, exported) text is
            // bounded while the classifier still sees everything.
            detail: truncate_detail(detail),
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
    ///
    /// # Example
    ///
    /// A `wasi:cli/exit` is contained self-termination, not a crash: the
    /// guest abandoned its own request, and the status stays in the detail
    /// for triage.
    ///
    /// ```
    /// # use qqq_host::trap::Trap;
    /// let err = wasmtime::Error::new(wasmtime_wasi::I32Exit(0));
    /// let trap = Trap::from_wasmtime_error(&err);
    /// assert_eq!(trap.message, "the guest trapped");
    /// assert!(trap.detail.contains("Exited with i32 exit status"));
    /// ```
    #[must_use]
    pub fn from_wasmtime_error(err: &wasmtime::Error) -> Self {
        // `wasi:cli/exit` (H9): wasmtime-wasi surfaces `proc_exit` as
        // `I32Exit`, an ordinary error in the chain — the process does not
        // exit and other tenants are unaffected (one `GuestApp` holds one
        // store, so a guest can only abandon its own request). It maps to
        // `GuestTrap` deliberately: the guest terminated itself, which is
        // contained, and the status stays in `detail` for triage. The match
        // is on the type, not the message, so a future classifier arm cannot
        // re-read "exited" as a different class, and guest-controlled frame
        // names stay out of the decision entirely. The fallthrough below
        // agrees today (the message matches no other arm); this arm pins the
        // mapping against classifier drift rather than changing it.
        let exit = err
            .downcast_ref::<wasmtime_wasi::I32Exit>()
            .map(|exit| exit.0);
        // Classify from the error CHAIN, not the formatted string: chain
        // sources are engine diagnostics, while the alternate-format string
        // embeds backtrace frames whose module/function names are
        // guest-controlled. Classifying the formatted text lets a guest name
        // containing `": "` plus a signal word forge another class; walking
        // the chain keeps guest names out of the match entirely. The first
        // non-trap source wins (outermost first); a chain of pure traps falls
        // back to the top message, exactly as before. The stored `detail`
        // stays the full formatted error — the backtrace text belongs in
        // diagnostics even though it must not drive classification.
        let mut trap = Self::from_engine_error(&format!("{err:#}"));
        let code = match exit {
            Some(_) => ErrorCode::GuestTrap,
            None => classify_trap(&first_signal_in_chain(err)),
        };
        trap.code = code;
        human_message(code).clone_into(&mut trap.message);

        let frames: Vec<WasmFrame> = err
            .downcast_ref::<wasmtime::WasmBacktrace>()
            .map(|bt| bt.frames().iter().take(64).map(frame_from).collect())
            .unwrap_or_default();

        if !frames.is_empty() {
            trap.backtrace = frames;
        }
        trap
    }

    /// Attach a parsed backtrace.
    #[must_use]
    pub fn with_backtrace(mut self, mut frames: Vec<WasmFrame>) -> Self {
        // Bound the stored frames: a deep recursion could hand back
        // thousands, and the trap record lives in host memory.
        frames.truncate(64);
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
        ErrorCode::HostPanicContained => "a host function panicked and was contained",
        ErrorCode::HostResourceExhausted => "the host ran out of a system resource",
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
        ErrorCode::HostPanicContained => {
            "this is a host bug, not a guest bug: fix the panicking host function. \
             The SEV1 `host-panic-contained` log line names it"
        }
        ErrorCode::HostResourceExhausted => {
            "the host ran out of memory or file descriptors, not the guest out of \
             its budget: retry after backoff, otherwise raise OS limits"
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

    /// These strings are pinned deliberately. They are the compatibility
    /// surface with Wasmtime: if an upgrade changes them, CI fails here rather
    /// than silently misclassifying a trap in production.
    #[test]
    fn an_oversize_detail_is_stored_truncated_not_dropped() {
        // Classification still sees the whole text: the signal sits past
        // the cut, and the code must not change because storage did.
        let signal = "Caused by:\n    all fuel consumed by WebAssembly";
        let big = format!("{}{}", "f".repeat(8 * 1024), signal);
        let trap = Trap::from_engine_error(&big);
        assert_eq!(
            trap.code,
            ErrorCode::FuelExhausted,
            "classification reads the full text, not the stored prefix"
        );
        assert!(
            trap.detail.len() < big.len(),
            "the stored detail is bounded"
        );
        assert!(
            trap.detail.ends_with("[truncated]"),
            "a cut is marked, never silent"
        );
        // Short details pass through untouched.
        let short = Trap::from_engine_error("all fuel consumed by WebAssembly");
        assert_eq!(short.detail, "all fuel consumed by WebAssembly");
        assert_eq!(short.code, ErrorCode::FuelExhausted);
    }

    /// Stored backtraces are bounded: a deep recursion must not grow host
    /// memory without limit.
    #[test]
    fn backtrace_frames_are_capped() {
        let frames: Vec<WasmFrame> = (0u64..200)
            .map(|i| WasmFrame {
                module: Some("m".to_owned()),
                func: format!("f{i}"),
                offset: Some(i),
                file: None,
                line: None,
            })
            .collect();
        let trap = Trap::from_engine_error("test").with_backtrace(frames);
        assert_eq!(trap.backtrace.len(), 64);
    }

    /// Classification reads the 64 KiB head, not the whole megabyte:
    /// a giant backtrace tail prices bounded work, and the engine puts
    /// the cause first, so the verdict cannot change past the cut.
    #[test]
    fn classification_is_bounded_but_sees_past_storage() {
        let mut detail = String::from("all fuel consumed by WebAssembly");
        detail.push_str(&"x".repeat(1024 * 1024));
        assert_eq!(classify_trap(&detail), ErrorCode::FuelExhausted);
    }

    /// Stored frame strings are bounded: a guest-controlled name cannot
    /// grow host memory without limit across the 64 kept frames.
    #[test]
    fn frame_name_lengths_are_capped() {
        assert_eq!(capped_name(&"m".repeat(300), 256).chars().count(), 256);
        assert_eq!(capped_name("short", 256), "short");
    }
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

    /// `wasi:cli/exit` is contained self-termination, never a crash: the
    /// guest abandoned its own request, which classifies as `GuestTrap`.
    /// The mapping is pinned here so a future classifier arm cannot silently
    /// re-read "exited" as a different class (H9).
    #[test]
    fn a_guest_exit_classifies_as_a_contained_trap() {
        for status in [0, 1] {
            let err = wasmtime::Error::new(wasmtime_wasi::I32Exit(status));
            let trap = Trap::from_wasmtime_error(&err);
            assert_eq!(
                trap.code,
                ErrorCode::GuestTrap,
                "exit({status}) must stay a contained trap"
            );
            assert!(
                trap.detail.contains("Exited with i32 exit status"),
                "the status must stay in the detail for triage: {}",
                trap.detail
            );
        }
        // Engine wrapping (context layers between the embedder and the
        // `I32Exit`) must not lose the mapping: downcast walks the chain.
        let wrapped = wasmtime::Error::new(wasmtime_wasi::I32Exit(0))
            .context("error while executing at wasm backtrace");
        assert_eq!(
            Trap::from_wasmtime_error(&wrapped).code,
            ErrorCode::GuestTrap,
            "a context-wrapped exit must stay a contained trap"
        );
    }

    #[test]
    fn a_contained_host_panic_is_a_host_fault_not_a_guest_panic() {
        // The exact sentence `guard` writes: the function name varies, the
        // frame does not. Without the dedicated arm this contains "panic"
        // and would classify as `GuestPanic` — blaming the guest for a host
        // defect on both the report and the metric.
        assert_eq!(
            classify_trap("host function `qqq:crypto/digest` panicked; the host contained it"),
            ErrorCode::HostPanicContained
        );
        // And the guest class still fires for real guest panics.
        assert_eq!(
            classify_trap("panicked at src/lib.rs:42: assertion failed"),
            ErrorCode::GuestPanic
        );
    }

    #[test]
    fn a_host_allocation_failure_is_not_a_guest_trap() {
        for detail in [
            "failed to allocate 1073741824 bytes for linear memory",
            "memory allocation failed: out of memory",
        ] {
            assert_eq!(
                classify_trap(detail),
                ErrorCode::HostResourceExhausted,
                "host OOM must not blame the guest: {detail:?}"
            );
        }
        let trap = Trap::from_engine_error("failed to allocate 64 bytes");
        assert!(
            trap.to_error().is_retryable(),
            "host OOM is transient: retry"
        );
    }

    #[test]
    fn a_bare_fuel_mention_is_not_a_classification() {
        // The anchor is consumption/exhaustion wording: "refuel" and bare
        // mentions must not trip the fuel metric or remediation.
        assert_eq!(
            classify_trap("call refuel() before continuing"),
            ErrorCode::GuestTrap
        );
        // While the engine's own signals still fire.
        assert_eq!(
            classify_trap("all fuel consumed by WebAssembly"),
            ErrorCode::FuelExhausted
        );
    }

    #[test]
    fn a_forged_frame_name_does_not_reclassify_the_trap() {
        // A guest that names a function after another class's signal must not
        // move its own trap into that class: only the frame's engine-message
        // suffix classifies, never the guest-controlled names.
        for forged in [
            "error while executing at wasm backtrace:\n\
             0: 0x1234 - <unknown>!all fuel consumed by WebAssembly",
            "error while executing at wasm backtrace:\n\
             0: 0x1234 - <unknown>!memory limit exceeded",
        ] {
            assert_eq!(
                classify_trap(forged),
                ErrorCode::GuestTrap,
                "a frame-named signal must not match: {forged:?}"
            );
        }
        // And cutting the names must not eat genuine signals this engine
        // version embeds in frame lines.
        for (frame, code) in [
            (
                "error while executing at wasm backtrace:\n\
                 0: 0x2d - m!<wasm function 0>: wasm trap: all fuel consumed by WebAssembly",
                ErrorCode::FuelExhausted,
            ),
            (
                "error while executing at wasm backtrace:\n\
                 0: 0x2d - m!<wasm function 0>: wasm trap: interrupt",
                ErrorCode::EpochDeadlineExceeded,
            ),
        ] {
            assert_eq!(
                classify_trap(frame),
                code,
                "a real signal in the frame suffix must still classify"
            );
        }
        // And stripping frames must not eat the engine's own signal, which
        // lives in the `Caused by:` chain the filter keeps.
        assert_eq!(
            classify_trap(
                "error while executing at wasm backtrace:\n\
                 0: 0x1234 - <unknown>!spin\n\
                 Caused by:\n    all fuel consumed by WebAssembly"
            ),
            ErrorCode::FuelExhausted
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
            ErrorCode::HostPanicContained,
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
            ErrorCode::HostPanicContained,
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
        assert!(
            e.context
                .iter()
                .any(|(k, v)| k == "memory-peak" && v.contains("MiB"))
        );
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
