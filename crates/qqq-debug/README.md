# qqq-debug

DWARF source mapping for QQQ: turning a Wasm bytecode offset into a file and line
a human can open.

Implements the `qqq-debug` row of `QQQ-Proposal-V1.md` §4.3 and Checklist
`HOST-009`.

## The problem

A trap reports a **Wasm bytecode offset**. That is precise and useless: no tool a
developer owns can turn `offset 0x1a3` into a line of Rust.

Wasmtime resolves frames *in memory* when `debug_info` is enabled, but QQQ needs
the mapping in two places where there is no live engine to ask:

1. **A trap that crossed a process boundary** — the error travels as JSON to a
   log, a UI or an agent, and by then the engine is gone.
2. **A `.cwasm` cache** — the artifact is compiled once and reused, and the debug
   info that produced it is not necessarily alongside.

So the mapping is a **lookup table extracted from the artifact**, held
independently of any engine. Extraction is a pure function of the bytes.

## The rule

> **An unmapped frame reports no location. It never reports a guessed one.**

A trap with `file: None` says "there is no debug info here", which a reader
interprets correctly. A trap with a *wrong* file and line sends them somewhere
that does not explain the failure, and they will spend that time believing the
debug info is fine and their understanding is wrong.

Same asymmetry as the interface mapping in `§O-038b` and the remediation in
`§O-043a`: a confident wrong answer costs more than an absent one, and it costs
more the further from the author it travels.

## Where the DWARF lives, and why that was not obvious

A Rust `wasm32-wasip2` build emits DWARF in **custom sections of the core
module**: `.debug_info`, `.debug_line`, `.debug_abbrev` and the rest.

But `qqqai build` emits a **component** (layer 1), which wraps the core module
(layer 0) in section id `1`. The DWARF is one level down. A parser that walks the
outer section table finds a module wrapper and no custom sections — and reports
"no debug info" for an artifact `wasm-tools objdump` shows to be 265 KB of it.

Measured, not assumed: the first version of this crate did exactly that.

## What a project must do to have source lines

Two settings in the generated `Cargo.toml`, and both matter:

```toml
[profile.release]
debug = true
```

Without `debug`, there is no DWARF at all. With `lto = true` and **nothing
exported**, there is DWARF for the standard library and none for your own code —
because the linker eliminated it. A crate with no referenced symbols has no
frames to map.

`qqqai new` sets `debug = true`. The scaffolded template is a pure library with
no exported entry point, so its own source does not yet appear in the map; that
is closed by the guest ABI export, tracked separately.

## What is not built

| Area | State |
|---|---|
| Offset → file/line extraction | **implemented** |
| Range lookup (an offset inside a line's span) | **implemented** |
| Deterministic, serialisable map | **implemented** |
| Source **text** for context lines | not implemented |
| Function-name resolution from DWARF | not implemented — Wasmtime's frame info already names frames at trap time, which is free |
| Time-travel / reverse stepping (`FUT-009`) | not implemented |
| DevTools-protocol inspector (`DX-017`) | not implemented |
| Coverage (`TEST-004`) | not implemented |

The map deliberately carries **locations, not source text**. Shipping text would
mean the map's size tracks the source rather than the code, and a map extracted
on one machine could carry a file the reader should not see.

## Checklist coverage

`HOST-009`. See `QQQ-Proposal-V1.md` §4.3, §6.1, §10.5.
