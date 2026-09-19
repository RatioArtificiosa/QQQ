//! # qqq-host
//!
//! The QQQ execution engine. Owns the Wasmtime engine and turns a component
//! plus a capability grant set into a running, limited, isolated instance.
//!
//! ## The two invariants this crate enforces
//!
//! 1. **A guest gets only the imports its grants name.** The linker is built
//!    *per instance* from the resolved grant set, so an ungranted capability is
//!    not merely denied at call time — it is **absent**, and instantiation
//!    fails with a clear code. Verified against the real toolchain.
//! 2. **A trap never takes down the host, and never reuses the instance.**
//!    Every trap discards; see [`trap`] for why that is a security property
//!    rather than a performance one.
//!
//! ## Protocol note
//!
//! Proposal §4.7 fixes the default guest concurrency model as
//! **async-single-threaded**: one logical task per request, using the Component
//! Model's `async`/`future`/`stream`. Shared linear memory is opt-in and
//! discouraged, because it undermines per-instance memory accounting — which is
//! a core security property.
//!
//! ## Checklist coverage
//!
//! `HOST-001` … `HOST-024`. See `QQQ-Proposal-V1.md` §6.1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod trap;

pub use config::{
    aot_cache_key, build_pooling, target_triple, EngineConfig, StoreLimits,
};
pub use trap::{
    classify_trap, format_bytes, human_message, remediation_for, Trap, WasmFrame,
};
