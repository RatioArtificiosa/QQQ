//! # qqq-abi
//!
//! The QQQ host interfaces, defined in **WIT first** and implemented in Rust
//! second.
//!
//! ## The invariant
//!
//! > Every host capability is defined here in WIT before it is implemented.
//! > A host function without a WIT definition does not compile into a release
//! > build.
//!
//! That is what makes the multi-language claim *structural* rather than
//! aspirational: a capability expressible in WIT can be bound into every
//! language from a single definition, and one definition means the five
//! toolchains cannot disagree about what an interface does.
//!
//! ## What makes this crate load-bearing
//!
//! [`registry`] holds the **single** mapping from capability to interface. It is
//! used by both the runtime (`qqq-host` builds its linker from it) and the
//! static analyser (`qqqai inspect` reports from it). One mapping means the
//! security report a user reads and the enforcement the runtime performs cannot
//! drift apart — the difference between a report you can trust and one that
//! merely looks plausible.
//!
//! ## Checklist coverage
//!
//! `ABI-001` … `ABI-016`, `CON-011`, `CON-014`. See `QQQ-Proposal-V1.md` §6.3.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod registry;
pub mod wit;

pub use registry::{
    interface_for, interfaces, required_interfaces, unimplemented_capabilities, HostInterface,
};
pub use wit::{
    wit_source, AI_WIT, ALL_WIT, CLOCK_WIT, CRYPTO_WIT, DNS_WIT, ENV_WIT, FS_WIT, HTTP_WIT,
    KV_WIT, LOG_WIT, QUEUE_WIT, SECRETS_WIT, SQL_WIT, TRACE_WIT,
};
