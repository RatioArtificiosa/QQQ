//! # qqq-run
//!
//! The `qqqai` command-line interface.
//!
//! ## The one rule
//!
//! **Every command supports `--json`, and a new command cannot ship without a
//! JSON shape.** Non-Negotiable #1 (`PRINCIPLES.md`) says an AI agent is a
//! first-class user; a command that prints prose and forgets `--json` is
//! invisible to every automated consumer. See [`output`] for the three
//! mechanisms that make the omission impossible rather than merely discouraged.
//!
//! ## Naming
//!
//! The binary, the crate and the npm package are all **`qqqai`**, because
//! `qqq` is taken on crates.io and npm (Observations `§D-001`). The brand is
//! **QQQ**. A build that produces a `qqq` binary is a defect.
//!
//! ## Checklist coverage
//!
//! `CLI-001` … `CLI-024`, `DX-001` … `DX-020`. See `QQQ-Proposal-V1.md` §5.2
//! and §6.6.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod output;

pub use output::{
    command_schemas, CommandName, CommandOutput, CommandSchema, Envelope, ErrorContextEntry,
    ErrorPayload, Format, Output,
};
