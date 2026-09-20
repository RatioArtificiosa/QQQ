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

pub mod build;
pub mod commands;
pub mod manifest_loader;
pub mod output;
pub mod run;
/// `qqqai new` — the scaffold generator.
///
/// The module is named `scaffold` rather than `new` because `new` is a Rust
/// keyword and cannot be a module path segment. The file keeps its natural
/// name via `#[path]` so the directory listing still reads clearly.
#[path = "new.rs"]
pub mod scaffold;

pub use build::{
    plan, plan_pure, probe, rust_artifact_path, shell_quote, toolchain_for, verify_artifact,
    ArtifactKind, BuildOptions, BuildOutput, BuildPlan, ToolRequirement, COMPONENT_EXTENSION,
    OUTPUT_DIR,
};
pub use commands::{
    caps, classify_posture, developer_overlay, fix_stanza_for, inspect, why, CapsOutput,
    InspectOutput, InterfaceReport, LimitsReport, NamespaceGroup, Posture, WhyOutput, WhyStep,
};
pub use manifest_loader::{LoadedManifest, MANIFEST_NAME};
pub use output::{
    command_schemas, CommandName, CommandOutput, CommandSchema, Envelope, ErrorContextEntry,
    ErrorPayload, Format, Output,
};
pub use run::{
    capability_for_interface, check_imports, locate_artifact, new_engine, parse_cap_flag, prepare,
    resolve_grants, ImportCheck, Prepared, RunOptions, RunOutcome, RunOutput,
};
pub use scaffold::{
    crate_name, create, detect, files_for, init, manifest_for, readme_for, validate_name,
    Detection, DetectionSource, InitOptions, InitOutput, Language, NewOptions, NewOutput, Template,
    WrittenFile,
};
