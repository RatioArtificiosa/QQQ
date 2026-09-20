//! # qqq-pkg
//!
//! The dependency manager: content-addressed store, version solving, and the
//! lockfile.
//!
//! Implements Proposal §6.5 and Checklist `PKG-001` … `PKG-024`.
//!
//! ## Scope, stated honestly
//!
//! | Area | State |
//! |---|---|
//! | `qqq.lock` read/write, with a covering hash | **implemented** (`PKG-004`) |
//! | Capability diff between two lockfiles | **implemented** (`PKG-009`, §5.4) |
//! | Semver requirement parsing and matching | **implemented** (`PKG-003` partial) |
//! | Content-addressed store layout and verification | **implemented** (`PKG-001` partial) |
//! | Full dependency solver with backtracking | not implemented (`PKG-003`) |
//! | Registry client, fetching, resume | not implemented (`PKG-002`, `PKG-011`) |
//! | Signature verification and trust policy | not implemented (`PKG-015`) |
//! | `qqqai add` / `install` / `update` | not implemented (`CLI-005` … `CLI-007`) |
//! | The registry itself | not implemented (`PKG-006` … `PKG-008`, `PKG-012`) |
//! | First-party and ported packages | not implemented (`PKG-016`, `PKG-017`) |
//!
//! ## The one feature that is genuinely new
//!
//! Proposal §5.4: *"`caps` is recorded per dependency. `qqqai install` prints a
//! **capability diff** — 'this update adds `http.client` to `qqqai/telemetry`'.
//! Supply-chain attacks today hide in code; here the **authority** delta is
//! visible in the diff."*
//!
//! That is the reason this crate exists before the registry does. A dependency
//! update that adds no code changes but gains `http.client` is a supply-chain
//! event, and no mainstream package manager can currently show it. Building the
//! lockfile and its diff first means the property is designed in rather than
//! retrofitted onto a registry that was built without it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod lock;
pub mod semver;
pub mod store;

pub use lock::{CapabilityDelta, DependencyChange, LockDiff, LockPackage, Lockfile, LockfileError};
pub use semver::{Requirement, Version};
pub use store::{Digest, StoreLayout};
