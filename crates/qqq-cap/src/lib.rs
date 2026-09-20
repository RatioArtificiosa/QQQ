//! # qqq-cap
//!
//! The QQQ capability engine — **the single authority gate**, and the subsystem
//! that justifies the project (`QQQ-Proposal-V1.md` §6.2).
//!
//! ## The one rule that matters
//!
//! > A capability is denied unless something explicitly granted it, and **no
//! > configuration layer may ever widen a grant. Overlays may only narrow.**
//!
//! This is what makes "the manifest is the truth" a *property* rather than a
//! promise. Every other crate trusts this one to enforce it.
//!
//! ## The resolution pipeline
//!
//! ```text
//! qqq.toml [capabilities]
//!         │
//!         ▼
//!  1. PARSE       validate, rejecting unknown names with a suggestion
//!  2. NORMALIZE   expand patterns, resolve secret refs, canonicalize paths
//!  3. DEVELOPER   developer overlay  ─┐
//!  4. ORGANIZATION Fabric policy      ├─ may only NARROW
//!  5. PLATFORM    deployment config  ─┘
//!  6. RESOLVE     → Grants
//!  7. BIND        → per-instance linker (in qqq-host)
//!  8. RECORD      → digest into the audit stream
//! ```
//!
//! ## Why the narrowing rule is enforced structurally
//!
//! Overlays are applied through a narrowing operation that computes a **set
//! intersection** and cannot express a widening — there is no code path that
//! adds a capability. A test proves that applying every overlay in *every*
//! order yields the same, smallest result.
//!
//! ## Checklist coverage
//!
//! `CAP-001` … `CAP-016`, `SEC-001`, `SEC-003`. See Proposal §6.2.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod capability;
pub mod manifest;
pub mod normalize;
pub mod resolve;

pub use capability::{
    Capability, CapabilityKind, CapabilitySelector, Namespace, UnknownCapability,
};
pub use manifest::{
    group_by_namespace, ByteSize, Capabilities, ClockCapability, CryptoCapability, DnsCapability,
    EnvCapability, FsCapability, FsMode, HttpCapability, Manifest, ManifestError, Package,
};
pub use normalize::{
    path_is_within, FsGrant, HostEnv, HostPattern, NormalizeError, Normalized, RealEnv, SecretRef,
};
pub use resolve::{
    denial, CapabilityExplanation, GrantSet, Layer, NarrowMode, Overlay, Resolution, WhyNode,
};
