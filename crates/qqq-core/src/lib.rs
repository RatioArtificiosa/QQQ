// SPDX-License-Identifier: Apache-2.0

//! # qqq-core
//!
//! Shared types for the QQQ runtime: identifiers, the version model, and the
//! stable [`ErrorCode`]-based error contract.
//!
//! **This crate performs no I/O.** That is deliberate: it sits at the bottom of
//! the dependency graph (Proposal §4.3) and every other crate depends on it, so
//! keeping it pure keeps the whole workspace's compile times and its test
//! surface small.
//!
//! ## The error contract
//!
//! Every failure carries a stable `QQQ-<class><nnn>` code with a permanent
//! documentation URL, an optional cause chain, and an actionable remediation.
//! `message` is **explicitly unstable** — do not parse it; match on `code`.
//!
//! ```
//! use qqq_core::{Error, ErrorCode};
//!
//! let err = Error::new(ErrorCode::CapabilityDenied, "sql.query is not granted")
//!     .with_context("component", "orders-api")
//!     .with_remediation("add [[capabilities.sql]] to qqq.toml");
//!
//! assert_eq!(err.id(), "QQQ-4003");
//! assert!(!err.is_retryable()); // deterministic: retrying cannot help
//! print!("{}", err.render());
//! ```
//!
//! ## Naming
//!
//! The brand is **QQQ**; the executable, crate and package are **`qqqai`**
//! (Observations `§D-001` — `qqq` is taken on crates.io and npm). Both values
//! are exposed as constants in [`ids`] so the decision cannot drift.
//!
//! ## Checklist coverage
//!
//! Implements `ARCH-007`, `ARCH-008`, `CON-009`, `CON-016`, `AGENT-021`,
//! `AGENT-022`. See `QQQ-Proposal-V1.md` §4.3 and §8.3.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// The crate is a library whose whole purpose is a stable public API; the
// pedantic lint set is valuable but a few rules fight that purpose directly.
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod ids;

pub use error::{Error, ErrorClass, ErrorCode, Result};
pub use ids::{
    ComponentId, IdError, PackageName, TenantId, Version, VersionParseError, BINARY_NAME,
    BRAND_NAME, MAX_ID_LEN, SCHEMA_VERSION, VERSION, WASI_TARGET_VERSION, WASMTIME_LINE,
};

#[cfg(test)]
mod integration_tests {
    //! Cross-module invariants that belong to no single module.

    use super::*;

    /// The two halves of the naming decision must agree everywhere they appear.
    #[test]
    fn naming_is_consistent_across_the_crate() {
        assert_eq!(BINARY_NAME, "qqqai");
        assert_eq!(BRAND_NAME, "QQQ");
        assert!(
            !BINARY_NAME.contains("qqq-"),
            "the binary name must not be hyphenated"
        );
    }

    /// Every error can be rendered, and its docs URL is well-formed and
    /// round-trips back to the same code.
    #[test]
    fn every_error_has_a_renderable_block_and_valid_url() {
        for &code in ErrorCode::all() {
            let e = Error::new(code, "synthetic message for rendering");
            let block = e.render();
            assert!(
                block.contains(&code.id()),
                "rendered block must contain the code id for {code}"
            );
            let url = code.docs_url();
            assert!(
                url.starts_with("https://qqq.codes/errors/QQQ-"),
                "docs url has the wrong shape: {url}"
            );
            let tail = url.rsplit('/').next().unwrap();
            assert_eq!(
                ErrorCode::parse(tail),
                Some(code),
                "docs url for {code} does not round-trip"
            );
        }
    }

    /// A tenant id and a component id are not distinguished by the wire
    /// format, so the *consumer* must name the right type. This test documents
    /// that the risk is handled by naming discipline, not by the format.
    #[test]
    fn serde_does_not_distinguish_id_types() {
        let j = serde_json::to_string(&TenantId::new("acme").unwrap()).unwrap();
        let as_component: ComponentId = serde_json::from_str(&j).unwrap();
        assert_eq!(as_component.as_str(), "acme");
    }

    /// The version constants must be mutually consistent and parsable, so a
    /// release cannot ship a broken `qqqai schema --all`.
    #[test]
    fn version_constants_are_parsable() {
        VERSION.parse::<Version>().expect("runtime version");
        SCHEMA_VERSION.parse::<Version>().expect("schema version");
    }
}
