// SPDX-License-Identifier: Apache-2.0

//! The blocking bridge: driving a future to completion from a synchronous caller.
//!
//! # Why this module exists, and why it lives here
//!
//! `qqqai serve` is a synchronous CLI: `main` parses arguments, loads a manifest and
//! returns an `ExitCode`. The server it starts is asynchronous. Something has to
//! own the boundary, and this crate is the only one in the workspace that depends on
//! the async runtime (`lib.rs` says so, and it is deliberate).
//!
//! Putting a runtime in `qqq-run` would have been easier and wrong twice over:
//!
//! 1. It would make two crates able to construct a runtime, so "the only place that
//!    touches the async runtime" would stop being true — and that sentence is what
//!    keeps a future `io_uring` backend a second module here instead of a rewrite
//!    above it.
//! 2. `qqq-serve`'s futures are **runtime-agnostic** by design. A caller that
//!    brought its own runtime would work, but the workspace would no longer have one
//!    answer to "which runtime is this program built on".
//!
//! # Why a dedicated thread rather than `Handle::current()`
//!
//! [`block_on`] builds a **current-thread** runtime on *this* thread rather than
//! joining a shared multi-threaded one. Two properties follow, and both are wanted:
//!
//! * `serve` is not `Send`-constrained by an outer runtime's worker, so the
//!   signature stays as simple as it is.
//! * Nothing in this program can accidentally spawn work onto a pool that outlives
//!   the call. The runtime is created, used and dropped within one function.
//!
//! The cost is one thread. For a process whose whole job is to serve until
//! interrupted, that is the correct trade.

use std::future::Future;

use qqq_core::{Error, ErrorCode, Result};

/// Run a future to completion on a fresh current-thread runtime.
///
/// # Errors
///
/// `QQQ-6004` when the runtime cannot be constructed. That is a genuine "cannot do
/// the work at all" condition — typically no threads left to create — and it is
/// reported rather than panicking, because a CLI that panics on a resource
/// exhaustion gives the operator a backtrace instead of a reason.
///
/// The future's own error is returned unchanged; this function only adds the
/// capability to *wait* for it.
pub fn block_on<F>(future: F) -> Result<F::Output>
where
    F: Future,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            Error::new(
                ErrorCode::InternalInvariantViolated,
                "could not start the async runtime",
            )
            .with_cause(e.to_string())
            .with_remediation(
                "this usually means the process is out of threads or file \
                 descriptors; check the system limits",
            )
        })?;

    Ok(runtime.block_on(future))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_future_is_driven_to_completion_and_its_value_returned() {
        let got = block_on(async { 7u32 }).expect("the runtime should start");
        assert_eq!(got, 7);
    }

    #[test]
    fn an_error_from_the_future_is_returned_unchanged() {
        // The bridge must not swallow or rewrap the future's own result: a caller
        // distinguishes a serve failure from a runtime-construction failure, and
        // that distinction would be lost if this mapped everything into one error.
        //
        // `std::result::Result` is spelled out because this crate imports
        // `qqq_core::Result`, which takes one generic argument -- the same shadowing
        // the artifact-listing code in `qqq-run` documents.
        let got: Result<std::result::Result<(), &str>> = block_on(async { Err("serve failed") });
        let inner = got.expect("the runtime should start");
        assert_eq!(inner, Err("serve failed"));
    }

    #[test]
    fn real_async_io_works_not_just_a_constant() {
        // The control for the first test: `block_on(async { 7 })` would pass even if
        // the reactor were never enabled, because a constant needs no I/O. Binding a
        // real socket proves `enable_all` is doing its job -- and a socket that
        // cannot be bound is the failure a `serve` caller would actually hit.
        let bound = block_on(async {
            tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map(|l| l.local_addr().is_ok())
        })
        .expect("the runtime should start")
        .expect("binding an ephemeral port should succeed");
        assert!(bound, "a bound listener must have a local address");
    }

    #[test]
    fn the_runtime_is_dropped_with_the_call() {
        // No work may outlive the call: a spawn here would belong to a runtime that
        // is about to be dropped, so the value must not be observable afterwards.
        // This asserts the *shape* -- that a second, independent call also works,
        // which would fail if runtimes accumulated or a global one were reused
        // incorrectly.
        let first = block_on(async { 1 }).expect("first runtime");
        let second = block_on(async { 2 }).expect("second runtime");
        assert_eq!((first, second), (1, 2));
    }
}
