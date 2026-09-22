// SPDX-License-Identifier: Apache-2.0

//! The request body, as a flat handler receives it.
//!
//! # Why this type exists, and why it is not just `Vec<u8>`
//!
//! `SRV-004` makes a body a `stream<u8>` end to end: backpressure propagates, and
//! nothing is fully buffered unless the manifest asked for it. A **flat** handler
//! cannot stream — it returns one `Response` — so giving it a `Vec<u8>` would silently
//! promise that the whole body is in memory, which for a 10 MiB upload against a
//! manifest cap of 10 MiB is true but expensive, and for a chunked body of unknown
//! length is a decision the *runtime* should be seen making.
//!
//! Hence a named type with the fact in it, and a variant that says so:
//!
//! | Variant | Meaning |
//! |---|---|
//! | [`BodyBytes::Absent`] | No body was declared. Not the same as an empty one. |
//! | [`BodyBytes::Buffered`] | The body was read into memory, up to the cap. |
//! | [`BodyBytes::TooLarge`] | The cap was reached. **The bytes are not here.** |
//!
//! # Why `Absent` and `Buffered(vec![])` are different
//!
//! `POST` with no `Content-Length` and `Content-Length: 0` are distinguishable on the
//! wire and mean different things to an application: the first is a request that
//! declares no body, the second a request that declares an empty one. A guest writing
//! `req.body.is_some()` should see that difference, so the server does not collapse it.
//!
//! # Why `TooLarge` is a variant rather than an error
//!
//! `drain_body` already refuses an over-cap body **before** the handler runs and closes
//! the connection (`SRV-005`: a request that exceeded the cap must not appear to
//! succeed). So a handler cannot normally observe `TooLarge`. The variant exists for
//! the one path that can produce it — a per-tenant cap that is stricter than the
//! global one — and it is reported rather than silently truncated, because a handler
//! that saw a short body it believed was complete would produce a wrong answer from
//! incomplete input.

use std::sync::Arc;

/// A request body, as a flat handler sees it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BodyBytes {
    /// The request declared no body.
    ///
    /// Distinct from `Buffered(vec![])`: a `Content-Length: 0` request is an empty
    /// body, and a request with neither framing header is no body at all.
    #[default]
    Absent,
    /// The body, read into memory.
    Buffered(Vec<u8>),
    /// The body exceeded a cap and was **not** read into memory.
    ///
    /// The bytes are deliberately absent rather than truncated. A handler acting on a
    /// truncated body would answer from incomplete input while believing it had the
    /// whole thing, which is worse than a refusal.
    TooLarge,
}

impl BodyBytes {
    /// The body's bytes, or an empty slice.
    ///
    /// # Why this returns an empty slice for `TooLarge`
    ///
    /// Because the alternative is a panic or an `Option`, and both push a decision into
    /// every caller. A handler that must distinguish the cases matches on the enum;
    /// one that only wants the bytes gets them and cannot be surprised by a truncation,
    /// because `TooLarge` never carries a partial body in the first place.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Buffered(b) => b,
            Self::Absent | Self::TooLarge => &[],
        }
    }

    /// The body's length, or zero.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Whether there are no bytes to read.
    ///
    /// True for both `Absent` and an empty `Buffered`. A caller that needs to tell
    /// those apart must match on the variant — which is the point of having them.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    /// Whether a body was declared at all.
    #[must_use]
    pub fn is_present(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

/// A handler that receives the request body.
///
/// # Why a second type instead of changing [`crate::server::Handler`]
///
/// `Handler` is `Fn(&RequestHead, &RouteMatch) -> Response`, and every flat route in
/// the workspace — twelve call sites across six integration tests and the guest bridge
/// — is written against it. Widening the signature would be a breaking change to
/// `qqq-serve`'s public API for callers that have no interest in the body, and it would
/// make "I ignore bodies" invisible in a type.
///
/// So the body-aware form is a **separate** type, registered separately, and a route
/// with no `BodyHandler` uses the flat one exactly as before. That is the same shape
/// `Dispatch` already uses for streaming and WebSocket handlers, and for the same
/// reason: the kinds differ, so the type says which is in use.
pub type BodyHandler =
    Arc<dyn Fn(&crate::http1::RequestHead, &BodyBytes) -> crate::response::Response + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_and_an_empty_buffer_are_different_facts() {
        // The distinction the server goes out of its way to preserve: a request that
        // declares no body versus one that declares an empty body.
        let absent = BodyBytes::Absent;
        let empty = BodyBytes::Buffered(Vec::new());

        assert_ne!(absent, empty);
        assert!(!absent.is_present(), "`Absent` declares no body");
        assert!(
            empty.is_present(),
            "an empty buffer is still a declared body"
        );

        // The convenience accessors deliberately agree, because code that only wants
        // bytes should not have to care.
        assert_eq!(absent.as_slice(), empty.as_slice());
        assert!(absent.is_empty() && empty.is_empty());
        assert_eq!(absent.len(), 0);
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn a_buffered_body_reports_its_bytes() {
        let b = BodyBytes::Buffered(b"id=7".to_vec());
        assert_eq!(b.as_slice(), b"id=7");
        assert_eq!(b.len(), 4);
        assert!(!b.is_empty());
        assert!(b.is_present());
    }

    #[test]
    fn too_large_carries_no_bytes_at_all() {
        // The property that makes truncation impossible to observe: `TooLarge` cannot
        // present a partial body, so a handler that ignores the variant sees an empty
        // body rather than half of one.
        let big = BodyBytes::TooLarge;
        assert_eq!(
            big.as_slice(),
            b"",
            "`TooLarge` must not carry a partial body"
        );
        assert!(big.is_empty());
        assert_eq!(big.len(), 0);
        assert!(
            big.is_present(),
            "a body was declared -- it simply was not read"
        );
    }

    #[test]
    fn the_default_is_absent_not_empty() {
        // `Default` matters because the server constructs a `BodyBytes` for a request
        // with no body, and deriving it the other way round would make "no body"
        // indistinguishable from "empty body" at exactly the call site that cares.
        assert_eq!(BodyBytes::default(), BodyBytes::Absent);
    }
}
