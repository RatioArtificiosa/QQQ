//! # qqq-io
//!
//! The reactor abstraction: accept loops, listener sharding, and readiness.
//!
//! Implements the transport half of Proposal §4.4 step 1 (*"LISTENER SHARD —
//! kernel accepts; shard thread picks it up (same core)"*) and the listener
//! portion of §4.2's process and thread model.
//!
//! ## Why this is a separate crate
//!
//! Two reasons, and the second is the one that matters:
//!
//! 1. **It is the only place that touches the async runtime.** Everything above
//!    it — `qqq-serve`'s routing, parsing and connection state — is synchronous
//!    and pure. Keeping the runtime at the bottom means a future `io_uring`
//!    backend is a second module here rather than a rewrite above.
//! 2. **Sharding is where the performance claim is either real or not.** §4.2
//!    specifies shard-per-core with same-core accept, so the kernel's accept and
//!    the thread that reads the socket are on one CPU. Getting that wrong is
//!    invisible at low load and decisive at high load, so it is isolated where
//!    it can be reasoned about rather than buried in the server.
//!
//! ## What is implemented, and what is not
//!
//! | Area | State |
//! |---|---|
//! | Listen-address parsing and validation | **implemented** |
//! | Round-robin shard assignment | **implemented** |
//! | Accept admission (backpressure at the accept point) | **implemented** |
//! | Cooperative shutdown signalling | **implemented** |
//! | Accept loop over `TcpListener` | **implemented** |
//! | `io_uring` backend | not implemented — Linux-only, tracked as `FUT-*` |
//! | Socket tuning beyond `TCP_NODELAY` and `SO_REUSEADDR` | not implemented |
//!
//! ## Why `SO_REUSEPORT` is deliberately *not* set
//!
//! Proposal §4.2 implies kernel-side sharding, and `SO_REUSEPORT` is the classic
//! way to build it: several sockets bind the same port and the kernel spreads
//! accepts across them.
//!
//! It is the right answer on Linux and **does not behave consistently
//! elsewhere**. macOS implements it but distributes differently; Windows has it
//! in recent versions with different semantics again. Setting it and hoping
//! would mean sharding behaves one way in Linux CI and another on a developer's
//! Mac — precisely the class of platform divergence §4.2 exists to prevent.
//!
//! So this crate implements **userspace round-robin assignment**: one acceptor,
//! connections handed to shards in order. That behaves identically everywhere.
//! The kernel-level version is a documented optimisation for a later round, not
//! a silent divergence now. The cost is one extra hop on the accept path, which
//! is measured rather than assumed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod listener;
pub mod shard;

pub use listener::{
    parse_listen_addr, AcceptError, ListenAddr, Listener, ListenerConfig, Shutdown,
};
pub use shard::{Shard, ShardAssignment, ShardSet};
