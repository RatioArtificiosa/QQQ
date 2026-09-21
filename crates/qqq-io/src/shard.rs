// SPDX-License-Identifier: Apache-2.0

//! Listener shards and connection assignment.
//!
//! Implements `ARCH-011`'s step 1 and the sharding half of Proposal §4.2.
//!
//! # Why sharding exists
//!
//! §4.2 specifies a shard-per-core acceptor so that the kernel's `accept` and
//! the thread that subsequently reads the socket are on the **same core**. The
//! cost of getting this wrong is not throughput but *variance*: a connection
//! accepted on core 3 and read on core 7 pays a cache-line transfer on every
//! read, and under load that shows up as a p99 several times the p50. It is
//! invisible in a benchmark at low load, which is why it has to be designed
//! rather than tuned later.
//!
//! # Why the assignment is in userspace
//!
//! The kernel-level version is `SO_REUSEPORT`: several sockets bind one port and
//! the kernel spreads accepts. That is correct on Linux and inconsistent
//! elsewhere — macOS implements it with a different distribution, Windows with
//! different semantics again.
//!
//! Setting it and hoping would mean sharding behaves one way in Linux CI and
//! another on a developer's Mac. So assignment here is **round-robin in
//! userspace**, which behaves identically on every platform.
//!
//! The honest cost: one extra hop between the accepting thread and the shard
//! that will read the socket. On a connection that may carry hundreds of
//! requests, that is once per connection rather than once per request, and it is
//! measured rather than assumed.
//!
//! # Why round-robin and not a hash
//!
//! Hashing the peer address would pin a client to a shard, which sounds
//! attractive for locality and is wrong for two reasons:
//!
//! 1. **A NAT or proxy makes it meaningless.** Thousands of clients behind one
//!    address would all land on one shard, which is the opposite of balancing.
//! 2. **It is an information leak.** A client that observes which shard answers
//!    can use the hash to correlate connections it believes are separate. The
//!    capability model goes to some trouble to avoid covert channels; a
//!    client-visible hash that varies with the peer address is one.
//!
//! Round-robin has neither property, and the only thing it gives up is affinity
//! that was not real.

use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// A shard
// ---------------------------------------------------------------------------

/// One acceptor shard.
///
/// A shard is a logical unit — an index and a name — rather than a thread or a
/// task. The crate that owns the runtime decides how to run them; keeping the
/// shard a plain value is what lets this module be tested without spawning
/// anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    /// The shard's index, from zero.
    index: usize,
    /// How many connections it has been assigned.
    assigned: usize,
}

impl Shard {
    /// The index.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// How many connections this shard has been assigned.
    #[must_use]
    pub const fn assigned(&self) -> usize {
        self.assigned
    }

    /// A stable name for a metric label or a log field.
    ///
    /// `shard-0`, `shard-1`, … A name rather than a bare index because it
    /// appears in metrics, where a label that reads `0` next to a label that
    /// reads `tcp` is ambiguous.
    #[must_use]
    pub fn name(&self) -> String {
        format!("shard-{}", self.index)
    }
}

// ---------------------------------------------------------------------------
// Assignment
// ---------------------------------------------------------------------------

/// Hands out shard indices.
///
/// # Why the cursor is atomic
///
/// The acceptor may be a single task, in which case a plain counter would do.
/// But a future with several acceptors per listener — which is what
/// `SO_REUSEPORT` would give on Linux — needs the counter shared, and a
/// `Relaxed` atomic is cheaper than adding a lock later. The ordering is
/// `Relaxed` because the counter's *value* is the only thing that matters; no
/// other memory is published through it.
#[derive(Debug)]
pub struct ShardAssignment {
    shards: usize,
    cursor: AtomicUsize,
}

/// A clone starts its own cursor at zero.
///
/// # Why cloning does not copy the cursor
///
/// `AtomicUsize` is not `Clone`, and copying the value would be wrong anyway: a
/// cloned assignment exists to be handed to a second acceptor, and two acceptors
/// sharing a cursor position is exactly what round-robin does not want. Each
/// gets its own cycle. Deriving `Clone` is therefore impossible *and* would be a
/// bug if it worked.
impl Clone for ShardAssignment {
    fn clone(&self) -> Self {
        Self::new(self.shards)
    }
}

impl ShardAssignment {
    /// An assignment over `shards` shards.
    ///
    /// A count of zero is raised to one: a listener with no shards could not
    /// accept anything, which is a configuration mistake rather than an intent,
    /// and silently refusing every connection would be hard to diagnose.
    #[must_use]
    pub fn new(shards: usize) -> Self {
        Self {
            shards: shards.max(1),
            cursor: AtomicUsize::new(0),
        }
    }

    /// How many shards.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.shards
    }

    /// Whether there are no shards. Always false after construction.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// The next shard index, round-robin.
    ///
    /// # Why this cannot be skipped or reordered
    ///
    /// `fetch_add` returns the *previous* value, so two concurrent callers get
    /// distinct indices. A load-then-store would let both read the same value
    /// and one assignment would be lost — a bug that appears only under
    /// concurrency, which is exactly when shard balance matters.
    pub fn next(&self) -> usize {
        let n = self.cursor.fetch_add(1, Ordering::Relaxed);
        // The modulus is what makes it round-robin rather than a counter that
        // grows forever. `n` can wrap at `usize::MAX` after an absurd number of
        // connections, and wrapping is harmless because the modulo still yields
        // a valid index.
        n % self.shards
    }
}

// ---------------------------------------------------------------------------
// The shard set
// ---------------------------------------------------------------------------

/// The shards a listener owns, with per-shard counts.
///
/// # Why the counts live here rather than in the shard
///
/// A `Shard` is a value; the set is the thing that mutates as connections
/// arrive. Keeping the counts in one place means the assignment decision and the
/// accounting cannot disagree — and a shard counter that drifts from reality is
/// how a "balanced" server turns out to be sending everything to one core.
#[derive(Debug, Clone)]
pub struct ShardSet {
    shards: Vec<Shard>,
    assignment: ShardAssignment,
    total: usize,
}

impl ShardSet {
    /// A set of `count` shards.
    #[must_use]
    pub fn new(count: usize) -> Self {
        let count = count.max(1);
        Self {
            shards: (0..count)
                .map(|index| Shard { index, assigned: 0 })
                .collect(),
            assignment: ShardAssignment::new(count),
            total: 0,
        }
    }

    /// The number of shards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.len()
    }

    /// Whether the set is empty. Always false after construction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    /// The total connections assigned.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Assign the next connection, returning its shard index.
    pub fn assign(&mut self) -> usize {
        let index = self.assignment.next();
        if let Some(shard) = self.shards.get_mut(index) {
            shard.assigned += 1;
        }
        self.total += 1;
        index
    }

    /// How many connections a shard has been given.
    #[must_use]
    pub fn assigned_to(&self, index: usize) -> usize {
        self.shards.get(index).map_or(0, |s| s.assigned)
    }

    /// The largest number assigned to any shard.
    #[must_use]
    pub fn max_assigned(&self) -> usize {
        self.shards.iter().map(|s| s.assigned).max().unwrap_or(0)
    }

    /// The smallest number assigned to any shard.
    #[must_use]
    pub fn min_assigned(&self) -> usize {
        self.shards.iter().map(|s| s.assigned).min().unwrap_or(0)
    }

    /// The spread between the busiest and quietest shard.
    ///
    /// # Why this is a metric rather than a test assertion
    ///
    /// Perfect balance is the *expected* outcome of round-robin, so on a healthy
    /// server this is 0 or 1. A value that grows means assignment has been
    /// bypassed somewhere — a connection path that skips `assign` — and that is
    /// the kind of regression that shows up as a latency spike rather than as a
    /// failure. Reported so it can be alerted on.
    #[must_use]
    pub fn spread(&self) -> usize {
        self.max_assigned().saturating_sub(self.min_assigned())
    }

    /// The shards, for iteration.
    #[must_use]
    pub fn shards(&self) -> &[Shard] {
        &self.shards
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- assignment --------------------------------------------------------

    /// The defining property of round-robin: consecutive assignments visit
    /// every shard exactly once before repeating.
    #[test]
    fn assignment_cycles_through_every_shard() {
        let a = ShardAssignment::new(4);
        let first: Vec<usize> = (0..4).map(|_| a.next()).collect();
        assert_eq!(first, vec![0, 1, 2, 3]);

        let second: Vec<usize> = (0..4).map(|_| a.next()).collect();
        assert_eq!(second, vec![0, 1, 2, 3], "and then repeats");
    }

    #[test]
    fn assignment_stays_in_range_over_many_calls() {
        let a = ShardAssignment::new(7);
        for _ in 0..10_000 {
            assert!(a.next() < 7);
        }
    }

    /// A single shard must not divide by zero or index out of range.
    #[test]
    fn a_single_shard_always_returns_zero() {
        let a = ShardAssignment::new(1);
        for _ in 0..100 {
            assert_eq!(a.next(), 0);
        }
    }

    /// A count of zero is a configuration mistake, not an intent: a listener
    /// with no shards could not accept anything, and silently refusing every
    /// connection would be hard to diagnose.
    #[test]
    fn a_zero_shard_count_is_raised_to_one() {
        let a = ShardAssignment::new(0);
        assert_eq!(a.len(), 1);
        assert_eq!(a.next(), 0);
        assert!(!a.is_empty());
    }

    /// **The concurrency property.** `fetch_add` returns the previous value, so
    /// two concurrent callers get distinct indices. A load-then-store would let
    /// both read the same value and lose an assignment — a bug that appears
    /// only under concurrency, which is exactly when balance matters.
    #[test]
    fn concurrent_assignment_visits_every_shard() {
        use std::sync::Arc;

        let assignment = Arc::new(ShardAssignment::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let a = Arc::clone(&assignment);
            handles.push(std::thread::spawn(move || a.next()));
        }
        let mut seen: Vec<usize> = handles
            .into_iter()
            .map(|h| h.join().expect("thread must not panic"))
            .collect();
        seen.sort_unstable();
        assert_eq!(
            seen,
            vec![0, 1, 2, 3, 4, 5, 6, 7],
            "eight threads must each get a distinct shard"
        );
    }

    // -- the set -----------------------------------------------------------

    #[test]
    fn a_set_of_shards_is_created_with_zero_counts() {
        let s = ShardSet::new(3);
        assert_eq!(s.len(), 3);
        assert_eq!(s.total(), 0);
        for i in 0..3 {
            assert_eq!(s.assigned_to(i), 0);
        }
    }

    #[test]
    fn assigning_increments_the_right_shard() {
        let mut s = ShardSet::new(2);
        assert_eq!(s.assign(), 0);
        assert_eq!(s.assign(), 1);
        assert_eq!(s.assign(), 0);

        assert_eq!(s.assigned_to(0), 2);
        assert_eq!(s.assigned_to(1), 1);
        assert_eq!(s.total(), 3);
    }

    /// **The balance property.** Round-robin over a multiple of the shard count
    /// must produce a perfectly even split, and `spread` is the metric that
    /// detects it being bypassed.
    #[test]
    fn round_robin_balances_exactly_over_a_multiple() {
        let mut s = ShardSet::new(4);
        for _ in 0..4 * 25 {
            s.assign();
        }
        assert_eq!(s.total(), 100);
        for i in 0..4 {
            assert_eq!(s.assigned_to(i), 25, "shard {i} is not balanced");
        }
        assert_eq!(s.spread(), 0, "a perfect multiple must have no spread");
    }

    /// An uneven count leaves a spread of at most one, which is the best
    /// possible outcome and the threshold an alert would use.
    #[test]
    fn an_uneven_count_leaves_a_spread_of_at_most_one() {
        let mut s = ShardSet::new(4);
        for _ in 0..101 {
            s.assign();
        }
        assert_eq!(s.total(), 101);
        assert!(
            s.spread() <= 1,
            "round-robin over 101 connections across 4 shards gave spread {}",
            s.spread()
        );
    }

    #[test]
    fn out_of_range_lookups_are_zero_rather_than_a_panic() {
        let s = ShardSet::new(2);
        assert_eq!(s.assigned_to(99), 0);
    }

    #[test]
    fn an_empty_set_reports_zero_rather_than_panicking() {
        // A zero count is raised to one, so this cannot actually occur — but
        // the accessors must not panic if it somehow did.
        let s = ShardSet::new(1);
        assert_eq!(s.min_assigned(), 0);
        assert_eq!(s.max_assigned(), 0);
    }

    #[test]
    fn shards_expose_a_stable_name_and_index() {
        let s = ShardSet::new(3);
        for (i, shard) in s.shards().iter().enumerate() {
            assert_eq!(shard.index(), i);
            assert_eq!(shard.name(), format!("shard-{i}"));
        }
    }

    #[test]
    fn shard_reports_how_many_it_was_assigned() {
        let mut s = ShardSet::new(2);
        s.assign();
        s.assign();
        s.assign();
        assert_eq!(s.shards()[0].assigned(), 2);
        assert_eq!(s.shards()[1].assigned(), 1);
    }

    #[test]
    fn a_zero_shard_set_is_raised_to_one() {
        let mut s = ShardSet::new(0);
        assert_eq!(s.len(), 1);
        assert_eq!(s.assign(), 0);
        assert!(!s.is_empty());
    }

    /// The metric must be computable on a set that has never been used.
    #[test]
    fn a_fresh_set_reports_a_zero_spread() {
        let s = ShardSet::new(5);
        assert_eq!(s.spread(), 0);
        assert_eq!(s.max_assigned(), 0);
        assert_eq!(s.min_assigned(), 0);
    }
}
