// SPDX-License-Identifier: Apache-2.0

//! Resource-handle tables: pooling and lifetime diagnostics -- `HOST-022`.
//!
//! # What a handle is, and why the table matters
//!
//! §4.5 prices a resource handle at *"~10-30 ns + table slot"* and §6.1 lists
//! *"open handles"* among the limits a breach must trap on. Both facts point at
//! the same structure: a per-instance table that maps an integer the guest holds
//! to a host-side value, allocating and freeing slots as the guest creates and
//! drops resources.
//!
//! Three requirements follow, and they pull in different directions:
//!
//! | Requirement | Source | Consequence |
//! |---|---|---|
//! | Creation is ~tens of ns | §4.5 | Slot allocation must be O(1) and allocation-free |
//! | `max_open_handles` is enforced | §6.1 | The table must *refuse*, not grow |
//! | Handles have documented lifetimes | §4.5 | Generation checking, or a freed slot reused by a new resource is indistinguishable from the old one |
//!
//! # The core problem: a handle must not be forgeable or recyclable
//!
//! An integer handle the guest holds is **guest-controlled input**. Two attacks
//! follow directly:
//!
//! 1. **Forgery.** The guest passes `9999` when only three handles exist. The
//!    table must answer "no such handle" rather than indexing out of bounds or
//!    panicking.
//! 2. **Recycling.** The guest closes handle 3, the host allocates handle 3 for a
//!    *different* resource, and the guest (or a stale copy of a pointer) uses the
//!    old value. It now reaches a resource it never opened legitimately. This is
//!    a real class of bug — it is how use-after-free becomes a security issue in
//!    systems that use bare indices.
//!
//! The fix for both is a **generation counter** packed into the handle alongside
//! the slot index: a slot's generation increments on every free, and a handle
//! whose generation does not match is rejected. A recycled slot is therefore
//! *unaddressable* by the stale handle, which turns a use-after-free into a clean
//! error.
//!
//! # The packing, and why it is a decision
//!
//! ```text
//!  63            32 31                             0
//! ┌────────────────┬───────────────────────────────┐
//! │  generation    │           slot index          │
//! └────────────────┴───────────────────────────────┘
//! ```
//!
//! 32 bits of slot index is far beyond `max_open_handles = 256` and leaves 32 bits
//! of generation — 4 billion reuses of one slot before it could wrap, which at
//! one million allocations per second is over an hour of continuous churn *in the
//! same slot*. When it does wrap, the table **refuses** rather than reusing the
//! generation ([`HandleTable::insert`]), so the wrap is an error rather than a
//! silent unsoundness.
//!
//! # Why this does not use Wasmtime's resource machinery
//!
//! Wasmtime has its own handle tables for Component Model `resource` types, and
//! those are what a guest's `own<T>`/`borrow<T>` lower to. This table is for
//! **QQQ's own host-side handles** — the file descriptors, database connections
//! and sockets that `qqq:fs`, `qqq:sql` and `qqq:http` will hand out, which need
//! limit accounting that is independent of what the component model does, because
//! `max_open_handles` is a QQQ manifest field rather than a component-model
//! concept.

use qqq_core::{Error, ErrorCode, Result};

/// A guest-visible handle: a slot index plus a generation.
///
/// Opaque to the guest, which receives it as a `u64` and can only pass it back.
/// Not `Ord`/`Hash`-derived beyond what is useful: a handle is an identity, not a
/// number to be reasoned about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(u64);

impl Handle {
    /// The number of bits used for the generation.
    const GENERATION_BITS: u32 = 32;
    /// The mask selecting the slot index.
    const SLOT_MASK: u64 = (1 << Self::GENERATION_BITS) - 1;

    /// Pack a slot index and generation.
    ///
    /// # Panics
    ///
    /// Panics if `slot` does not fit in 32 bits. That is unreachable from
    /// [`HandleTable`], whose slot count is bounded by `max_open_handles`, and a
    /// panic is the right response to an impossible state rather than a
    /// truncation that would alias two slots.
    #[must_use]
    fn pack(slot: u32, generation: u32) -> Self {
        assert!(
            u64::from(slot) <= Self::SLOT_MASK,
            "slot index {slot} exceeds the 32-bit field; the table is misconfigured"
        );
        Self((u64::from(generation) << Self::GENERATION_BITS) | u64::from(slot))
    }

    /// The slot index.
    #[must_use]
    const fn slot(self) -> u32 {
        (self.0 & Self::SLOT_MASK) as u32
    }

    /// The generation.
    #[must_use]
    const fn generation(self) -> u32 {
        (self.0 >> Self::GENERATION_BITS) as u32
    }

    /// The raw value a guest holds.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Interpret a raw `u64` from the guest.
    ///
    /// # Why this is not a constructor
    ///
    /// It produces a *candidate*. Nothing here validates that the handle names a
    /// live resource — only the table can, because only the table knows what is
    /// live. Making this a `from_raw` that returned a usable handle would invite a
    /// caller to skip the lookup, which is the forgery attack.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

impl std::fmt::Display for Handle {
    /// `index:generation`, which is what an operator needs to see in a diagnostic
    /// and what makes a recycled slot obvious when two handles are compared.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.slot(), self.generation())
    }
}

/// One table slot.
#[derive(Debug, Clone)]
enum Slot<T> {
    /// Occupied by a live resource.
    Live {
        /// The live resource.
        value: T,
        /// The generation this slot's handle carries.
        generation: u32,
    },
    /// Free, and remembering the generation a *future* handle will carry.
    ///
    /// The generation is stored rather than derived from a counter so that a slot
    /// reused after an intervening free cannot resurrect an old handle: the
    /// number only ever moves forward.
    Free {
        /// The generation the next allocation in this slot will use.
        next_generation: u32,
    },
}

/// A per-instance table of host-side resource handles.
///
/// # Why it is not `Sync`
///
/// Each instance has its own table (§4.4 step 7: grants and limits are per
/// instance), and a table is reached only from that instance's execution, which
/// is single-threaded by the `§D-006` default. Requiring `Sync` would force a
/// lock into the hot path for a contention that does not exist.
#[derive(Debug)]
pub struct HandleTable<T> {
    slots: Vec<Slot<T>>,
    /// How many slots are live, maintained incrementally.
    ///
    /// Maintained rather than counted on demand: `open()` is read on every
    /// `insert` to enforce the limit, so counting would make insertion O(n) and
    /// turn a paginated workload into a quadratic one.
    live: usize,
    /// The limit from `limits.max_open_handles`.
    limit: u32,
    /// Diagnostic counters, which is the "lifetime diagnostics" half of the item.
    stats: HandleStats,
}

/// Lifetime diagnostics for one table.
///
/// # Why these are counters and not just the live count
///
/// A guest that opens 256 handles, closes 256, opens 256 again is healthy. A guest
/// that never closes is **leaking**, and the two look identical if only the live
/// count is tracked. `opened` and `closed` together are what make a leak visible,
/// and `refused` is what makes an exhausted limit visible before it becomes an
/// outage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandleStats {
    /// Handles handed out since the table was created.
    pub opened: u64,
    /// Handles explicitly dropped.
    pub closed: u64,
    /// Insertions refused because the limit was reached.
    pub refused: u64,
    /// Lookups rejected because the handle named no live resource.
    ///
    /// **The security counter.** A steady non-zero value means a guest is
    /// guessing handles, holding stale ones, or has a bug — and in the first case
    /// it is an attack signature.
    pub invalid: u64,
    /// Slots whose generation counter wrapped and were retired.
    ///
    /// Expected to be zero in any real deployment. Non-zero means one slot was
    /// reused four billion times.
    pub generations_exhausted: u64,
}

impl<T> HandleTable<T> {
    /// A table that may hold `limit` live handles.
    ///
    /// # Why the slot vector starts empty
    ///
    /// Preallocating `limit` slots would cost `limit` times `size_of::<Slot<T>>()`
    /// per instance — at 256 handles and a 64-byte slot that is 16 KB per
    /// instance, against instances that the pressure of a workload may number in
    /// the thousands. Slots are appended on demand instead, which makes a
    /// component using three handles cost three slots.
    ///
    /// A `limit` of zero is treated as zero, not as "unlimited": a manifest that
    /// declares no handles means none, and `0 == unlimited` is the kind of
    /// implicit rule §2.5 forbids.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            slots: Vec::new(),
            live: 0,
            limit,
            stats: HandleStats::default(),
        }
    }

    /// Insert a resource, returning the handle a guest holds.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-3005 InvalidResourceHandle` when the limit is reached. The
    /// code is the trap class because reaching the limit is a **guest** behaviour
    /// — it opened too many — rather than a host fault.
    pub fn insert(&mut self, value: T) -> Result<Handle> {
        if self.live >= self.limit as usize {
            self.stats.refused += 1;
            return Err(Error::new(
                ErrorCode::InvalidResourceHandle,
                "the open-handle limit for this instance has been reached",
            )
            .with_context("limit", self.limit.to_string())
            .with_context("live", self.live.to_string())
            .with_remediation(
                "close handles when they are no longer needed, or raise \
                 `limits.max_open_handles` in `qqq.toml`",
            ));
        }

        // Reuse a free slot when one exists. Scanning from the front keeps the
        // table densely packed, which matters because a paginated workload
        // usually has one or two free slots rather than many.
        //
        // The scan is O(n) in the worst case, bounded by `limit` (256 by
        // default). That is deliberate: a free-list would make insertion O(1)
        // but would need its own allocation and its own correctness argument for
        // the generation handoff. At this bound the scan is cheaper than the
        // structure, and the bound is a manifest field so the tradeoff is
        // visible rather than hidden.
        for i in 0..self.slots.len() {
            if let Slot::Free { next_generation } = self.slots[i] {
                // A generation of `u32::MAX` cannot be incremented, so the slot is
                // retired rather than reused. Refusing is the safe direction: a
                // wrapped generation would make an old handle valid again, which
                // is exactly the recycling attack the generation exists to stop.
                if next_generation == u32::MAX {
                    self.stats.generations_exhausted += 1;
                    continue;
                }
                let generation = next_generation;
                self.slots[i] = Slot::Live { value, generation };
                self.live += 1;
                self.stats.opened += 1;
                // As above: `i < slots.len() <= limit` and `limit` is a `u32`.
                let slot = u32::try_from(i).map_err(|_| {
                    Error::new(
                        ErrorCode::InternalInvariantViolated,
                        "the handle table exceeded its representable slot count",
                    )
                    .with_remediation("this is a QQQ bug; please report it")
                })?;
                return Ok(Handle::pack(slot, generation));
            }
        }

        // No free slot: append. The `limit` check above guarantees this cannot
        // exceed the limit, because `live == slots.len()` when nothing is free.
        let index = self.slots.len();
        debug_assert!(
            index < self.limit as usize,
            "appending slot {index} would exceed the limit {}",
            self.limit
        );
        self.slots.push(Slot::Live {
            value,
            generation: 0,
        });
        self.live += 1;
        self.stats.opened += 1;
        // The conversion cannot truncate: `slots.len() <= limit`, and `limit` is
        // a `u32`, so the value fits by construction. `try_from` makes that a
        // checked fact rather than an assumption resting on the assert above.
        let slot = u32::try_from(index).map_err(|_| {
            Error::new(
                ErrorCode::InternalInvariantViolated,
                "the handle table exceeded its representable slot count",
            )
            .with_remediation("this is a QQQ bug; please report it")
        })?;
        Ok(Handle::pack(slot, 0))
    }

    /// Look up a handle's resource.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-3005` when the handle names no live resource — a forged
    /// handle, a stale one, or one whose slot has been reused. All three are the
    /// same answer to the guest, deliberately: distinguishing them would tell an
    /// attacker whether a guess named a slot that once existed.
    pub fn get(&self, handle: Handle) -> Result<&T> {
        let index = handle.slot() as usize;
        match self.slots.get(index) {
            Some(Slot::Live { value, generation }) if *generation == handle.generation() => {
                Ok(value)
            }
            _ => Err(Self::invalid_handle_message(handle)),
        }
    }

    /// Look up a handle's resource, mutably.
    ///
    /// # Errors
    ///
    /// As [`HandleTable::get`].
    pub fn get_mut(&mut self, handle: Handle) -> Result<&mut T> {
        let index = handle.slot() as usize;
        let generation = handle.generation();

        // Liveness is established BEFORE the mutable borrow of slots, because
        // building the error needs &self and the two borrows overlap. Checking
        // first also means the failure path never holds a mutable borrow, which
        // is what lets it count the rejection through &mut self.
        let live = matches!(
            self.slots.get(index),
            Some(Slot::Live { generation: g, .. }) if *g == generation
        );
        if !live {
            self.stats.invalid += 1;
            return Err(Self::invalid_handle_message(handle));
        }

        match self.slots.get_mut(index) {
            Some(Slot::Live { value, .. }) => Ok(value),
            _ => unreachable!("the match above established Live"),
        }
    }

    /// Drop a handle's resource and free its slot.
    ///
    /// # Errors
    ///
    /// As [`HandleTable::get`] — dropping a handle that names nothing is an
    /// error rather than a no-op, because a double-close is a guest bug worth
    /// surfacing.
    pub fn remove(&mut self, handle: Handle) -> Result<T> {
        let index = handle.slot() as usize;
        let generation = handle.generation();

        let ok = matches!(
            self.slots.get(index),
            Some(Slot::Live { generation: g, .. }) if *g == generation
        );
        if !ok {
            return Err(Self::invalid_handle_message(handle));
        }

        // Replace with a free slot carrying the NEXT generation. Doing this by
        // assignment rather than by `take` + `put` is what keeps the generation
        // monotonic: the slot never passes through a state where an old handle
        // would match.
        let placeholder = Slot::Free {
            next_generation: generation.wrapping_add(1),
        };
        let old = std::mem::replace(&mut self.slots[index], placeholder);
        self.live -= 1;
        self.stats.closed += 1;

        match old {
            Slot::Live { value, .. } => Ok(value),
            Slot::Free { .. } => unreachable!("the match above established Live"),
        }
    }

    /// How many handles are live.
    #[must_use]
    pub const fn open(&self) -> usize {
        self.live
    }

    /// The configured limit.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Lifetime diagnostics.
    #[must_use]
    pub const fn stats(&self) -> HandleStats {
        self.stats
    }

    /// Whether the table is at its limit.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.live >= self.limit as usize
    }

    /// Build the error for a handle that names nothing.
    ///
    /// # Why this takes no receiver
    ///
    /// It began as `&self`, from a design where it also bumped the `invalid`
    /// counter. Once the counter moved to the `&mut self` paths — because
    /// `&self` cannot mutate and adding a `Cell` to every table for one
    /// diagnostic is the wrong trade — the receiver became dead weight, and
    /// clippy's `unused_self` said so. A free function is the honest signature.
    #[must_use]
    pub fn invalid_handle_message(handle: Handle) -> Error {
        Error::new(
            ErrorCode::InvalidResourceHandle,
            "the handle names no live resource",
        )
        .with_context("handle", handle.to_string())
        .with_remediation(
            "a handle is valid only between the call that created it and the call \
             that closed it; a forged or stale handle is rejected by design",
        )
    }

    /// Look up a handle, counting a rejection.
    ///
    /// The `&mut self` form of [`HandleTable::get`], for callers that want the
    /// `invalid` diagnostic to be accurate. `get` cannot count on `&self`, and
    /// the module doc states that rather than pretending otherwise.
    ///
    /// # Errors
    ///
    /// As [`HandleTable::get`].
    pub fn get_counted(&mut self, handle: Handle) -> Result<&T> {
        let index = handle.slot() as usize;
        let generation = handle.generation();
        let live = matches!(
            self.slots.get(index),
            Some(Slot::Live { generation: g, .. }) if *g == generation
        );
        if !live {
            self.stats.invalid += 1;
            return Err(Self::invalid_handle_message(handle));
        }
        match self.slots.get(index) {
            Some(Slot::Live { value, .. }) => Ok(value),
            _ => unreachable!("the match above established Live"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_round_trip() {
        let mut t = HandleTable::new(8);
        let h = t.insert("first").expect("fits");
        assert_eq!(t.get(h).expect("live"), &"first");
        assert_eq!(t.open(), 1);
    }

    /// The limit is enforced rather than grown through.
    #[test]
    fn the_limit_is_enforced_with_a_remediation() {
        let mut t = HandleTable::new(2);
        let _a = t.insert(1).expect("first");
        let _b = t.insert(2).expect("second");

        let err = t.insert(3).expect_err("the limit is 2");
        assert_eq!(err.code, ErrorCode::InvalidResourceHandle);
        assert!(err.context.iter().any(|(k, v)| k == "limit" && v == "2"));
        assert!(err.remediation.is_some());
        assert_eq!(t.stats().refused, 1);
        assert!(t.is_full());
    }

    /// A manifest declaring no handles means none, not "unlimited".
    #[test]
    fn a_zero_limit_permits_nothing() {
        let mut t = HandleTable::new(0);
        assert!(t.insert(1).is_err());
        assert_eq!(t.open(), 0);
    }

    /// **The forgery case.** A guest passing a number it was never given must be
    /// rejected, not indexed into.
    #[test]
    fn a_forged_handle_is_rejected() {
        let mut t = HandleTable::new(8);
        let _a = t.insert("real").expect("fits");

        // A slot that was never allocated.
        let forged = Handle::from_raw(9999);
        let err = t.get(forged).expect_err("no such slot");
        assert_eq!(err.code, ErrorCode::InvalidResourceHandle);
        assert!(err.context.iter().any(|(k, _)| k == "handle"));

        // And the maximum representable raw value must not panic either.
        assert!(t.get(Handle::from_raw(u64::MAX)).is_err());
    }

    /// **The recycling case, which is the security property.** A slot reused for
    /// a new resource must be *unaddressable* by the old handle.
    ///
    /// Without the generation, this test fails: the stale handle would reach the
    /// new resource, turning a use-after-free into a cross-resource leak.
    #[test]
    fn a_recycled_slot_is_not_addressable_by_a_stale_handle() {
        let mut t = HandleTable::new(4);
        let old = t.insert("original").expect("fits");
        assert_eq!(t.get(old).expect("live"), &"original");

        let _taken = t.remove(old).expect("live");
        let new = t.insert("replacement").expect("fits");

        // The slot is the same: the table reused it.
        assert_eq!(
            old.slot(),
            new.slot(),
            "the fixture must exercise recycling"
        );

        // But the old handle names nothing, and the new one works.
        assert!(
            t.get(old).is_err(),
            "a stale handle must not reach the resource that reused its slot"
        );
        assert_eq!(t.get(new).expect("live"), &"replacement");
        assert_ne!(old, new, "the generation must differ");
    }

    /// The generation must advance on *every* free, not just the first, so a
    /// handle from two cycles ago is also dead.
    #[test]
    fn generations_advance_on_every_reuse() {
        let mut t = HandleTable::new(2);
        let mut seen = std::collections::BTreeSet::new();

        for i in 0..20 {
            let h = t.insert(i).expect("always room for one");
            assert!(
                t.get(h).is_ok(),
                "the current handle must always be live (cycle {i})"
            );
            assert!(
                seen.insert(h.raw()),
                "handle {h} was reissued; a stale holder could reach a new resource"
            );
            t.remove(h).expect("live");
        }
        assert_eq!(t.stats().closed, 20);
        assert_eq!(t.open(), 0);
    }

    /// A double close is an error, not a silent no-op.
    #[test]
    fn a_double_remove_is_rejected() {
        let mut t = HandleTable::new(4);
        let h = t.insert("x").expect("fits");
        t.remove(h).expect("first close is fine");

        let err = t.remove(h).expect_err("the second close must fail");
        assert_eq!(err.code, ErrorCode::InvalidResourceHandle);
    }

    /// Slots are reused rather than appended forever, so a long-lived guest does
    /// not grow the table without bound.
    #[test]
    fn a_freed_slot_is_reused_rather_than_appended() {
        let mut t = HandleTable::new(2);
        let a = t.insert(1).expect("fits");
        let b = t.insert(2).expect("fits");
        assert_eq!(b.slot(), 1, "the second insert appends");

        t.remove(a).expect("live");
        let c = t.insert(3).expect("the freed slot must be reusable");
        assert_eq!(c.slot(), 0, "the freed slot 0 must be reused");
        assert_eq!(t.open(), 2);
    }

    /// A table never grows past its limit, however the inserts and removes
    /// interleave. This is the property a free-list bug would break.
    #[test]
    fn the_table_never_exceeds_its_limit() {
        let limit = 4_u32;
        let mut t = HandleTable::new(limit);
        let mut held: Vec<Handle> = Vec::new();

        // Insert ONCE per iteration. The first version of this test called
        // `insert` twice -- once to test `is_ok()` and once to keep the handle --
        // so the second call failed whenever the table was full and the harness
        // panicked inside its own assertion helper rather than exercising the
        // table. A test that calls a fallible operation twice is testing the
        // second call.
        for i in 0..100 {
            if i % 3 == 0 && !held.is_empty() {
                let h = held.remove(0);
                t.remove(h).expect("live");
            } else if let Ok(h) = t.insert(i) {
                held.push(h);
            }
            assert!(
                t.open() <= limit as usize,
                "open count {} exceeded the limit {limit}",
                t.open()
            );
            assert!(
                t.slots.len() <= limit as usize,
                "slot vector grew past the limit"
            );
        }
    }

    /// `get_mut` must enforce the generation too, or a mutation path bypasses the
    /// check every other path makes.
    #[test]
    fn get_mut_enforces_the_generation() {
        let mut t = HandleTable::new(4);
        let old = t.insert(1_u32).expect("fits");
        t.remove(old).expect("live");
        let new = t.insert(2_u32).expect("fits");

        assert!(t.get_mut(old).is_err(), "a stale handle must not mutate");
        *t.get_mut(new).expect("live") = 42;
        assert_eq!(*t.get(new).expect("live"), 42);
    }

    /// The diagnostics distinguish a healthy churn from a leak.
    #[test]
    fn the_stats_distinguish_churn_from_a_leak() {
        // Healthy: open and close in a loop.
        let mut healthy = HandleTable::new(4);
        for _ in 0..10 {
            let h = healthy.insert(1).expect("fits");
            healthy.remove(h).expect("live");
        }
        assert_eq!(healthy.open(), 0);
        assert_eq!(healthy.stats().opened, 10);
        assert_eq!(healthy.stats().closed, 10);

        // Leaking: open and never close, until the limit refuses.
        let mut leaking = HandleTable::new(4);
        while leaking.insert(1).is_ok() {}
        assert_eq!(leaking.open(), 4);
        assert_eq!(leaking.stats().opened, 4);
        assert_eq!(leaking.stats().closed, 0);
        assert_eq!(leaking.stats().refused, 1);
    }

    /// The `invalid` counter is the attack signature, and must actually count.
    #[test]
    fn probing_is_counted_by_the_counted_lookup() {
        let mut t = HandleTable::new(4);
        for raw in [1_u64, 7, 12345] {
            assert!(t.get_counted(Handle::from_raw(raw)).is_err());
        }
        assert_eq!(t.stats().invalid, 3);
        // And a valid lookup does not count as invalid.
        let h = t.insert(1).expect("fits");
        assert!(t.get_counted(h).is_ok());
        assert_eq!(t.stats().invalid, 3);
    }

    /// The generation wrap refuses rather than reusing, because a wrapped
    /// generation re-validates an old handle.
    #[test]
    fn a_wrapped_generation_refuses_the_slot_rather_than_reusing_it() {
        let mut t = HandleTable::new(2);
        let h = t.insert("x").expect("fits");
        t.remove(h).expect("live");

        // Force the slot to the edge of its generation space.
        if let Some(slot) = t.slots.first_mut() {
            *slot = Slot::Free {
                next_generation: u32::MAX,
            };
        }

        // Either outcome is correct: the exhausted slot was skipped, or there
        // was no other slot free.
        if let Ok(new) = t.insert("y") {
            assert_ne!(new.slot(), 0, "the exhausted slot must not be reused");
        }
        assert_eq!(t.stats().generations_exhausted, 1);
    }

    /// The handle's text form must show the generation, so a diagnostic makes a
    /// recycled slot visible.
    #[test]
    fn a_handle_displays_its_slot_and_generation() {
        let mut t = HandleTable::new(2);
        let first = t.insert(1).expect("fits");
        assert_eq!(first.to_string(), "0:0");
        t.remove(first).expect("live");
        let second = t.insert(2).expect("fits");
        assert_eq!(second.to_string(), "0:1");
    }

    /// The packing must not alias two slots, and must survive the extremes.
    #[test]
    fn the_packing_is_injective_at_the_extremes() {
        let a = Handle::pack(0, 0);
        let b = Handle::pack(0, 1);
        let c = Handle::pack(1, 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);

        let high = Handle::pack(u32::MAX, u32::MAX);
        assert_eq!(high.slot(), u32::MAX);
        assert_eq!(high.generation(), u32::MAX);
        assert_eq!(high.raw(), u64::MAX);
    }

    #[test]
    fn the_stats_default_to_zero() {
        let s = HandleStats::default();
        assert_eq!(s.opened, 0);
        assert_eq!(s.closed, 0);
        assert_eq!(s.refused, 0);
        assert_eq!(s.invalid, 0);
        assert_eq!(s.generations_exhausted, 0);
    }

    // -----------------------------------------------------------------------
    // SEC-008: handle exhaustion attempts
    //
    // The items below are the proof that the host survives a guest that tries to
    // exhaust the handle table. Two of them are *negative* — they assert that a
    // legal heavy workload still succeeds — because a table that refused
    // everything would satisfy every exhaustion assertion while being useless.
    // -----------------------------------------------------------------------

    /// **The accumulation attack.** A guest that opens handles and never closes
    /// them is refused at the limit, and the refusal does not disturb the table.
    ///
    /// This is the shape `SEC-008` names: "prove the host survives handle
    /// exhaustion attempts". The assertions are not merely `is_err()` — the
    /// *state* after the failed attempt is what matters. A table that refused
    /// but corrupted its own accounting would pass an `is_err()` check and fail
    /// here.
    #[test]
    fn an_accumulating_guest_is_refused_without_disturbing_the_table() {
        const LIMIT: u32 = 8;
        let mut t = HandleTable::new(LIMIT);
        let mut held = Vec::new();

        // Fill exactly to the limit.
        for i in 0..LIMIT {
            held.push(t.insert(i).expect("within the limit"));
        }
        assert_eq!(t.open(), LIMIT as usize);
        assert!(t.is_full());

        // Now attempt twenty more. Every one must be refused.
        for i in 0..20 {
            let err = t.insert(1000 + i).expect_err("the table is full");
            assert_eq!(err.code, ErrorCode::InvalidResourceHandle);
            assert!(err.remediation.is_some());
        }

        // The refusals changed nothing: still exactly LIMIT live, still LIMIT
        // slots, and every handle handed out before the attack still works.
        assert_eq!(
            t.open(),
            LIMIT as usize,
            "a refusal must not change liveness"
        );
        assert_eq!(
            t.slots.len(),
            LIMIT as usize,
            "a refusal must not grow slots"
        );
        assert_eq!(t.stats().refused, 20);
        assert_eq!(t.stats().opened, u64::from(LIMIT));
        assert_eq!(t.stats().closed, 0);
        for (i, h) in held.iter().enumerate() {
            assert_eq!(
                t.get(*h)
                    .expect("handles from before the attack must still work"),
                &u32::try_from(i).expect("the limit fits in u32"),
                "handle {i} was invalidated by a refused insert"
            );
        }
    }

    /// **Handle churn is legal and cheap.** The control that stops the limit
    /// becoming a denial of service against honest guests.
    ///
    /// A table whose limit counted *total* allocations rather than *live* ones
    /// would refuse a long-lived guest at its limit-th allocation and be a
    /// production outage. This proves the limit is on concurrency, not on
    /// throughput — which is the distinction between "handle-count limit" and
    /// "handle-rate limit", and §6.1 specifies the first.
    #[test]
    fn churn_is_unbounded_because_the_limit_is_on_concurrency_not_throughput() {
        const LIMIT: u32 = 4;
        let mut t = HandleTable::new(LIMIT);

        // 10,000 open/close cycles through a table that can hold 4.
        for i in 0..10_000_u64 {
            let h = t
                .insert(i)
                .expect("churn within the limit must never be refused");
            assert_eq!(t.get(h).expect("live"), &i);
            assert_eq!(t.remove(h).expect("live"), i);
        }

        assert_eq!(t.open(), 0);
        assert_eq!(t.stats().opened, 10_000);
        assert_eq!(t.stats().closed, 10_000);
        assert_eq!(
            t.stats().refused,
            0,
            "churn must not consume the concurrency budget"
        );
    }

    /// **The probing attack.** A guest guessing handle values is rejected, and
    /// the rejections are counted so the attack is visible.
    ///
    /// Distinct from the exhaustion attack: this one never reaches the limit.
    /// It is the guest trying to *name* resources it was never given, and the
    /// generation check is what stops it.
    #[test]
    fn a_probing_guest_is_rejected_and_the_probes_are_counted() {
        let mut t = HandleTable::new(64);
        let real = t.insert("the one real handle").expect("fits");

        // Probe a wide space, including values adjacent to the real handle's
        // generation and the extremes of the u64 space.
        //
        // `0` and `1` matter here for a reason worth stating: the real handle is
        // slot 0 generation 0, whose raw value IS `0`. So `0` is not a probe at
        // all, and the list deliberately contains it to assert that the *real*
        // handle still resolves after the probing — an earlier version of this
        // test counted it as a probe and expected 8 rejections out of 8 raw
        // values, which was arithmetic on the wrong quantity rather than a
        // finding about the table.
        let real_raw = real.raw();
        let mut probes: Vec<u64> = vec![
            real_raw.wrapping_add(1),
            real_raw.wrapping_sub(1),
            real_raw ^ (1 << 32),
            1,
            u64::from(u32::MAX),
            u64::MAX,
            u64::MAX - 1,
        ];
        probes.push(real_raw); // Not a forgery — the control.
        let forged: Vec<u64> = probes.iter().copied().filter(|r| *r != real_raw).collect();

        let mut rejected = 0;
        for raw in &forged {
            if t.get_counted(Handle::from_raw(*raw)).is_err() {
                rejected += 1;
            }
        }

        assert_eq!(
            rejected,
            forged.len(),
            "every probe other than the real handle must be rejected"
        );
        assert_eq!(t.stats().invalid, forged.len() as u64);
        // And the real handle is untouched by the probing.
        assert!(
            t.get_counted(real).is_ok(),
            "the real handle must still work"
        );
        assert_eq!(
            t.stats().invalid,
            forged.len() as u64,
            "a valid lookup must not count as invalid"
        );
    }

    /// **The interleaved attack.** Fill, free, fill, free — with the probe and
    /// exhaustion shapes mixed in. The invariant that must hold throughout is
    /// `live <= limit`, and it must hold for the slot vector too.
    ///
    /// This is a property test over an adversarial schedule rather than a
    /// scripted sequence, because the bug a free-list would have is exactly an
    /// off-by-one that only appears for some interleaving.
    #[test]
    fn the_limit_holds_across_an_adversarial_interleaving() {
        const LIMIT: u32 = 6;
        let mut t = HandleTable::new(LIMIT);
        let mut held: Vec<Handle> = Vec::new();

        // A cheap deterministic PRNG. `rand` is not a dependency of this crate
        // and adding one for a test would be the tail wagging the dog; this
        // schedule only needs to be irregular, not statistically sound.
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for tick in 0..5_000_u64 {
            match next() % 4 {
                // Try to insert.
                0 | 1 => {
                    if let Ok(h) = t.insert(tick) {
                        held.push(h);
                    }
                }
                // Close a random held handle.
                2 => {
                    if !held.is_empty() {
                        // `held.len()` is at most `LIMIT` (6), so the modulo fits
                        // in `usize` on every target; `try_from` states that
                        // rather than casting, because a cast here would truncate
                        // silently on a 16-bit `usize` and index the wrong slot.
                        let len = u64::try_from(held.len()).expect("a handle count fits in u64");
                        let idx = usize::try_from(next() % len).expect("index < held.len()");
                        let h = held.swap_remove(idx);
                        t.remove(h).expect("a held handle must be live");
                    }
                }
                // Probe a forged handle.
                _ => {
                    let _ = t.get_counted(Handle::from_raw(next()));
                }
            }

            assert!(
                t.open() <= LIMIT as usize,
                "live count {} exceeded the limit at tick {tick}",
                t.open()
            );
            assert!(
                t.slots.len() <= LIMIT as usize,
                "the slot vector ({}) exceeded the limit at tick {tick}",
                t.slots.len()
            );
            // Every handle still held must resolve, whatever the schedule did.
            for h in &held {
                assert!(
                    t.get(*h).is_ok(),
                    "a held handle stopped resolving at tick {tick}; the table \
                     invalidated a live resource"
                );
            }
        }

        assert_eq!(
            t.open(),
            held.len(),
            "the open count must match what is held"
        );
    }

    /// **The zero limit, as a security property.** A manifest that grants no
    /// handles must hand out none — and must keep refusing, not fail once and
    /// then permit.
    #[test]
    fn a_zero_limit_refuses_indefinitely_rather_than_sporadically() {
        let mut t = HandleTable::new(0);
        for i in 0..100 {
            assert!(
                t.insert(i).is_err(),
                "insert {i} succeeded against a zero limit"
            );
        }
        assert_eq!(t.open(), 0);
        assert_eq!(t.slots.len(), 0);
        assert_eq!(t.stats().refused, 100);
    }

    /// The huge limit must not panic or mis-account. A manifest may legitimately
    /// declare `max_open_handles = 100_000` (the range ceiling).
    #[test]
    fn a_huge_limit_is_representable_and_not_preallocated() {
        let t: HandleTable<u32> = HandleTable::new(100_000);
        assert_eq!(t.limit(), 100_000);
        assert_eq!(
            t.slots.len(),
            0,
            "slots must be allocated on demand, not preallocated to the limit"
        );
    }
}
