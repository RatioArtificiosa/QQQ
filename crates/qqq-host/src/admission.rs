// SPDX-License-Identifier: Apache-2.0

//! Admission control: refuse a component whose declared requirements exceed the
//! host's capacity — `HOST-023`.
//!
//! # The problem this solves
//!
//! Wasmtime's pooling allocator is a **reservation**. `total_memories(n)` with
//! `max_memory_size(m)` reserves `n × m` of address space up front, whether or not
//! those instances ever exist. That is what makes instantiation cheap, and it is
//! also what makes a misconfiguration fatal in a specific and unpleasant way:
//!
//! * Reserve **too little** and the pool refuses instances at the worst moment —
//!   under load, in production, with `QQQ-6001`.
//! * Reserve **too much** and the *engine constructor* fails, or the process is
//!   OOM-killed at startup, or — worst — it starts fine on the developer's
//!   32 GB machine and dies on the 2 GB container.
//!
//! Neither is a runtime condition anyone handles well. Both are decidable
//! **before** the engine is built, from two numbers that are already known: what
//! the manifest requires, and what the host can provide.
//!
//! # What counts as a requirement
//!
//! | Requirement | Source | Why it is admission-relevant |
//! |---|---|---|
//! | Memory per instance | `limits.memory` | Multiplied by the instance count, this is the reservation |
//! | Instance count | `limits.max_instances` | The multiplier |
//! | Fuel per execution | `limits.fuel` | Not a reservation, but a floor: a budget of 0 traps before the guest runs |
//! | Deadline | `limits.epoch_deadline_ms` | A deadline of 0 traps at the first tick |
//! | Resident baseline | measured, see [`HostCapacity::resident_bytes`] | The Wasmtime runtime itself, before any guest |
//!
//! # The refusal, and why it is at load rather than at first request
//!
//! §7.3's defence timeline puts the gates on the path *into* execution, and
//! admission is the earliest of them. Refusing at load means:
//!
//! * an operator learns at deploy time, from a message naming both numbers;
//! * no capacity is consumed by a component that cannot run;
//! * the pool is sized once, from an accepted set, rather than re-derived.
//!
//! The alternative — accepting the component and failing on the first request —
//! produces a `QQQ-6001` under load, where the cause is three steps away from the
//! symptom.

use qqq_core::{Error, ErrorCode, Result};

use crate::config::StoreLimits;

/// What a host can provide.
///
/// # Why this is a value and not a query
///
/// It is passed in rather than measured here, so that admission is a **pure
/// function** of two values and therefore testable without a machine of any
/// particular size. A test that asserted "this fits" against the real host would
/// pass or fail depending on the CI runner — the environment-dependent check this
/// project has already been bitten by (`§O-058f`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCapacity {
    /// Bytes the host is willing to commit to guest linear memory, in total.
    ///
    /// **The sum, not per instance.** This is the number a container memory limit
    /// or a `systemd` `MemoryMax` actually corresponds to.
    pub memory_budget_bytes: u64,
    /// The most instances the host will run at once.
    pub max_instances: u64,
    /// Bytes the runtime occupies before any guest exists.
    ///
    /// The Wasmtime runtime, the compiled component, and the host's own
    /// structures. Subtracted from the budget because a reservation that ignores
    /// it is a reservation that does not fit — and the failure mode is the
    /// OOM-kill described above.
    ///
    /// Defaults to a conservative value rather than zero: assuming the runtime is
    /// free is precisely the assumption that produces a host which passes
    /// admission and then dies.
    pub resident_bytes: u64,
    /// Cap on the total virtual-address reservation, in bytes (`F-10`).
    ///
    /// The pool reserves address space — not RSS — for every memory slot plus
    /// its guard regions, so a large shape can exhaust a container's mappable
    /// space while RSS looks healthy. The platform limit is not queryable
    /// without `unsafe` (no `getrlimit` in safe Rust), so this is an explicit
    /// configuration value instead. The default is unlimited (`u64::MAX`):
    /// a default that refused previously-admitted shapes would turn an
    /// upgrade into an outage. Deployments in constrained containers set it.
    pub max_virtual_reservation_bytes: u64,
}

impl Default for HostCapacity {
    /// A deliberately modest default, as `default` should be: 2 GiB of guest
    /// memory, 64 instances, 128 MiB resident.
    ///
    /// **Not** derived from the machine it happens to run on. A default that
    /// varied by host would make a manifest that passes admission on a laptop
    /// fail in a container, which is the class of bug this module exists to move
    /// *earlier* rather than later.
    fn default() -> Self {
        Self {
            memory_budget_bytes: 2 * 1024 * 1024 * 1024,
            max_instances: 64,
            resident_bytes: 128 * 1024 * 1024,
            max_virtual_reservation_bytes: u64::MAX,
        }
    }
}

impl HostCapacity {
    /// Bytes actually available to guest memory, after the resident baseline.
    ///
    /// Saturates at zero rather than underflowing: a host whose resident
    /// footprint exceeds its budget has **no** guest capacity, and reporting a
    /// wrapped enormous number would admit everything.
    #[must_use]
    pub const fn available_bytes(&self) -> u64 {
        self.memory_budget_bytes.saturating_sub(self.resident_bytes)
    }

    /// The largest per-instance memory that fits `max_instances` of them.
    ///
    /// Useful as the number to tell an operator who has to lower
    /// `limits.memory`: it is the ceiling their configuration can support.
    #[must_use]
    pub const fn max_memory_per_instance(&self) -> u64 {
        let n = if self.max_instances == 0 {
            1
        } else {
            self.max_instances
        };
        self.available_bytes() / n
    }
}

/// Why an admission request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The reservation exceeds the host's memory budget.
    MemoryReservation {
        /// What the manifest requires in total.
        required_bytes: u64,
        /// What the host can provide.
        available_bytes: u64,
    },
    /// The manifest asks for more instances than the host runs.
    TooManyInstances {
        /// What the manifest asks for.
        requested: u64,
        /// The host ceiling.
        host_max: u64,
    },
    /// The virtual-address reservation exceeds the configured cap.
    VirtualReservation {
        /// What the shape requires in total.
        required_bytes: u64,
        /// What the host allows to be mapped.
        available_bytes: u64,
    },
    /// A limit that traps the guest before it runs.
    DegenerateLimit {
        /// The field, e.g. `limits.fuel`.
        field: &'static str,
    },
}

impl Refusal {
    /// A stable, bounded name for the refusal kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryReservation { .. } => "memory_reservation",
            Self::TooManyInstances { .. } => "too_many_instances",
            Self::VirtualReservation { .. } => "virtual_reservation",
            Self::DegenerateLimit { .. } => "degenerate_limit",
        }
    }

    /// Machine-readable context, in a stable order.
    ///
    /// Ordered rather than a `HashMap` because §10.3 requires structured output
    /// that diffs identically between runs, and an unordered map does not.
    #[must_use]
    pub fn context(self) -> Vec<(&'static str, String)> {
        match self {
            Self::MemoryReservation {
                required_bytes,
                available_bytes,
            }
            | Self::VirtualReservation {
                required_bytes,
                available_bytes,
            } => vec![
                ("required_bytes", required_bytes.to_string()),
                ("available_bytes", available_bytes.to_string()),
                (
                    "overcommit_bytes",
                    required_bytes.saturating_sub(available_bytes).to_string(),
                ),
            ],
            Self::TooManyInstances {
                requested,
                host_max,
            } => vec![
                ("requested", requested.to_string()),
                ("host_max", host_max.to_string()),
            ],
            Self::DegenerateLimit { field } => vec![("field", field.to_owned())],
        }
    }

    /// What an operator should do about it.
    ///
    /// Names **computed** numbers rather than placeholders: an operator told
    /// "lower `limits.memory`" still has to work out by how much, and the
    /// numbers are already available here. The memory figure is derived from
    /// the admitted shape — budget per admitted instance minus this shape's
    /// fixed overhead — because under own-number admission the host-wide
    /// ceiling points at a configuration this manifest never asked for
    /// (`CodeRabbit` on F-10).
    #[must_use]
    pub fn remediation(self, capacity: &HostCapacity, shape: &crate::config::PoolShape) -> String {
        match self {
            Self::MemoryReservation { .. } => {
                let instances = u64::from(shape.instances);
                let overhead = shape
                    .rss_per_instance_bytes()
                    .saturating_sub(shape.memory_ceiling_bytes);
                let fitting = capacity
                    .available_bytes()
                    .checked_div(instances.max(1))
                    .unwrap_or(0)
                    .saturating_sub(overhead);
                // A zero fitting limit is itself degenerate (admission
                // refuses `limits.memory == 0` just below), so the message
                // must never recommend it: with nothing positive to name, it
                // names only the instance count and the budget (`CodeRabbit`
                // on F-10).
                if fitting == 0 {
                    format!(
                        "lower `limits.max_instances` (this shape reserves {} \
                         bytes per instance across {instances} instance(s)), \
                         or raise the host's memory budget: no positive memory \
                         limit fits this host.",
                        shape.rss_per_instance_bytes(),
                    )
                } else {
                    format!(
                        "lower `limits.memory` to {fitting} bytes or fewer (this shape \
                         reserves {} bytes per instance across {instances} instance(s)), \
                         lower `limits.max_instances`, or raise the host's memory budget.",
                        shape.rss_per_instance_bytes(),
                    )
                }
            }
            Self::TooManyInstances { host_max, .. } => format!(
                "lower `limits.max_instances` to {host_max} or fewer, or raise \
                 the host's `max_instances`. Either ceiling can refuse: the \
                 host admission capacity and the engine config's \
                 `max_instances` (which sizes the pool) — the effective limit \
                 is the smaller of the two. The pooling allocator reserves \
                 for the count, so a larger number costs address space \
                 whether or not the instances exist."
            ),
            Self::VirtualReservation { .. } => {
                "lower `limits.memory`, lower `limits.max_instances`, or raise \
                 the host's `max_virtual_reservation_bytes`. The pool maps every \
                 slot up front: this refusal is about address space, and the \
                 machine may still have memory free."
                    .to_owned()
            }
            Self::DegenerateLimit { field } => format!(
                "raise `{field}` above zero. A limit of zero is not a tight limit, \
                 it is a guest that traps before its first instruction executes"
            ),
        }
    }
}

/// The result of an admission check that passed.
///
/// Carries the computed reservation so the caller does not recompute it — and so
/// a reviewer can see the number that was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// The per-instance memory the reservation was computed from: the
    /// aggregate ceiling, the number F-10 admission treats as the total.
    pub per_instance_bytes: u64,
    /// The total RSS reservation: `instances × rss_per_instance`. This is the
    /// number that must fit the host budget — it exceeds the bare memory
    /// product by the async stacks, full-size tables, and metadata estimate.
    pub reserved_bytes: u64,
    /// The instance count the reservation was computed for: the manifest's
    /// number when it fits, never the host ceiling silently substituted.
    pub instances: u64,
    /// The total virtual-address reservation: every slot mapped up front.
    pub virtual_reservation_bytes: u64,
}

impl Admitted {
    /// The fraction of the host's available memory this reservation consumes.
    ///
    /// The number an operator wants when deciding whether the next component
    /// will fit, and the reason it is reported rather than left to arithmetic at
    /// the call site.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn utilisation(&self, capacity: &HostCapacity) -> f64 {
        let available = capacity.available_bytes();
        if available == 0 {
            return 1.0;
        }
        (self.reserved_bytes as f64 / available as f64).min(1.0)
    }
}

/// Decide whether a component's declared requirements fit this host.
///
/// # Order of the checks, and why
///
/// 1. **Degenerate limits first.** A fuel budget of zero traps every execution
///    before its first instruction, and a deadline of zero traps at the first
///    tick. Both are configuration mistakes with a one-line fix, and reporting
///    them as a *capacity* problem would send an operator to resize a machine
///    that was never too small.
/// 2. **Instance count**, because it is the multiplier in the memory check and
///    the message is more actionable alone. A manifest asking for more than
///    the host runs is refused here — never silently clamped.
/// 3. **RSS reservation**, the arithmetic that actually determines fit: the
///    aggregate ceiling plus stacks, tables, and metadata, times instances.
/// 4. **Virtual reservation**, compared against the configured virtual cap.
///
/// # Errors
///
/// Returns `QQQ-2005 LimitOutOfRange` carrying the refusal kind and its numbers.
pub fn admit(
    limits: &StoreLimits,
    shape: &crate::config::PoolShape,
    capacity: &HostCapacity,
) -> Result<Admitted> {
    if capacity.available_bytes() == 0 {
        return Err(refuse(
            Refusal::MemoryReservation {
                // The shape's RSS total, in the same units as the later
                // reservation path — not the bare memory number
                // (`CodeRabbit` on F-10).
                required_bytes: shape.reserved_rss_bytes(),
                available_bytes: 0,
            },
            capacity,
            shape,
        ));
    }

    if limits.fuel == 0 {
        return Err(refuse(
            Refusal::DegenerateLimit {
                field: "limits.fuel",
            },
            capacity,
            shape,
        ));
    }
    if limits.epoch_deadline_ms == 0 {
        return Err(refuse(
            Refusal::DegenerateLimit {
                field: "limits.epoch_deadline_ms",
            },
            capacity,
            shape,
        ));
    }
    if limits.memory_bytes == 0 {
        return Err(refuse(
            Refusal::DegenerateLimit {
                field: "limits.memory",
            },
            capacity,
            shape,
        ));
    }

    // The manifest's number against both host ceilings: more asked than run
    // is a refusal with both numbers, not a silent clamp that sheds load
    // later. (The old code charged `capacity.max_instances` while the comment
    // above it promised the manifest's number.) There are TWO ceilings — the
    // engine config that sized the pool and the capacity checked here — so
    // the comparison is against both: `instances` is already
    // `min(requested, engine-config)`, and anything below the request means
    // the engine config clamped it. A host ceiling of zero refuses any
    // positive request here, which also retires the old zero-case
    // special-casing below — one check instead of two. The reported ceiling
    // is the effective one: the smaller of the two host numbers.
    let requested = u64::from(shape.requested_instances);
    let clamped = u64::from(shape.instances);
    if requested > capacity.max_instances || clamped < requested {
        return Err(refuse(
            Refusal::TooManyInstances {
                requested,
                host_max: clamped.min(capacity.max_instances),
            },
            capacity,
            shape,
        ));
    }
    let instances = clamped;

    // `saturating_mul` rather than `*`: a manifest declaring `1TiB` per instance
    // with a large count overflows `u64`, and a wrapped product would be a
    // *small* number that passes admission — the unsafe direction. (The shape
    // totals saturate the same way for the same reason.)
    let reserved_bytes = shape.reserved_rss_bytes();
    if reserved_bytes > capacity.available_bytes() {
        return Err(refuse(
            Refusal::MemoryReservation {
                required_bytes: reserved_bytes,
                available_bytes: capacity.available_bytes(),
            },
            capacity,
            shape,
        ));
    }

    let virtual_reservation_bytes = shape.virtual_reservation_bytes();
    if virtual_reservation_bytes > capacity.max_virtual_reservation_bytes {
        return Err(refuse(
            Refusal::VirtualReservation {
                required_bytes: virtual_reservation_bytes,
                available_bytes: capacity.max_virtual_reservation_bytes,
            },
            capacity,
            shape,
        ));
    }

    Ok(Admitted {
        per_instance_bytes: limits.memory_bytes,
        reserved_bytes,
        instances,
        virtual_reservation_bytes,
    })
}

/// Turn a refusal into the error a caller reports.
fn refuse(refusal: Refusal, capacity: &HostCapacity, shape: &crate::config::PoolShape) -> Error {
    let mut e = Error::new(
        ErrorCode::LimitOutOfRange,
        match refusal {
            Refusal::MemoryReservation { .. } => {
                "the component's memory reservation exceeds the host's capacity"
            }
            Refusal::TooManyInstances { .. } => {
                "the component asks for more instances than this host runs"
            }
            Refusal::VirtualReservation { .. } => {
                "the component's virtual-address reservation exceeds the host's cap"
            }
            Refusal::DegenerateLimit { .. } => {
                "the component declares a limit that traps the guest before it runs"
            }
        },
    );
    for (k, v) in refusal.context() {
        e = e.with_context(k, v);
    }
    e.with_context("refusal", refusal.as_str().to_owned())
        .with_remediation(refusal.remediation(capacity, shape))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(memory_bytes: u64, fuel: u64, deadline_ms: u64) -> StoreLimits {
        StoreLimits {
            memory_bytes,
            fuel,
            epoch_deadline_ms: deadline_ms,
            max_open_handles: 64,
            max_subrequests: 32,
        }
    }

    fn capacity(budget: u64, instances: u64, resident: u64) -> HostCapacity {
        HostCapacity {
            memory_budget_bytes: budget,
            max_instances: instances,
            resident_bytes: resident,
            // Unlimited: these tests pin the RSS arithmetic, and a virtual
            // cap would only move the refusal earlier. The cap itself is
            // pinned by its own tests below.
            max_virtual_reservation_bytes: u64::MAX,
        }
    }

    /// A 1-memory/1-table/1-core shape for the pre-F-10 tests: the instance
    /// count is the host's (their fixtures predate requested counts) and the
    /// ceiling is the test's memory number, so the RSS math is exercised
    /// without the instance-count question, which is F-10's own tests' job.
    fn shape_for(host_instances: u64, ceiling_bytes: u64) -> crate::config::PoolShape {
        crate::config::PoolShape {
            requested_instances: u32::try_from(host_instances).unwrap_or(u32::MAX),
            instances: u32::try_from(host_instances).unwrap_or(u32::MAX),
            memories_per_instance: 1,
            tables_per_instance: 1,
            core_instances_per_instance: 1,
            memory_ceiling_bytes: ceiling_bytes,
            table_elements: 1000,
        }
    }

    /// RSS per instance for the 1-1-1 test shape: ceiling + 2 MiB stack +
    /// 1000×8 B tables + 64 KiB metadata. Named once so the boundary tests
    /// below read as arithmetic, not magic.
    fn rss_1_1_1(ceiling_bytes: u64) -> u64 {
        ceiling_bytes + 2 * MIB + 8000 + 64 * 1024
    }

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn a_component_that_fits_is_admitted_with_its_numbers() {
        let cap = capacity(1024 * MIB, 8, 128 * MIB);
        // 1024 - 128 = 896 MiB available.
        let ok = admit(
            &limits(64 * MIB, 1_000_000, 5_000),
            &shape_for(8, 64 * MIB),
            &cap,
        )
        .expect("must fit");

        assert_eq!(ok.per_instance_bytes, 64 * MIB);
        assert_eq!(ok.instances, 8);
        // The reservation is the RSS bound, not the bare memory product.
        assert_eq!(ok.reserved_bytes, 8 * rss_1_1_1(64 * MIB));
        // 1024 - 128 = 896 MiB available; utilisation is reserved / available
        // (554,236,416 / 939,524,096 ≈ 0.58991187 — asserted to six places so
        // the arithmetic is checked, not trusted).
        let available = 896 * MIB;
        assert_eq!(ok.reserved_bytes * 1_000_000 / available, 589_911);
        assert!((ok.utilisation(&cap) - 0.589_912).abs() < 1e-6);
    }

    /// **The property the item is named for.** A reservation larger than the
    /// budget is refused, and the error names both numbers.
    #[test]
    fn an_overcommit_is_refused_with_both_numbers() {
        let cap = capacity(512 * MIB, 8, 0);
        // 8 × rss(128 MiB) against 512 MiB available.
        let required = 8 * rss_1_1_1(128 * MIB);
        let err = admit(
            &limits(128 * MIB, 1_000_000, 5_000),
            &shape_for(8, 128 * MIB),
            &cap,
        )
        .expect_err("must be refused");

        assert_eq!(err.code, ErrorCode::LimitOutOfRange);
        let ctx: std::collections::BTreeMap<_, _> = err.context.iter().cloned().collect();
        assert_eq!(
            ctx.get("refusal").map(String::as_str),
            Some("memory_reservation")
        );
        assert_eq!(
            ctx.get("required_bytes").map(String::as_str),
            Some(required.to_string().as_str())
        );
        assert_eq!(
            ctx.get("available_bytes").map(String::as_str),
            Some((512 * MIB).to_string().as_str())
        );
        assert_eq!(
            ctx.get("overcommit_bytes").map(String::as_str),
            Some((required - 512 * MIB).to_string().as_str())
        );
    }

    /// The resident baseline is subtracted, not ignored. A reservation that
    /// assumes the runtime is free is the one that passes admission and OOMs.
    #[test]
    fn the_resident_baseline_reduces_available_memory() {
        let cap = capacity(1024 * MIB, 4, 256 * MIB);
        assert_eq!(cap.available_bytes(), 768 * MIB);
        assert_eq!(cap.max_memory_per_instance(), 192 * MIB);

        // Exactly the RSS ceiling fits; one byte over does not. The RSS
        // overhead per instance is 2 MiB + 8000 B + 64 KiB, so the memory
        // number that exactly fills 768 MiB across 4 is 192 MiB minus that.
        let overhead = 2 * MIB + 8000 + 64 * 1024;
        let exact = 192 * MIB - overhead;
        admit(&limits(exact, 1, 1), &shape_for(4, exact), &cap)
            .expect("exactly the ceiling must fit");
        assert!(admit(&limits(exact + 1, 1, 1), &shape_for(4, exact + 1), &cap).is_err());
    }

    #[test]
    fn a_host_with_no_capacity_refuses_everything() {
        let cap = capacity(128 * MIB, 4, 128 * MIB);
        assert_eq!(cap.available_bytes(), 0);

        let err = admit(&limits(1, 1, 1), &shape_for(4, 1), &cap).expect_err("no capacity");
        let ctx: std::collections::BTreeMap<_, _> = err.context.iter().cloned().collect();
        assert_eq!(
            ctx.get("refusal").map(String::as_str),
            Some("memory_reservation")
        );
        // Same units as the later reservation path: the shape's RSS total
        // (4 × (1 + 2 MiB + 8000 + 64 KiB) = 8,682,756), not the bare memory
        // number (`CodeRabbit` on F-10).
        assert_eq!(
            ctx.get("required_bytes").map(String::as_str),
            Some("8682756")
        );
    }

    /// A resident footprint *above* the budget saturates rather than wrapping.
    /// A wrapped `available_bytes` would report petabytes and admit everything.
    #[test]
    fn an_oversized_resident_footprint_saturates() {
        let cap = capacity(128 * MIB, 4, 512 * MIB);
        assert_eq!(cap.available_bytes(), 0, "must clamp, not wrap");
        assert_eq!(cap.max_memory_per_instance(), 0);
    }

    /// A degenerate limit is reported as a **configuration** problem, not a
    /// capacity one — otherwise an operator resizes a machine that was never too
    /// small.
    #[test]
    fn degenerate_limits_are_named_as_such() {
        let cap = capacity(1024 * MIB, 4, 0);

        for (l, field) in [
            (limits(64 * MIB, 0, 5_000), "limits.fuel"),
            (limits(64 * MIB, 1_000, 0), "limits.epoch_deadline_ms"),
            (limits(0, 1_000, 5_000), "limits.memory"),
        ] {
            let shape = shape_for(4, l.memory_bytes);
            let err = admit(&l, &shape, &cap).expect_err("a degenerate limit must be refused");
            let ctx: std::collections::BTreeMap<_, _> = err.context.iter().cloned().collect();
            assert_eq!(
                ctx.get("refusal").map(String::as_str),
                Some("degenerate_limit")
            );
            assert_eq!(ctx.get("field").map(String::as_str), Some(field));
        }
    }

    /// Degenerate checks come before the capacity arithmetic, so a zero fuel
    /// budget on an over-committed host reports the fuel.
    ///
    /// The ordering is a decision, not an accident: the one-line fix an operator
    /// can make themselves is reported ahead of the one that needs a machine.
    #[test]
    fn a_degenerate_limit_outranks_a_capacity_problem() {
        let cap = capacity(64 * MIB, 8, 0); // hopelessly over-committed
        let err = admit(&limits(512 * MIB, 0, 5_000), &shape_for(8, 512 * MIB), &cap)
            .expect_err("refused");
        let ctx: std::collections::BTreeMap<_, _> = err.context.iter().cloned().collect();
        assert_eq!(
            ctx.get("refusal").map(String::as_str),
            Some("degenerate_limit"),
            "the fixable-in-one-line problem must be reported first"
        );
    }

    /// **Overflow must not admit.** A wrapped product is a small number, and a
    /// small number passes every capacity check — so the dangerous case is a
    /// *tiny* budget against a huge reservation, not a huge budget.
    ///
    /// # Why the first version of this test was wrong
    ///
    /// It used `memory_budget_bytes: u64::MAX` and asserted a refusal. That
    /// budget genuinely *does* fit a saturated reservation, so the refusal never
    /// happened and the test failed against correct code. The saturation is what
    /// makes it safe (it can never wrap downward), and a test of the safety
    /// property has to use a budget where the difference is observable.
    #[test]
    fn an_overflowing_reservation_cannot_wrap_into_fitting() {
        // A realistic host budget: 4 GiB.
        let cap = capacity(4 * 1024 * MIB, 64, 0);
        // 2^60 bytes per instance × 64 instances overflows u64 in the exact
        // product. Saturated, it is u64::MAX, which is far above 4 GiB.
        let err = admit(
            &limits(1_u64 << 60, 1_000_000, 5_000),
            &shape_for(64, 1_u64 << 60),
            &cap,
        )
        .expect_err("a huge reservation must be refused, not wrapped");
        assert!(
            err.context
                .iter()
                .any(|(k, v)| k == "refusal" && v == "memory_reservation"),
            "the refusal must name the memory reservation: {err}"
        );

        // And the saturated value is asserted directly, so the arithmetic is
        // pinned rather than inferred from the refusal above.
        let saturated = (1_u64 << 60).saturating_mul(64);
        assert_eq!(saturated, u64::MAX, "saturation must clamp, not wrap");
        assert!(saturated > cap.available_bytes());
    }

    #[test]
    fn a_zero_instance_host_refuses_rather_than_dividing_by_zero() {
        let cap = capacity(1024 * MIB, 0, 0);
        // Any positive request against a zero host is over-host, refused
        // with the count named — this is also what retired the old zero-case
        // special-casing in `admit`: one check instead of two.
        let shape = shape_for(0, 64 * MIB);
        let shape = crate::config::PoolShape {
            requested_instances: 4,
            ..shape
        };
        let err = admit(&limits(64 * MIB, 1, 1), &shape, &cap).expect_err("refused");
        assert!(err
            .context
            .iter()
            .any(|(k, v)| k == "refusal" && v == "too_many_instances"));
        // And `max_memory_per_instance` must not panic on the same input.
        assert_eq!(cap.max_memory_per_instance(), 1024 * MIB);
    }

    /// **F-10: a manifest asking for more than the host runs is refused, not
    /// silently clamped.**
    ///
    /// Written first and failing first: `admit` takes no requested count yet,
    /// so this does not compile — which is the red. The refusal names both
    /// numbers so the operator knows which side to move.
    #[test]
    fn f10_manifest_asking_for_more_instances_than_host_is_refused() {
        use crate::config::PoolShape;
        let cap = capacity(4 * 1024 * MIB, 64, 0);
        let shape = PoolShape {
            requested_instances: 1000,
            instances: 64,
            memories_per_instance: 1,
            tables_per_instance: 1,
            core_instances_per_instance: 1,
            memory_ceiling_bytes: MIB,
            table_elements: 1000,
        };
        let err = admit(&limits(MIB, 1_000_000, 5_000), &shape, &cap)
            .expect_err("1000 requested against 64 allowed must be refused");
        assert_eq!(err.code, ErrorCode::LimitOutOfRange);
        let ctx: std::collections::BTreeMap<_, _> = err.context.iter().cloned().collect();
        assert_eq!(
            ctx.get("refusal").map(String::as_str),
            Some("too_many_instances")
        );
        assert_eq!(ctx.get("requested").map(String::as_str), Some("1000"));
        assert_eq!(ctx.get("host_max").map(String::as_str), Some("64"));
    }

    /// **F-10: a manifest asking for fewer is admitted at its own number.**
    ///
    /// The comment above `admit` promises the manifest's number and the code
    /// charges it too, since the F-10 fix: more asked than run is a refusal
    /// with both numbers, never a silent clamp. This test pins the promise
    /// against the old behaviour it replaced (charging the host ceiling) —
    /// the old test is gone, not kept alongside, because two tests asserting
    /// opposite arithmetics is a suite that passes either way.
    #[test]
    fn f10_manifest_asking_for_fewer_instances_is_admitted_at_its_own_number() {
        use crate::config::PoolShape;
        let cap = capacity(4 * 1024 * MIB, 64, 0);
        let shape = PoolShape {
            requested_instances: 8,
            instances: 8,
            memories_per_instance: 1,
            tables_per_instance: 1,
            core_instances_per_instance: 1,
            memory_ceiling_bytes: 64 * MIB,
            table_elements: 1000,
        };
        let ok = admit(&limits(64 * MIB, 1_000_000, 5_000), &shape, &cap)
            .expect("8 requested against 64 allowed must fit");
        assert_eq!(ok.instances, 8);
        // The reservation is the RSS bound for 8, not the host-ceiling
        // multiple: per instance 64 MiB memory + 2 MiB async stack +
        // 1000×8 B tables + 64 KiB metadata estimate.
        let per_instance = 64 * MIB + 2 * MIB + 8000 + 64 * 1024;
        assert_eq!(ok.per_instance_bytes, 64 * MIB);
        assert_eq!(ok.reserved_bytes, 8 * per_instance);
    }

    /// **F-10: the memory remediation names the fitting limit for THIS
    /// shape, not the host-wide ceiling.**
    ///
    /// `CodeRabbit` on F-10, reproduced red first: under own-number admission
    /// the host-wide "at most N bytes per instance at M instances" points at
    /// numbers this manifest never asked for. The message must carry the
    /// memory value that would actually pass: budget per admitted instance
    /// minus this shape's fixed overhead (async stack, full tables,
    /// metadata). For 1024 MiB across 8 against a 128 MiB ceiling that is
    /// 134,217,728 − 2,170,688 = 132,047,040.
    #[test]
    fn f10_memory_remediation_names_the_fitting_limit_for_this_shape() {
        use crate::config::PoolShape;
        let cap = capacity(1024 * MIB, 8, 0);
        let shape = PoolShape {
            requested_instances: 8,
            instances: 8,
            memories_per_instance: 1,
            tables_per_instance: 1,
            core_instances_per_instance: 1,
            memory_ceiling_bytes: 128 * MIB,
            table_elements: 1000,
        };
        let err = admit(&limits(128 * MIB, 1, 1), &shape, &cap).expect_err("must be refused");
        let remedy = err
            .remediation
            .as_deref()
            .expect("a remediation is present");
        assert!(
            remedy.contains("132047040"),
            "the remediation must name the fitting memory for this shape: {remedy}"
        );
        assert!(
            !remedy.contains("capacity.") && !remedy.contains("()"),
            "the remediation must not contain a code reference: {remedy}"
        );
    }

    /// **F-10: a clamp by the engine config is refused, not silent.**
    ///
    /// `CodeRabbit` on F-10 (committed review), reproduced red first: the
    /// over-host check compared the request against the capacity ceiling
    /// only, but the effective count is `min(requested, engine-config)` —
    /// so a manifest asking 100 against an engine config of 50 and a host
    /// capacity of 1000 was admitted at 50 without refusal. Two ceilings
    /// means two chances to over-ask; the refusal names the effective one.
    #[test]
    fn f10_clamp_by_engine_config_is_refused_not_silent() {
        use crate::config::PoolShape;
        let cap = capacity(4 * 1024 * MIB, 1000, 0);
        let shape = PoolShape {
            requested_instances: 100,
            instances: 50,
            memories_per_instance: 1,
            tables_per_instance: 1,
            core_instances_per_instance: 1,
            memory_ceiling_bytes: MIB,
            table_elements: 1000,
        };
        let err = admit(&limits(MIB, 1_000_000, 5_000), &shape, &cap)
            .expect_err("100 requested against an effective 50 must be refused");
        assert_eq!(err.code, ErrorCode::LimitOutOfRange);
        let ctx: std::collections::BTreeMap<_, _> = err.context.iter().cloned().collect();
        assert_eq!(
            ctx.get("refusal").map(String::as_str),
            Some("too_many_instances")
        );
        assert_eq!(ctx.get("requested").map(String::as_str), Some("100"));
        assert_eq!(ctx.get("host_max").map(String::as_str), Some("50"));
        // Both ceilings can trigger this refusal (here the engine config
        // did), so the guidance must name both (`CodeRabbit` on F-10).
        let remedy = err
            .remediation
            .as_deref()
            .expect("a remediation is present");
        assert!(
            remedy.contains("engine config"),
            "the guidance must name the engine ceiling too: {remedy}"
        );
    }

    /// **F-10: a zero fitting limit is not recommended.**
    ///
    /// `CodeRabbit` on F-10 (second committed review), reproduced red first:
    /// on a host so constrained that no positive memory fits, the message
    /// said "lower `limits.memory` to 0 bytes or fewer" — and a zero memory
    /// limit is itself refused as degenerate, so the guidance recommended a
    /// value another check refuses. With nothing positive to name, the
    /// message names only the instance count and the budget.
    #[test]
    fn f10_zero_fitting_limit_names_instances_and_budget_only() {
        use crate::config::PoolShape;
        let cap = capacity(4 * MIB, 8, 0);
        let shape = PoolShape {
            requested_instances: 8,
            instances: 8,
            memories_per_instance: 1,
            tables_per_instance: 1,
            core_instances_per_instance: 1,
            memory_ceiling_bytes: MIB,
            table_elements: 1000,
        };
        let err = admit(&limits(MIB, 1, 1), &shape, &cap).expect_err("must be refused");
        let remedy = err
            .remediation
            .as_deref()
            .expect("a remediation is present");
        assert!(
            !remedy.contains("to 0 bytes"),
            "must never recommend a degenerate zero limit: {remedy}"
        );
        assert!(
            remedy.contains("`limits.max_instances`"),
            "must name the instance count instead: {remedy}"
        );
    }

    #[test]
    fn every_refusal_has_a_distinct_name_and_a_remediation() {
        let cap = capacity(1024 * MIB, 8, 0);
        let refusals = [
            Refusal::MemoryReservation {
                required_bytes: 1,
                available_bytes: 0,
            },
            Refusal::TooManyInstances {
                requested: 2,
                host_max: 1,
            },
            Refusal::VirtualReservation {
                required_bytes: 2,
                available_bytes: 1,
            },
            Refusal::DegenerateLimit {
                field: "limits.fuel",
            },
        ];
        let mut names = std::collections::BTreeSet::new();
        // The shape the remediation derives its numbers from: 8 instances of
        // a 64 MiB ceiling, so the fitting memory is 1024 MiB / 8 minus the
        // 1-1-1 overhead (2 MiB + 8000 B + 64 KiB) = 132,047,040.
        let shape = shape_for(8, 64 * MIB);
        for r in refusals {
            assert!(
                names.insert(r.as_str()),
                "duplicate refusal name: {}",
                r.as_str()
            );
            let remedy = r.remediation(&cap, &shape);
            assert!(!remedy.is_empty());
            assert!(!r.context().is_empty());
            // The memory remediation must carry the COMPUTED fitting limit
            // for the shape, not a placeholder pointing at a function name --
            // an operator reading it needs the number.
            if matches!(r, Refusal::MemoryReservation { .. }) {
                assert!(
                    remedy.contains("132047040"),
                    "the memory remediation must state the fitting limit it computed: {remedy}"
                );
                assert!(
                    !remedy.contains("capacity.") && !remedy.contains("()"),
                    "the remediation must not contain a code reference: {remedy}"
                );
            }
        }
    }

    /// The default capacity must not depend on the machine it runs on, or a
    /// manifest passing on a laptop would fail in a container.
    #[test]
    fn the_default_capacity_is_fixed_rather_than_measured() {
        let a = HostCapacity::default();
        let b = HostCapacity::default();
        assert_eq!(a, b);
        assert!(a.resident_bytes > 0, "the runtime is not free");
        assert_eq!(a.memory_budget_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(a.max_instances, 64);
        assert_eq!(
            a.max_virtual_reservation_bytes,
            u64::MAX,
            "the virtual cap defaults to unlimited: a default that refused \
             previously-admitted shapes would turn an upgrade into an outage"
        );
    }

    #[test]
    fn utilisation_is_bounded_by_one() {
        let cap = capacity(1024 * MIB, 8, 0);
        // Fill the budget exactly in RSS terms: 8 × rss(X) = 1024 MiB with
        // the 1-1-1 overhead (2 MiB + 8000 B + 64 KiB) per instance.
        let ceiling = 128 * MIB - (2 * MIB + 8000 + 64 * 1024);
        let ok = admit(&limits(ceiling, 1, 1), &shape_for(8, ceiling), &cap).expect("fits");
        assert!((ok.utilisation(&cap) - 1.0).abs() < f64::EPSILON);
        assert!((ok.utilisation(&cap) - 1.0).abs() < f64::EPSILON);
        // A host with no capacity reports fully utilised rather than dividing by
        // zero.
        let empty = capacity(0, 1, 0);
        assert!((ok.utilisation(&empty) - 1.0).abs() < f64::EPSILON);
    }
}
