// SPDX-License-Identifier: Apache-2.0

//! Poison-tolerant mutex acquisition (`F-21`).
//!
//! A `std::sync::Mutex` is poisoned when a thread panics while holding it.
//! Under `panic = "abort"` poisoning could never be observed (the process
//! died first), so `.lock().expect("not poisoned")` was dead weight. Once
//! release builds unwind (`F-01`), a panic in one request thread while
//! holding a lock poisons it — and every later `.expect()` on that lock
//! panics, including inside `Drop`, where a panic during unwinding aborts
//! the process. One caught panic becomes a total outage.
//!
//! # The rule, per lock
//!
//! Recovery is sound only where the critical sections are panic-free between
//! statements (plain integer and map work — no allocation that can fail, no
//! callbacks, no I/O). Then a recovered guard necessarily holds consistent
//! values: either the whole transition ran or none of it did. Each lock's
//! declaration states which rule applies:
//!
//! * Counters, idle lists, tenant maps: [`LockRecover::lock_recover`]. The
//!   state is re-established by RAII guards (`RequestPermit`,
//!   `TenantOutputGuard`), so a recovered map is never observed half-built.
//! * The audit chain head and any lock protecting a multi-field invariant a
//!   panic could break: do NOT recover silently; on poison return an error
//!   and fail closed (a `QQQ-` code), log, and mark the component unhealthy.
//!
//! ```
//! use qqq_core::sync::LockRecover;
//!
//! let lock = std::sync::Mutex::new(0u64);
//! *lock.lock_recover() += 1;
//! assert_eq!(*lock.lock_recover(), 1);
//! ```
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Recover a poisoned mutex instead of panicking on it.
///
/// Implemented for `std::sync::Mutex<T>` directly so call sites read as the
/// rule: `lock_recover()` where recovery is sound, an explicit fail-closed
/// error where it is not. See the module docs for which locks qualify.
///
/// ```
/// use qqq_core::sync::LockRecover;
///
/// let lock = std::sync::Mutex::new(String::new());
/// lock.lock_recover().push_str("recovered");
/// assert_eq!(*lock.lock_recover(), "recovered");
/// ```
pub trait LockRecover<T> {
    /// Lock, recovering the guard when a previous holder panicked.
    ///
    /// ```
    /// use qqq_core::sync::LockRecover;
    ///
    /// let lock = std::sync::Mutex::new(vec![1u8]);
    /// lock.lock_recover().push(2);
    /// assert_eq!(*lock.lock_recover(), vec![1, 2]);
    /// ```
    fn lock_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> LockRecover<T> for Mutex<T> {
    fn lock_recover(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// **F-21: recovery returns the guard with the holder's values.**
    ///
    /// The trait's whole contract in one test: a thread panics while holding
    /// the lock, the mutex is poisoned, and `lock_recover()` still yields a
    /// usable guard instead of panicking. The `is_poisoned` assertion is the
    /// anti-vacuity pin — without it the test could pass with no poison.
    /// Callers (pool counters, tenant maps) rely on exactly this: the values
    /// the panicking holder left, delivered without a panic.
    #[test]
    fn f21_lock_recover_returns_the_guard_after_poison() {
        let lock = Arc::new(Mutex::new(41u64));
        let poisoner = Arc::clone(&lock);
        let _ = std::thread::spawn(move || {
            let mut guard = poisoner.lock().expect("test setup: unpoisoned");
            *guard = 42;
            panic!("poison the lock on purpose");
        })
        .join();
        assert!(
            lock.is_poisoned(),
            "the fixture must really poison the lock, or this test proves nothing"
        );
        assert_eq!(*lock.lock_recover(), 42, "recovery yields the held values");
        *lock.lock_recover() += 1;
        assert_eq!(*lock.lock_recover(), 43, "the recovered lock stays usable");
    }
}
