// SPDX-License-Identifier: Apache-2.0

//! Versioned component ownership for live replacement (DX-006).
//!
//! ```
//! use qqq_run::generations::Registry;
//! let plugins = Registry::new(8, 8);
//! let token = plugins.reserve("formatter").unwrap();
//! plugins.publish(token, "source-digest", "version-1").unwrap();
//! assert_eq!(plugins.list().unwrap().len(), 1);
//! ```
//!
//! Preparation runs outside this registry. A reservation orders updates before
//! expensive work begins; publication compares that reservation under the same
//! lock used for admission. Leases own immutable generations, so removal stops
//! new admissions without invalidating existing work. No guest code runs here.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use qqq_core::{Error, ErrorCode, Result};

/// Immutable code and identity retained by an invocation or session.
///
/// # Examples
///
/// ```
/// # fn main() -> qqq_core::Result<()> {
/// use qqq_run::generations::Registry;
/// let registry = Registry::new(4, 4);
/// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
/// let lease = registry.acquire("agent")?;
/// assert_eq!(*lease.value(), 7);
/// # Ok(())
/// # }
/// ```
pub struct Generation<T> {
    revision: u64,
    digest: String,
    value: T,
}

impl<T> Generation<T> {
    /// Monotonic activation identity; never reused after removal.
    #[must_use]
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// assert!(registry.revision()? > 0);
    /// assert!(registry.acquire("agent")?.revision() > 0);
    /// # Ok(())
    /// # }
    /// ```
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Identity of the prepared source bytes.
    #[must_use]
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// assert_eq!(registry.acquire("agent")?.digest(), "sha256");
    /// # Ok(())
    /// # }
    /// ```
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The generation's immutable prepared value.
    #[must_use]
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// assert_eq!(*registry.acquire("agent")?.value(), 7);
    /// # Ok(())
    /// # }
    /// ```
    pub const fn value(&self) -> &T {
        &self.value
    }
}

struct Entry<T> {
    requested: u64,
    active: Option<Arc<Generation<T>>>,
}

struct State<T> {
    revision: u64,
    entries: BTreeMap<String, Entry<T>>,
    retired: Vec<Weak<Generation<T>>>,
}

/// Permission to publish one preparation result into its originating registry.
///
/// A later reservation or removal invalidates it. Tokens cannot be constructed
/// or moved between registries by callers.
///
/// # Examples
///
/// ```
/// # fn main() -> qqq_core::Result<()> {
/// use qqq_run::generations::Registry;
/// let registry = Registry::<u32>::new(4, 4);
/// let update = registry.reserve("agent")?;
/// registry.cancel(update)?;
/// # Ok(())
/// # }
/// ```
pub struct Update<T> {
    owner: Weak<Mutex<State<T>>>,
    name: String,
    revision: u64,
}

/// Bounded registry with atomic admission and revision-checked publication.
///
/// ```
/// use qqq_run::generations::Registry;
/// let registry = Registry::new(8, 8);
/// let update = registry.reserve("app").unwrap();
/// registry.publish(update, "digest-a", 42).unwrap();
/// let lease = registry.acquire("app").unwrap();
/// assert_eq!(*lease.value(), 42);
/// registry.remove("app").unwrap();
/// assert_eq!(*lease.value(), 42); // already admitted work remains valid
/// ```
pub struct Registry<T> {
    state: Arc<Mutex<State<T>>>,
    capacity: usize,
    retired_limit: usize,
}

impl<T> Clone for Registry<T> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            capacity: self.capacity,
            retired_limit: self.retired_limit,
        }
    }
}

impl<T> Registry<T> {
    /// Construct explicit bounds. Zero permits no entries or retained generations.
    #[must_use]
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::<u32>::new(4, 4);
    /// assert!(registry.list()?.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(capacity: usize, retired_limit: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                revision: 0,
                entries: BTreeMap::new(),
                retired: Vec::new(),
            })),
            capacity,
            retired_limit,
        }
    }

    /// Order an update before preparing it. Concurrent preparations are allowed;
    /// only the latest reservation for a name can activate.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// let pending = registry.reserve("agent")?;
    /// registry.publish(pending, "next-sha256", 8)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Refuses invalid names, full registries, revision exhaustion or poisoned locks.
    pub fn reserve(&self, name: &str) -> Result<Update<T>> {
        if name.is_empty() || name.len() > 256 {
            return Err(refused("component name must contain 1..=256 bytes"));
        }
        let mut state = self.lock()?;
        if !state.entries.contains_key(name) && state.entries.len() >= self.capacity {
            return Err(refused("component registry is full"));
        }
        let revision = advance(&mut state)?;
        state
            .entries
            .entry(name.to_owned())
            .and_modify(|e| e.requested = revision)
            .or_insert(Entry {
                requested: revision,
                active: None,
            });
        Ok(Update {
            owner: Arc::downgrade(&self.state),
            name: name.to_owned(),
            revision,
        })
    }

    /// Publish already prepared code. A failed or stale update leaves the active
    /// generation untouched. Destruction of replaced values occurs outside the lock.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// assert_eq!(*registry.acquire("agent")?.value(), 7);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Refuses stale or foreign reservations, exhausted retirement capacity or poisoned locks.
    pub fn publish(&self, update: Update<T>, digest: impl Into<String>, value: T) -> Result<u64> {
        let generation = Arc::new(Generation {
            revision: update.revision,
            digest: digest.into(),
            value,
        });
        let previous = {
            let mut state = self.lock()?;
            self.validate(&state, &update)?;
            state.retired.retain(|g| g.strong_count() != 0);
            let pinned = state
                .entries
                .get(&update.name)
                .and_then(|e| e.active.as_ref())
                .is_some_and(|g| Arc::strong_count(g) > 1);
            if pinned && state.retired.len() >= self.retired_limit {
                return Err(refused(
                    "retired generation limit reached; wait for existing sessions to drain",
                ));
            }
            advance(&mut state)?; // publication must be observable after preparation
            let previous = state
                .entries
                .get_mut(&update.name)
                .ok_or_else(|| refused("component was removed during preparation"))?
                .active
                .replace(generation);
            if let Some(old) = &previous
                && pinned
            {
                state.retired.push(Arc::downgrade(old));
            }
            previous
        };
        drop(previous);
        let revision = update.revision;
        drop(update); // consume the single-use reservation
        Ok(revision)
    }

    /// Cancel a failed preparation. An existing active generation keeps serving.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// registry.cancel(registry.reserve("agent")?)?;
    /// assert_eq!(*registry.acquire("agent")?.value(), 7);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Refuses stale or foreign reservations and poisoned locks.
    pub fn cancel(&self, update: Update<T>) -> Result<()> {
        let mut state = self.lock()?;
        self.validate(&state, &update)?;
        if state
            .entries
            .get(&update.name)
            .is_some_and(|e| e.active.is_none())
        {
            state.entries.remove(&update.name);
        } else {
            let revision = advance(&mut state)?;
            if let Some(entry) = state.entries.get_mut(&update.name) {
                entry.requested = revision;
            }
        }
        drop(update); // cancellation consumes the reservation too
        Ok(())
    }

    /// Admit a call or session and pin its generation through completion.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// let session = registry.acquire("agent")?;
    /// registry.remove("agent")?;
    /// assert_eq!(*session.value(), 7);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Refuses absent or inactive names and poisoned locks.
    pub fn acquire(&self, name: &str) -> Result<Arc<Generation<T>>> {
        self.lock()?
            .entries
            .get(name)
            .and_then(|e| e.active.clone())
            .ok_or_else(|| refused("component has no active generation"))
    }

    /// Stop new admissions, invalidating outstanding preparations for this name.
    /// Existing leases continue to own their code.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// assert!(registry.remove("agent")?);
    /// assert!(registry.acquire("agent").is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Refuses exhausted retirement capacity, revision exhaustion and poisoned locks.
    pub fn remove(&self, name: &str) -> Result<bool> {
        let previous = {
            let mut state = self.lock()?;
            state.retired.retain(|g| g.strong_count() != 0);
            let pinned = state
                .entries
                .get(name)
                .and_then(|e| e.active.as_ref())
                .is_some_and(|g| Arc::strong_count(g) > 1);
            if pinned && state.retired.len() >= self.retired_limit {
                return Err(refused(
                    "retired generation limit reached; wait before removal",
                ));
            }
            advance(&mut state)?;
            let old = state.entries.remove(name);
            if pinned && let Some(g) = old.as_ref().and_then(|e| e.active.as_ref()) {
                state.retired.push(Arc::downgrade(g));
            }
            old
        };
        Ok(previous.is_some())
    }

    /// Stable active listing: name, generation and source digest. Observers may
    /// resynchronize by listing after noticing a changed registry revision.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// assert_eq!(registry.list()?[0].0, "agent");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the registry lock is poisoned.
    pub fn list(&self) -> Result<Vec<(String, u64, String)>> {
        Ok(self
            .lock()?
            .entries
            .iter()
            .filter_map(|(name, entry)| {
                entry
                    .active
                    .as_ref()
                    .map(|g| (name.clone(), g.revision, g.digest.clone()))
            })
            .collect())
    }

    /// Monotonic change counter, advancing for reservation, activation and removal.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// assert!(registry.revision()? > 0);
    /// assert!(registry.acquire("agent")?.revision() > 0);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the registry lock is poisoned.
    pub fn revision(&self) -> Result<u64> {
        Ok(self.lock()?.revision)
    }

    /// Number of retired generations still pinned by callers.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// use qqq_run::generations::Registry;
    /// let registry = Registry::new(4, 4);
    /// registry.publish(registry.reserve("agent")?, "sha256", 7)?;
    /// let old = registry.acquire("agent")?;
    /// registry.publish(registry.reserve("agent")?, "new-sha256", 8)?;
    /// assert_eq!(registry.draining()?, 1);
    /// drop(old);
    /// assert_eq!(registry.draining()?, 0);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the registry lock is poisoned.
    pub fn draining(&self) -> Result<usize> {
        let mut state = self.lock()?;
        state.retired.retain(|g| g.strong_count() != 0);
        Ok(state.retired.len())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State<T>>> {
        self.state
            .lock()
            .map_err(|_| refused("component registry lock is poisoned"))
    }

    fn validate(&self, state: &State<T>, update: &Update<T>) -> Result<()> {
        if !Weak::ptr_eq(&update.owner, &Arc::downgrade(&self.state))
            || state
                .entries
                .get(&update.name)
                .is_none_or(|e| e.requested != update.revision)
        {
            return Err(refused(
                "stale component preparation; a newer update or removal won",
            ));
        }
        Ok(())
    }
}

fn advance<T>(state: &mut State<T>) -> Result<u64> {
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or_else(|| refused("component revision exhausted"))?;
    Ok(state.revision)
}

fn refused(message: &str) -> Error {
    Error::new(ErrorCode::ComponentLoadFailed, message)
        .with_remediation("retain the active component and retry after inspecting reload status")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_lease_survives_and_is_reclaimed_after_drop() {
        let r = Registry::new(1, 2);
        r.publish(r.reserve("app").unwrap(), "a", 1).unwrap();
        let old = r.acquire("app").unwrap();
        let weak = Arc::downgrade(&old);
        r.publish(r.reserve("app").unwrap(), "b", 2).unwrap();
        assert_eq!(*old.value(), 1);
        assert_eq!(*r.acquire("app").unwrap().value(), 2);
        assert_eq!(r.draining().unwrap(), 1);
        drop(old);
        assert!(weak.upgrade().is_none());
        assert_eq!(r.draining().unwrap(), 0);
    }

    #[test]
    fn stale_and_foreign_updates_cannot_publish() {
        let r = Registry::new(2, 2);
        let stale = r.reserve("app").unwrap();
        let latest = r.reserve("app").unwrap();
        r.publish(latest, "b", 2).unwrap();
        assert!(r.publish(stale, "a", 1).is_err());
        let other = Registry::new(2, 2);
        let foreign = other.reserve("app").unwrap();
        assert!(r.publish(foreign, "x", 3).is_err());
        assert_eq!(*r.acquire("app").unwrap().value(), 2);
    }

    #[test]
    fn removal_and_readdition_do_not_resurrect_old_tokens() {
        let r = Registry::new(1, 2);
        let stale = r.reserve("app").unwrap();
        assert!(r.remove("app").unwrap());
        r.publish(r.reserve("app").unwrap(), "b", 2).unwrap();
        assert!(r.publish(stale, "a", 1).is_err());
        let lease = r.acquire("app").unwrap();
        assert!(r.remove("app").unwrap());
        assert!(r.acquire("app").is_err());
        assert_eq!(*lease.value(), 2);
    }

    #[test]
    fn bounded_retirement_and_failed_preparation_preserve_service() {
        let r = Registry::new(1, 1);
        r.publish(r.reserve("app").unwrap(), "a", 1).unwrap();
        let a = r.acquire("app").unwrap();
        r.publish(r.reserve("app").unwrap(), "b", 2).unwrap();
        let b = r.acquire("app").unwrap();
        assert!(r.publish(r.reserve("app").unwrap(), "c", 3).is_err());
        r.cancel(r.reserve("app").unwrap()).unwrap();
        assert_eq!(*r.acquire("app").unwrap().value(), 2);
        assert!(r.reserve("other").is_err());
        drop(a);
        r.publish(r.reserve("app").unwrap(), "c", 3).unwrap();
        assert_eq!(*b.value(), 2);
    }
}
