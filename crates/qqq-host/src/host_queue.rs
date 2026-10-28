// SPDX-License-Identifier: Apache-2.0

//! `qqq:queue/messaging` — bounded in-memory publish/subscribe with
//! acknowledgement, lease expiry with redelivery, and order-preserving
//! semantics.
//!
//! Publishing and subscribing are **separate capabilities** (Proposal §6.3):
//! a component that may announce an event is not thereby entitled to consume
//! it. The manifest grants each direction per queue; the deploy layer
//! resolves that list once into a [`QueueConfig`], and every call re-checks
//! both the grant and the config.
//!
//! The data lives in a [`QueueBackend`] shared across the requests one
//! deployment serves (per-instance state would drop the queue with the
//! instance, which serve rebuilds per request). The backend travels as
//! `Arc<Mutex<..>>` — a short-held lock, never held across a guest call.
//!
//! `receive` never waits: the backend is local, so a message published
//! before the call is visible, and waiting would stall the reactor and
//! poison deterministic replay. `timeout-ms` is accepted and validated as a
//! `u64` but the host does not sleep on it — a polling consumer that finds
//! nothing receives `none`, which the WIT defines as the normal steady
//! state, not an error.
//!
//! The full loop in one place — publish, receive, acknowledge:
//!
//! ```
//! let mut backend = qqq_host::host_queue::QueueBackend::new();
//! backend.publish("q", b"hello".to_vec(), 0).expect("fits");
//! let delivery = backend.receive("q", 0).expect("a message waits");
//! assert_eq!(delivery.delivery_count, 1);
//! backend.acknowledge("q", &delivery.id, 0).expect("the lease is live");
//! assert_eq!(backend.pending_count("q"), 0);
//! assert_eq!(backend.in_flight_count("q"), 0);
//! ```
//!
//! Leases are host-timed: an acknowledgement for a delivery whose lease has
//! expired fails `lease-expired`, because the message has already been
//! redelivered and the original consumer must not assume its work stands.
//! The lease length is a fixed host default (`QUEUE_LEASE_SECS`); the
//! manifest configures names and directions, not durations.
//!
//! ```
//! use qqq_cap::manifest::QueueDirection;
//! let config = qqq_host::host_queue::QueueConfig::new(vec![
//!     ("orders.events".to_owned(), QueueDirection::Publish),
//!     ("orders.events".to_owned(), QueueDirection::Subscribe),
//! ]);
//! assert!(config.allows_publish("orders.events"));
//! assert!(config.allows_subscribe("orders.events"));
//! assert!(!config.allows_publish("other"));
//! ```

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use qqq_cap::capability::Capability::{QueuePublish, QueueSubscribe};
use qqq_cap::manifest::QueueDirection;

/// The WIT package this module implements.
///
/// ```
/// assert_eq!(qqq_host::host_queue::INTERFACE, "qqq:queue@1.0.0");
/// ```
pub const INTERFACE: &str = "qqq:queue@1.0.0";

/// The generated bindings carry no doc comments of their own, and re-exporting
/// them would fail `missing_docs` on the WIT's definition rather than on any
/// prose this crate wrote. The allow is scoped to the generated module so
/// hand-written items keep the lint.
#[allow(missing_docs)]
mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-queue.wit",
        interfaces: "import qqq:queue/messaging@1.0.0;",
    });
}

/// The WIT `queue-error`, re-exported rather than re-declared: the WIT
/// variant is the definition. (Same rule as `host_log` and `host_kv`.)
pub use bindings::qqq::queue::messaging::QueueError as WitQueueError;

/// The largest single message the host accepts, in bytes.
///
/// Symmetric with the kv value bound: one guest, one budget shape to learn.
pub(crate) const MAX_QUEUE_MESSAGE_BYTES: usize = 64 * 1024;

/// The most messages one `publish-many` call may carry.
///
/// Batch-first per the WIT style guide; unbounded batches would be one call's
/// unbounded host allocation.
pub(crate) const MAX_QUEUE_BATCH_MESSAGES: usize = 128;

/// The most pending messages one queue may hold.
///
/// The quota signal is `quota-exceeded`. A million-message backlog of
/// 64 KiB bodies would be tens of gigabytes; a thousand is the backpressure
/// point at which a publisher learns the consumer is gone.
pub(crate) const MAX_QUEUE_DEPTH: usize = 1024;

/// How long a delivery stays leased, in seconds.
///
/// A fixed host default: the manifest configures names and directions, and
/// per-queue durations are future work. Thirty seconds is long enough for a
/// normal handler and short enough that a dead consumer's work is visibly
/// redelivered rather than silently stuck.
pub(crate) const QUEUE_LEASE_SECS: u64 = 30;

/// Which queues the guest may use, in which direction.
///
/// Resolved once at deploy from the manifest; cloned per request, never
/// re-resolved per call.
///
/// ```
/// use qqq_cap::manifest::QueueDirection;
/// let config = qqq_host::host_queue::QueueConfig::new(vec![
///     ("q".to_owned(), QueueDirection::Publish),
/// ]);
/// assert!(config.allows_publish("q"));
/// assert!(!config.allows_subscribe("q"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct QueueConfig {
    /// Configured `(name, direction)` pairs, in declaration order.
    pub queues: Vec<(String, QueueDirection)>,
}

impl QueueConfig {
    /// The deploy-time resolution: exactly what the manifest configures.
    #[must_use]
    pub fn new(queues: Vec<(String, QueueDirection)>) -> Self {
        Self { queues }
    }

    /// Whether `queue` is configured for publishing.
    #[must_use]
    pub fn allows_publish(&self, queue: &str) -> bool {
        self.queues
            .iter()
            .any(|(name, direction)| name == queue && matches!(direction, QueueDirection::Publish))
    }

    /// Whether `queue` is configured for subscribing.
    #[must_use]
    pub fn allows_subscribe(&self, queue: &str) -> bool {
        self.queues.iter().any(|(name, direction)| {
            name == queue && matches!(direction, QueueDirection::Subscribe)
        })
    }
}

/// One message waiting in a queue.
#[derive(Debug, Clone)]
struct QueuedMessage {
    /// Host-assigned identifier, used to acknowledge. Assigned by the host,
    /// never the publisher: a publisher-chosen id would let one tenant
    /// collide with another's in-flight messages.
    id: String,
    body: Vec<u8>,
    /// How many times this message has been handed out. A consumer that
    /// sees a count above one knows a previous attempt did not acknowledge.
    deliveries: u32,
}

/// A message handed out and awaiting acknowledgement.
#[derive(Debug, Clone)]
struct InFlight {
    queue: String,
    body: Vec<u8>,
    deliveries: u32,
    /// Monotonic nanoseconds at which the lease expires.
    deadline: u64,
}

/// One queue's state: the waiting line plus the leased-out set.
#[derive(Debug, Default)]
struct QueueState {
    pending: VecDeque<QueuedMessage>,
    in_flight: BTreeMap<String, InFlight>,
}

/// The shared in-memory backend: every queue one deployment serves.
///
/// Ordered maps throughout (`DET-006`): pending is a FIFO, in-flight is
/// keyed by id, and redelivery order is creation order — so two runs that
/// publish the same messages in the same order deliver the same sequence.
///
/// ```
/// let mut backend = qqq_host::host_queue::QueueBackend::new();
/// backend.publish("q", b"hello".to_vec(), 0).expect("fits");
/// let delivery = backend.receive("q", 0).expect("a message waits");
/// assert_eq!(delivery.body, b"hello".to_vec());
/// ```
#[derive(Debug, Default)]
pub struct QueueBackend {
    queues: BTreeMap<String, QueueState>,
    /// Monotonic message counter. Mixed into ids so every id is unique
    /// without randomness — deterministic across replays of the same
    /// publication order, and never a secret.
    next_id: u64,
}

impl QueueBackend {
    /// Empty: no queues, no ids minted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensure a queue entry exists. Queues are created by configuration, but
    /// the backend tolerates unknown names internally: the Host layer
    /// refuses unconfigured queues before they reach here, so this is a
    /// lookup convenience, never an allowlist.
    fn state_for(&mut self, queue: &str) -> &mut QueueState {
        self.queues.entry(queue.to_owned()).or_default()
    }

    /// Publish one message. Returns its host-assigned id.
    ///
    /// ```
    /// let mut backend = qqq_host::host_queue::QueueBackend::new();
    /// let id = backend.publish("q", b"hello".to_vec(), 0).expect("fits");
    /// assert!(!id.is_empty());
    /// assert_eq!(backend.pending_count("q"), 1);
    /// ```
    ///
    /// # Errors
    ///
    /// `message-too-large` when the body exceeds the host bound;
    /// `quota-exceeded` when the queue is full.
    pub fn publish(
        &mut self,
        queue: &str,
        body: Vec<u8>,
        _now: u64,
    ) -> std::result::Result<String, WitQueueError> {
        if body.len() > MAX_QUEUE_MESSAGE_BYTES {
            return Err(WitQueueError::MessageTooLarge);
        }
        let pending = self.state_for(queue).pending.len();
        let in_flight = self.state_for(queue).in_flight.len();
        // The quota counts every message the queue holds, waiting or
        // leased: leased messages are still stored, so counting only the
        // pending line would let a receive-publish loop grow memory
        // without bound while the quota reported room.
        if pending + in_flight >= MAX_QUEUE_DEPTH {
            return Err(WitQueueError::QuotaExceeded);
        }
        self.next_id = self.next_id.wrapping_add(1);
        // Zero-padded so lexicographic order is numeric order: `BTreeMap`
        // iterates ids as strings, and `q:10` must sort after `q:2` for
        // redelivery order to be creation order (`DET-006`).
        let id = format!("{queue}:{:020}", self.next_id);
        self.state_for(queue).pending.push_back(QueuedMessage {
            id: id.clone(),
            body,
            deliveries: 0,
        });
        Ok(id)
    }

    /// Return expired leases to the pending line, earliest deadline first.
    ///
    /// Redelivery is what makes `lease-expired` honest: an acknowledgement
    /// that arrives after this point refers to a message already handed to
    /// someone else, so the original consumer must not assume its work stands.
    ///
    /// Each redelivery mints a **new id**: the stale handle names a lease
    /// that no longer exists, so acknowledging with it fails `lease-expired`
    /// instead of completing another consumer's delivery. (A `reject` keeps
    /// its id — that path is cooperative, not a presumed-dead consumer —
    /// so an immediate re-receive is recognizable.)
    fn reap_expired(&mut self, queue: &str, now: u64) {
        let expired: Vec<(String, InFlight)> = self
            .queues
            .get(queue)
            .map(|state| {
                state
                    .in_flight
                    .iter()
                    .filter(|(_, flight)| now >= flight.deadline)
                    .map(|(id, flight)| (id.clone(), flight.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if expired.is_empty() {
            return;
        }
        // Reverse iteration order (BTreeMap yields creation order, and ids
        // mint monotonically in zero-padded form) so the earliest-expired
        // lease ends up front.
        let mut fresh: Vec<(String, QueuedMessage)> = Vec::with_capacity(expired.len());
        for (_, flight) in &expired {
            self.next_id = self.next_id.wrapping_add(1);
            fresh.push((
                flight.queue.clone(),
                QueuedMessage {
                    id: format!("{}:{:020}", flight.queue, self.next_id),
                    body: flight.body.clone(),
                    deliveries: flight.deliveries,
                },
            ));
        }
        let Some(state) = self.queues.get_mut(queue) else {
            return;
        };
        for (id, _) in &expired {
            state.in_flight.remove(id);
        }
        for (_, message) in fresh.into_iter().rev() {
            state.pending.push_front(message);
        }
    }

    /// Receive the next delivery, or `None` when the queue is empty.
    ///
    /// Never waits: expired leases are reaped first, then the head of the
    /// pending line is leased out. An empty queue is the normal steady state
    /// of a polling consumer, not an error.
    ///
    /// ```
    /// let mut backend = qqq_host::host_queue::QueueBackend::new();
    /// assert!(backend.receive("q", 0).is_none());
    /// backend.publish("q", b"m".to_vec(), 0).expect("fits");
    /// let delivery = backend.receive("q", 0).expect("a message waits");
    /// assert_eq!(delivery.body, b"m".to_vec());
    /// assert_eq!(delivery.delivery_count, 1);
    /// ```
    ///
    /// Redelivery after lease expiry mints a new id: the stale handle
    /// names a dead lease, so acknowledging with it fails `lease-expired`
    /// instead of completing another consumer's delivery.
    ///
    /// ```
    /// let mut backend = qqq_host::host_queue::QueueBackend::new();
    /// backend.publish("q", b"m".to_vec(), 0).expect("fits");
    /// let first = backend.receive("q", 0).expect("first delivery");
    /// // One lease past the handout (`QUEUE_LEASE_SECS` is 30 seconds).
    /// let after_lease = 30u64.saturating_mul(1_000_000_000);
    /// let second = backend.receive("q", after_lease).expect("redelivery");
    /// assert_ne!(second.id, first.id);
    /// assert_eq!(second.delivery_count, 2);
    /// ```
    pub fn receive(
        &mut self,
        queue: &str,
        now: u64,
    ) -> Option<bindings::qqq::queue::messaging::Delivery> {
        self.reap_expired(queue, now);
        let state = self.queues.get_mut(queue)?;
        let mut message = state.pending.pop_front()?;
        // Saturating: 4 billion handouts without an ack is a wedged
        // consumer, not a counter worth trapping on — and a trap would
        // refuse a receive for arithmetic, which is never the honest error.
        message.deliveries = message.deliveries.saturating_add(1);
        let delivery = bindings::qqq::queue::messaging::Delivery {
            id: message.id.clone(),
            body: message.body.clone(),
            delivery_count: message.deliveries,
        };
        state.in_flight.insert(
            message.id.clone(),
            InFlight {
                queue: queue.to_owned(),
                body: message.body,
                deliveries: message.deliveries,
                deadline: now.saturating_add(QUEUE_LEASE_SECS.saturating_mul(1_000_000_000)),
            },
        );
        Some(delivery)
    }

    /// Acknowledge a delivery, removing it from the queue.
    ///
    /// ```
    /// let mut backend = qqq_host::host_queue::QueueBackend::new();
    /// backend.publish("q", b"m".to_vec(), 0).expect("fits");
    /// let delivery = backend.receive("q", 0).expect("a message waits");
    /// backend.acknowledge("q", &delivery.id, 0).expect("the lease is live");
    /// assert_eq!(backend.in_flight_count("q"), 0);
    /// ```
    ///
    /// A second acknowledgement fails: ids are single-use, so a double ack
    /// cannot be told apart from an ack of a redelivered id, and both must
    /// fail rather than silently succeed.
    ///
    /// ```
    /// let mut backend = qqq_host::host_queue::QueueBackend::new();
    /// backend.publish("q", b"m".to_vec(), 0).expect("fits");
    /// let delivery = backend.receive("q", 0).expect("a message waits");
    /// backend.acknowledge("q", &delivery.id, 0).expect("first ack works");
    /// let err = backend.acknowledge("q", &delivery.id, 0).expect_err("double ack fails");
    /// assert!(matches!(
    ///     err,
    ///     qqq_host::host_queue::WitQueueError::LeaseExpired
    /// ));
    /// ```
    ///
    /// # Errors
    ///
    /// `lease-expired` when the id is unknown or its lease already passed —
    /// including double acknowledgements. Ids are single-use by design: an
    /// ack that names a missing id cannot be told apart from one that names
    /// a redelivered id, and both must fail rather than silently succeed.
    pub fn acknowledge(
        &mut self,
        queue: &str,
        id: &str,
        now: u64,
    ) -> std::result::Result<(), WitQueueError> {
        self.reap_expired(queue, now);
        match self.queues.get_mut(queue).and_then(|state| {
            let flight = state.in_flight.get(id)?;
            (flight.queue == queue).then(|| state.in_flight.remove(id))
        }) {
            Some(_) => Ok(()),
            None => Err(WitQueueError::LeaseExpired),
        }
    }

    /// Return a delivery to the queue without acknowledging it.
    ///
    /// The message becomes immediately available to another consumer —
    /// the correct response to "I cannot process this right now", rather
    /// than waiting out a lease timeout.
    ///
    /// ```
    /// let mut backend = qqq_host::host_queue::QueueBackend::new();
    /// backend.publish("q", b"m".to_vec(), 0).expect("fits");
    /// let first = backend.receive("q", 0).expect("first delivery");
    /// backend.reject("q", &first.id, 0).expect("reject works");
    /// let second = backend.receive("q", 0).expect("redelivery");
    /// assert_eq!(second.delivery_count, 2);
    /// ```
    ///
    /// A cooperative reject keeps the id: the same handle comes back, so
    /// an immediate re-receive is recognizable. (Expiry redelivery mints a
    /// new id instead — a presumed-dead consumer must not share an
    /// identifier with the consumer that replaced it.)
    ///
    /// ```
    /// let mut backend = qqq_host::host_queue::QueueBackend::new();
    /// backend.publish("q", b"m".to_vec(), 0).expect("fits");
    /// let first = backend.receive("q", 0).expect("first delivery");
    /// backend.reject("q", &first.id, 0).expect("reject works");
    /// let second = backend.receive("q", 0).expect("redelivery");
    /// assert_eq!(second.id, first.id);
    /// ```
    ///
    /// # Errors
    ///
    /// `lease-expired` when the id is unknown or already expired, for the
    /// same single-use reason as [`Self::acknowledge`].
    pub fn reject(
        &mut self,
        queue: &str,
        id: &str,
        now: u64,
    ) -> std::result::Result<(), WitQueueError> {
        self.reap_expired(queue, now);
        let flight = self
            .queues
            .get_mut(queue)
            .and_then(|state| {
                let flight = state.in_flight.get(id)?;
                (flight.queue == queue).then(|| state.in_flight.remove(id))?
            })
            .ok_or(WitQueueError::LeaseExpired)?;
        if let Some(state) = self.queues.get_mut(queue) {
            state.pending.push_front(QueuedMessage {
                id: id.to_owned(),
                body: flight.body,
                deliveries: flight.deliveries,
            });
        }
        Ok(())
    }

    /// Pending messages in `queue` — for tests and operators, not guests.
    ///
    /// ```
    /// let mut backend = qqq_host::host_queue::QueueBackend::new();
    /// assert_eq!(backend.pending_count("q"), 0);
    /// backend.publish("q", b"m".to_vec(), 0).expect("fits");
    /// assert_eq!(backend.pending_count("q"), 1);
    /// ```
    #[must_use]
    pub fn pending_count(&self, queue: &str) -> usize {
        self.queues
            .get(queue)
            .map_or(0, |state| state.pending.len())
    }

    /// In-flight messages in `queue` — for tests and operators, not guests.
    ///
    /// ```
    /// let mut backend = qqq_host::host_queue::QueueBackend::new();
    /// backend.publish("q", b"m".to_vec(), 0).expect("fits");
    /// assert_eq!(backend.in_flight_count("q"), 0);
    /// backend.receive("q", 0).expect("a message waits");
    /// assert_eq!(backend.in_flight_count("q"), 1);
    /// ```
    #[must_use]
    pub fn in_flight_count(&self, queue: &str) -> usize {
        self.queues
            .get(queue)
            .map_or(0, |state| state.in_flight.len())
    }
}

/// The per-instance view: deploy-resolved config plus the shared backend.
///
/// Both halves are `Arc` clones: the config is read-only after deploy, and
/// the backend is the one map every request of the deployment shares. A
/// rotation (`replacement`) clones both, so queued work survives deploys
/// exactly as stored kv values do.
///
/// Cloning shares, not forks — that is the whole point of the `Arc`s:
///
/// ```
/// let view = qqq_host::host_queue::QueueView::new(
///     std::sync::Arc::new(qqq_host::host_queue::QueueConfig::new(Vec::new())),
///     std::sync::Arc::new(std::sync::Mutex::new(qqq_host::host_queue::QueueBackend::new())),
/// );
/// let rotated = view.clone();
/// assert!(std::sync::Arc::ptr_eq(&view.backend, &rotated.backend));
/// ```
#[derive(Debug, Clone, Default)]
pub struct QueueView {
    /// The deploy-resolved queue names and directions.
    pub config: Arc<QueueConfig>,
    /// The shared queues every request of the deployment publishes to and
    /// receives from.
    pub backend: Arc<Mutex<QueueBackend>>,
}

impl QueueView {
    /// A view over `config` and `backend`.
    ///
    /// ```
    /// let view = qqq_host::host_queue::QueueView::new(
    ///     std::sync::Arc::new(qqq_host::host_queue::QueueConfig::new(Vec::new())),
    ///     std::sync::Arc::new(std::sync::Mutex::new(qqq_host::host_queue::QueueBackend::new())),
    /// );
    /// assert!(view.config.queues.is_empty());
    /// ```
    #[must_use]
    pub fn new(config: Arc<QueueConfig>, backend: Arc<Mutex<QueueBackend>>) -> Self {
        Self { config, backend }
    }
}

/// Register the queue interface for the granted capabilities.
///
/// Links `qqq:queue/messaging` only when `queue.publish` or `queue.subscribe`
/// is granted; every function re-checks at call time.
///
/// ```
/// let engine = wasmtime::Engine::default();
/// let mut linker = wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
/// qqq_host::host_queue::register(&mut linker, &qqq_cap::resolve::GrantSet::empty())
///     .expect("empty grants register nothing");
/// ```
///
/// A granted manifest links:
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
///      [[capabilities.queue]]\nname = \"q\"\ndirection = \"publish\"\n",
/// )
/// .expect("manifest parses");
/// let grants = qqq_cap::resolve::GrantSet::from_manifest(&manifest);
/// let engine = wasmtime::Engine::default();
/// let mut linker = wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
/// qqq_host::host_queue::register(&mut linker, &grants).expect("granted links");
/// ```
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects an interface.
pub fn register(
    linker: &mut wasmtime::component::Linker<crate::linker::StoreData>,
    grants: &qqq_cap::resolve::GrantSet,
) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    if !(grants.grants(QueuePublish) || grants.grants(QueueSubscribe)) {
        return Ok(());
    }
    bindings::qqq::queue::messaging::add_to_linker::<
        crate::linker::StoreData,
        HasSelf<crate::linker::StoreData>,
    >(linker, |state| state)?;
    Ok(())
}

/// Check a publish: the direction grant, then the queue membership.
///
/// Directions never widen: a subscribe grant says nothing about publishing,
/// so the missing direction is `not-granted` rather than a configured
/// refusal. Membership comes second because the queue list is public anyway
/// (`queues()`), and an unlisted queue is unconfigured however the call
/// arrived.
fn check_publish(
    data: &crate::linker::StoreData,
    queue: &str,
) -> std::result::Result<(), WitQueueError> {
    if !data.grants.grants(QueuePublish) {
        return Err(WitQueueError::NotGranted);
    }
    if !valid_queue_name(queue) || !data.queue.config.allows_publish(queue) {
        return Err(WitQueueError::QueueNotConfigured);
    }
    Ok(())
}

/// Check a subscribe-side call: the subscribe grant, then the membership.
fn check_subscribe(
    data: &crate::linker::StoreData,
    queue: &str,
) -> std::result::Result<(), WitQueueError> {
    if !data.grants.grants(QueueSubscribe) {
        return Err(WitQueueError::NotGranted);
    }
    if !valid_queue_name(queue) || !data.queue.config.allows_subscribe(queue) {
        return Err(WitQueueError::QueueNotConfigured);
    }
    Ok(())
}

/// Whether a queue name is safe to use as a map key.
///
/// Names arrive per call and become map keys, so an unbounded name is an
/// unbounded host allocation for one lookup. Empty names are refused for
/// the same reason blank store names are: a nameless queue would render as
/// structure without identity.
fn valid_queue_name(queue: &str) -> bool {
    const MAX_QUEUE_NAME_BYTES: usize = 256;
    !queue.is_empty() && queue.len() <= MAX_QUEUE_NAME_BYTES
}

/// Lock the shared backend, recovering from a poisoned lock.
///
/// Poisoning means a previous holder panicked mid-access — and shipping code
/// forbids panicking paths, so the map itself is intact. Refusing every
/// later request for a panic that cannot name would turn one failed call
/// into a dead queue; recovering keeps the failure where it happened.
fn lock_backend(data: &crate::linker::StoreData) -> std::sync::MutexGuard<'_, QueueBackend> {
    data.queue.backend.lock().unwrap_or_else(|poisoned| {
        let _ = &poisoned;
        poisoned.into_inner()
    })
}

/// The monotonic instant for lease math, or a backend failure.
///
/// A replay error (an exhausted log) is a host fault, and `queue-error` has
/// no host-fault case — so it surfaces as `backend-failed`, naming the
/// clock. Read before the lock: the instant and the mutation are not one
/// atomic step, so a lease can expire between them by nanoseconds. The
/// boundary is inclusive (`now >= deadline`), which makes that skew a
/// slightly-early expiry rather than a missed one — fail closed, not silent.
fn now_or_fail(data: &crate::linker::StoreData) -> std::result::Result<u64, WitQueueError> {
    data.ambient
        .read_monotonic_nanos()
        .map_err(|error| WitQueueError::BackendFailed(error.to_string()))
}

/// The host implementation of `qqq:queue/messaging`.
///
/// # Why every method re-checks both the grant and the config
///
/// Registration is conditional on the direction grants AND the body
/// re-checks them, so a mis-built linker still denies (`ARCH-012`). The
/// config check is separate because grants are direction-level while queues
/// are named: `queue.publish` says the guest may publish *somewhere*, and
/// only the config says where.
impl bindings::qqq::queue::messaging::Host for crate::linker::StoreData {
    fn publish(&mut self, queue: String, body: Vec<u8>) -> std::result::Result<(), WitQueueError> {
        check_publish(self, &queue)?;
        lock_backend(self).publish(&queue, body, now_or_fail(self)?)?;
        Ok(())
    }

    fn publish_many(
        &mut self,
        queue: String,
        bodies: Vec<Vec<u8>>,
    ) -> std::result::Result<(), WitQueueError> {
        // Atomic like `emit-many`: every body validates before any is
        // stored, so a batch that fails on its last body leaves no prefix
        // for a retry to duplicate. Sizes are checked after lifting: the
        // Component Model materializes the batch before the host runs, so
        // the per-message bound governs storage, not transfer — and the
        // transfer itself is bounded by the instance's memory and fuel.
        check_publish(self, &queue)?;
        if bodies.len() > MAX_QUEUE_BATCH_MESSAGES {
            return Err(WitQueueError::QuotaExceeded);
        }
        if bodies
            .iter()
            .any(|body| body.len() > MAX_QUEUE_MESSAGE_BYTES)
        {
            return Err(WitQueueError::MessageTooLarge);
        }
        let now = now_or_fail(self)?;
        let mut backend = lock_backend(self);
        // The publish path bounds the same total, so the batch cannot
        // overflow a queue that single publishes could not.
        if backend.pending_count(&queue) + backend.in_flight_count(&queue) + bodies.len()
            > MAX_QUEUE_DEPTH
        {
            return Err(WitQueueError::QuotaExceeded);
        }
        for body in bodies {
            backend.publish(&queue, body, now)?;
        }
        Ok(())
    }

    fn receive(
        &mut self,
        queue: String,
        _timeout_ms: u64,
    ) -> std::result::Result<Option<bindings::qqq::queue::messaging::Delivery>, WitQueueError> {
        // V1 never waits: the timeout is accepted (it is a `u64`, so any
        // guest value is representable) but the host does not sleep on it.
        // A local backend makes waiting pointless — everything published
        // before the call is already visible — and sleeping would stall the
        // reactor and poison deterministic replay.
        check_subscribe(self, &queue)?;
        let now = now_or_fail(self)?;
        Ok(lock_backend(self).receive(&queue, now))
    }

    fn acknowledge(&mut self, queue: String, id: String) -> std::result::Result<(), WitQueueError> {
        check_subscribe(self, &queue)?;
        let now = now_or_fail(self)?;
        lock_backend(self).acknowledge(&queue, &id, now)
    }

    fn reject(&mut self, queue: String, id: String) -> std::result::Result<(), WitQueueError> {
        check_subscribe(self, &queue)?;
        let now = now_or_fail(self)?;
        lock_backend(self).reject(&queue, &id, now)
    }

    fn queues(&mut self) -> Vec<(String, String)> {
        // Infallible by WIT design (the manifest set is public), so the
        // grant re-check fails closed by answering empty rather than by
        // erroring: an ungranted caller learns nothing, including membership.
        if !(self.grants.grants(QueuePublish) || self.grants.grants(QueueSubscribe)) {
            return Vec::new();
        }
        self.queue
            .config
            .queues
            .iter()
            .map(|(name, direction)| {
                (
                    name.clone(),
                    match direction {
                        QueueDirection::Publish => "publish".to_owned(),
                        QueueDirection::Subscribe => "subscribe".to_owned(),
                    },
                )
            })
            .collect()
    }
}

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::linker::StoreData;
    use qqq_cap::manifest::Manifest;
    use qqq_cap::resolve::GrantSet;

    fn test_manifest(both: bool, publish_only: bool) -> Manifest {
        let stanza = if both {
            "[[capabilities.queue]]\nname = \"q\"\ndirection = \"publish\"\n\
             [[capabilities.queue]]\nname = \"q\"\ndirection = \"subscribe\"\n"
        } else if publish_only {
            "[[capabilities.queue]]\nname = \"q\"\ndirection = \"publish\"\n"
        } else {
            "[[capabilities.queue]]\nname = \"q\"\ndirection = \"subscribe\"\n"
        };
        Manifest::parse(&format!(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n{stanza}"
        ))
        .expect("manifest parses")
    }

    fn granted_store(both: bool, publish_only: bool) -> StoreData {
        let manifest = test_manifest(both, publish_only);
        let grants = GrantSet::from_manifest(&manifest);
        let mut directions = Vec::new();
        if both || publish_only {
            directions.push(("q".to_owned(), QueueDirection::Publish));
        }
        if both || !publish_only {
            directions.push(("q".to_owned(), QueueDirection::Subscribe));
        }
        let config = Arc::new(QueueConfig::new(directions));
        let view = QueueView::new(config, Arc::new(Mutex::new(QueueBackend::new())));
        StoreData::new(grants).with_queue(view)
    }

    fn ungranted_store() -> StoreData {
        StoreData::new(GrantSet::empty())
    }

    /// Publish then receive then acknowledge: the round trip works and the
    /// queue is empty afterwards.
    #[test]
    fn publish_receive_acknowledge_round_trip() {
        let mut backend = QueueBackend::new();
        let id = backend.publish("q", b"hello".to_vec(), 0).expect("fits");
        assert_eq!(backend.pending_count("q"), 1);
        let delivery = backend.receive("q", 0).expect("a message waits");
        assert_eq!(delivery.body, b"hello".to_vec());
        assert_eq!(delivery.delivery_count, 1);
        assert_eq!(backend.in_flight_count("q"), 1);
        backend
            .acknowledge("q", &delivery.id, 0)
            .expect("the lease is live");
        assert_eq!(backend.pending_count("q"), 0);
        assert_eq!(backend.in_flight_count("q"), 0);
        let _ = id;
    }

    /// Reject returns the message immediately with the same delivery count;
    /// the next receive hands it out again with the count incremented.
    #[test]
    fn reject_redelivers_immediately() {
        let mut backend = QueueBackend::new();
        backend.publish("q", b"m".to_vec(), 0).expect("fits");
        let first = backend.receive("q", 0).expect("first delivery");
        assert_eq!(first.delivery_count, 1);
        backend.reject("q", &first.id, 0).expect("reject works");
        assert_eq!(backend.pending_count("q"), 1);
        assert_eq!(backend.in_flight_count("q"), 0);
        let second = backend.receive("q", 0).expect("redelivery");
        assert_eq!(second.id, first.id, "the same message comes back");
        assert_eq!(second.delivery_count, 2);
        backend
            .acknowledge("q", &second.id, 0)
            .expect("the redelivery acknowledges");
    }

    /// An expired lease redelivers under a new id, and the stale
    /// acknowledgement fails `lease-expired` instead of double-completing.
    #[test]
    fn expired_leases_redeliver_and_stale_acks_fail() {
        let mut backend = QueueBackend::new();
        backend.publish("q", b"m".to_vec(), 0).expect("fits");
        let first = backend.receive("q", 0).expect("first delivery");
        let after_lease = QUEUE_LEASE_SECS.saturating_mul(1_000_000_000);
        let second = backend
            .receive("q", after_lease)
            .expect("the expired lease redelivers");
        assert_ne!(
            second.id, first.id,
            "redelivery mints a new id: the stale handle names a dead lease"
        );
        assert_eq!(second.delivery_count, 2);
        assert_eq!(second.body, b"m".to_vec());
        let err = backend
            .acknowledge("q", &first.id, after_lease)
            .expect_err("the stale ack must fail");
        assert!(matches!(err, WitQueueError::LeaseExpired));
        backend
            .acknowledge("q", &second.id, after_lease)
            .expect("the live delivery acknowledges");
        assert_eq!(backend.pending_count("q"), 0);
        assert_eq!(backend.in_flight_count("q"), 0);
    }

    /// Unknown ids fail `lease-expired`: ids are single-use, and an ack
    /// that names a missing id cannot be told apart from a redelivered one.
    #[test]
    fn unknown_ids_fail_lease_expired() {
        let mut backend = QueueBackend::new();
        assert!(matches!(
            backend.acknowledge("q", "q:999", 0),
            Err(WitQueueError::LeaseExpired)
        ));
        assert!(matches!(
            backend.reject("q", "q:999", 0),
            Err(WitQueueError::LeaseExpired)
        ));
    }

    /// Oversize bodies and full queues fail before anything is stored, and
    /// oversize batches fail as quota — not as oversize entries, since no
    /// single entry is too large.
    #[test]
    fn oversize_bodies_and_full_queues_fail_closed() {
        let mut backend = QueueBackend::new();
        let big = vec![0u8; MAX_QUEUE_MESSAGE_BYTES + 1];
        assert!(matches!(
            backend.publish("q", big, 0),
            Err(WitQueueError::MessageTooLarge)
        ));
        for _ in 0..MAX_QUEUE_DEPTH {
            backend.publish("q", b"v".to_vec(), 0).expect("fits");
        }
        assert!(matches!(
            backend.publish("q", b"one more".to_vec(), 0),
            Err(WitQueueError::QuotaExceeded)
        ));
        assert_eq!(backend.pending_count("q"), MAX_QUEUE_DEPTH);
    }

    /// Directions never widen: a publish grant cannot receive, and a
    /// subscribe grant cannot publish — each names its own denial.
    #[test]
    fn directions_do_not_widen() {
        let mut publish_only = granted_store(false, true);
        let err =
            bindings::qqq::queue::messaging::Host::receive(&mut publish_only, "q".to_owned(), 0)
                .expect_err("publish cannot receive");
        assert!(matches!(err, WitQueueError::NotGranted));
        let mut subscribe_only = granted_store(false, false);
        let err = bindings::qqq::queue::messaging::Host::publish(
            &mut subscribe_only,
            "q".to_owned(),
            b"v".to_vec(),
        )
        .expect_err("subscribe cannot publish");
        assert!(matches!(err, WitQueueError::NotGranted));
    }

    /// Unconfigured queues are unconfigured however the call arrived, and
    /// a write-only direction still refuses reads by grant first.
    #[test]
    fn unlisted_queues_are_not_configured() {
        let mut data = granted_store(true, false);
        let err = bindings::qqq::queue::messaging::Host::publish(
            &mut data,
            "nope".to_owned(),
            b"v".to_vec(),
        )
        .expect_err("unlisted");
        assert!(matches!(err, WitQueueError::QueueNotConfigured));
    }

    /// `queues()` without a grant answers empty: the manifest set is public
    /// to granted guests, but an ungranted caller learns nothing.
    #[test]
    fn queues_without_grant_is_empty() {
        let mut data = ungranted_store();
        assert_eq!(
            bindings::qqq::queue::messaging::Host::queues(&mut data),
            Vec::<(String, String)>::new()
        );
    }

    /// Hostile queue names are unconfigured, not lookups.
    #[test]
    fn hostile_queue_names_are_not_configured() {
        let mut data = granted_store(true, false);
        for hostile in ["", &"q".repeat(257)] {
            let err = bindings::qqq::queue::messaging::Host::publish(
                &mut data,
                hostile.to_owned(),
                b"v".to_vec(),
            )
            .expect_err("hostile queue name refused");
            assert!(
                matches!(err, WitQueueError::QueueNotConfigured),
                "{hostile:?} must fail closed"
            );
        }
    }

    /// Oversize batches fail as quota: no single message is too large, so
    /// blaming an entry would misdirect the guest at 129 tiny messages.
    #[test]
    fn oversize_batches_fail_as_quota() {
        let mut data = granted_store(true, false);
        let keys: Vec<Vec<u8>> = (0..=MAX_QUEUE_BATCH_MESSAGES)
            .map(|i| vec![u8::try_from(i).expect("batch indexes fit in a byte")])
            .collect();
        let err =
            bindings::qqq::queue::messaging::Host::publish_many(&mut data, "q".to_owned(), keys)
                .expect_err("too many bodies");
        assert!(matches!(err, WitQueueError::QuotaExceeded));
        assert_eq!(
            lock_backend(&data).pending_count("q"),
            0,
            "no prefix of a refused batch may persist"
        );
    }

    /// The register links only when a queue grant is present.
    #[test]
    fn register_links_only_when_granted() {
        const EMPTY: &str = r#"(component
          (import "qqq:queue/messaging@1.0.0" (instance $m))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        const NAMED: &str = r#"(component
          (import "qqq:queue/messaging@1.0.0" (instance $m
            (export "queues" (func (result (list (tuple string string)))))))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        fn link(grants: &GrantSet, wat: &str) -> wasmtime::Result<()> {
            let mut config = wasmtime::Config::new();
            config.wasm_component_model(true);
            let engine = wasmtime::Engine::new(&config).expect("engine builds");
            let mut linker = wasmtime::component::Linker::new(&engine);
            register(&mut linker, grants)?;
            let bytes = wat::parse_str(wat).expect("fixture assembles");
            let component =
                wasmtime::component::Component::new(&engine, &bytes).expect("fixture compiles");
            let mut store = wasmtime::Store::new(&engine, StoreData::new(grants.clone()));
            linker.instantiate(&mut store, &component).map(|_| ())
        }
        let manifest = Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [[capabilities.queue]]\nname = \"q\"\ndirection = \"publish\"\n",
        )
        .expect("manifest parses");
        link(&GrantSet::from_manifest(&manifest), EMPTY).expect("a granted import links");
        // And a granted import of a NAMED function links too: the empty
        // shape above proves gating, and this proves the named shape the
        // guest actually imports resolves under the same grant.
        link(&GrantSet::from_manifest(&manifest), NAMED).expect("granted names link");
        let err = link(&GrantSet::empty(), NAMED).expect_err("no grant means no instance");
        assert!(
            format!("{err:#}").contains("qqq:queue/messaging"),
            "the refusal must name the interface: {err:#}"
        );
    }
}
