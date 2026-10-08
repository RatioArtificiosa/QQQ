// SPDX-License-Identifier: Apache-2.0

//! One dedicated writer thread per physical sink ("lane").
//!
//! # Why a lane rather than a pump per output
//!
//! Every request used to build fresh outputs, each with its own pump task,
//! and every sink write was a `spawn_blocking` call that pump awaited — all
//! of them writing to the same physical stream. A stalled sink pinned one
//! blocking-pool thread per output, and at 2R threads for R requests a slow
//! log consumer starved the pool that also runs guest handlers: logging
//! stopped request handling. A lane moves that work off the pool entirely:
//! one OS thread per physical sink, created once, draining one FIFO shared
//! by every output on that sink.
//!
//! # What a lane is and is not
//!
//! A lane is a thread plus a bounded queue. It batches whatever is already
//! queued into at most [`LANE_BATCH_BYTES`] per sink write (throughput comes
//! from fewer, larger writes, not from thread hand-off per message), wakes
//! parked writers after each completed write, and answers flush markers in
//! order. It carries today's framing unchanged — structured framing is a
//! separate decision, and smuggling it in here would mix a transport change
//! with a format change.
//!
//! Fairness lives at admission, not in the thread: [`OUTPUT_IN_FLIGHT_BYTES`]
//! caps each output's undrained bytes, so one noisy output parks instead of
//! filling the shared lane. Order is structural: one FIFO, one writer thread,
//! so bytes reach the sink in the order they were accepted, per output and
//! overall.

use std::io;
use std::sync::{Arc, Mutex};
use std::task::Waker;

use tokio::sync::{mpsc, oneshot};

use crate::guest_output::{GuestSink, OutputBudget};

/// How many messages wait in one lane's queue before writers park.
///
/// Shared across every output on the sink (unlike the old per-output pump
/// bound): 256 small writes, or fewer large ones once the byte pressure
/// parks first. A full queue parks the writer with the message held for the
/// retry — never blocking an executor worker on a slow sink.
///
/// ```
/// use qqq_host::sink_lane::LANE_QUEUE_MSGS;
///
/// assert_eq!(LANE_QUEUE_MSGS, 256);
/// ```
pub const LANE_QUEUE_MSGS: usize = 256;

/// How many bytes one sink write carries at most.
///
/// The lane drains whatever is already queued up to this size, so N small
/// messages become one syscall instead of N thread hand-offs. Larger than any
/// single test message and far below the queue's worst case, which is what
/// makes the coalescing ratio worth asserting rather than assuming.
///
/// ```
/// use qqq_host::sink_lane::LANE_BATCH_BYTES;
///
/// assert_eq!(LANE_BATCH_BYTES, 64 * 1024);
/// ```
pub const LANE_BATCH_BYTES: usize = 64 * 1024;

/// How many undrained bytes one output may hold before it parks.
///
/// Per-output fairness for the shared lane: without it one noisy output fills
/// the queue and every other output's writers park behind it. Parking delays
/// writes rather than refusing them — the lifetime quota still refuses — so a
/// burst that fits nowhere right now waits instead of failing.
///
/// ```
/// use qqq_host::sink_lane::OUTPUT_IN_FLIGHT_BYTES;
///
/// assert_eq!(OUTPUT_IN_FLIGHT_BYTES, 256 * 1024);
/// ```
pub const OUTPUT_IN_FLIGHT_BYTES: usize = 256 * 1024;

/// Bytes reserved against the in-flight caps, released when drained.
///
/// Built in `poll_write` after the lifetime reservation succeeds; carried by
/// the lane message (or held in the writer's pending slot while parked) and
/// dropped by the lane thread after the bytes reach the sink — or on any path
/// that abandons the message, so held counts can never leak. This is the
/// second half of the in-flight accounting: the queue bound counts messages,
/// this counts their bytes against the per-output fairness cap and the tenant
/// ceiling.
pub struct InFlight {
    child: Arc<OutputBudget>,
    bytes: u64,
}

impl InFlight {
    /// Hold `bytes` of in-flight space on `child` (and its tenant parent).
    ///
    /// Returns `None` — admitting nothing — when either cap is over, unless
    /// that counter is empty: an empty queue admits one message of any size,
    /// since parking it would wait for a drain that can never start. A `None`
    /// caller must park or refuse without queueing; a `Some` caller owns
    /// counts the lane thread releases on drain.
    pub(crate) fn reserve(child: &Arc<OutputBudget>, bytes: u64) -> Option<Self> {
        if child.reserve_in_flight(bytes) {
            Some(Self {
                child: Arc::clone(child),
                bytes,
            })
        } else {
            None
        }
    }
}

impl Drop for InFlight {
    /// Panic-free by construction (`F-21`): saturating counters only, no locks
    /// beyond the parent link read, which tolerates a missing entry. A `Drop`
    /// that panics during unwinding aborts the process even after `F-01` —
    /// this one cannot.
    fn drop(&mut self) {
        self.child.release_in_flight(self.bytes);
    }
}

/// Work for one lane, in arrival order.
pub(crate) enum LaneMsg {
    /// Escaped bytes to append to the sink, with their budget guard and the
    /// owning output's failure slot.
    ///
    /// The failure slot travels per message rather than per lane because the
    /// lane is shared: a sink failure must taint exactly the outputs whose
    /// bytes it dropped, not every present and future output on the lane. A
    /// lane-wide slot would poison the process streams permanently after one
    /// transient sink error, since nothing ever clears it.
    Data {
        bytes: Vec<u8>,
        flight: InFlight,
        failure: Arc<std::sync::Mutex<Option<String>>>,
    },
    /// Flush the sink, then report completion through the channel.
    Flush(oneshot::Sender<io::Result<()>>),
}

/// The outcome of one non-blocking lane send.
pub(crate) enum LaneSend {
    /// The lane owns the message now.
    Sent,
    /// The lane queue is full; the message is back for the retry.
    Full(LaneMsg),
    /// The lane thread is gone; queued work will never complete.
    Closed,
}

/// One physical sink's dedicated writer thread and its inbox.
///
/// Shared by every output on the sink through `Arc`: cloneable on purpose,
/// so `GuestOutput` stays cloneable too. The thread ends when the last sender
/// drops — the inbox drains shut and `blocking_recv` returns `None` — so a
/// lane cannot outlive the outputs it serves.
pub struct SinkLane {
    tx: mpsc::Sender<LaneMsg>,
    parked: Arc<Mutex<Vec<Waker>>>,
    sink: Arc<dyn GuestSink>,
}

impl SinkLane {
    /// Start the lane thread for `sink`, returning the shared handle.
    ///
    /// The thread fail-stops on panic (`F-01`): a lane that died silently
    /// would leave writers `Pending` forever, which is a hang shaped like
    /// backpressure. A dead lane surfaces as `Closed` sends instead.
    ///
    /// Public because the type is: a constructor only tests and future crates
    /// can name is a half-open API, and doctests — which are external crates —
    /// cannot exercise a `pub(crate)` one (which is also how the missing
    /// coverage was caught: the doctest below failed to compile).
    ///
    /// ```
    /// use std::sync::{Arc, Mutex};
    /// use qqq_host::sink_lane::SinkLane;
    ///
    /// let lane = SinkLane::spawn(
    ///     "doctest-lane",
    ///     Arc::new(Mutex::new(Vec::<u8>::new())),
    /// )
    /// .expect("a lane thread spawns");
    /// drop(lane);
    /// ```
    ///
    /// # Errors
    ///
    /// When the OS refuses the thread. Near-impossible on a machine that can
    /// run a server at all; the caller decides whether that is fatal.
    pub fn spawn(name: &'static str, sink: Arc<dyn GuestSink>) -> io::Result<Arc<Self>> {
        let (tx, mut rx) = mpsc::channel::<LaneMsg>(LANE_QUEUE_MSGS);
        let parked: Arc<Mutex<Vec<Waker>>> = Arc::new(Mutex::new(Vec::new()));
        let parked_thread = Arc::clone(&parked);
        let thread_sink = Arc::clone(&sink);
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let _fail_stop = crate::guard::AbortOnPanic::new(name);
                let mut batch: Vec<u8> = Vec::with_capacity(LANE_BATCH_BYTES);
                let mut guards: Vec<InFlight> = Vec::new();
                let mut failures: Vec<Arc<std::sync::Mutex<Option<String>>>> = Vec::new();
                while let Some(first) = rx.blocking_recv() {
                    let mut next = Some(first);
                    loop {
                        match next.take() {
                            Some(LaneMsg::Data {
                                bytes,
                                flight,
                                failure,
                            }) => {
                                batch.extend_from_slice(&bytes);
                                guards.push(flight);
                                failures.push(failure);
                            }
                            Some(LaneMsg::Flush(done)) => {
                                let result = match write_batch(&*thread_sink, &mut batch) {
                                    Ok(()) => thread_sink.flush_shared(),
                                    Err(error) => {
                                        // The batch write died here, not in
                                        // the post-loop drain below, so this
                                        // arm must attribute it: clearing the
                                        // slots unrecorded would let the data
                                        // owner's next flush report `Ok` over
                                        // lost bytes.
                                        let message = error.to_string();
                                        for failure in failures.drain(..) {
                                            crate::guest_output::record_failure(
                                                &failure,
                                                message.clone(),
                                            );
                                        }
                                        Err(error)
                                    }
                                };
                                guards.clear();
                                failures.clear();
                                let _ = done.send(result);
                            }
                            None => break,
                        }
                        if batch.len() >= LANE_BATCH_BYTES {
                            break;
                        }
                        next = rx.try_recv().ok();
                    }
                    if let Err(error) = write_batch(&*thread_sink, &mut batch) {
                        // Every output whose bytes died in this batch learns
                        // it on its own slot; outputs with nothing here — and
                        // outputs created later — stay clean.
                        for failure in failures.drain(..) {
                            crate::guest_output::record_failure(&failure, error.to_string());
                        }
                    }
                    // Drained means written (or recorded as failed): either way
                    // the bytes are no longer queued, so the budgets release
                    // here and the parked writers recheck against the new count.
                    guards.clear();
                    failures.clear();
                    wake_all(&parked_thread);
                }
            })?;
        Ok(Arc::new(Self { tx, parked, sink }))
    }

    /// Try one send without blocking; the message comes back when full.
    pub(crate) fn send(&self, msg: LaneMsg) -> LaneSend {
        use mpsc::error::TrySendError;
        match self.tx.try_send(msg) {
            Ok(()) => LaneSend::Sent,
            Err(TrySendError::Full(msg)) => LaneSend::Full(msg),
            Err(TrySendError::Closed(_)) => LaneSend::Closed,
        }
    }

    /// The sink this lane drains to, for outputs that share the lane.
    pub(crate) fn sink(&self) -> Arc<dyn GuestSink> {
        Arc::clone(&self.sink)
    }

    /// Park `waker` until the next completed write, deduplicated.
    ///
    /// A writer polled repeatedly while the lane is full registers once:
    /// without the [`Waker::will_wake`] check every poll clones another entry
    /// and the list grows with polls rather than writers. Spurious wakes are
    /// harmless — every woken writer rechecks before proceeding.
    pub(crate) fn park(&self, waker: &Waker) {
        if let Ok(mut parked) = self.parked.lock() {
            if !parked.iter().any(|w| w.will_wake(waker)) {
                parked.push(waker.clone());
            }
        }
    }
}

/// Write the batch unless it is empty, then reset it.
///
/// Empty batches arise when a flush marker arrives with nothing queued: a
/// zero-length syscall would still count as a write call against the
/// coalescing observable, so the guard keeps the measurement honest.
///
/// Failed bytes are dropped, not retried: the failure is recorded against
/// the outputs that owned them (which then fail fast with its message), and
/// retrying a broken sink inside the drain loop would park the whole lane
/// behind one bad write. This mirrors the old per-output pump, which
/// consumed a failed message after recording it.
fn write_batch(sink: &dyn GuestSink, batch: &mut Vec<u8>) -> io::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let result = sink.write_all_shared(batch);
    batch.clear();
    result
}

/// Wake every parked writer, outside the lock.
///
/// Taken under the mutex and woken after it drops: waking while holding the
/// lock risks lock-order issues with writers that re-park on waking, and a
/// woken writer that immediately re-parks must find the list unlocked.
fn wake_all(parked: &Arc<Mutex<Vec<Waker>>>) {
    let wakers = parked.lock().map(|mut list| std::mem::take(&mut *list));
    if let Ok(wakers) = wakers {
        for waker in wakers {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **F-12: repeated polls register one waker.**
    ///
    /// A writer polled a thousand times against a full lane must leave one
    /// waker, not a thousand clones: the list grows with writers, never with
    /// polls.
    #[test]
    fn f12_repeated_polls_register_one_waker() {
        let lane = SinkLane::spawn("test-waker", Arc::new(Mutex::new(Vec::new())))
            .expect("a lane thread spawns");
        let waker = std::task::Waker::noop();
        for _ in 0..1000 {
            lane.park(waker);
        }
        assert_eq!(
            lane.parked.lock().expect("not poisoned").len(),
            1,
            "a thousand polls with one waker must register once"
        );
    }
}
