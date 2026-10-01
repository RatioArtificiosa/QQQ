// SPDX-License-Identifier: Apache-2.0

//! Live HTTP components. The controller is a host API, never a guest capability.
//! Call `replace` on a coordinator thread, outside the socket executor.
//!
//! ```
//! # fn install(app: qqq_run::guest_handler::GuestApp) -> qqq_core::Result<()> {
//! let controller = qqq_run::live::LiveApp::new(app)?;
//! let _dispatch = qqq_serve::Dispatch::flat(controller.dispatch());
//! # Ok(())
//! # }
//! ```

use crate::generations::{Generation, Registry};
use crate::guest_handler::{failure_response, GuestApp};
use qqq_core::Result;
use std::sync::Arc;

/// A stable routing handle with version-pinned invocations.
#[derive(Clone)]
///
/// # Examples
///
/// ```
/// # fn main() -> qqq_core::Result<()> {
/// # fn host(app: qqq_run::guest_handler::GuestApp) -> qqq_core::Result<()> {
/// let live = qqq_run::live::LiveApp::new(app)?;
/// let _dispatch = live.dispatch();
/// # Ok(())
/// # }
/// # Ok(())
/// # }
/// ```
pub struct LiveApp {
    registry: Registry<GuestApp>,
    preparing: Arc<std::sync::Mutex<()>>,
}

impl LiveApp {
    /// Admit the initial component after checking its complete HTTP signature.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn host(app: qqq_run::guest_handler::GuestApp) -> qqq_core::Result<()> {
    /// let live = qqq_run::live::LiveApp::new(app)?;
    /// assert!(live.acquire()?.revision() > 0);
    /// # Ok(())
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Refuses incompatible HTTP signatures and component initialization failures.
    pub fn new(app: GuestApp) -> Result<Self> {
        app.validate_interface()?;
        let registry = Registry::new(1, 8);
        registry.publish(registry.reserve("app")?, app.digest().to_owned(), app)?;
        Ok(Self {
            registry,
            preparing: Arc::new(std::sync::Mutex::new(())),
        })
    }

    /// Pin the current code for an invocation or a caller-managed session.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn host(live: &qqq_run::live::LiveApp) -> qqq_core::Result<()> {
    /// let session = live.acquire()?;
    /// let revision = session.revision();
    /// assert!(revision > 0);
    /// # Ok(())
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error on registry failure or when the requested generation is unavailable.
    pub fn acquire(&self) -> Result<Arc<Generation<GuestApp>>> {
        self.registry.acquire("app")
    }

    /// Compile, validate, and publish under the existing policy. On failure the
    /// previous code remains active. Only the latest accepted reservation can publish.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn host(live: &qqq_run::live::LiveApp) -> qqq_core::Result<()> {
    /// let candidate = std::fs::read("next.component.wasm").expect("candidate file");
    /// live.replace(&candidate)?;
    /// # Ok(())
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Refuses concurrent preparation, invalid components, incompatible signatures or exhausted retirement capacity; active code is retained.
    pub fn replace(&self, bytes: &[u8]) -> Result<u64> {
        self.replace_checked(bytes, || Ok(()))
    }

    /// Recheck the coordinator's source/policy snapshot after preparation.
    pub(crate) fn replace_checked(
        &self,
        bytes: &[u8],
        check: impl FnOnce() -> Result<()>,
    ) -> Result<u64> {
        let _preparing = self.preparing.try_lock().map_err(|_| {
            qqq_core::Error::new(
                qqq_core::ErrorCode::ComponentLoadFailed,
                "another component preparation is active; retry later",
            )
        })?;
        let current = self.acquire()?;
        let update = self.registry.reserve("app")?;
        let next = match current.value().replacement(bytes) {
            Ok(next) => next,
            Err(error) => {
                let _ = self.registry.cancel(update);
                return Err(error);
            }
        };
        if let Err(error) = check() {
            let _ = self.registry.cancel(update);
            return Err(error);
        }
        drop(current);
        self.registry
            .publish(update, next.digest().to_owned(), next)
    }

    /// Stop admitting new work. Existing leases drain independently.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn host(live: &qqq_run::live::LiveApp) -> qqq_core::Result<()> {
    /// live.remove()?;
    /// assert!(live.acquire().is_err());
    /// # Ok(())
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error on registry failure or when the requested generation is unavailable.
    pub fn remove(&self) -> Result<bool> {
        self.registry.remove("app")
    }

    /// Count retired versions whose work has not finished.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn host(live: &qqq_run::live::LiveApp) -> qqq_core::Result<()> {
    /// let retained_versions = live.draining()?;
    /// assert!(retained_versions <= 8);
    /// # Ok(())
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error on registry failure or when the requested generation is unavailable.
    pub fn draining(&self) -> Result<usize> {
        self.registry.draining()
    }

    /// Flat handler resolving the active version at request admission.
    #[must_use]
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn host(live: &qqq_run::live::LiveApp) -> qqq_core::Result<()> {
    /// let _dispatch = qqq_serve::Dispatch::flat(live.dispatch());
    /// # Ok(())
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn dispatch(&self) -> qqq_serve::Handler {
        let live = self.clone();
        Arc::new(move |head, matched| live.answer(head, None, &matched.handler))
    }

    /// Body-aware handler with the same admission boundary.
    #[must_use]
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> qqq_core::Result<()> {
    /// # fn host(live: &qqq_run::live::LiveApp) -> qqq_core::Result<()> {
    /// let _dispatch = qqq_serve::Dispatch::flat(live.dispatch())
    ///     .with_body("handler", live.dispatch_with_body());
    /// # Ok(())
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub fn dispatch_with_body(&self) -> qqq_serve::BodyHandler {
        let live = self.clone();
        Arc::new(move |head, body, tenant| {
            let body = match body {
                qqq_serve::BodyBytes::Absent => None,
                other => Some(other.as_slice().to_vec()),
            };
            live.answer(head, body, tenant)
        })
    }
    fn answer(
        &self,
        head: &qqq_serve::http1::RequestHead,
        body: Option<Vec<u8>>,
        tenant: &str,
    ) -> qqq_serve::response::Response {
        let lease = match self.acquire() {
            Ok(lease) => lease,
            Err(error) => {
                let mut response = failure_response(&error);
                response.status = 503;
                return response;
            }
        };
        match lease.value().handle_request(head, body, tenant) {
            Ok(response) => response,
            Err(error) => failure_response(&error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_can_reject_a_candidate_after_compilation() {
        let source = include_str!("../tests/fixtures/live-http.wat");
        let engine = wasmtime::Engine::new(
            &qqq_host::config::EngineConfig::default()
                .to_wasmtime_config()
                .unwrap(),
        )
        .unwrap();
        let app = GuestApp::new(
            engine,
            source.as_bytes(),
            qqq_cap::resolve::GrantSet::empty(),
            qqq_host::LimitSet {
                memory_bytes: 16 * 1024 * 1024,
                fuel: 1_000_000,
                epoch_deadline_ms: 5_000,
                max_open_handles: 16,
                max_subrequests: 16,
            },
            "localhost:3000",
        )
        .unwrap();
        let live = LiveApp::new(app).unwrap();
        let before = live.acquire().unwrap();
        assert!(live
            .replace_checked(source.replace("\"v1\"", "\"v2\"").as_bytes(), || {
                Err(qqq_core::Error::new(
                    qqq_core::ErrorCode::CompilationFailed,
                    "policy changed",
                ))
            })
            .is_err());
        assert_eq!(live.acquire().unwrap().revision(), before.revision());
        assert_eq!(live.acquire().unwrap().digest(), before.digest());
        live.replace(source.as_bytes()).unwrap();
        assert_ne!(live.acquire().unwrap().revision(), before.revision());
    }
}
