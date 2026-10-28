// SPDX-License-Identifier: Apache-2.0

//! Resolve `qqq:queue` configuration at the deploy layer — `HOST-033`.
//!
//! The manifest names queues and the direction each entry grants;
//! this module turns that list into the [`QueueConfig`] the host enforces.
//! No I/O, no ambient reads: the allowlist is data. The shared backend is
//! created where the view is installed (`serve`/`run`), not here, so
//! resolution stays a pure function of the manifest — which is what makes
//! it unit-testable without a store.

use qqq_cap::manifest::{Manifest, QueueDirection};
use qqq_host::host_queue::{QueueBackend, QueueConfig, QueueView};

/// The deploy-time queue configuration: exactly what the manifest configures.
///
/// An absent queue list resolves to empty: no queues, no directions — the
/// same deny-by-default the host applies to an instance built without the
/// entries. Names keep declaration order (duplicates included — the host
/// treats the list as a set, and collapsing here would hide what the
/// manifest actually declares); blank names are dropped, because validation
/// refuses them at parse and direct construction bypasses validation.
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
/// )
/// .expect("manifest parses");
/// let config = qqq_run::queue::resolve_queue_config(&manifest);
/// assert!(config.queues.is_empty());
/// ```
#[must_use]
pub fn resolve_queue_config(manifest: &Manifest) -> QueueConfig {
    // A `Vec` membership check, not a set: queue lists are short, and the
    // direction enum carries no ordering or hash impl to key a set on —
    // adding either trait for the deploy layer's convenience would be the
    // tail wagging the manifest type.
    let mut seen: Vec<(String, QueueDirection)> = Vec::new();
    let queues: Vec<(String, QueueDirection)> = manifest
        .capabilities
        .queue
        .iter()
        .filter(|entry| {
            !entry.name.trim().is_empty() && {
                let key = (entry.name.clone(), entry.direction);
                if seen.contains(&key) {
                    false
                } else {
                    seen.push(key);
                    true
                }
            }
        })
        .map(|entry| (entry.name.clone(), entry.direction))
        .collect();
    QueueConfig::new(queues)
}

/// The per-deployment queue view: resolved config plus a fresh shared backend.
///
/// One call site for both `run` (fresh backend per execution, like the
/// instance) and `serve` (one backend shared across every request the
/// deployment serves). The sharing lives in the `Arc`s, not in this
/// function — calling it twice forks the data, which is exactly what a
/// rotation must not do and exactly what a fresh `run` wants.
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
///      [[capabilities.queue]]\nname = \"q\"\ndirection = \"publish\"\n",
/// )
/// .expect("manifest parses");
/// let view = qqq_run::queue::view_for_manifest(&manifest);
/// assert!(view.config.allows_publish("q"));
/// assert!(!view.config.allows_subscribe("q"));
/// ```
#[must_use]
pub fn view_for_manifest(manifest: &Manifest) -> QueueView {
    QueueView::new(
        std::sync::Arc::new(resolve_queue_config(manifest)),
        std::sync::Arc::new(std::sync::Mutex::new(QueueBackend::new())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with(body: &str) -> Manifest {
        Manifest::parse(&format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n{body}"
        ))
        .expect("manifest parses")
    }

    /// Absent queues resolve to empty: deny by default.
    #[test]
    fn absent_queues_resolve_empty() {
        let config = resolve_queue_config(&manifest_with(""));
        assert!(config.queues.is_empty());
        assert!(!config.allows_publish("anything"));
        assert!(!config.allows_subscribe("anything"));
    }

    /// Directions resolve per entry, and blanks are dropped.
    #[test]
    fn directions_resolve_per_entry() {
        let config = resolve_queue_config(&manifest_with(
            "[[capabilities.queue]]\nname = \"pub.q\"\ndirection = \"publish\"\n\
             [[capabilities.queue]]\nname = \"sub.q\"\ndirection = \"subscribe\"\n",
        ));
        assert_eq!(config.queues.len(), 2);
        assert!(config.allows_publish("pub.q"));
        assert!(!config.allows_subscribe("pub.q"));
        assert!(config.allows_subscribe("sub.q"));
        assert!(!config.allows_publish("sub.q"));
        assert!(!config.allows_publish("   "));
    }

    /// Blanks are dropped and duplicates collapsed even when validation is
    /// bypassed by direct construction: parse refuses blanks, but the
    /// derive path must stay honest too.
    #[test]
    fn resolve_dedupes_and_drops_blanks() {
        use qqq_cap::manifest::{Capabilities, QueueCapability};
        let manifest = Manifest {
            capabilities: Capabilities {
                queue: vec![
                    QueueCapability {
                        name: "q".to_owned(),
                        direction: QueueDirection::Publish,
                    },
                    QueueCapability {
                        name: "   ".to_owned(),
                        direction: QueueDirection::Publish,
                    },
                    QueueCapability {
                        name: "q".to_owned(),
                        direction: QueueDirection::Publish,
                    },
                ],
                ..manifest_with("").capabilities
            },
            ..manifest_with("")
        };
        let config = resolve_queue_config(&manifest);
        assert_eq!(
            config
                .queues
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["q"]
        );
    }
}
