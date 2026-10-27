// SPDX-License-Identifier: Apache-2.0

//! Resolve `qqq:kv` configuration at the deploy layer — `HOST-032`.
//!
//! The manifest names stores and the write direction; this module turns that
//! into the [`KvConfig`] the host enforces. No environment reads, no I/O:
//! the allowlist is data, and data resolves without touching anything
//! ambient. The shared backend is created where the view is installed
//! (`serve`/`run`), not here, so resolution stays a pure function of the
//! manifest — which is what makes it unit-testable without a store.
//!
//! ```
//! let manifest = qqq_cap::manifest::Manifest::parse(
//!     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.kv]\nstores = [\"s\"]\n",
//! )
//! .expect("manifest parses");
//! let config = qqq_run::kv::resolve_kv_config(&manifest);
//! assert!(config.allows("s"));
//! ```

use qqq_cap::manifest::Manifest;
use qqq_host::host_kv::{KvBackend, KvConfig, KvView};

/// The deploy-time kv configuration: exactly what the manifest configures.
///
/// An absent `[capabilities.kv]` resolves to an empty, read-only config —
/// the same deny-by-default the host applies to an instance built without
/// the stanza. Stores keep declaration order; the host treats the list as
/// a set.
///
/// Blank names are dropped and duplicates collapsed: manifest validation
/// refuses blanks at parse, but direct construction bypasses validation —
/// and a `stores()` answer with the same name twice would be a lie about
/// the configuration, however it arrived.
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
/// )
/// .expect("manifest parses");
/// let config = qqq_run::kv::resolve_kv_config(&manifest);
/// assert!(config.stores.is_empty());
/// assert!(!config.write);
/// ```
#[must_use]
pub fn resolve_kv_config(manifest: &Manifest) -> KvConfig {
    match &manifest.capabilities.kv {
        None => KvConfig::new(Vec::new(), false),
        Some(kv) => {
            let mut seen = std::collections::BTreeSet::new();
            let stores: Vec<String> = kv
                .stores
                .iter()
                .filter(|name| !name.trim().is_empty() && seen.insert((*name).clone()))
                .cloned()
                .collect();
            KvConfig::new(stores, kv.write)
        }
    }
}

/// The per-deployment kv view: resolved config plus a fresh shared backend.
///
/// One call site for both `run` (fresh backend per execution, like the
/// instance) and `serve` (one backend shared across every request the
/// deployment serves). The sharing lives in the `Arc`s, not in this
/// function — calling it twice forks the data, which is exactly what a
/// rotation must not do and exactly what a fresh `run` wants.
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.kv]\nstores = [\"s\"]\nwrite = true\n",
/// )
/// .expect("manifest parses");
/// let view = qqq_run::kv::view_for_manifest(&manifest);
/// assert!(view.config.allows("s"));
/// assert!(view.config.write);
/// ```
#[must_use]
pub fn view_for_manifest(manifest: &Manifest) -> KvView {
    KvView::new(
        std::sync::Arc::new(resolve_kv_config(manifest)),
        std::sync::Arc::new(std::sync::Mutex::new(KvBackend::new())),
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

    /// Absent kv resolves to empty and read-only: deny by default.
    #[test]
    fn absent_kv_resolves_empty_read_only() {
        let config = resolve_kv_config(&manifest_with(""));
        assert!(config.stores.is_empty());
        assert!(!config.write);
        assert!(!config.allows("anything"));
    }

    /// Blanks are dropped and duplicates collapsed: validation refuses
    /// blanks at parse, but direct construction bypasses validation, and a
    /// `stores()` answer with the same name twice would lie about the
    /// configuration.
    #[test]
    fn resolve_dedupes_and_drops_blanks() {
        let manifest = Manifest {
            capabilities: qqq_cap::manifest::Capabilities {
                kv: Some(qqq_cap::manifest::KvCapability {
                    stores: vec![
                        "s".to_owned(),
                        "   ".to_owned(),
                        "s".to_owned(),
                        "t".to_owned(),
                    ],
                    write: true,
                }),
                ..Default::default()
            },
            ..manifest_with("")
        };
        let config = resolve_kv_config(&manifest);
        assert_eq!(config.stores, vec!["s".to_owned(), "t".to_owned()]);
        assert!(config.write);
    }

    /// Stores and the write flag travel verbatim from the manifest.
    #[test]
    fn stores_and_write_flag_resolve() {
        let read_only = resolve_kv_config(&manifest_with(
            "[capabilities.kv]\nstores = [\"sessions\", \"cart\"]\n",
        ));
        assert_eq!(
            read_only.stores,
            vec!["sessions".to_owned(), "cart".to_owned()]
        );
        assert!(!read_only.write);
        assert!(read_only.allows("sessions"));
        assert!(!read_only.allows("orders"));

        let writable = resolve_kv_config(&manifest_with(
            "[capabilities.kv]\nstores = [\"sessions\"]\nwrite = true\n",
        ));
        assert!(writable.write);
        assert!(writable.allows("sessions"));
    }
}
