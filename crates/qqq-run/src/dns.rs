// SPDX-License-Identifier: Apache-2.0

//! Resolve `qqq:dns` configuration at the deploy layer — `HOST-035`.
//!
//! The manifest names resolvable names; this module turns that list into
//! the [`DnsConfig`] the host enforces. No I/O, no ambient reads, no
//! lookups: the allowlist is data. The resolver is chosen where the view
//! is installed (`serve`/`run`), not here, so resolution stays a pure
//! function of the manifest — which is what makes it unit-testable without
//! the network.

use qqq_cap::manifest::Manifest;
use qqq_host::host_dns::{DnsConfig, DnsView, SystemResolver};

/// The deploy-time DNS configuration: exactly what the manifest configures.
///
/// An absent `[capabilities.dns]` resolves to empty: no names, no lookups —
/// the same deny-by-default the host applies to an instance built without
/// the entries. Names are trimmed and lowercased per RFC 4343 §2.1 (DNS is
/// case-insensitive), then deduplicated with first-seen order kept:
/// `API.example.com` and `api.example.com` name the same host, so they must
/// agree here exactly as they do in `Normalized::dns_allows`, which
/// normalizes the same way. Blank names are dropped, because validation
/// refuses them at parse and direct construction bypasses validation.
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
/// )
/// .expect("manifest parses");
/// let config = qqq_run::dns::resolve_dns_config(&manifest);
/// assert!(config.names.is_empty());
/// ```
#[must_use]
pub fn resolve_dns_config(manifest: &Manifest) -> DnsConfig {
    let Some(dns) = manifest.capabilities.dns.as_ref() else {
        return DnsConfig::new(Vec::new());
    };
    let mut seen: Vec<String> = Vec::new();
    let names: Vec<String> = dns
        .resolve
        .iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| {
            !name.is_empty() && {
                if seen.contains(name) {
                    false
                } else {
                    seen.push(name.clone());
                    true
                }
            }
        })
        .collect();
    DnsConfig::new(names)
}

/// The per-deployment DNS view: resolved config plus the system resolver.
///
/// One call site for both `run` (fresh view per execution, like the
/// instance) and `serve` (one view shared across every request the
/// deployment serves). The sharing lives in the `Arc`s, not in this
/// function — and since the resolver is stateless, sharing needs no
/// locking.
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
///      [capabilities.dns]\nresolve = [\"api.example.com\"]\n",
/// )
/// .expect("manifest parses");
/// let view = qqq_run::dns::view_for_manifest(&manifest);
/// assert!(view.config.allows("api.example.com"));
/// assert!(!view.config.allows("other.example.com"));
/// ```
#[must_use]
pub fn view_for_manifest(manifest: &Manifest) -> DnsView {
    DnsView::new(
        std::sync::Arc::new(resolve_dns_config(manifest)),
        std::sync::Arc::new(SystemResolver),
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

    /// Absent dns resolves empty: deny by default.
    #[test]
    fn absent_dns_resolves_empty() {
        let config = resolve_dns_config(&manifest_with(""));
        assert!(config.names.is_empty());
        assert!(!config.allows("anything"));
    }

    /// Names are trimmed, lowercased, deduped; blanks are dropped.
    ///
    /// Direct construction bypasses parse-time validation on purpose: the
    /// derive gate (`validate_dns`) refuses blanks at admission, and this
    /// proves the deploy layer stays honest even when constructed by hand.
    #[test]
    fn names_resolve_normalized() {
        use qqq_cap::manifest::{Capabilities, DnsCapability};
        let manifest = Manifest {
            capabilities: Capabilities {
                dns: Some(DnsCapability {
                    resolve: vec![
                        "B.Example.COM ".to_owned(),
                        "   ".to_owned(),
                        "b.example.com".to_owned(),
                        "a.example.com".to_owned(),
                    ],
                }),
                ..manifest_with("").capabilities
            },
            ..manifest_with("")
        };
        let config = resolve_dns_config(&manifest);
        assert_eq!(
            config.names,
            vec!["b.example.com".to_owned(), "a.example.com".to_owned()]
        );
        assert!(config.allows("B.EXAMPLE.COM"));
        assert!(config.allows("  b.example.com  "));
        assert!(!config.allows("   "));
        assert!(!config.allows("other.example.com"));
    }
}
