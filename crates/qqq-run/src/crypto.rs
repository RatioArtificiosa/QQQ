// SPDX-License-Identifier: Apache-2.0

//! Resolve `qqq:crypto` configuration at the deploy layer — `HOST-037`.
//!
//! The manifest names algorithms and constructions; this module turns those
//! lists into the [`CryptoConfig`] the host enforces. No I/O, no ambient
//! reads, no entropy: the allowlist is data, and data resolves without
//! touching anything ambient — which is what makes it unit-testable without
//! a guest.
//!
//! Unknown names are dropped, never refused: the host fails closed at call
//! time with the allowlist error, so an unknown name behaves exactly like
//! an unlisted one and a guest cannot enumerate the host's supported set
//! by watching parse refuse.

use qqq_cap::manifest::Manifest;
use qqq_host::host_crypto::{CryptoConfig, CryptoView};

/// The deploy-time crypto configuration: exactly what the manifest configures.
///
/// Resolved once per deployment; cloned per request, never re-resolved per
/// call.
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
/// )
/// .expect("manifest parses");
/// let config = qqq_run::crypto::resolve_crypto_config(&manifest);
/// assert!(config.hashes.is_empty());
/// assert!(config.hmacs.is_empty());
/// ```
#[must_use]
pub fn resolve_crypto_config(manifest: &Manifest) -> CryptoConfig {
    CryptoConfig::from_manifest(manifest)
}

/// The per-deployment crypto view: resolved config, no shared backend.
///
/// Cryptography is pure computation against the allowlist — no backend to
/// share, no connections to open — so the view is just the config, cloned
/// per request. One call site for both `run` (fresh view per execution)
/// and `serve` (one view shared across every request the deployment serves).
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
///      [capabilities.crypto]\nhash = [\"sha256\"]\n",
/// )
/// .expect("manifest parses");
/// let view = qqq_run::crypto::view_for_manifest(&manifest);
/// assert_eq!(view.config.hashes.len(), 1);
/// ```
#[must_use]
pub fn view_for_manifest(manifest: &Manifest) -> CryptoView {
    CryptoView::new(std::sync::Arc::new(resolve_crypto_config(manifest)))
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

    /// Absent crypto resolves empty: deny by default.
    #[test]
    fn absent_crypto_resolves_empty() {
        let config = resolve_crypto_config(&manifest_with(""));
        assert!(config.hashes.is_empty());
        assert!(config.hmacs.is_empty());
        assert!(config.aeads.is_empty());
        assert!(config.signs.is_empty());
    }

    /// Known names resolve; unknown names are dropped, never refused at
    /// parse — the call-time allowlist check fails closed instead.
    #[test]
    fn known_names_resolve_and_unknown_ones_drop() {
        use qqq_host::ambient::HashAlgorithm;
        use qqq_host::host_crypto::{AeadConstruction, SignAlgorithm};
        let config = resolve_crypto_config(&manifest_with(
            "[capabilities.crypto]\nrandom = true\n\
             hash = [\"sha256\", \"rot13\"]\n\
             hmac = [\"sha512\"]\naead = [\"aes-256-gcm\"]\nsign = [\"ed25519\"]\n",
        ));
        assert_eq!(config.hashes, vec![HashAlgorithm::Sha256]);
        assert_eq!(config.hmacs, vec![HashAlgorithm::Sha512]);
        assert_eq!(config.aeads, vec![AeadConstruction::Aes256Gcm]);
        assert_eq!(config.signs, vec![SignAlgorithm::Ed25519]);
    }

    /// Each interface's list is independent: naming a hash does not grant
    /// HMAC, and an empty hmac list grants nothing even beside a hash.
    #[test]
    fn lists_are_per_interface() {
        use qqq_cap::resolve::GrantSet;
        let manifest = manifest_with("[capabilities.crypto]\nhash = [\"sha256\"]\n");
        let view = view_for_manifest(&manifest);
        assert_eq!(view.config.hashes.len(), 1);
        assert!(view.config.hmacs.is_empty());
        let grants = GrantSet::from_manifest(&manifest);
        assert!(grants.grants(qqq_cap::Capability::CryptoHash));
        assert!(!grants.grants(qqq_cap::Capability::CryptoHmac));
    }
}
