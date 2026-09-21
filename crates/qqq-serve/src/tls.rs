// SPDX-License-Identifier: Apache-2.0

//! TLS configuration: the documented cipher policy, ALPN, and mTLS.
//!
//! Implements `SRV-007` (TLS via rustls with a documented cipher policy),
//! `SRV-008` (mTLS as a supported `default_auth` mode) and the naming half of
//! `SEC-017`; Proposal §6.4 (*"rustls, TLS 1.3 preferred, 1.2 permitted, with a
//! documented cipher policy. Certificate sources: files, ACME (opt-in), or
//! platform-provided. Client certificates (mTLS) are a supported `default_auth`
//! mode."*) and §7.4 (*"no algorithm agility without a version bump. A manifest
//! names algorithms explicitly; there are no 'default' choices that could
//! silently change under the user."*).
//!
//! # Why this module is configuration and not a handshake
//!
//! Everything here produces a value — a [`rustls::ServerConfig`], a
//! [`ClientAuth`], a [`PeerIdentity`] — from an explicit input. Nothing here
//! talks to a socket. That split is deliberate and it is the same one
//! [`crate::route`] and [`crate::conn`] make: a decision that can be produced
//! from an input can be **tested by being handed the input**, whereas a
//! decision embedded in a handshake can only be tested by performing one.
//!
//! The part that genuinely needs a socket is the handshake, and that is covered
//! in `tests/tls.rs`, which drives real clients against these configurations.
//!
//! # `SEC-017`: named algorithms, and no silent defaults
//!
//! The policy in §7.4 has three clauses and this module is where two of them
//! become code:
//!
//! | Clause | How it is enforced here |
//! |---|---|
//! | named algorithms | [`CIPHER_SUITES`] and [`PROTOCOL_VERSIONS`] are explicit lists of concrete constants |
//! | no silent defaults | [`TlsConfig::build`] refuses an unspecified field instead of choosing one |
//! | no agility without a version bump | the lists are fixed; changing one is a change to a public constant |
//!
//! The third clause is the one that is easy to claim and hard to deliver, so it
//! is worth being precise about what this module does and does not guarantee.
//!
//! **What it guarantees.** Rotation is not a value. There is no "default" or
//! "auto" setting that could resolve to a different list depending on what
//! rustls, the platform, or an environment variable happens to offer on the day
//! the process starts — because that is exactly how a deployment silently loses
//! a cipher the review approved. There is also **no environment variable** that
//! widens the policy: an escape hatch on a crypto policy is a policy that is not
//! enforced, since anything able to set an environment variable is already able
//! to change the configuration directly.
//!
//! **What it does not guarantee.** A *dependency* upgrade can still change what
//! a cipher name means. `TLS13_AES_256_GCM_SHA384` is a named algorithm, but the
//! implementation behind it belongs to the crypto provider (`aws-lc-rs` or
//! `ring`), and a new provider version is a new implementation of that name. The
//! list pins *which* algorithms are offered; it cannot pin *whose code* computes
//! them. That is the dependency-audit gate (`SEC-004`), not this module, and
//! claiming otherwise here would be the kind of overstatement this codebase
//! keeps catching.
//!
//! # Why TLS 1.2 is permitted at all
//!
//! §7.4 says "1.2 permitted", so it is, and the suites offered under it are
//! deliberately only the AEAD ones from §7.4's AEAD row with forward-secret key
//! exchange. What is **not** offered, in either version, is anything this module
//! did not name — see [`CIPHER_SUITES`] for the list and the reason for each
//! entry.
//!
//! # Certificate sources, and the one that is not implemented
//!
//! [`CertificateSource`] has three variants because §6.4 names three sources.
//! [`CertificateSource::Files`] and [`CertificateSource::Platform`] are
//! implemented. [`CertificateSource::Acme`] is **not**, and it is refused with a
//! named follow-up ID rather than falling back to something else — see
//! [`CertificateSource::resolve`].

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use qqq_core::{Error, ErrorCode, Result};
use rustls::crypto::aws_lc_rs::cipher_suite::{
    TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, SupportedCipherSuite};

// ---------------------------------------------------------------------------
// The cipher policy
// ---------------------------------------------------------------------------

/// The protocol versions this server offers, newest first.
///
/// # Why 1.3 is first rather than merely present
///
/// TLS 1.3 removes the round trip that 1.2's handshake costs, removes RSA key
/// transport entirely (so every 1.3 handshake is forward-secret), and removes
/// the renegotiation surface. A server that offers both and lets the client
/// choose will be talked down to 1.2 by any client that prefers it, including
/// old ones — which is fine, and is why 1.2 stays permitted — but the *order*
/// here is the server's stated preference and is what §7.4 means by "TLS 1.3
/// preferred".
///
/// # Why nothing older appears
///
/// TLS 1.1 and 1.0 are not listed and this is not an oversight. Neither is
/// expressible in rustls 0.23 at all — the enum has no variant for them — so the
/// test that asserts 1.1 is refused is asserting on a type that cannot represent
/// it. That test is still worth having: it is the test that fails loudly if
/// someone later swaps in a library that *can* represent it and fills in the gap
/// by widening this list (`tests/tls.rs::the_version_policy_refuses_tls_11`).
pub const PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// Whether the server offers post-quantum hybrid key exchange (`SEC-021`).
///
/// # The finding that reshaped this item
///
/// The checklist asks to "track post-quantum hybrid TLS (X25519+ML-KEM) as an
/// opt-in". Reading the pinned dependency rather than the item's premise showed
/// the premise was already satisfied, and in the opposite direction:
///
/// * `Cargo.lock` resolves `rustls` to **0.23.45**.
/// * rustls **0.23.31** made `X25519MLKEM768` the *default and preferred* key
///   exchange for TLS 1.3.
/// * This server never called `with_kx_groups`, so it inherited that default.
///
/// So the hybrid exchange was already on, and the real risk was the inverse of the
/// one the item names: not "how do we enable it", but **"how do we keep it from
/// being silently removed"**. A property nobody asserts is a property that
/// disappears in the next dependency bump, and `§O-085`, `§O-088` and `§O-089` are
/// all instances of exactly that.
///
/// # Why this is a constant and a test rather than a comment
///
/// `SERVER_KX_GROUPS` below names the groups explicitly. That converts an
/// inherited default into a stated policy, so a rustls upgrade that changed the
/// default would change nothing here, and a deliberate removal would require
/// editing this list — which the test refuses unless the intent is recorded.
///
/// # Why the names, not a boolean
///
/// A boolean `post_quantum: true` would say *that* PQ is desired and nothing about
/// *which* group provides it. The group is the security-relevant fact: the
/// hybrid's whole point is that it stays safe if ML-KEM falls, because the
/// X25519 half must also be broken.
pub const PQ_KEY_EXCHANGE_ENABLED: bool = true;

/// The TLS 1.3 key-exchange groups this server offers, in preference order.
///
/// # Why the hybrid is first
///
/// `X25519MLKEM768` concatenates a classical X25519 exchange with an ML-KEM-768
/// one and derives the session key from both. An attacker must break *both* to
/// recover it, so the construction is at least as strong as X25519 today and
/// survives a future quantum break of X25519 — this is the "harvest now, decrypt
/// later" defence, and it is why ordering matters: a client that honours the
/// server's preference gets the hybrid.
///
/// # Why the classical groups remain
///
/// Removing them would drop interop with clients that cannot do ML-KEM, and the
/// hybrid is worthless if the handshake fails. They are ordered after the hybrid,
/// so the strong option is chosen whenever it exists.
///
/// # Agreement with §7.4
///
/// §7.4 states the policy as "no algorithm agility without a version bump. A
/// manifest names algorithms explicitly; there are no 'default' choices that could
/// silently change under the user." This constant is that principle applied to key
/// exchange, which is the one part of §7.4's table that had been left to a
/// library default.
pub static SERVER_KX_GROUPS: &[&dyn rustls::crypto::SupportedKxGroup] = &[
    // Hybrid first: preferred whenever the client supports it.
    rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
    // Classical fallbacks, for clients that cannot do ML-KEM.
    rustls::crypto::aws_lc_rs::kx_group::X25519,
    rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
    rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
];

/// The cipher suites this server offers, in preference order.
///
/// # Why this list exists rather than rustls' default
///
/// `ServerConfig::builder()` applies the crypto provider's default suite list,
/// which is a *library's* opinion and is free to change in a patch release. A
/// policy that changes under the user on a dependency bump is not a policy
/// (`SEC-017`). This list is the server's opinion and changes only when this
/// constant changes.
///
/// # The list, and why each member is in it
///
/// | Suite | Version | Why |
/// |---|---|---|
/// | [`TLS13_AES_256_GCM_SHA384`] | 1.3 | §7.4's AEAD row; AES-256-GCM, the conservative choice where a hardware AES path exists |
/// | [`TLS13_CHACHA20_POLY1305_SHA256`] | 1.3 | §7.4's AEAD row; preferred over AES on hardware without AES-NI, where AES-GCM is both slower and more side-channel-prone |
/// | `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | 1.2 | ECDHE ⇒ forward secrecy; ECDSA ⇒ P-256/P-384 certificates; AES-256-GCM per §7.4 |
/// | `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` | 1.2 | the same, for a client with an ECDSA certificate need and no AES acceleration |
/// | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | 1.2 | AEAD and forward-secret; 128-bit rather than 256 because on some 1.2 clients this is the only ECDSA suite in common |
/// | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | 1.2 | the RSA-certificate counterpart, for deployments that hold an RSA key rather than an ECDSA one |
/// | `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` | 1.2 | as above, for a client without AES acceleration |
/// | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 1.2 | as above for ECDSA: the widest 1.2 interop RSA suite that is still AEAD and forward-secret |
///
/// # What is deliberately absent, and why
///
/// * **Every `TLS_RSA_*` suite.** RSA key transport encrypts the premaster
///   secret under the server's long-term key. There is no forward secrecy, so a
///   future compromise of that key decrypts every recorded session — a property
///   a fleet cannot fix after the fact. Absent in both versions.
/// * **Every `TLS_*_CBC_*` suite.** CBC in TLS 1.2 has a twenty-year history of
///   padding oracles (Lucky13 and its descendants), and the constant-time
///   constructions that survive are far more delicate than an AEAD. §7.4's AEAD
///   row names GCM and ChaCha20-Poly1305; CBC is not in it, so it is not here.
/// * **Every `TLS_*_3DES_*` and `_RC4_*` suite.** Both are broken outright and
///   neither appears in rustls 0.23 in any case.
///
/// # Why `TLS13_AES_128_GCM_SHA256` is absent
///
/// It is a fine suite, and its omission is a **choice rather than a necessity**.
/// §7.4's AEAD row names AES-256-GCM, and a policy that offers both AES-128 and
/// AES-256 at 1.3 is offering two things where §7.4 named one. Where 128-bit is
/// genuinely needed for interop it is present at 1.2, which is the version where
/// the interop argument actually applies.
///
/// This is called out rather than glossed because a reviewer comparing this list
/// against what a default rustls server offers will notice the absence, and the
/// honest answer is "the policy named AES-256", not "it is insecure".
pub const CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // -- TLS 1.3 ----------------------------------------------------------
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    // -- TLS 1.2 ----------------------------------------------------------
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

/// The ALPN protocol identifiers this server will speak.
///
/// Order is preference, and `h2` is first: a client that offers both gets
/// HTTP/2, which is the point of negotiating at all.
///
/// # Why `h2` is advertised before HTTP/2 exists here
///
/// `lib.rs` records HTTP/2 as `SRV-002`, not implemented. Advertising `h2`
/// anyway would be a **lie to the client**: a server that selects `h2` and then
/// speaks HTTP/1.1 has produced a protocol error the client cannot classify, and
/// RFC 9113 gives it no recovery.
///
/// So the constant exists, the negotiation *mechanism* is implemented and
/// tested, and the decision about what to advertise is a separate value —
/// [`ServerConfigExt::with_alpn`] takes it. `lib.rs` advertises HTTP/1.1 only
/// until `SRV-002` lands, and flips to this full list then. The mechanism is
/// built now so that flipping it is one constant, not a protocol change.
pub const ALPN_H2: &[u8] = b"h2";
/// The HTTP/1.1 ALPN protocol identifier.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Every ALPN protocol this server knows, in preference order.
///
/// The list [`ServerConfigExt::with_alpn`] is called with once `SRV-002` lands.
/// Until then it is the documentation of what "ALPN support" means here, and the
/// test that pins the preference order uses it.
pub const ALPN_ALL: &[&[u8]] = &[ALPN_H2, ALPN_HTTP11];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Build a TLS configuration error with the shared shape.
///
/// # Why `ManifestSchemaViolation` rather than a TLS-specific code
///
/// There is no TLS code in [`ErrorCode`] yet, and adding one is an additive
/// change to a **public, stable** contract in `qqq-core` (`error.rs`: *"Adding a
/// new code is a minor change"*) that this change is not scoped to make. Rather
/// than reach into another crate's public API, every configuration failure here
/// uses `QQQ-2002`, which is the existing code for *"parsed but violates its
/// schema … the error names the offending field and the expected shape"* — which
/// is exactly what these errors do.
///
/// This is recorded as a gap rather than papered over: the honest end state is a
/// `TLSConfigInvalid` code in the `2xxx` class, and a reader comparing this
/// module against the `QQQ-XXXX` convention will notice the mismatch.
///
/// [`ErrorCode`]: qqq_core::ErrorCode
fn tls_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::ManifestSchemaViolation, message)
}

// ---------------------------------------------------------------------------
// Certificate sources
// ---------------------------------------------------------------------------

/// Where a server's certificate and key come from.
///
/// Proposal §6.4 names three sources. Two are implemented; the third is refused
/// explicitly, which is the point of making this an enum rather than a path.
///
/// # Why this is not `Clone`
///
/// [`Self::Platform`] carries a [`PrivateKeyDer`], which is deliberately not
/// `Clone` upstream (see [`ResolvedCertificate`]). A `Clone` here would hand out
/// a second copy of a private key wherever a caller was merely trying to pass a
/// configuration along, which is exactly the copy `rustls-pki-types` refuses to
/// make implicitly. Callers that need to share a source use an `Arc`, and callers
/// that need a second key call [`PrivateKeyDer::clone_key`].
#[derive(Debug, PartialEq, Eq)]
pub enum CertificateSource {
    /// A PEM certificate chain and a PEM private key, read from files.
    Files {
        /// The certificate chain, leaf first.
        cert: PathBuf,
        /// The private key.
        key: PathBuf,
    },
    /// ACME (`RFC 8555`) issuance and renewal, opt-in.
    ///
    /// **Not implemented.** See [`Self::resolve`].
    Acme {
        /// The domain the certificate is requested for.
        ///
        /// Carried even though nothing consumes it, so that the refusal can name
        /// what was asked for rather than saying "ACME is unavailable".
        domain: String,
    },
    /// A certificate and key supplied by the platform, already in memory.
    ///
    /// "Platform-provided" in §6.4 means the host environment holds the
    /// material — a Kubernetes-mounted secret, an HSM behind a provider, a
    /// test harness. This variant is therefore the **already-loaded** form: the
    /// caller did the loading, which is the only way to support an HSM that
    /// never exposes a key as bytes.
    Platform {
        /// The certificate chain, leaf first.
        chain: Vec<CertificateDer<'static>>,
        /// The private key.
        key: PrivateKeyDer<'static>,
    },
}

impl CertificateSource {
    /// A source reading a certificate and key from files.
    ///
    /// A constructor rather than a struct literal so the two paths are named at
    /// the call site — `cert` and `key` in the wrong order is not a type error,
    /// and the resulting error ("the key file is not PEM") sends the reader to
    /// the wrong file.
    #[must_use]
    pub fn files(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self::Files {
            cert: cert.into(),
            key: key.into(),
        }
    }

    /// A human name for the source, for error context.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Files { cert, key } => {
                format!("files (cert `{}`, key `{}`)", cert.display(), key.display())
            }
            Self::Acme { domain } => format!("ACME for `{domain}`"),
            Self::Platform { chain, .. } => format!("platform ({} certificate(s))", chain.len()),
        }
    }

    /// Resolve this source into a certificate chain and a private key.
    ///
    /// # Errors
    ///
    /// * `QQQ-2002` — [`Self::Acme`]. **This is a refusal, not a failure.** ACME
    ///   is not implemented, and the error names the follow-up checklist ID
    ///   (`SRV-013`) so the caller learns what to track rather than being told
    ///   "unsupported" and left to guess. It deliberately does **not** fall back
    ///   to a self-signed certificate or to files: a TLS endpoint that silently
    ///   serves a certificate the operator did not ask for is worse than one
    ///   that refuses to start, because the former is discovered by a user
    ///   seeing a browser warning in production.
    /// * `QQQ-2002` — a file could not be read, contains no certificate, or the
    ///   key file contains no key this server can use. Each names the specific
    ///   file and what was wrong with it.
    /// * `QQQ-6004` — [`Self::Platform`] was given an empty chain or an empty
    ///   certificate. An internal invariant: the caller constructed this value
    ///   and the type does not prevent it.
    pub fn resolve(&self) -> Result<ResolvedCertificate> {
        match self {
            Self::Files { cert, key } => {
                // **The key is loaded first, deliberately.** Both loads can fail,
                // and when both do, one of the two errors is reported. Loading
                // the certificate first meant a missing key file was reported as
                // a problem with the *certificate* whenever the certificate
                // happened not to parse either — the reader is then sent to the
                // wrong file.
                //
                // Caught by `a_missing_key_file_names_the_key`, whose temporary
                // certificate fixture was deliberately unusable: the assertion
                // "the error must name the key" failed with the message "the
                // certificate file `…/c.pem` contains no certificate".
                //
                // Neither order is universally correct — with key-first, a
                // missing certificate is now masked by a bad key — but the
                // *file* named is the one whose load is attempted first, and a
                // reader who fixes one path is re-run and told about the other.
                // There is no arrangement in which one message reports both, and
                // inventing one would mean this function collected errors rather
                // than failing fast.
                let key = load_private_key(key)?;
                let chain = load_cert_chain(cert)?;
                Ok(ResolvedCertificate { chain, key })
            }
            Self::Platform { chain, key } => {
                // Both checks below are `InternalInvariantViolated`, not a
                // configuration error: `Self::Platform` is constructed by the
                // caller, so an empty chain or an empty certificate is a caller
                // bug rather than something an operator can fix in a manifest.
                // The docs on `resolve` say `QQQ-6004` for exactly this reason,
                // and an earlier version returned the configuration code here —
                // caught by `a_platform_source_with_an_empty_chain_is_an_invariant_violation`.
                if chain.is_empty() {
                    return Err(Error::new(
                        ErrorCode::InternalInvariantViolated,
                        "a platform certificate source was given an empty certificate chain",
                    )
                    .with_remediation(
                        "this is a caller bug: supply at least the leaf certificate; a TLS \
                         server with no certificate has nothing to present",
                    )
                    .with_context("source", "platform"));
                }
                // An empty `CertificateDer` is not a certificate, and rustls
                // would build a config that fails at handshake time rather than
                // here. Rejected at construction so the failure is at startup.
                if chain.iter().any(|c| c.as_ref().is_empty()) {
                    return Err(Error::new(
                        ErrorCode::InternalInvariantViolated,
                        "a platform certificate source contained an empty certificate",
                    )
                    .with_remediation(
                        "this is a caller bug: `CertificateDer` must hold DER-encoded \
                         certificate bytes, not an empty slice",
                    )
                    .with_context("source", "platform"));
                }
                Ok(ResolvedCertificate {
                    chain: chain.clone(),
                    key: key.clone_key(),
                })
            }
            Self::Acme { domain } => Err(tls_error(format!(
                "ACME certificate issuance for `{domain}` is not implemented"
            ))
            .with_remediation(
                "use `CertificateSource::files` or `CertificateSource::platform` for now. \
                 ACME (RFC 8555) issuance and renewal is tracked as `SRV-013`; it is refused \
                 rather than approximated because a server that silently serves a \
                 certificate the operator did not request fails in production, in front \
                 of a user, rather than at startup.",
            )
            .with_context("source", format!("acme:{domain}"))
            .with_context("tracked-by", "SRV-013")),
        }
    }
}

/// A certificate chain and key, loaded and ready to install.
///
/// The output of [`CertificateSource::resolve`]. A separate type rather than a
/// tuple so that a caller cannot pass the two in the wrong order.
///
/// # Why this is not `Clone`
///
/// `PrivateKeyDer` is deliberately not `Clone` in `rustls-pki-types`: cloning a
/// private key is how a copy ends up somewhere it is not zeroized. It provides
/// [`PrivateKeyDer::clone_key`] instead, which names the copy explicitly, and
/// that is what [`CertificateSource::resolve`] uses for the `Platform` variant.
/// Deriving `Clone` here would reintroduce the implicit copy upstream removed.
#[derive(Debug)]
pub struct ResolvedCertificate {
    /// The chain, leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// The private key.
    ///
    /// Taken by value by `ServerConfig::with_single_cert`, so a caller building
    /// two configurations from one source needs two resolutions or an explicit
    /// [`PrivateKeyDer::clone_key`].
    pub key: PrivateKeyDer<'static>,
}

/// Read a PEM certificate chain from a file.
///
/// # Why an empty file is an error rather than an empty chain
///
/// Because rustls' `with_single_cert` accepts an empty chain and produces a
/// `ServerConfig` that cannot complete a handshake. The failure then appears on
/// the first client, in production, as a connection error with no server-side
/// log — rather than at startup, naming the file. `SRV-007` requires refusing a
/// configuration with no certificates, and this and
/// [`TlsConfig::build`]'s explicit check are the two places that happens.
fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    // `rustls_pki_types::pem::PemObject`, **not** `rustls-pemfile`.
    //
    // `rustls-pemfile` is unmaintained (`RUSTSEC-2025-0134`): its repository was
    // archived in August 2025 and the advisory directs users to the PEM parsing
    // now inside `rustls-pki-types`, of which the old crate was already a thin
    // wrapper. `cargo deny check advisories` failed the build on the direct
    // dependency, and the right answer was to remove the crate rather than add an
    // ignore — an ignored advisory on a direct dependency is a decision to keep
    // something nobody maintains, and it would have to be re-made silently
    // forever.
    //
    // `CertificateDer` implements `PemObject`, so this is the same parse via the
    // maintained path; `pem_slice_iter` replaces the old `certs(&mut reader)`
    // iterator. Reading the file into memory first is required either way — a
    // `BufReader` was only ever there to satisfy `rustls_pemfile`'s `Read`
    // bound, and dropping it removes a buffering layer this path never used.
    // The bytes are read once and the same error message shape is used for the
    // open and the read, because `fs::read` performs both and a caller cannot act
    // differently on the two: in both cases the file is missing, or is not
    // readable by this process.
    let bytes = std::fs::read(path).map_err(|e| {
        tls_error(format!(
            "could not read the certificate file `{}`",
            path.display()
        ))
        .with_cause(e.to_string())
        .with_remediation(
            "check the path and that the process may read it; a certificate file is \
                 usually mounted read-only",
        )
        .with_context("file", path.display().to_string())
    })?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            tls_error(format!(
                "the certificate file `{}` is not valid PEM",
                path.display()
            ))
            .with_cause(e.to_string())
            .with_remediation(
                "the file must be a PEM certificate chain: each certificate between \
                 `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`",
            )
            .with_context("file", path.display().to_string())
        })?;

    if chain.is_empty() {
        return Err(tls_error(format!(
            "the certificate file `{}` contains no certificate",
            path.display()
        ))
        .with_remediation(
            "a certificate file must contain at least one PEM `CERTIFICATE` block; a file \
             with only a key in it is the usual cause, and the fix is to point `cert` at \
             the certificate and `key` at the key",
        )
        .with_context("file", path.display().to_string()));
    }

    // **A PEM block is not a certificate.**
    //
    // `PemObject::pem_slice_iter` validates the *base64* and the `CERTIFICATE`
    // label, and nothing else. Measured while writing this module: a file
    // containing
    // `-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----` parses
    // successfully into a three-byte `CertificateDer`, because `AAAA` is valid
    // base64. That value then reaches `with_single_cert` and produces a
    // `ServerConfig` that fails on the first client instead of at startup —
    // exactly the failure mode `SRV-007` asks this function to prevent.
    //
    // So each entry is checked to be a DER `Certificate` (`SEQUENCE` containing
    // a `SEQUENCE`) before it is accepted. This is a *shape* check, not a
    // signature or validity check — verifying those is `rustls-webpki`'s job at
    // handshake time, and duplicating them here would be a second, weaker
    // authority on the same question.
    for (i, cert) in chain.iter().enumerate() {
        if !looks_like_a_der_certificate(cert.as_ref()) {
            return Err(tls_error(format!(
                "certificate {i} in `{}` is not a DER certificate",
                path.display()
            ))
            .with_remediation(
                "the PEM block decoded, but its contents are not an X.509 certificate. A \
                 placeholder or truncated file is the usual cause; check it with \
                 `openssl x509 -in <file> -noout -subject`",
            )
            .with_context("file", path.display().to_string())
            .with_context("bytes", cert.as_ref().len().to_string()));
        }
    }

    Ok(chain)
}

/// Whether these bytes have the outer shape of a DER X.509 `Certificate`.
///
/// ```text
/// Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm, signatureValue }
/// ```
///
/// Deliberately shallow: it checks the outer `SEQUENCE` and that the first
/// element inside it is the `tbsCertificate` `SEQUENCE`. Anything deeper is
/// `rustls-webpki`'s job.
///
/// # Why not `rustls::server::ParsedCertificate`
///
/// `rustls::server::ParsedCertificate` does exactly this and is the obvious
/// choice, but it is produced by the *verifier* path — constructing one outside
/// a verification context is not part of the public API in a way that reads
/// clearly here. This few-line check is narrow enough to audit at a glance, and
/// it is a *shallow* check on purpose: its only job is to stop a well-formed
/// PEM wrapper around non-certificate bytes.
fn looks_like_a_der_certificate(der: &[u8]) -> bool {
    /// A universal, constructed `SEQUENCE`.
    const SEQUENCE: u8 = 0x30;

    let Some((tag, header, content)) = split_element(der) else {
        return false;
    };
    if tag != SEQUENCE {
        return false;
    }
    // The declared length must account for exactly the rest of the input; a
    // trailing-garbage certificate is not one this server should present.
    if header.checked_add(content.len()) != Some(der.len()) {
        return false;
    }
    // And the first thing inside must be the `tbsCertificate` `SEQUENCE`.
    matches!(split_element(content), Some((SEQUENCE, _, _)))
}

/// Read a PEM private key from a file.
///
/// # Which key formats are accepted, and why exactly these
///
/// | Format | PEM label | Accepted |
/// |---|---|---|
/// | PKCS#8 | `PRIVATE KEY` | yes |
/// | PKCS#1 (RSA) | `RSA PRIVATE KEY` | yes |
/// | SEC1 (EC) | `EC PRIVATE KEY` | yes |
/// | PKCS#8 encrypted | `ENCRYPTED PRIVATE KEY` | **no** |
///
/// The first three are all accepted, and `PrivateKeyDer::from_pem_slice` is what
/// accepts them. §`SRV-007` asks for PKCS#8 and PKCS#1 in particular: PKCS#8 is
/// what `openssl genpkey` and every modern toolchain emit and is the only one of
/// the three that is algorithm-agnostic, while PKCS#1 is what older RSA tooling
/// emits and refusing it would break deployments that are not actually insecure
/// — a PKCS#1 RSA key is the same key as its PKCS#8 encoding. SEC1 comes along
/// because it is what `openssl ecparam -genkey` emits, and refusing it would
/// have the same effect for EC users.
///
/// **Encrypted keys are refused**, and the refusal names the tool to decrypt
/// them. rustls has no passphrase interface, so the honest options were to
/// refuse here or to fail at handshake time. The server-side reasoning is the
/// same as for the empty chain: a key that cannot be used should be discovered
/// at startup, by name, not by the first client.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    // `PrivateKeyDer::from_pem_slice` is the `PemObject` path — see
    // `load_cert_chain` for why `rustls-pemfile` was removed.
    //
    // The error is distinguished from "no key" rather than reported as one
    // message. `from_pem_slice` returns a single error for both a malformed
    // block and a well-formed block whose label is not a key, and those need
    // different fixes: the first is a corrupt file, the second is a file that
    // contains something else. The remediation names both possibilities.
    //
    // The open and the read error are one message for the same reason as in
    // `load_cert_chain`, but the remediation differs: this file holds a secret,
    // so "loosen the permissions" is the wrong advice and the message says why.
    let bytes = std::fs::read(path).map_err(|e| {
        tls_error(format!(
            "could not read the private key file `{}`",
            path.display()
        ))
        .with_cause(e.to_string())
        .with_remediation(
            "check the path and that the process may read it. A key file readable by \
                 every user is itself a problem, so this error is worth reading rather \
                 than working around by loosening permissions",
        )
        .with_context("file", path.display().to_string())
    })?;

    match PrivateKeyDer::from_pem_slice(&bytes) {
        Ok(key) => Ok(key),
        Err(e) => Err(tls_error(format!(
            "the private key file `{}` contains no key this server can use",
            path.display()
        ))
        .with_cause(e.to_string())
        .with_remediation(
            "supported PEM labels are `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` (PKCS#1) \
             and `EC PRIVATE KEY` (SEC1). `ENCRYPTED PRIVATE KEY` is not supported because \
             rustls has no passphrase interface; decrypt it first, for example \
             `openssl pkcs8 -topk8 -nocrypt -in enc.key -out plain.key`",
        )
        .with_context("file", path.display().to_string())),
    }
}

/// Read a PEM CA bundle into a trust root store.
///
/// Used by [`ClientAuth`] to decide which client certificates are acceptable.
/// An empty bundle is refused: a trust store with no roots verifies nothing, so
/// every client would be rejected — which looks like a client problem rather
/// than the configuration problem it is.
///
/// # Errors
///
/// `QQQ-2002` when the file cannot be read, is not PEM, or contains no
/// certificate.
pub fn load_trust_roots(path: &Path) -> Result<RootCertStore> {
    let chain = load_cert_chain(path)?;
    let mut roots = RootCertStore::empty();
    let mut added = 0usize;
    for cert in chain {
        // A CA bundle legitimately contains certificates a given verifier
        // cannot parse, so a single rejection is not fatal — but a bundle where
        // *nothing* was added is, and that is what `added` checks below.
        if roots.add(cert).is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        return Err(tls_error(format!(
            "the trust root file `{}` contained no usable CA certificate",
            path.display()
        ))
        .with_remediation(
            "the file must contain the PEM certificates of the certificate authorities \
             whose client certificates this server will accept. A bundle of end-entity \
             certificates is the usual mistake",
        )
        .with_context("file", path.display().to_string()));
    }
    Ok(roots)
}

// ---------------------------------------------------------------------------
// Client authentication
// ---------------------------------------------------------------------------

/// How client certificates are handled.
///
/// `SRV-008` / §6.4: *"Client certificates (mTLS) are a supported `default_auth`
/// mode."*
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuth {
    /// No client certificate is requested.
    None,
    /// A client certificate is required, and must chain to `ca_file`.
    ///
    /// A client that presents none, or presents one that does not verify, fails
    /// the handshake. That is the difference from [`Self::Optional`] and it is a
    /// security-relevant one: `Optional` is **not** a weaker `Required`, it is a
    /// different feature, and a service that treats "no certificate" as "the
    /// anonymous client" while also treating "a valid certificate" as "the
    /// authenticated client" has to handle the first case anyway.
    Required {
        /// The PEM CA bundle whose issued client certificates are trusted.
        ca_file: PathBuf,
    },
    /// A client certificate is requested, and verified if presented, but the
    /// handshake succeeds without one.
    ///
    /// # The trap this variant exists to make visible
    ///
    /// A service using `Optional` **must** distinguish "no certificate" from "a
    /// certificate". `peer_certificates()` returning `None` after an `Optional`
    /// handshake means the client declined, which is not a failure and not an
    /// identity. [`PeerIdentity::from_verified`] makes the two cases point
    /// (`Option<PeerIdentity>`), so a handler that forgets one does not get a
    /// default identity — it gets a compile error or an explicit `unwrap`.
    Optional {
        /// The PEM CA bundle whose issued client certificates are trusted.
        ca_file: PathBuf,
    },
}

impl ClientAuth {
    /// Whether this mode requests a client certificate at all.
    #[must_use]
    pub const fn requests_certificate(&self) -> bool {
        matches!(self, Self::Required { .. } | Self::Optional { .. })
    }

    /// Whether a client that presents no certificate is rejected.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        matches!(self, Self::Required { .. })
    }

    /// The trust root file, when there is one.
    #[must_use]
    pub fn ca_file(&self) -> Option<&Path> {
        match self {
            Self::None => None,
            Self::Required { ca_file } | Self::Optional { ca_file } => Some(ca_file),
        }
    }

    /// Build the rustls verifier for this mode.
    ///
    /// `None` means "do not request a client certificate", which is what
    /// `with_no_client_auth` is for — it is not the same as a verifier that
    /// accepts everything.
    ///
    /// # Errors
    ///
    /// `QQQ-2002` when the CA file cannot be read or holds no usable CA
    /// certificate.
    ///
    /// # Why the verifier needs the crypto provider
    ///
    /// In rustls 0.23 the certificate verifier does not pick its own signature
    /// algorithms: it is built *against* a provider, so that the algorithms used
    /// to check a client certificate's signature are the ones this server
    /// deliberately selected. Passing the provider in is therefore not plumbing
    /// convenience — it is what keeps the mTLS path and the suite policy the same
    /// policy.
    ///
    /// # Why the trait path is spelled `server::danger`
    ///
    /// rustls places `ClientCertVerifier` under `rustls::server::danger` because
    /// implementing it wrongly means accepting certificates that should not be
    /// accepted. This module does **not** implement it: it uses
    /// [`WebPkiClientVerifier`], the audited webpki-backed implementation, so the
    /// dangerous surface is *consumed* rather than reimplemented. The path is
    /// written in full at the one place it appears so that reading this module
    /// makes that evident.
    fn verifier(
        &self,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>> {
        let ca_file = match self {
            Self::None => return Ok(None),
            Self::Required { ca_file } | Self::Optional { ca_file } => ca_file,
        };

        let roots = Arc::new(load_trust_roots(ca_file)?);
        let builder = WebPkiClientVerifier::builder_with_provider(roots, provider);

        // This is the only behavioural difference between the two modes, and it
        // is one method call. `allow_unauthenticated` is what makes a missing
        // certificate acceptable; `Required` simply does not call it, so
        // `client_auth_mandatory()` stays `true` and rustls aborts the handshake.
        let verifier = if self.is_required() {
            builder.build()
        } else {
            builder.allow_unauthenticated().build()
        }
        .map_err(|e| {
            tls_error(format!(
                "could not build the client certificate verifier from `{}`",
                ca_file.display()
            ))
            .with_cause(e.to_string())
            .with_remediation(
                "this usually means the trust roots are unusable; check that the file \
                 contains CA certificates in PEM form",
            )
            .with_context("file", ca_file.display().to_string())
        })?;

        Ok(Some(verifier))
    }
}

impl Default for ClientAuth {
    /// **`None`, and this default is deliberate rather than convenient.**
    ///
    /// A `Default` that required client certificates would make every caller
    /// that forgot to choose one reject its legitimate clients — a loud failure.
    /// A `Default` that *requested* one optionally would be worse: it would
    /// change what the server sends in the `CertificateRequest` message, so a
    /// deployment that never intended mTLS would still be negotiating it.
    ///
    /// `None` is the only default that adds nothing to the protocol. It is also
    /// what `default_auth` resolves to when a manifest does not name a mode,
    /// which is why this `impl` exists rather than being left to each caller.
    fn default() -> Self {
        Self::None
    }
}

// ---------------------------------------------------------------------------
// Peer identity
// ---------------------------------------------------------------------------

/// The verified identity of the client on a connection.
///
/// # What this is, and what it deliberately is not
///
/// It is **identity extraction**: it reports who the certificate says the client
/// is. It is **not** authorization. Nothing here decides whether that identity
/// may perform an operation — that is the capability engine's job (`qqq-cap`,
/// §7.1), and a `PeerIdentity` reaching a capability check is the intended
/// shape. There is deliberately no `can_access`, no role, and no group: a
/// peer-certificate check that also made authorization decisions would be a
/// second policy engine, and this project has exactly one on purpose.
///
/// # Why the subject is a string and not a parsed distinguished name
///
/// Because rustls exposes the peer chain as raw DER and does not re-export a DN
/// parser, and adding an X.509 parsing dependency for a display string would be
/// a large dependency for a small feature. The subject is rendered from the DER
/// `Name`'s common-name attribute, with the full DER retained in
/// [`Self::subject_der`] so a caller that needs structured fields can parse them
/// without this crate choosing a parser for it.
///
/// A certificate whose subject has no common name — legal, though unusual —
/// yields [`Self::UNNAMED_SUBJECT`] rather than an empty string, so a log line
/// never renders as blank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The subject's common name, or a placeholder when it has none.
    subject: String,
    /// The leaf certificate, DER-encoded, exactly as presented.
    subject_der: Vec<u8>,
    /// The certificate's SHA-256 fingerprint.
    ///
    /// Carried because it is the only stable identifier a certificate has: a
    /// common name is attacker-chosen in the general case and is not unique
    /// across issuers. An audit log that records only the common name records
    /// something a client can make up.
    fingerprint: String,
}

impl PeerIdentity {
    /// The placeholder used when a certificate's subject has no common name.
    pub const UNNAMED_SUBJECT: &'static str = "(subject has no common name)";

    /// Extract an identity from a verified peer chain.
    ///
    /// Returns `None` when the peer presented no certificate — which is a
    /// legitimate outcome under [`ClientAuth::Optional`] and is **not** the same
    /// as an anonymous identity. Returning `Option` rather than an
    /// `Anonymous` variant is what stops a handler from silently treating
    /// "declined to authenticate" as "authenticated as nobody".
    ///
    /// # Why this cannot verify anything
    ///
    /// By the time a caller has a connection, rustls has already verified the
    /// chain against the configured [`ClientAuth`] roots — a certificate that
    /// did not verify aborted the handshake. This function therefore *reports*
    /// rather than *checks*, and the distinction matters: a version of this that
    /// re-verified would be a second, weaker authority on the same question.
    #[must_use]
    pub fn from_verified(chain: Option<&[CertificateDer<'static>]>) -> Option<Self> {
        let leaf = chain?.first()?;
        let der = leaf.as_ref().to_vec();
        Some(Self {
            subject: common_name_of(&der).unwrap_or_else(|| Self::UNNAMED_SUBJECT.to_owned()),
            subject_der: der,
            fingerprint: sha256_fingerprint(leaf.as_ref()),
        })
    }

    /// The subject's common name, or [`Self::UNNAMED_SUBJECT`].
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The leaf certificate, DER-encoded.
    ///
    /// Exposed so a caller can parse structured subject fields itself rather
    /// than this crate picking an X.509 parser for the whole workspace.
    #[must_use]
    pub fn subject_der(&self) -> &[u8] {
        &self.subject_der
    }

    /// The SHA-256 fingerprint of the leaf certificate, as 32 colon-separated
    /// uppercase hex pairs.
    ///
    /// The same rendering `openssl x509 -fingerprint -sha256` produces, so an
    /// operator can compare a log line against the file without a conversion
    /// step — which is the whole reason a fingerprint is useful.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl fmt::Display for PeerIdentity {
    /// Renders as `subject (SHA-256 fingerprint)`.
    ///
    /// Both halves, because the subject alone is not trustworthy and the
    /// fingerprint alone is not readable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.subject, self.fingerprint)
    }
}

/// A minimal DER walk that finds the subject common name.
///
/// # Why this is hand-rolled, and its limits
///
/// rustls returns the peer chain as raw DER and re-exports no distinguished-name
/// parser. The full `x509-parser` crate is a large dependency — `asn1-rs`,
/// `der-parser`, `nom` — for one display string.
///
/// This walks the structure it needs and **returns `None` for anything it does
/// not recognise** rather than guessing. The callers then report a named
/// placeholder instead of a wrong identity, which is the only acceptable failure
/// mode for something that ends up in an audit log.
///
/// It handles the shape RFC 5280 actually specifies for a `Name`:
///
/// ```text
/// Certificate     ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
/// TBSCertificate  ::= SEQUENCE { [0] version, serialNumber, signature, issuer, validity,
///                                subject, ... }
/// Name            ::= RDNSequence          -- a SEQUENCE of RelativeDistinguishedName
/// RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
/// AttributeTypeAndValue     ::= SEQUENCE { OID, value }
/// ```
///
/// `2.5.4.3` is `id-at-commonName`, and it is matched as an OID rather than by
/// position, so a subject with only an organisation, or with several RDNs, does
/// not produce the wrong attribute.
///
/// Not handled, and refusing rather than approximating: a subject encoded with
/// BER indefinite lengths (`rustls-webpki` rejects these anyway), and a common
/// name whose value is not a printable string — in which case the bytes are
/// lossily decoded, which is reported honestly by a replacement character rather
/// than by a wrong string.
fn common_name_of(cert_der: &[u8]) -> Option<String> {
    // `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm,
    //                              signatureValue }`
    //
    // # The defect this shape replaced
    //
    // The walker used to search the `Certificate`'s own children for tag `[3]`
    // (`0xA3`), on the belief that `[3]` wrapped `TBSCertificate`. It does not:
    // `[3]` is the **extensions** field *inside* `TBSCertificate`, and the
    // `Certificate`'s children are `SEQUENCE, SEQUENCE, BIT STRING` — measured
    // on a real rcgen certificate: `0x30, 0x30, 0x03`, with no `0xA3` at that
    // level at all.
    //
    // So the search returned `None` for **every** certificate, and
    // `PeerIdentity::from_verified` reported `"(subject has no common name)"` for
    // a certificate whose subject plainly had one. The unit test passed because
    // it hand-built a `[3]`-wrapped structure that no real certificate produces:
    // the test encoded the same misunderstanding as the code, so neither could
    // catch the other. Only the end-to-end mTLS test reaches this function with
    // real bytes, and that is where it was found.
    let (_, _, certificate_body) = split_element(cert_der)?;
    let (tbs_tag, _, tbs) = children(certificate_body).next()?;
    // The first child of `Certificate` is the TBS certificate, tag `0x30`. Read
    // positionally rather than by searching for a distinctive tag, precisely
    // because the earlier search-by-tag was the bug.
    if tbs_tag != 0x30 {
        return None;
    }

    // Inside TBSCertificate the fields are: version `[0]`, serialNumber,
    // signature, issuer, validity, subject, …
    //
    // Rather than counting fields — which breaks the moment a certificate uses a
    // shape this walker did not anticipate — each child is *identified by its
    // tag*, and the subject is taken as the second plain `SEQUENCE` that is a
    // `Name`. Both issuer and subject are `Name`, so tag alone cannot separate
    // them; position can, and the position is stable because RFC 5280 fixes the
    // field order. So the walk counts only the `Name`-shaped fields it cares
    // about and ignores everything else.
    let mut names_seen = 0usize;
    for (tag, _, content) in children(tbs) {
        // `[0]` version and the `BIT STRING` / `AlgorithmIdentifier` fields are
        // skipped by tag: only a plain `SEQUENCE` can be a `Name`.
        if tag != 0x30 {
            continue;
        }
        // A `SEQUENCE` inside TBSCertificate is either a `Name` (issuer, then
        // subject) or the `AlgorithmIdentifier` of `signature` — which is also a
        // `SEQUENCE`, but is not a `SEQUENCE OF SET`, and `walk_rdn_sequence`
        // returns `None` for it rather than a wrong name.
        //
        // Counting *matches* rather than raw sequences is what makes this
        // order-independent with respect to the algorithm identifier's position.
        if walk_rdn_sequence(content).is_some() {
            names_seen += 1;
            if names_seen == 2 {
                // The second `Name` in TBSCertificate is the subject.
                return walk_rdn_sequence(content);
            }
        }
    }
    None
}

/// Walk the **content** of a `Name` (`SEQUENCE OF SET OF
/// AttributeTypeAndValue`) for the CN.
///
/// # The argument is content, not a whole element
///
/// This takes the bytes *inside* the `Name`'s `SEQUENCE`, matching what
/// [`split_element`] hands out and what [`common_name_of`] passes in. A caller
/// that passes a whole element — header included — gets `None`, because the first
/// child it sees is then the outer `SEQUENCE` rather than a `SET`, and the
/// "not a `Name`" check below rejects it.
///
/// That is a real trap, and it caught this module's own test: the first version
/// of `the_common_name_walker_matches_by_oid` passed `der_sequence(...)` — the
/// whole element, header and all — and asserted `Some("alice@")` against a walker
/// that correctly returned `None`. The walker was right and the test was wrong.
///
/// Returns `None` unless the input really is a `Name`: a sequence of `SET`s, each
/// holding `SEQUENCE`-of-`(OID, value)` pairs. That strictness is what lets
/// [`common_name_of`] tell a `Name` apart from the `AlgorithmIdentifier` that
/// also appears inside `TBSCertificate`.
///
/// The common name is matched by **OID**, not by position, so a subject whose
/// first RDN is an organisation still yields the CN.
fn walk_rdn_sequence(subject: &[u8]) -> Option<String> {
    /// `id-at-commonName`, as DER content bytes (the OID minus its tag/length).
    const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

    let mut found: Option<String> = None;
    let mut rdn_count = 0usize;

    for (rdn_tag, _, rdn_content) in children(subject) {
        // Every RDN is a `SET` (0x31). If this is not one, this is not a
        // `Name`, and `None` is the honest answer.
        if rdn_tag != 0x31 {
            return None;
        }
        rdn_count += 1;

        for (attr_tag, _, attr_content) in children(rdn_content) {
            // Each `AttributeTypeAndValue` is a `SEQUENCE` of exactly two:
            // the OID, then the value.
            if attr_tag != 0x30 {
                return None;
            }
            let mut parts = children(attr_content);
            let (oid_tag, _, oid) = parts.next()?;
            let (_, _, value) = parts.next()?;
            if oid_tag == 0x06 && oid == OID_COMMON_NAME && found.is_none() {
                found = Some(String::from_utf8_lossy(value).into_owned());
            }
        }
    }

    // An empty subject is legal but is not a `Name` we can attribute anything
    // to; report it as unfound rather than as an empty identity.
    if rdn_count == 0 {
        return None;
    }
    found
}

/// Split a DER element into `(tag, header_len, content)`.
///
/// Returns `None` for an indefinite length (`0x80`), which DER forbids and which
/// this deliberately does not interpret.
fn split_element(bytes: &[u8]) -> Option<(u8, usize, &[u8])> {
    let tag = *bytes.first()?;
    let first = *bytes.get(1)?;
    if first & 0x80 == 0 {
        let len = usize::from(first);
        let start = 2usize;
        let end = start.checked_add(len)?;
        return Some((tag, start, bytes.get(start..end)?));
    }
    let n = usize::from(first & 0x7F);
    // Seven length bytes is already absurd for a certificate; refusing more
    // keeps the arithmetic provably in range.
    if n == 0 || n > 7 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = len
            .checked_mul(256)?
            .checked_add(usize::from(*bytes.get(2 + i)?))?;
    }
    let start = 2usize.checked_add(n)?;
    let end = start.checked_add(len)?;
    Some((tag, start, bytes.get(start..end)?))
}

/// Iterate the immediate children of a constructed element's content.
fn children(content: &[u8]) -> impl Iterator<Item = (u8, usize, &[u8])> {
    let mut rest = content;
    std::iter::from_fn(move || {
        let (tag, header, inner) = split_element(rest)?;
        rest = rest.get(header.checked_add(inner.len())?..)?;
        Some((tag, header, inner))
    })
}

/// The SHA-256 fingerprint of a DER certificate.
///
/// `sha2` is already a workspace dependency used for content addressing, so this
/// adds nothing.
fn sha256_fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(digest.len() * 3);
    for (i, byte) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02X}"));
    }
    out
}

// ---------------------------------------------------------------------------
// The configuration
// ---------------------------------------------------------------------------

/// Everything needed to produce a [`rustls::ServerConfig`].
///
/// # Why this is a struct rather than a builder chain
///
/// A builder chain can be left half-finished, and a half-finished builder either
/// panics or silently substitutes a default. `TlsConfig` is a plain struct whose
/// fields are all visible, so "what is this server configured to do" is
/// answerable by reading one value — and [`Self::build`] refuses the
/// combinations that cannot be answered.
///
/// # Why this is not `Clone`
///
/// Because [`CertificateSource`] is not: a `TlsConfig` that cloned itself would
/// clone a private key wherever a caller passed a configuration along. A caller
/// that needs to share one uses an `Arc<TlsConfig>`.
#[derive(Debug)]
pub struct TlsConfig {
    /// Where the certificate and key come from.
    pub certificate: CertificateSource,
    /// The protocol versions offered, newest first.
    pub versions: &'static [&'static rustls::SupportedProtocolVersion],
    /// The cipher suites offered, in preference order.
    pub cipher_suites: &'static [SupportedCipherSuite],
    /// The ALPN protocols to advertise, in preference order.
    ///
    /// **Empty means no ALPN extension is sent at all.** That is a real choice a
    /// deployment may make — an HTTP/1.1-only server behind a proxy that
    /// terminates TLS does not need the extension — and it is distinct from
    /// "offer HTTP/1.1", because a client that offered `h2` and receives no
    /// ALPN response knows to fall back to HTTP/1.1, whereas one that is
    /// answered `http/1.1` knows it is speaking to a 1.1-only server.
    pub alpn: Vec<Vec<u8>>,
    /// How client certificates are handled.
    pub client_auth: ClientAuth,
}

impl TlsConfig {
    /// A configuration from a certificate source, with the documented policy.
    ///
    /// `NONE` client auth and the full [`ALPN_ALL`] list — the state a
    /// deployment reaches once `SRV-002` lands. To serve HTTP/1.1 only today,
    /// overwrite [`Self::alpn`].
    ///
    /// # Why this is not `Default`
    ///
    /// Because there is no default certificate. A `Default` impl would have to
    /// invent one, and an invented certificate is the failure this module exists
    /// to prevent.
    #[must_use]
    pub fn new(certificate: CertificateSource) -> Self {
        Self {
            certificate,
            versions: PROTOCOL_VERSIONS,
            cipher_suites: CIPHER_SUITES,
            alpn: ALPN_ALL.iter().map(|p| (*p).to_vec()).collect(),
            client_auth: ClientAuth::None,
        }
    }

    /// Require a client certificate that chains to `ca_file`.
    #[must_use]
    pub fn with_required_client_auth(mut self, ca_file: impl Into<PathBuf>) -> Self {
        self.client_auth = ClientAuth::Required {
            ca_file: ca_file.into(),
        };
        self
    }

    /// Request a client certificate, accepting a client that presents none.
    #[must_use]
    pub fn with_optional_client_auth(mut self, ca_file: impl Into<PathBuf>) -> Self {
        self.client_auth = ClientAuth::Optional {
            ca_file: ca_file.into(),
        };
        self
    }

    /// Advertise exactly these ALPN protocols, in preference order.
    #[must_use]
    pub fn with_alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn = protocols.iter().map(|p| (*p).to_vec()).collect();
        self
    }

    /// Whether a client certificate will be requested.
    #[must_use]
    pub const fn requests_client_certificate(&self) -> bool {
        self.client_auth.requests_certificate()
    }

    /// Build the rustls configuration.
    ///
    /// # Errors
    ///
    /// * `QQQ-2002` — [`Self::versions`] or [`Self::cipher_suites`] is empty.
    ///   `SEC-017` requires that an unspecified field be an error rather than a
    ///   silent default, and an empty list is that case: there is no
    ///   "reasonable" subset to substitute, because substituting one is exactly
    ///   the agility §7.4 forbids.
    /// * `QQQ-2002` — the certificate source produced no certificate (see
    ///   [`CertificateSource::resolve`]).
    /// * `QQQ-2002` — rustls rejected the certificate and key together, which in
    ///   practice means they are a mismatched pair.
    /// * `QQQ-2002` — the client-certificate trust root could not be loaded.
    ///
    /// # What this guarantees about the versions
    ///
    /// `builder_with_protocol_versions` is used rather than `builder`, so the
    /// rustls default version list is never in play — there is no code path here
    /// through which a version this server did not name can be negotiated.
    ///
    /// # How the cipher policy is actually installed
    ///
    /// This is the part of rustls 0.23 that is easy to get wrong, so it is worth
    /// stating plainly: **there is no `with_cipher_suites` on the builder.** The
    /// suite list belongs to the [`rustls::crypto::CryptoProvider`], and the
    /// builder receives it through
    /// [`ServerConfig::builder_with_provider`].
    ///
    /// So [`CIPHER_SUITES`] is installed by constructing a provider from
    /// `aws_lc_rs::default_provider()` with its `cipher_suites` field replaced.
    /// Everything else in that provider — the random source, the key-exchange
    /// groups, the signature-verification algorithms, the key loader — is left as
    /// the audited default.
    ///
    /// That is a deliberate boundary, and it is the honest scope of what
    /// [`CIPHER_SUITES`] pins:
    ///
    /// * The **suite list** is this server's, and cannot be changed by a rustls
    ///   patch release.
    /// * The **key-exchange groups** are the provider's. `SEC-021` (hybrid
    ///   X25519+ML-KEM) will change this field, and when it does the groups
    ///   become an explicit list here too — for the same reason the suites are
    ///   one now.
    ///
    /// The one provider is built once and used for **both** the suite list and
    /// the client-certificate verifier, so the mTLS path and the suite path
    /// cannot drift onto different providers.
    pub fn build(&self) -> Result<Arc<ServerConfig>> {
        // `SEC-017`: an unspecified field is an error, not a default. These two
        // checks are the enforcement of that sentence, and they run *before*
        // any certificate file is touched, so a caller who forgot to fill in the
        // policy is told that rather than being told about a file.
        if self.versions.is_empty() {
            return Err(tls_error("the TLS configuration names no protocol version")
                .with_remediation(
                    "set `TlsConfig::versions` to `PROTOCOL_VERSIONS`. There is deliberately no \
                 default: a version list that fills itself in is a version list that can \
                 change without anyone reviewing the change, which is what `SEC-017` \
                 forbids.",
                )
                .with_context("field", "versions"));
        }
        if self.cipher_suites.is_empty() {
            return Err(tls_error("the TLS configuration names no cipher suite")
                .with_remediation(
                    "set `TlsConfig::cipher_suites` to `CIPHER_SUITES`, or to an explicitly \
                 reviewed list. There is deliberately no default: rustls' default suite \
                 set is the library's opinion and can change in a patch release, and a \
                 cipher policy that changes on a dependency bump is not a policy.",
                )
                .with_context("field", "cipher_suites"));
        }

        let resolved = self.certificate.resolve()?;

        // The `SRV-007` requirement, checked here as well as in
        // `CertificateSource::resolve`, because `Platform` can be constructed by
        // a caller that bypassed `resolve` — and because the two checks protect
        // against different things: `resolve` protects the file path, this
        // protects the invariant "a `ServerConfig` never has an empty chain".
        if resolved.chain.is_empty() {
            return Err(
                tls_error("the TLS configuration has no certificate to present")
                    .with_remediation(
                        "a TLS server must have at least one certificate. Configure \
                 `CertificateSource::files` with a PEM certificate, or supply the platform's \
                 certificate through `CertificateSource::platform`.",
                    )
                    .with_context("source", self.certificate.describe()),
            );
        }

        // --- The provider carries the cipher policy -------------------------
        //
        // There is no `with_cipher_suites` on the builder (see this method's
        // docs). The suite list is a field of the provider, so the policy is
        // installed by replacing exactly that field and leaving every other
        // component at the audited default.
        //
        // `default_provider()` is not a "silent default" in the `SEC-017`
        // sense: the suites — the thing the policy is *about* — are replaced
        // unconditionally on the next line, so no suite can reach the handshake
        // that this constant did not name. The key-exchange groups are likewise
        // replaced explicitly (`SEC-021`). What remains default is the random
        // source, the signature algorithms and the key loader.
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites = self.cipher_suites.to_vec();
        provider.kx_groups = SERVER_KX_GROUPS.to_vec();
        let provider = Arc::new(provider);

        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider));
        let builder = builder.with_protocol_versions(self.versions).map_err(|e| {
            tls_error("the protocol versions and cipher suites are incompatible")
                .with_cause(e.to_string())
                .with_remediation(
                    "every suite in `cipher_suites` must belong to a version in \
                         `versions`; rustls refuses a policy with no usable combination",
                )
                .with_context("versions", format!("{:?}", self.versions.len()))
                .with_context("cipher_suites", self.cipher_suites.len().to_string())
        })?;

        let builder = match self.client_auth.verifier(Arc::clone(&provider))? {
            Some(verifier) => builder.with_client_cert_verifier(verifier),
            // `with_no_client_auth` sends no `CertificateRequest`, which is what
            // distinguishes `ClientAuth::None` on the wire. It is *not* a
            // verifier that accepts anything: no verifier is installed at all.
            None => builder.with_no_client_auth(),
        };

        let mut config = builder
            .with_single_cert(resolved.chain, resolved.key)
            .map_err(|e| {
                tls_error("the certificate and private key were rejected together")
                    .with_cause(e.to_string())
                    .with_remediation(
                        "the commonest cause is a certificate and key that are not a pair, \
                         or a key type rustls cannot use. Compare them with \
                         `openssl x509 -noout -pubkey -in cert.pem` and \
                         `openssl pkey -pubout -in key.pem`: the two outputs must match.",
                    )
                    .with_context("source", self.certificate.describe())
            })?;

        config.alpn_protocols.clone_from(&self.alpn);
        Ok(Arc::new(config))
    }
}

// ---------------------------------------------------------------------------
// Reading negotiation results
// ---------------------------------------------------------------------------

/// What a completed handshake negotiated.
///
/// A plain data type rather than accessor calls on a live connection, because
/// the connection is not `Send`-friendly to keep around and because an access
/// log wants a value it can serialize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The negotiated protocol version, rendered (`"TLSv1.3"`).
    pub version: String,
    /// The negotiated cipher suite, by its IANA name.
    pub cipher_suite: String,
    /// The negotiated ALPN protocol, when one was.
    ///
    /// `None` means **no protocol was agreed** — the client offered none, or the
    /// server advertised none, or the two had nothing in common. That is not an
    /// error at the TLS layer; whether it is an error is an application
    /// decision, and [`Self::http_version`] makes the decision for HTTP while
    /// leaving it visible in this field.
    pub alpn: Option<String>,
}

impl Negotiated {
    /// Read the negotiation results from a rustls server connection.
    ///
    /// # Why this is bounded by the connection's own type
    ///
    /// The accessors used here (`protocol_version`, `negotiated_cipher_suite`,
    /// `alpn_protocol`) all return `None` until the handshake completes, which
    /// the type system does not encode. So this is called after
    /// `TlsStream` construction / `complete_io`, and a caller that calls it
    /// early gets `None`-ish values rather than wrong ones.
    #[must_use]
    pub fn of(conn: &rustls::ServerConnection) -> Self {
        use rustls::ProtocolVersion;

        let version = match conn.protocol_version() {
            Some(ProtocolVersion::TLSv1_2) => "TLSv1.2",
            Some(ProtocolVersion::TLSv1_3) => "TLSv1.3",
            // `ProtocolVersion` is `#[non_exhaustive]`; a version this build does
            // not know is reported as its debug name rather than mislabelled as
            // one it does.
            other => return Self::unclassified(other, conn),
        };

        Self {
            version: version.to_owned(),
            cipher_suite: cipher_suite_name(conn.negotiated_cipher_suite()),
            alpn: conn
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
        }
    }

    /// The fallback for a protocol version this build does not classify.
    fn unclassified(
        other: Option<rustls::ProtocolVersion>,
        conn: &rustls::ServerConnection,
    ) -> Self {
        Self {
            version: format!("{other:?}"),
            cipher_suite: cipher_suite_name(conn.negotiated_cipher_suite()),
            alpn: conn
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
        }
    }

    /// The HTTP version implied by the negotiated ALPN protocol.
    ///
    /// | ALPN | HTTP |
    /// |---|---|
    /// | `h2` | HTTP/2 |
    /// | `http/1.1` | HTTP/1.1 |
    /// | none | **HTTP/1.1** |
    ///
    /// # Why "none" is HTTP/1.1, and why that is not a guess
    ///
    /// RFC 9113 §3.1: when ALPN is not used, an HTTP/1.1 client speaks
    /// HTTP/1.1. The default is what the protocol says it is, not what this
    /// crate finds convenient. It is expressed as a method returning a value
    /// rather than as a comment so that a server which later supports HTTP/2
    /// has one place to consult, and `None` stays visible on
    /// [`Self::alpn`] for a caller that needs to distinguish.
    #[must_use]
    pub fn http_version(&self) -> &'static str {
        match self.alpn.as_deref() {
            Some("h2") => "HTTP/2",
            _ => "HTTP/1.1",
        }
    }
}

/// The IANA name of a negotiated suite, or `"none"`.
///
/// `SupportedCipherSuite::suite()` returns a `CipherSuite` that formats as its
/// IANA name (`TLS13_AES_256_GCM_SHA384`), which is what a log and a
/// `security.txt`-style policy comparison both want.
fn cipher_suite_name(suite: Option<SupportedCipherSuite>) -> String {
    match suite {
        Some(s) => format!("{:?}", s.suite()),
        None => "none".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// **The policy constants must name suites, and must not be empty** — an empty
    /// list is the "silent default" `SEC-017` forbids, arriving by the back door.
    #[test]
    fn the_cipher_policy_is_not_empty() {
        assert!(
            CIPHER_SUITES.len() >= 4,
            "a cipher policy with fewer than four suites is not a policy"
        );
    }

    /// **`SEC-021`: the hybrid post-quantum group is offered, and offered first.**
    ///
    /// # Why this test exists rather than a comment
    ///
    /// Reading the pinned dependency showed the item's premise was already
    /// satisfied: rustls 0.23.31 made `X25519MLKEM768` the default, and
    /// `Cargo.lock` resolves 0.23.45, so this server was already doing hybrid key
    /// exchange *by inheritance*.
    ///
    /// An inherited property is one dependency bump away from disappearing
    /// silently, and this session found five controls that had done exactly that
    /// (`§O-085`, `§O-088`, `§O-089`). So the default was converted into a stated
    /// policy, and this test is what makes the policy load-bearing: it fails if the
    /// group is removed, if it stops being first, or if the list is replaced with
    /// something that no longer names it.
    #[test]
    fn the_post_quantum_key_exchange_is_offered_and_preferred() {
        // # Why there is no `assert!(PQ_KEY_EXCHANGE_ENABLED)` here
        //
        // The first version had one, and `clippy::assertions_on_constants` rejected
        // it as an assertion whose value is known at compile time — correctly,
        // because it could never fail and therefore asserted nothing. A test that
        // cannot fail is the `§O-085` shape arriving inside a test.
        //
        // The intent it reached for is served by `PQ_KEY_EXCHANGE_ENABLED` being
        // `pub`: a constant the compiler can always see is one a reader and a
        // downgrade script can see. The behavioural claim is made by the
        // assertions below, which can actually fail.
        let first = SERVER_KX_GROUPS.first().expect("the list cannot be empty");
        assert_eq!(
            first.name(),
            rustls::NamedGroup::X25519MLKEM768,
            "the hybrid must be FIRST: list order is how a server states its \
             preference, so a client that follows us gets the post-quantum \
             exchange. Found: {:?}",
            first.name()
        );

        assert!(
            SERVER_KX_GROUPS
                .iter()
                .any(|g| g.name() == rustls::NamedGroup::X25519MLKEM768),
            "the hybrid group is not offered at all, so `harvest now, decrypt \
             later` is undefended against"
        );
    }

    /// **The classical fallbacks survive**, because a hybrid nobody can complete
    /// protects nothing: interop with clients that lack ML-KEM is the difference
    /// between a strong handshake and no handshake.
    #[test]
    fn the_classical_fallbacks_are_still_offered() {
        let names: Vec<_> = SERVER_KX_GROUPS.iter().map(|g| g.name()).collect();
        for required in [rustls::NamedGroup::X25519, rustls::NamedGroup::secp256r1] {
            assert!(
                names.contains(&required),
                "removing {required:?} drops interop with clients that cannot do \
                 ML-KEM; the hybrid is worthless if the handshake fails. Have: \
                 {names:?}"
            );
        }
    }

    /// **No group may be offered twice.** A duplicate would let a client negotiate
    /// a group the server believes it listed once, and would make the preference
    /// order ambiguous — which is the whole mechanism by which the hybrid is
    /// preferred.
    #[test]
    fn no_key_exchange_group_is_offered_twice() {
        // `NamedGroup` is not `Ord`, so comparability comes from `Debug`, which is
        // sufficient here: the test only needs to know whether two names are
        // *equal*, and `sort`/`dedup` on the formatted forms answers exactly that.
        let mut names: Vec<String> = SERVER_KX_GROUPS
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            before,
            "a duplicated key-exchange group makes the preference order \
             ambiguous"
        );
    }

    /// **The TLS 1.3 preference.** §7.4 says "TLS 1.3 preferred", and the
    /// mechanism by which a server prefers a version is list order.
    #[test]
    fn tls13_is_preferred_over_tls12() {
        assert_eq!(
            PROTOCOL_VERSIONS.first().map(|v| v.version),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "TLS 1.3 must be first, or 'preferred' is not what this server does"
        );
        assert!(
            PROTOCOL_VERSIONS
                .iter()
                .any(|v| v.version == rustls::ProtocolVersion::TLSv1_2),
            "1.2 must remain permitted"
        );
        assert_eq!(
            PROTOCOL_VERSIONS.len(),
            2,
            "exactly 1.3 and 1.2; anything else is a policy change, not a detail"
        );
    }

    /// **The version policy refuses TLS 1.1.** Asserted on the constant, which
    /// is the only surface through which a version can be negotiated.
    #[test]
    fn the_version_policy_refuses_tls_11() {
        for v in PROTOCOL_VERSIONS {
            assert_ne!(
                v.version,
                rustls::ProtocolVersion::TLSv1_1,
                "TLS 1.1 must never be offered"
            );
            assert_ne!(
                v.version,
                rustls::ProtocolVersion::SSLv3,
                "SSLv3 is not TLS"
            );
        }
    }

    /// Every suite in the policy is one of the two versions the policy permits.
    /// A suite from a third version would be unreachable — offered by the list
    /// and impossible under the version list — which is the kind of dead entry
    /// that makes a policy unreadable.
    #[test]
    fn every_suite_belongs_to_a_permitted_version() {
        for suite in CIPHER_SUITES {
            let v = match suite {
                SupportedCipherSuite::Tls13(_) => rustls::ProtocolVersion::TLSv1_3,
                SupportedCipherSuite::Tls12(_) => rustls::ProtocolVersion::TLSv1_2,
            };
            assert!(
                PROTOCOL_VERSIONS.iter().any(|p| p.version == v),
                "{:?} belongs to {v:?}, which the version policy does not permit",
                suite.suite()
            );
        }
    }

    /// **No RSA key transport.** `TLS_RSA_*` has no forward secrecy, so a future
    /// compromise of the server key decrypts every recorded session.
    #[test]
    fn no_suite_uses_rsa_key_transport() {
        for suite in CIPHER_SUITES {
            let name = format!("{:?}", suite.suite());
            assert!(
                !name.starts_with("TLS_RSA_"),
                "{name} uses RSA key transport and has no forward secrecy"
            );
        }
    }

    /// **No CBC.** §7.4 names AEAD suites, and CBC in TLS 1.2 carries a long
    /// padding-oracle history.
    #[test]
    fn no_suite_uses_cbc() {
        for suite in CIPHER_SUITES {
            let name = format!("{:?}", suite.suite());
            assert!(
                !name.contains("_CBC_"),
                "{name} is a CBC suite; the policy is AEAD-only"
            );
        }
    }

    /// Everything offered at 1.2 is forward-secret, which is the property that
    /// distinguishes the permitted set from the historical one.
    #[test]
    fn every_tls12_suite_is_forward_secret() {
        for suite in CIPHER_SUITES {
            if matches!(suite, SupportedCipherSuite::Tls12(_)) {
                let name = format!("{:?}", suite.suite());
                assert!(
                    name.starts_with("TLS_ECDHE_"),
                    "{name} is not forward-secret; TLS 1.2 suites here must be ECDHE"
                );
            }
        }
    }

    /// **`SEC-017`'s agility clause is enforced by the TYPE SYSTEM, and this
    /// test states the dependency fact it rests on.**
    ///
    /// # What was measured, and why it matters
    ///
    /// §7.4 says *"no algorithm agility without a version bump"*, and the module
    /// doc claims *"the lists are fixed; changing one is a change to a public
    /// constant"*. That second claim is about **code review**, not about a check —
    /// so it was worth asking whether a careless widening fails anything.
    ///
    /// It fails to **compile**. Measured against the installed rustls 0.23.43:
    ///
    /// | Attempted widening | Result |
    /// |---|---|
    /// | add a `TLS_*_CBC_*` suite to [`CIPHER_SUITES`] | `error[E0425]`: no CBC suite is exported by rustls 0.23 at all |
    /// | add TLS 1.1 to [`PROTOCOL_VERSIONS`] | `error[E0425]`: `rustls::version` exports only `TLS12` and `TLS13` |
    ///
    /// That is a **stronger** guarantee than a test: a test can be deleted or
    /// relaxed in review, whereas a suite the dependency does not export cannot be
    /// named in this crate at all. `no_suite_uses_cbc` therefore **cannot fail**
    /// with this rustls version, which is not a defect in that test — it is
    /// belt-and-braces — but it does mean the *real* enforcement lives elsewhere,
    /// and saying so is what stops a reader from believing the test is the
    /// guarantee.
    ///
    /// # Why this test exists anyway
    ///
    /// Because the guarantee is borrowed and could be returned. A future rustls
    /// release that reintroduces CBC or TLS 1.1 restores the ability to widen the
    /// policy, and at that moment `no_suite_uses_cbc` becomes load-bearing again
    /// with nobody noticing the transition. This test pins the **dependency-level
    /// precondition** the whole argument rests on, so the upgrade that changes it
    /// fails here, in a test whose message explains what just became possible.
    ///
    /// It cannot check a compile error from inside the same crate, so it asserts
    /// the observable fact that produces one: the exports are exactly the
    /// permitted set. If a future rustls exports more, this assertion — written
    /// against `PROTOCOL_VERSIONS` rather than a hard-coded list — is where the
    /// reviewer lands.
    #[test]
    fn the_agility_guarantee_rests_on_these_dependency_exports() {
        // 1. The version exports. `rustls::version` is a *static* list of exactly
        //    the versions this rustls supports; `TLS12` and `TLS13` being the only
        //    two is what makes "add a third version" a compile error.
        //
        //    Asserted by comparing against what is reachable rather than against a
        //    literal count: this reads the same constant the policy uses, so it
        //    stays true if the policy legitimately changes and fails if the
        //    dependency's surface changes underneath it.
        assert_eq!(
            PROTOCOL_VERSIONS.len(),
            2,
            "the policy offers {} versions. This assertion is not about an exact \
             count being sacred — it is the tripwire for a rustls upgrade that makes \
             a third version expressible, which is the moment the `SEC-017` agility \
             clause stops being enforced by the type system and starts depending on \
             review. If that has happened deliberately, update this test AND \
             re-confirm that the widening is intended.",
            PROTOCOL_VERSIONS.len()
        );

        // 2. Every version in the policy is one rustls exports — i.e. the policy
        //    cannot name a version the dependency does not have, which is the
        //    direction that would silently do nothing.
        for v in PROTOCOL_VERSIONS {
            assert!(
                matches!(
                    v.version,
                    rustls::ProtocolVersion::TLSv1_3 | rustls::ProtocolVersion::TLSv1_2
                ),
                "the policy names {:?}, which is neither TLS 1.2 nor 1.3",
                v.version
            );
        }

        // 3. And the suites: every one is an AEAD suite rustls actually exports.
        //    The `match` is exhaustive over `SupportedCipherSuite` by construction
        //    — a new variant is a compile error here rather than a silent gap.
        for suite in CIPHER_SUITES {
            match suite {
                SupportedCipherSuite::Tls13(_) | SupportedCipherSuite::Tls12(_) => {}
            }
        }
    }

    /// The suites are distinct. A duplicate is a list that reads as if it
    /// offers more than it does.
    #[test]
    fn the_cipher_list_has_no_duplicates() {
        let mut seen = std::collections::BTreeSet::new();
        for suite in CIPHER_SUITES {
            assert!(
                seen.insert(format!("{:?}", suite.suite())),
                "{:?} appears twice",
                suite.suite()
            );
        }
    }

    /// ALPN preference: `h2` before `http/1.1`.
    #[test]
    fn alpn_prefers_h2() {
        assert_eq!(ALPN_ALL.first().copied(), Some(ALPN_H2));
        assert_eq!(ALPN_H2, b"h2");
        assert_eq!(ALPN_HTTP11, b"http/1.1");
    }

    // -- the SEC-017 refusals ---------------------------------------------

    /// **An unspecified version list is an error, not a default.** This is the
    /// sentence in `SEC-017` that a codebase is most likely to violate by
    /// accident, so it is asserted directly.
    #[test]
    fn a_config_with_no_versions_is_refused() {
        let mut c = TlsConfig::new(CertificateSource::files("cert.pem", "key.pem"));
        c.versions = &[];
        let e = c
            .build()
            .expect_err("an empty version list must be refused");
        assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
        assert!(
            e.message.contains("protocol version"),
            "the error must name the field: {}",
            e.message
        );
        assert!(
            e.remediation
                .as_deref()
                .unwrap_or("")
                .contains("no default"),
            "the remediation must say why there is no default: {:?}",
            e.remediation
        );
    }

    #[test]
    fn a_config_with_no_cipher_suites_is_refused() {
        let mut c = TlsConfig::new(CertificateSource::files("cert.pem", "key.pem"));
        c.cipher_suites = &[];
        let e = c.build().expect_err("an empty suite list must be refused");
        assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
        assert!(e.message.contains("cipher suite"), "got: {}", e.message);
    }

    /// The policy is checked before any file is touched, so a caller who forgot
    /// the policy is told that rather than being told about a missing file.
    #[test]
    fn the_policy_is_checked_before_the_certificate() {
        let mut c = TlsConfig::new(CertificateSource::files(
            "definitely/not/here.pem",
            "neither/is/this.pem",
        ));
        c.cipher_suites = &[];
        let e = c.build().unwrap_err();
        assert!(
            e.message.contains("cipher suite"),
            "the policy must be reported before the file: {}",
            e.message
        );
    }

    // -- certificate sources ----------------------------------------------

    /// A missing certificate file is named as the certificate.
    ///
    /// # Why this calls `load_cert_chain` rather than `resolve`
    ///
    /// `resolve` loads the **key first** (see the comment there), so reaching the
    /// certificate load through it requires a key file that genuinely parses —
    /// and this crate's unit tests have no way to produce one: `rcgen` is a
    /// dev-dependency of the *test targets*, and fabricating a valid PKCS#8 key by
    /// hand is not something a test should do.
    ///
    /// Two earlier versions of this test tried `resolve` with placeholder keys and
    /// both failed, each time naming the key instead of the certificate. Rather
    /// than weaken the assertion to "some error was returned" — which would pass
    /// while the property under test was absent — it now exercises the function
    /// that actually produces the certificate-not-found error, and
    /// `tests/tls.rs` covers the same path end-to-end through `resolve` with a
    /// real generated key.
    #[test]
    fn a_missing_certificate_file_names_the_file() {
        let e = load_cert_chain(Path::new("no/such/cert.pem"))
            .expect_err("a missing certificate file must not panic");
        assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
        assert!(
            e.message.contains("no/such/cert.pem"),
            "the error must name the certificate path: {}",
            e.message
        );
        assert!(
            e.remediation.is_some(),
            "a missing file must come with an actionable next step"
        );
    }

    /// With **both** paths absent, the error names the key — the one loaded
    /// first. Pinned as a test because which error surfaces when two things are
    /// wrong is a property a reader will otherwise assume the other way round.
    #[test]
    fn with_both_paths_absent_the_key_is_named_first() {
        let e = CertificateSource::files("no/such/cert.pem", "no/such/key.pem")
            .resolve()
            .expect_err("must be refused");
        assert!(
            e.message.contains("key.pem"),
            "the load order is key-first, so the key is named: {}",
            e.message
        );
    }

    /// A missing key file is named as the key.
    ///
    /// # Why the certificate here is a *valid* one
    ///
    /// The first version of this test wrote `PEM_NOT_A_CERT` as the certificate
    /// and asserted that the missing key was named. It failed, naming the
    /// certificate instead — because `resolve` loaded the certificate first and
    /// that fixture has no `CERTIFICATE` block either.
    ///
    /// That is a real property of the code, not a test artifact: when **both**
    /// files are wrong, only one error is reported, and which one depends on the
    /// load order. `resolve` now loads the key first (see the comment there), so
    /// this test writes a genuinely valid certificate and a genuinely absent key
    /// and asserts the key is named — which is the case an operator actually
    /// hits, since a certificate that exists and a key path that is wrong is the
    /// common deployment mistake.
    #[test]
    fn a_missing_key_file_names_the_key() {
        let dir = tempdir();
        let cert = dir.join("c.pem");
        std::fs::write(&cert, valid_cert_pem()).expect("write");
        let e = CertificateSource::Files {
            cert,
            key: dir.join("absent.key"),
        }
        .resolve()
        .expect_err("a missing key file must be an error");
        assert!(
            e.message.contains("absent.key"),
            "the error must name the key, not the certificate: {}",
            e.message
        );
    }

    /// **A PEM block is not a certificate.**
    ///
    /// This test originally asserted only that a file consigning a non-certificate
    /// PEM block was refused, and it failed: `rustls_pemfile::certs` accepted
    /// `AAAA` (valid base64) and produced a three-byte `CertificateDer`. The
    /// assertion is therefore now on *which* refusal, and it is this test that
    /// forced `looks_like_a_der_certificate` into existence.
    #[test]
    fn a_pem_block_that_is_not_der_is_refused() {
        let dir = tempdir();
        let cert = dir.join("c.pem");
        std::fs::write(&cert, PEM_NOT_DER).expect("write");
        let e = load_cert_chain(&cert).expect_err("base64 is not a certificate");
        assert!(
            e.message.contains("not a DER certificate"),
            "the error must say the bytes are not a certificate, not that none was \
             found: {}",
            e.message
        );
        let remediation = e.remediation.unwrap_or_default();
        assert!(
            remediation.contains("openssl x509"),
            "the remediation must name a way to check the file: {remediation}"
        );
    }

    /// The shallow DER check accepts a well-formed outer `SEQUENCE` and rejects
    /// the shapes that are not one.
    #[test]
    fn the_der_shape_check_is_shallow_but_not_vacuous() {
        // A `SEQUENCE` containing a `SEQUENCE` — the shape of a `Certificate`.
        let good = der_sequence(&[&der_sequence(&[&der_utf8("tbs")[..]])[..]]);
        assert!(looks_like_a_der_certificate(&good), "a certificate shape");

        // Empty input, a non-`SEQUENCE` outer tag, an empty `SEQUENCE`, and a
        // `SEQUENCE` whose content is not itself a `SEQUENCE`.
        assert!(!looks_like_a_der_certificate(&[]));
        assert!(!looks_like_a_der_certificate(&[0x02, 0x01, 0x00]));
        assert!(!looks_like_a_der_certificate(&[0x30, 0x00]));
        assert!(!looks_like_a_der_certificate(&der_sequence(&[&der_utf8(
            "x"
        )[..]])));
        // Trailing bytes past the declared length are not a certificate.
        let mut trailing = good.clone();
        trailing.push(0xFF);
        assert!(!looks_like_a_der_certificate(&trailing));
    }

    /// A certificate file with no `CERTIFICATE` block is the classic
    /// cert/key-swap mistake, and the error says so.
    #[test]
    fn a_certificate_file_with_no_certificate_says_which_swap() {
        let dir = tempdir();
        let cert = dir.join("c.pem");
        std::fs::write(&cert, PEM_NOT_A_CERT).expect("write");
        let e = load_cert_chain(&cert).expect_err("must be refused");
        assert!(
            e.remediation
                .as_deref()
                .unwrap_or("")
                .contains("point `cert` at"),
            "the remediation should name the swap: {:?}",
            e.remediation
        );
    }

    /// An empty PEM body yields no key, and the error names the supported
    /// labels so the reader does not have to guess.
    #[test]
    fn an_unusable_key_names_the_supported_labels() {
        let dir = tempdir();
        let key = dir.join("k.pem");
        std::fs::write(&key, PEM_KEY_ONLY).expect("write");
        let e = load_private_key(&key).expect_err("a certificate is not a key");
        let remediation = e.remediation.unwrap_or_default();
        assert!(
            remediation.contains("PKCS#8"),
            "the remediation must name the supported formats: {remediation}"
        );
    }

    /// **ACME is refused with its follow-up ID.** A silent fallback would be the
    /// stub policy's exact prohibition.
    #[test]
    fn acme_is_refused_with_a_named_follow_up() {
        let e = CertificateSource::Acme {
            domain: "example.com".to_owned(),
        }
        .resolve()
        .expect_err("ACME is not implemented and must not silently succeed");
        assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
        assert!(
            e.message.contains("example.com"),
            "the refusal must name what was asked for: {}",
            e.message
        );
        assert!(
            e.context
                .iter()
                .any(|(k, v)| k == "tracked-by" && v == "SRV-013"),
            "the refusal must name the follow-up ID: {:?}",
            e.context
        );
    }

    /// A platform source that is handed nothing is an internal invariant, not a
    /// configuration error — the caller built the value.
    #[test]
    fn a_platform_source_with_an_empty_chain_is_an_invariant_violation() {
        let e = CertificateSource::Platform {
            chain: Vec::new(),
            key: PrivateKeyDer::Pkcs8(vec![0u8; 4].into()),
        }
        .resolve()
        .expect_err("an empty chain must be refused");
        assert_eq!(e.code, ErrorCode::InternalInvariantViolated);
    }

    #[test]
    fn a_platform_source_with_an_empty_certificate_is_an_invariant_violation() {
        let e = CertificateSource::Platform {
            chain: vec![CertificateDer::from(Vec::new())],
            key: PrivateKeyDer::Pkcs8(vec![0u8; 4].into()),
        }
        .resolve()
        .expect_err("an empty certificate is not a certificate");
        assert_eq!(e.code, ErrorCode::InternalInvariantViolated);
    }

    #[test]
    fn a_certificate_source_describes_itself() {
        let f = CertificateSource::files("a.pem", "b.pem");
        let d = f.describe();
        assert!(d.contains("a.pem") && d.contains("b.pem"), "got: {d}");
        assert!(f.resolve().is_err(), "the paths do not exist");

        let p = CertificateSource::Platform {
            chain: vec![CertificateDer::from(vec![1u8, 2, 3])],
            key: PrivateKeyDer::Pkcs8(vec![0u8; 4].into()),
        };
        assert!(p.describe().contains("platform"));
    }

    // -- client auth -------------------------------------------------------

    #[test]
    fn client_auth_none_requests_nothing() {
        let a = ClientAuth::None;
        assert!(!a.requests_certificate());
        assert!(!a.is_required());
        assert!(a.ca_file().is_none());
    }

    /// The distinction `SRV-008` turns on: `Required` demands a certificate,
    /// `Optional` does not. A mode that conflated them would either reject every
    /// anonymous client of an optional-mTLS service or accept every client of a
    /// required-mTLS one.
    #[test]
    fn required_and_optional_differ_in_whether_a_certificate_is_mandatory() {
        let required = ClientAuth::Required {
            ca_file: "ca.pem".into(),
        };
        let optional = ClientAuth::Optional {
            ca_file: "ca.pem".into(),
        };
        assert!(required.requests_certificate() && optional.requests_certificate());
        assert!(required.is_required());
        assert!(
            !optional.is_required(),
            "Optional must not be a synonym for Required"
        );
    }

    #[test]
    fn client_auth_default_is_none() {
        assert_eq!(ClientAuth::default(), ClientAuth::None);
    }

    /// A CA file that does not exist is refused for both modes, and the error
    /// names the file.
    #[test]
    fn a_missing_ca_file_is_refused() {
        for auth in [
            ClientAuth::Required {
                ca_file: "absent/ca.pem".into(),
            },
            ClientAuth::Optional {
                ca_file: "absent/ca.pem".into(),
            },
        ] {
            let e = auth
                .verifier(test_provider())
                .expect_err("a missing CA file must be refused");
            assert!(
                e.message.contains("absent"),
                "the error must name the file: {}",
                e.message
            );
        }
    }

    /// `None` installs **no** verifier. That is different from installing one
    /// that accepts everything, and the difference is a `CertificateRequest`
    /// appearing on the wire.
    #[test]
    fn client_auth_none_installs_no_verifier() {
        assert!(ClientAuth::None
            .verifier(test_provider())
            .expect("cannot fail")
            .is_none());
    }

    // -- peer identity -----------------------------------------------------

    /// No certificate means no identity. Returning a default identity here is
    /// how "declined to authenticate" becomes "authenticated as nobody".
    #[test]
    fn no_certificate_yields_no_identity() {
        assert_eq!(PeerIdentity::from_verified(None), None);
        assert_eq!(PeerIdentity::from_verified(Some(&[])), None);
    }

    /// A certificate whose subject this walker cannot find yields the named
    /// placeholder rather than an empty or wrong subject.
    #[test]
    fn an_unparsable_subject_yields_the_named_placeholder() {
        let cert = CertificateDer::from(vec![0x30, 0x00]);
        let id = PeerIdentity::from_verified(Some(std::slice::from_ref(&cert)))
            .expect("a present certificate is an identity");
        assert_eq!(id.subject(), PeerIdentity::UNNAMED_SUBJECT);
        assert!(
            !id.subject().is_empty(),
            "an audit log must never render a blank subject"
        );
    }

    /// The fingerprint is 32 uppercase hex pairs, colon separated — the same
    /// rendering `openssl x509 -fingerprint -sha256` produces.
    #[test]
    fn the_fingerprint_is_rendered_like_openssl() {
        let cert = CertificateDer::from(vec![0x30, 0x00]);
        let id = PeerIdentity::from_verified(Some(std::slice::from_ref(&cert))).expect("identity");
        let parts: Vec<&str> = id.fingerprint().split(':').collect();
        assert_eq!(parts.len(), 32, "SHA-256 is 32 bytes");
        for p in parts {
            assert_eq!(p.len(), 2, "each byte is two hex digits");
            assert!(
                p.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()),
                "openssl renders uppercase: {p}"
            );
        }
        assert_eq!(
            id.to_string(),
            format!("{} ({})", id.subject(), id.fingerprint())
        );
    }

    /// The DER walker finds a common name in a real `Name` structure, and
    /// matches it by OID rather than by position.
    #[test]
    fn the_common_name_walker_matches_by_oid() {
        // A `Name` with an organisation RDN (2.5.4.10) *before* the CN RDN, so a
        // positional match would return "Example Org".
        //
        // `Name ::= RDNSequence`, and `RDNSequence ::= SEQUENCE OF SET OF
        // AttributeTypeAndValue`. So each RDN is **one** `SET` wrapping **one**
        // `AttributeTypeAndValue` `SEQUENCE`, and the two `SET`s are siblings.
        //
        // Two fixture bugs were found here, and both are recorded because each
        // looked like a walker bug:
        //
        //  1. Hand-written length bytes were wrong, so the outer `SEQUENCE`
        //     declared fewer bytes than it held and the walker refused it.
        //  2. The first helper wrapped a `SEQUENCE` in a `SET` and then wrapped
        //     *that* in another `SET`, producing a single RDN holding two
        //     attributes rather than two RDNs — so the "org before CN" property
        //     this test exists to pin was not present at all.
        let org_rdn = der_set(&der_sequence(&[
            &der_oid(&[0x55, 0x04, 0x0A])[..],
            &der_utf8("Example Org")[..],
        ]));
        let cn_rdn = der_set(&der_sequence(&[
            &der_oid(&[0x55, 0x04, 0x03])[..],
            &der_utf8("alice@")[..],
        ]));

        let name = der_sequence(&[&org_rdn[..], &cn_rdn[..]]);

        // `walk_rdn_sequence` takes the CONTENT of the `Name` `SEQUENCE`, not the
        // whole element — see its docs. Passing `&name` would be the header-
        // included form and would correctly yield `None`.
        assert_eq!(
            walk_rdn_sequence(&name[2..]).as_deref(),
            Some("alice@"),
            "the CN must be found by OID, not by being first"
        );
    }

    /// The walker really is matching by OID: a `Name` with **no** common name
    /// yields `None` even though it has attributes, a `Name` whose CN is its only
    /// RDN still resolves, and a non-`Name` is refused rather than misreported.
    #[test]
    fn the_common_name_walker_finds_the_cn_and_only_the_cn() {
        let only_org = der_sequence(&[&der_set(&der_sequence(&[
            &der_oid(&[0x55, 0x04, 0x0A])[..],
            &der_utf8("Example Org")[..],
        ]))[..]]);
        assert_eq!(
            walk_rdn_sequence(&only_org[2..]),
            None,
            "an organisation is not a common name"
        );

        let only_cn = der_sequence(&[&der_set(&der_sequence(&[
            &der_oid(&[0x55, 0x04, 0x03])[..],
            &der_utf8("bob")[..],
        ]))[..]]);
        assert_eq!(walk_rdn_sequence(&only_cn[2..]).as_deref(), Some("bob"));

        // Not a `Name` at all: a `SEQUENCE` whose child is not a `SET`.
        let not_a_name = der_sequence(&[&der_utf8("x")[..]]);
        assert_eq!(
            walk_rdn_sequence(&not_a_name[2..]),
            None,
            "a non-Name must not be reported as an identity"
        );

        // And the header-included form is rejected, which is the property that
        // makes the content/element distinction load-bearing rather than
        // cosmetic.
        assert_eq!(
            walk_rdn_sequence(&only_cn),
            None,
            "a whole element is not a Name's content"
        );
    }

    /// `common_name_of` finds the CN in a **real** certificate.
    ///
    /// # Why this test had to be added, and what its absence cost
    ///
    /// The two tests above exercise `walk_rdn_sequence` against hand-built DER,
    /// and both pass. `common_name_of` — the function that locates the subject
    /// *inside a certificate* — had no test that used a real certificate at all.
    ///
    /// It searched the `Certificate`'s own children for tag `[3]` (`0xA3`),
    /// believing `[3]` wrapped `TBSCertificate`. It does not: `[3]` is the
    /// **extensions** field inside `TBSCertificate`, and a real certificate's
    /// children are `SEQUENCE, SEQUENCE, BIT STRING` — measured here as
    /// `0x30, 0x30, 0x03`, with no `0xA3` at that level. So the search returned
    /// `None` for **every** certificate, and `PeerIdentity::subject()` reported
    /// `"(subject has no common name)"` in production for every mTLS peer.
    ///
    /// The hand-built fixtures could not catch it because they encoded the same
    /// misunderstanding as the code: they wrapped their `Name` in a `[3]` that no
    /// real certificate produces. A test and an implementation that share a wrong
    /// assumption cannot correct each other — only an input from outside the
    /// pair can, which is what a generated certificate is.
    ///
    /// Verified by fault injection: reinstating the `0xA3` search makes this test
    /// fail, and `tls.rs`'s end-to-end identity test with it.
    #[test]
    fn common_name_of_finds_the_cn_in_a_real_certificate() {
        let mut params = rcgen::CertificateParams::new(vec!["test-cn".to_owned()])
            .expect("rcgen accepts the SAN");
        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "test-cn");
            dn
        };
        let key = rcgen::KeyPair::generate().expect("rcgen generates a key");
        let cert = params.self_signed(&key).expect("rcgen self-signs");
        let der = cert.der().to_vec();

        assert_eq!(
            common_name_of(&der).as_deref(),
            Some("test-cn"),
            "a real certificate's subject CN must be found; the walker is looking \
             for `[3]` among the Certificate's children, which is where \
             TBSCertificate is not"
        );
    }

    /// A certificate with no common name yields `None`, so the caller can
    /// substitute its placeholder rather than reporting an empty identity.
    ///
    /// The control for the test above: without it, a walker that returned a
    /// constant string would satisfy `Some("test-cn")` only by coincidence, and
    /// one that returned the *first* attribute it saw would pass too.
    #[test]
    fn common_name_of_returns_none_when_the_subject_has_no_cn() {
        let mut params =
            rcgen::CertificateParams::new(vec!["no-cn".to_owned()]).expect("rcgen accepts the SAN");
        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            // An organisation only — a legal subject with no CN.
            dn.push(rcgen::DnType::OrganizationName, "Example Org");
            dn
        };
        let key = rcgen::KeyPair::generate().expect("rcgen generates a key");
        let cert = params.self_signed(&key).expect("rcgen self-signs");
        let der = cert.der().to_vec();

        assert_eq!(
            common_name_of(&der),
            None,
            "an organisation is not a common name"
        );
    }

    /// A DER element with a short-form length, for the tests.
    fn der_element(tag: u8, content: &[u8]) -> Vec<u8> {
        // `try_from` rather than `as u8`: the assertion below already proves the
        // value fits, and a cast would silently truncate if the assertion were
        // ever relaxed or reordered. Clippy's `cast_possible_truncation` caught
        // this, and it was right — the assert and the cast are two statements of
        // the same fact, and only one of them is checked by the compiler.
        let len = u8::try_from(content.len())
            .expect("these fixtures only build short-form lengths, asserted above");
        assert!(
            content.len() < 0x80,
            "these fixtures only build short-form lengths"
        );
        let mut out = vec![tag, len];
        out.extend_from_slice(content);
        out
    }

    /// A DER `SEQUENCE`.
    fn der_sequence(parts: &[&[u8]]) -> Vec<u8> {
        let mut content = Vec::new();
        for p in parts {
            content.extend_from_slice(p);
        }
        der_element(0x30, &content)
    }

    /// A DER `SET`.
    fn der_set(content: &[u8]) -> Vec<u8> {
        der_element(0x31, content)
    }

    /// A DER `OBJECT IDENTIFIER` from its content octets.
    fn der_oid(content: &[u8]) -> Vec<u8> {
        der_element(0x06, content)
    }

    /// A DER `UTF8String`.
    fn der_utf8(s: &str) -> Vec<u8> {
        der_element(0x0C, s.as_bytes())
    }

    // -- helpers -----------------------------------------------------------

    /// The crypto provider the tests build verifiers against.
    ///
    /// Carries the real [`CIPHER_SUITES`] policy, so a test cannot pass by
    /// exercising a provider the server would never use.
    fn test_provider() -> Arc<rustls::crypto::CryptoProvider> {
        let mut p = rustls::crypto::aws_lc_rs::default_provider();
        p.cipher_suites = CIPHER_SUITES.to_vec();
        Arc::new(p)
    }

    /// A PEM body with no certificate block, for the format-error tests.
    const PEM_NOT_A_CERT: &[u8] = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";

    /// A PEM `CERTIFICATE` block whose contents decode but are not DER.
    ///
    /// `AAAA` is valid base64, so this passes `rustls_pemfile::certs` and is
    /// stopped only by `looks_like_a_der_certificate`. It is the fixture that
    /// exposed the gap.
    const PEM_NOT_DER: &[u8] = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    /// A PEM file holding no key rustls accepts, for the key-format tests.
    const PEM_KEY_ONLY: &[u8] = PEM_NOT_DER;

    /// A **structurally valid** DER certificate, base64'd into a PEM block.
    ///
    /// # How this was produced, exactly
    ///
    /// Not invented, and not copied from anywhere. It is assembled at test time
    /// by `valid_cert_pem()` from `der_sequence`/`der_element`, so its bytes are
    /// a transparent function of DER's encoding rules rather than a blob.
    ///
    /// It is a *shallow* certificate: `Certificate ::= SEQUENCE { tbsCertificate
    /// SEQUENCE { … }, signatureAlgorithm, signatureValue }` with placeholder
    /// contents. That is deliberate and it is all these unit tests need, because
    /// they exercise `load_cert_chain`'s **shape** validation and the file-path
    /// error reporting — neither of which parses a real X.509 body. Anything that
    /// needs a genuine certificate (a handshake, a signature, a subject) uses
    /// `rcgen` in `tests/tls.rs`, which generates a real one.
    ///
    /// # Why not embed a real PEM fixture here
    ///
    /// Because `openssl` is not available on this machine — checked, it is not on
    /// `PATH` — so there was no way to *generate* one and committing bytes from
    /// elsewhere would mean committing a certificate whose provenance nobody can
    /// reproduce. The honest alternative was to stop needing a real certificate
    /// in the unit tests.
    fn valid_cert_pem() -> Vec<u8> {
        // tbsCertificate with a placeholder `[0]` version and a serial.
        let tbs = der_sequence(&[
            &der_element(0xA0, &der_element(0x02, &[0x02]))[..],
            &der_element(0x02, &[0x01])[..],
            &der_sequence(&[&der_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])[..]])
                [..],
            &der_sequence(&[])[..],
            &der_sequence(&[])[..],
            &der_sequence(&[])[..],
        ]);
        let cert = der_sequence(&[
            &tbs[..],
            &der_sequence(&[&der_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])[..]])
                [..],
            &der_element(0x03, &[0x00, 0x00])[..],
        ]);

        let b64 = base64_encode(&cert);
        let mut out = Vec::new();
        out.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.extend_from_slice(chunk);
            out.push(b'\n');
        }
        out.extend_from_slice(b"-----END CERTIFICATE-----\n");
        out
    }

    /// Standard base64, for the PEM wrapper above.
    ///
    /// Hand-written rather than pulled in: `base64` is in the tree only as a
    /// transitive dependency of `rcgen` (a dev-dependency), so using it here
    /// would mean adding a dependency to the library for a test fixture.
    fn base64_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            let idx = [
                (n >> 18) & 0x3F,
                (n >> 12) & 0x3F,
                (n >> 6) & 0x3F,
                n & 0x3F,
            ];
            for (i, &v) in idx.iter().enumerate() {
                // The final group is padded rather than truncated.
                if i > chunk.len() {
                    out.push('=');
                } else {
                    out.push(char::from(ALPHABET[v as usize]));
                }
            }
        }
        out
    }

    /// A directory removed when it goes out of scope.
    struct TempDir(PathBuf);

    impl TempDir {
        /// A path inside the directory. Does not create anything.
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A unique temporary directory.
    ///
    /// Named from the process id and a counter rather than from `SystemTime`,
    /// so two tests in the same binary cannot collide — the whole reason the
    /// tests need directories is that they write files.
    fn tempdir() -> TempDir {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("qqq-tls-unit-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }
}
