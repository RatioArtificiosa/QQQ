//! TLS and mTLS, driven by **real handshakes** in process.
//!
//! Implements the test half of `SRV-007`, `SRV-008` and `SEC-017`; Proposal §6.4
//! and §7.4.
//!
//! # Why these tests perform handshakes rather than assert on a config
//!
//! `src/tls.rs`'s unit tests assert on the *configuration*: that the version list
//! is ordered 1.3-first, that no suite uses RSA key transport, that an
//! unspecified field is refused. Those are necessary and they are not sufficient.
//!
//! A `ServerConfig` can be built correctly and still negotiate something else,
//! because negotiation is a *joint* outcome — the client contributes a version
//! list, a suite list and an ALPN list, and rustls picks the intersection. A test
//! that only inspects the server's own config cannot see a client dragging the
//! connection down to a version or a suite the server meant to exclude.
//!
//! So every assertion below is made on the result of an actual handshake between
//! a real `rustls` server connection and a real `rustls` client connection over
//! an in-memory duplex pipe. That is the only way to observe what was negotiated
//! rather than what was offered.
//!
//! # How the pipe works, and why not a socket
//!
//! `tokio::io::duplex` gives two connected ends over a channel. Neither is a
//! `TcpListener` or a `TcpStream`, so nothing here binds a port, races another
//! test for one, or depends on the host's networking. `tokio-rustls` is generic
//! over `AsyncRead + AsyncWrite`, so a duplex half is a perfectly good transport
//! — and the TLS layer cannot tell the difference, which is the point: this
//! exercises the real handshake state machine, not a mock of it.
//!
//! # The certificates are generated, not committed
//!
//! Every certificate here comes from `rcgen` (`docs.rs/rcgen`), generated inside
//! the test that uses it. Nothing is checked in under `tests/fixtures/`, so there
//! is no question of where a byte came from and no expired fixture to discover
//! later. `CA_MARKER` and `CLIENT_CN` name the values the assertions match on.
//!
//! `rcgen` 0.14.10 is a **dev-dependency**, which is why it does not appear in
//! the library's dependency list: the library never generates a certificate, it
//! only loads one.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::AsyncWriteExt;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use qqq_core::ErrorCode;
use qqq_serve::tls::{
    CertificateSource, ClientAuth, Negotiated, PeerIdentity, ResolvedCertificate, TlsConfig,
    ALPN_H2, ALPN_HTTP11, CIPHER_SUITES, PROTOCOL_VERSIONS,
};

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// The common name the generated server certificate carries.
const SERVER_CN: &str = "qqq-test-server";

/// The common name the generated client certificate carries.
///
/// `PeerIdentity` extraction is asserted against this value.
const CLIENT_CN: &str = "qqq-test-client";

/// A generated certificate and its key, written to disk as PEM.
///
/// The files are real files read by the real loader, because the code path under
/// test is "load a PEM chain and key from a path" — handing `TlsConfig` in-memory
/// DER would skip the parsing, the format detection and the error reporting that
/// `SRV-007` is mostly about.
struct CertFiles {
    dir: tempdir::TempDir,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

impl CertFiles {
    /// Generate a self-signed certificate with `rcgen` and write it as PEM.
    ///
    /// # The subject, and a comment that was wrong
    ///
    /// This used to call `generate_simple_self_signed(vec![cn])` and assert in a
    /// comment that *"rcgen sets the subject's common name from the first SAN"*.
    /// It does not. Measured: the resulting certificate's subject common name is
    /// rcgen's default, **`"rcgen self signed cert"`**, whatever `cn` is passed —
    /// so `PeerIdentity::subject()` returned that string, and the mTLS identity
    /// test failed comparing it against `CLIENT_CN`.
    ///
    /// The comment was the defect. It stated rcgen's behaviour confidently and
    /// wrongly, so nobody checked, and the test that would have caught the
    /// *code's* DN walker was blocked by the fixture's own wrong subject.
    ///
    /// The distinguished name is now set explicitly, which is both what the test
    /// needs and what a real certificate does — a certificate's subject is not
    /// derived from its SANs.
    fn generate(cn: &str) -> Self {
        let mut params =
            rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("rcgen must accept the SAN");
        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, cn);
            dn
        };
        let key = rcgen::KeyPair::generate().expect("rcgen must generate a key");
        let cert = params
            .self_signed(&key)
            .expect("rcgen must self-sign with the generated key");

        let dir = tempdir::TempDir::new();
        // `pem()` and `serialize_pem()` are the documented rcgen PEM outputs.
        // The key is PKCS#8, which is one of the three formats
        // `load_private_key` accepts — the PKCS#1 and SEC1 paths are covered by
        // the unit tests' format handling rather than by a second generated key.
        let cert_path = dir.write("cert.pem", cert.pem().as_bytes());
        let key_path = dir.write("key.pem", key.serialize_pem().as_bytes());
        Self {
            dir,
            cert: cert_path,
            key: key_path,
        }
    }

    /// The source `TlsConfig` reads.
    fn source(&self) -> CertificateSource {
        CertificateSource::files(self.cert.clone(), self.key.clone())
    }

    /// The DER of the certificate, for building a client's root store.
    fn cert_der(&self) -> CertificateDer<'static> {
        let pem = std::fs::read_to_string(&self.cert).expect("read cert");
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(pem.into_bytes()));
        // Collected inside the reader's scope: `certs` returns an iterator that
        // borrows the reader, so returning `next()`'s item straight out of this
        // function does not outlive it. The items themselves are `'static`
        // (`CertificateDer<'static>`), which is why collecting first works.
        let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("valid PEM");
        chain.into_iter().next().expect("one certificate")
    }

    /// The directory, kept alive so the files outlive the test.
    fn dir(&self) -> &std::path::Path {
        self.dir.path()
    }

    /// The path of the written private key file.
    ///
    /// Needed by the tests that pair a *valid* key with a deliberately broken
    /// certificate, so the failure they assert on is the one they name. Without
    /// it those tests write junk into the key slot as well, and the key loader
    /// reports first — which is correct behaviour and makes the assertion wrong.
    fn key_path(&self) -> &std::path::Path {
        &self.key
    }
}

// ---------------------------------------------------------------------------
// Handshaking
// ---------------------------------------------------------------------------

/// What a completed handshake produced.
struct Handshake {
    /// The server's view of what was negotiated.
    negotiated: Negotiated,
    /// The verified peer identity, when the client presented a certificate.
    peer: Option<PeerIdentity>,
    /// The server's negotiated ALPN protocol, raw.
    alpn: Option<Vec<u8>>,
    /// Why there is no negotiated session, when there is none.
    ///
    /// Several tests assert that a handshake is **refused** — an untrusted
    /// client under `Required`, a version policy that excludes the client's only
    /// version. Those tests need the reason, not just the fact: `"none"` for the
    /// version and the suite says only that nothing happened, and the first draft
    /// of this helper turned every failure into exactly that opaque value and
    /// made nine tests unreadable.
    ///
    /// `None` on a successful handshake.
    failure: Option<String>,
}

impl Handshake {
    /// A handshake that produced no session, carrying the server's reason.
    fn failed(reason: String) -> Self {
        Self {
            // `"none"` rather than a fabricated version: claiming a version for a
            // handshake that did not happen is precisely the plausible-wrong
            // value this project keeps recording.
            negotiated: Negotiated {
                version: "none".to_owned(),
                cipher_suite: "none".to_owned(),
                alpn: None,
            },
            peer: None,
            alpn: None,
            failure: Some(reason),
        }
    }

    /// Attach the client's error, when it reported one.
    ///
    /// Both sides are recorded because a failed handshake has two reports and
    /// which one is informative varies by test: a server rejecting an untrusted
    /// client says so from the server side, while a version mismatch is often
    /// clearer from the client.
    fn with_client_error(mut self, client_error: Option<String>) -> Self {
        if let Some(e) = client_error {
            let existing = self.failure.take();
            self.failure = Some(match existing {
                Some(server) => format!("{server}; the client reported: {e}"),
                None => format!("the client reported: {e} (the server side completed)"),
            });
        }
        self
    }

    /// Whether a session was established at all.
    fn connected(&self) -> bool {
        self.failure.is_none()
    }

    /// The reason there is no session, or a note that there is one.
    ///
    /// For assertion messages: `assert!(h.connected(), "{}", h.why())` explains a
    /// failure without the author guessing which half broke.
    fn why(&self) -> String {
        match &self.failure {
            Some(f) => f.clone(),
            None => format!("a session was established ({})", self.negotiated.version),
        }
    }
}

/// Drive a full handshake over an in-memory pipe.
///
/// # Why this returns a value rather than asserting
///
/// So each test asserts on the one property it is named for. A helper that
/// asserted internally would make a failure report the helper's line rather than
/// the property, and this module's whole purpose is to name properties.
///
/// # Why `TlsStream` rather than driving `complete_io` by hand
///
/// `tokio-rustls` owns the read/write loop that a handshake needs over an
/// asynchronous transport. Re-implementing it here would mean testing a hand
/// rolled handshake driver rather than the configuration, and the thing under
/// test is the configuration.
async fn handshake(server: Arc<rustls::ServerConfig>, client: Arc<ClientConfig>) -> Handshake {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let acceptor = TlsAcceptor::from(server);
    let connector = TlsConnector::from(client);

    // The server side: accept, and report whether it succeeded. The error is
    // carried out rather than unwrapped so a *rejected* handshake — which several
    // tests below assert on — is an ordinary value.
    let server_task = tokio::spawn(async move {
        let stream = acceptor.accept(server_io).await?;
        let (_, conn) = stream.get_ref();
        let negotiated = Negotiated::of(conn);
        let peer = PeerIdentity::from_verified(conn.peer_certificates());
        let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
        Ok::<_, std::io::Error>((negotiated, peer, alpn))
    });

    // The name the **client** verifies the server's certificate against, and it
    // must be the name the certificate actually carries.
    //
    // This read `"localhost"` while the generated certificate was issued for
    // `SERVER_CN` (`"qqq-test-server"`), so every handshake that was supposed to
    // succeed was refused with:
    //
    //   received fatal alert: BadCertificate
    //   invalid peer certificate: certificate not valid for name "localhost";
    //   certificate is only valid for DnsName("qqq-test-server")
    //
    // Nine tests failed and all nine reported the same opaque
    // `left: None, right: Some(...)` on ALPN or version — because the helper
    // discarded the reason. Naming the cause was what turned one defect into one
    // readable line, and using `SERVER_CN` here is what removes it: the client
    // asks for the name the certificate is for, which is what a real client does
    // by asking for the host it dialled.
    let server_name =
        ServerName::try_from(SERVER_CN).expect("the generated certificate's name must be valid");
    let client_result = connector.connect(server_name, client_io).await;

    // A handshake is *supposed* to fail in several tests, so the client error is
    // not propagated — but it is **recorded**, because silently discarding it is
    // how this helper's own first draft turned every failure into the same
    // opaque `"none"` and made nine tests unreadable.
    let client_error = match client_result {
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    };

    match tokio::time::timeout(Duration::from_secs(10), server_task).await {
        Ok(Ok(Ok((negotiated, peer, alpn)))) => Handshake {
            negotiated,
            peer,
            alpn,
            failure: None,
        },
        Ok(Ok(Err(server_error))) => {
            Handshake::failed(format!("the server rejected the handshake: {server_error}"))
        }
        // The task was cancelled or panicked.
        Ok(Err(join_error)) => {
            Handshake::failed(format!("the server task did not complete: {join_error}"))
        }
        // A timeout is a **test-harness** failure, not a refused handshake: the
        // two sides deadlocked rather than one rejecting the other. Reported as
        // `failed` rather than panicking, so the caller's assertion produces its
        // own message instead of this line's — but the reason names the timeout
        // distinctly, so the two are never confused.
        Err(elapsed) => Handshake::failed(format!(
            "the handshake neither completed nor was refused within the deadline: {elapsed}"
        )),
    }
    .with_client_error(client_error)
}

/// The reason a handshake produced no session, for assertion messages.
///
/// Used by the tests that assert a handshake *succeeds*: when one of those
/// fails, `left: None, right: Some([104, 50])` says only that ALPN was absent,
/// which is equally consistent with a rejected certificate, a version mismatch
/// and a client that never offered the protocol. Naming the cause turns nine
/// look-alike failures into one readable line.
macro_rules! assert_connected {
    ($h:expr) => {
        assert!(
            $h.connected(),
            "the handshake did not complete: {}",
            $h.why()
        )
    };
}

/// A client configuration that trusts `roots` and offers the given ALPN list.
fn client_config(
    roots: RootCertStore,
    alpn: &[&[u8]],
    versions: &'static [&'static rustls::SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // The *client* offers the same suite policy the server does, so a successful
    // mutual choice is possible; where a test wants a narrower client it passes
    // its own list through `client_config_with_suites`.
    provider.cipher_suites = CIPHER_SUITES.to_vec();

    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .expect("versions and suites are compatible");
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| (*p).to_vec()).collect();
    Arc::new(config)
}

/// A client configuration presenting `client_cert` as its client certificate.
fn client_config_with_identity(
    roots: RootCertStore,
    client_cert: &CertFiles,
    versions: &'static [&'static rustls::SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = CIPHER_SUITES.to_vec();

    let chain: Vec<CertificateDer<'static>> = {
        let pem = std::fs::read_to_string(&client_cert.cert).expect("read client cert");
        let mut r = std::io::BufReader::new(pem.as_bytes());
        rustls_pemfile::certs(&mut r)
            .collect::<Result<Vec<_>, _>>()
            .expect("client cert PEM")
    };
    let key: PrivateKeyDer<'static> = {
        let pem = std::fs::read_to_string(&client_cert.key).expect("read client key");
        let mut r = std::io::BufReader::new(pem.as_bytes());
        rustls_pemfile::private_key(&mut r)
            .expect("valid PEM")
            .expect("a key")
    };

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .expect("compatible")
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .expect("the client certificate must be installable");
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Arc::new(config)
}

/// A root store trusting exactly `cert`.
fn roots_trusting(cert: CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(cert)
        .expect("the generated cert must be a valid CA");
    roots
}

/// The default client version list, for tests that are not about versions.
const CLIENT_VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// TLS 1.3 only, for the version-floor tests.
///
/// Named constants rather than inline slices: `TlsConfig::versions` is
/// `&'static`, and a slice literal in an expression position is a temporary that
/// does not live long enough — the compiler rejected the inline form in this
/// file's first draft.
const ONLY_TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// TLS 1.2 only, for the version-floor tests.
const ONLY_TLS12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

// ---------------------------------------------------------------------------
// SRV-007 — a valid configuration builds and negotiates
// ---------------------------------------------------------------------------

/// **The baseline.** A generated certificate loads from files and a real client
/// completes a handshake, and what was negotiated is what the policy named.
///
/// If this fails, every other test in this module is measuring something other
/// than a working TLS endpoint.
#[tokio::test]
async fn a_valid_certificate_builds_and_a_real_client_negotiates() {
    let cert = CertFiles::generate(SERVER_CN);
    let config = TlsConfig::new(cert.source())
        .with_alpn(&[ALPN_HTTP11])
        .build()
        .expect("a valid certificate must build");

    let handshake = handshake(
        config,
        client_config(
            roots_trusting(cert.cert_der()),
            &[ALPN_HTTP11],
            CLIENT_VERSIONS,
        ),
    )
    .await;
    assert_connected!(handshake);

    assert_eq!(
        handshake.negotiated.version, "TLSv1.3",
        "TLS 1.3 is preferred and both ends offer it, so it must be chosen"
    );
    assert_eq!(
        handshake.alpn.as_deref(),
        Some(ALPN_HTTP11),
        "the client offered http/1.1 and the server advertises it"
    );
    assert!(
        handshake.negotiated.cipher_suite.starts_with("TLS13_"),
        "the suite must be one the policy named: {}",
        handshake.negotiated.cipher_suite
    );
    assert_eq!(handshake.negotiated.http_version(), "HTTP/1.1");
}

/// The negotiated cipher is a member of the documented policy — asserted against
/// the constant rather than a hard-coded name, so adding a suite to
/// [`CIPHER_SUITES`] does not break the test but removing the negotiated one does.
#[tokio::test]
async fn the_negotiated_cipher_is_one_the_policy_named() {
    let cert = CertFiles::generate(SERVER_CN);
    let config = TlsConfig::new(cert.source()).build().expect("builds");

    let handshake = handshake(
        config,
        client_config(roots_trusting(cert.cert_der()), &[], CLIENT_VERSIONS),
    )
    .await;
    assert_connected!(handshake);

    let legal: Vec<String> = CIPHER_SUITES
        .iter()
        .map(|s| format!("{:?}", s.suite()))
        .collect();
    assert!(
        legal.contains(&handshake.negotiated.cipher_suite),
        "negotiated {} is not in the policy {legal:?}",
        handshake.negotiated.cipher_suite
    );
}

// ---------------------------------------------------------------------------
// SRV-007 — the version policy
// ---------------------------------------------------------------------------

/// **The version policy actually refuses TLS 1.1 at the handshake.**
///
/// The unit test asserts 1.1 is absent from [`PROTOCOL_VERSIONS`]. This asserts
/// the *consequence*: a client restricted to 1.1 cannot establish a session.
///
/// rustls 0.23 cannot represent TLS 1.1 on either side, so the client here is
/// restricted to the oldest version the library *can* express — TLS 1.2 — and the
/// server is restricted to 1.3. That proves the version list is load-bearing in
/// negotiation rather than merely declared, which is the property that would
/// survive a library swap to one that *can* express 1.1.
#[tokio::test]
async fn a_client_below_the_version_floor_cannot_connect() {
    let cert = CertFiles::generate(SERVER_CN);

    // Server: TLS 1.3 only.
    let mut server_tls = TlsConfig::new(cert.source());
    server_tls.versions = ONLY_TLS13;
    let config = server_tls.build().expect("builds");

    // Client: TLS 1.2 only.
    let handshake = handshake(
        config,
        client_config(roots_trusting(cert.cert_der()), &[], ONLY_TLS12),
    )
    .await;

    assert_eq!(
        handshake.negotiated.version, "none",
        "a server offering only 1.3 and a client offering only 1.2 have no version \
         in common, so no session may be established"
    );
}

/// TLS 1.2 is permitted, and is negotiated when it is the only thing both ends
/// share. §7.4 says "1.2 permitted"; this is what permitted means.
#[tokio::test]
async fn tls12_is_permitted_when_it_is_the_only_common_version() {
    let cert = CertFiles::generate(SERVER_CN);

    let mut server_tls = TlsConfig::new(cert.source());
    server_tls.versions = ONLY_TLS12;
    let config = server_tls.build().expect("builds");

    let handshake = handshake(
        config,
        client_config(roots_trusting(cert.cert_der()), &[], ONLY_TLS12),
    )
    .await;
    assert_connected!(handshake);

    assert_eq!(
        handshake.negotiated.version, "TLSv1.2",
        "1.2 must remain usable when it is the only version in common"
    );
    assert!(
        handshake.negotiated.cipher_suite.starts_with("TLS_ECDHE_"),
        "the 1.2 suite must be a forward-secret one from the policy: {}",
        handshake.negotiated.cipher_suite
    );
}

// ---------------------------------------------------------------------------
// SRV-007 — ALPN
// ---------------------------------------------------------------------------

/// **ALPN selection.** A client offering `h2` gets `h2`.
///
/// This is what allows HTTP/2 to be added later without changing the TLS layer.
#[tokio::test]
async fn a_client_offering_h2_gets_h2() {
    let cert = CertFiles::generate(SERVER_CN);
    let config = TlsConfig::new(cert.source())
        .with_alpn(&[ALPN_H2, ALPN_HTTP11])
        .build()
        .expect("builds");

    let handshake = handshake(
        config,
        client_config(
            roots_trusting(cert.cert_der()),
            &[ALPN_H2, ALPN_HTTP11],
            CLIENT_VERSIONS,
        ),
    )
    .await;
    assert_connected!(handshake);

    assert_eq!(
        handshake.alpn.as_deref(),
        Some(ALPN_H2),
        "h2 is first in the server's preference order, so it must win"
    );
    assert_eq!(handshake.negotiated.http_version(), "HTTP/2");
}

/// A client offering **only** `http/1.1` gets `http/1.1`, even though the server
/// would prefer `h2`. Negotiation is an intersection, not a dictation.
#[tokio::test]
async fn a_client_offering_only_http11_gets_http11() {
    let cert = CertFiles::generate(SERVER_CN);
    let config = TlsConfig::new(cert.source())
        .with_alpn(&[ALPN_H2, ALPN_HTTP11])
        .build()
        .expect("builds");

    let handshake = handshake(
        config,
        client_config(
            roots_trusting(cert.cert_der()),
            &[ALPN_HTTP11],
            CLIENT_VERSIONS,
        ),
    )
    .await;
    assert_connected!(handshake);

    assert_eq!(
        handshake.alpn.as_deref(),
        Some(ALPN_HTTP11),
        "a client that cannot speak h2 must be answered http/1.1"
    );
    assert_eq!(handshake.negotiated.http_version(), "HTTP/1.1");
}

/// **A client offering neither gets the documented outcome**: no ALPN protocol,
/// and HTTP/1.1 by RFC 9113 §3.1's default.
///
/// The distinction matters and is why `alpn` stays `None` rather than being
/// filled in: a caller can tell "we agreed on nothing" from "we agreed on
/// http/1.1" by reading the field, while `http_version()` gives the value the
/// server must actually speak.
#[tokio::test]
async fn a_client_offering_no_alpn_gets_no_protocol_but_speaks_http11() {
    let cert = CertFiles::generate(SERVER_CN);
    let config = TlsConfig::new(cert.source())
        .with_alpn(&[ALPN_H2, ALPN_HTTP11])
        .build()
        .expect("builds");

    let handshake = handshake(
        config,
        // No ALPN offered at all.
        client_config(roots_trusting(cert.cert_der()), &[], CLIENT_VERSIONS),
    )
    .await;
    assert_connected!(handshake);

    assert!(
        handshake.alpn.is_none(),
        "no client ALPN means no agreed protocol; got {:?}",
        handshake.alpn
    );
    assert_eq!(
        handshake.negotiated.http_version(),
        "HTTP/1.1",
        "RFC 9113 §3.1: without ALPN an HTTP/1.1 client speaks HTTP/1.1"
    );
}

/// A server configured with no ALPN at all negotiates none, even against a client
/// that offered some. This is the HTTP/1.1-only deployment.
#[tokio::test]
async fn a_server_with_no_alpn_sends_no_alpn_extension() {
    let cert = CertFiles::generate(SERVER_CN);
    let config = TlsConfig::new(cert.source())
        .with_alpn(&[])
        .build()
        .expect("builds");

    let handshake = handshake(
        config,
        client_config(
            roots_trusting(cert.cert_der()),
            &[ALPN_H2, ALPN_HTTP11],
            CLIENT_VERSIONS,
        ),
    )
    .await;
    assert_connected!(handshake);

    assert!(
        handshake.alpn.is_none(),
        "advertising nothing must not produce an agreed protocol"
    );
}

/// When the two ALPN lists do not intersect, the handshake is **refused**.
///
/// # The comment here was wrong, and the test asserted the wrong thing
///
/// This test was written asserting the opposite — that "the handshake still
/// succeeds — which is correct TLS and an application-level decision" — and it
/// failed with `left: "none", right: "TLSv1.3"`.
///
/// Measured behaviour, from the failure's own diagnostic: the server reports
/// `peer doesn't support any known protocol` and the client receives
/// `fatal alert: NoApplicationProtocol`. That is `rustls`'s documented
/// behaviour and it is **not** an implementation choice QQQ made: once a server
/// configures ALPN, an RFC 7301 server MUST fail the connection with
/// `no_application_protocol` when no protocol is acceptable. Continuing without
/// ALPN would be the bug, because the client would then speak h2 to a server
/// that agreed to nothing.
///
/// So the assertion is that the handshake is refused **and** that the refusal is
/// attributable to ALPN rather than to the certificate or version — otherwise
/// this test would pass for a configuration that rejects everything.
#[tokio::test]
async fn disjoint_alpn_lists_refuse_the_handshake() {
    let cert = CertFiles::generate(SERVER_CN);
    // The server advertises h2 only.
    let config = TlsConfig::new(cert.source())
        .with_alpn(&[ALPN_H2])
        .build()
        .expect("builds");

    let handshake = handshake(
        config,
        client_config(
            roots_trusting(cert.cert_der()),
            &[ALPN_HTTP11],
            CLIENT_VERSIONS,
        ),
    )
    .await;

    assert!(
        !handshake.connected(),
        "disjoint ALPN lists must not produce a session: {}",
        handshake.why()
    );

    // The refusal must be about ALPN. A rejection caused by the certificate or
    // the version would satisfy the assertion above while proving nothing about
    // ALPN, which is the same "assertion that cannot fail for its own reason"
    // trap recorded in `§O-046b`.
    let why = handshake.why().to_lowercase();
    assert!(
        why.contains("protocol") || why.contains("alpn"),
        "the refusal must name the protocol disagreement, not something else: {why}"
    );
}

// ---------------------------------------------------------------------------
// SRV-007 — failures are errors, not panics
// ---------------------------------------------------------------------------

/// A missing certificate file produces a specific error naming the file, and
/// does not panic. This is the `SRV-007` "refuses a configuration with no
/// certificates" requirement, observed end to end.
///
/// # Why the key here is a real, valid key
///
/// The fixture used to write `"not a key"` into the key path, so the *key*
/// loader failed first and reported the key file — while the assertion demanded
/// the certificate file be named. The test failed, and the code was right:
/// `CertificateSource::Files` loads the key first, deliberately, and its own
/// comment documents the tradeoff (with either order, one bad file masks the
/// other, because failing fast is preferable to collecting errors).
///
/// So this test now uses a **valid** key and only the certificate is missing,
/// which is what its name claims to exercise. The complementary case — a missing
/// key with a valid certificate — is `a_missing_key_file_names_the_key`, and the
/// two together cover both orders without either masking the other.
#[test]
fn a_missing_certificate_file_fails_with_a_specific_error() {
    let cert = CertFiles::generate(SERVER_CN);
    let config = TlsConfig::new(CertificateSource::Files {
        cert: cert.dir().join("absent-cert.pem"),
        // A real key, so the key loader cannot be the thing that fails.
        key: cert.key_path().to_path_buf(),
    });

    let e = config.build().expect_err("must be refused, not panic");
    assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
    assert!(
        e.message.contains("absent-cert.pem"),
        "the error must name the file: {}",
        e.message
    );
    assert!(e.remediation.is_some());
    // The rendered form is the product surface; it must not be empty.
    assert!(e.render().contains("error[QQQ-2002]"));
}

/// A certificate file containing a real key but no certificate is refused, with
/// the remediation naming the cert/key swap — through the public API, with real
/// generated material.
#[test]
fn a_key_in_the_certificate_slot_is_refused_end_to_end() {
    let generated = CertFiles::generate(SERVER_CN);
    let config = TlsConfig::new(CertificateSource::Files {
        cert: generated.key.clone(),
        key: generated.key.clone(),
    });

    let e = config.build().expect_err("a key is not a certificate");
    assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
    assert!(e.message.contains("no certificate"), "got: {}", e.message);
}

/// **ACME is refused end to end**, not silently substituted, and the error names
/// the follow-up checklist ID. This is the stub policy's requirement observed
/// through the public API.
#[test]
fn acme_is_refused_and_names_its_follow_up() {
    let config = TlsConfig::new(CertificateSource::Acme {
        domain: "example.com".to_owned(),
    });

    let e = config.build().expect_err("ACME must not silently succeed");
    assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
    assert!(e.message.contains("example.com"), "got: {}", e.message);
    assert!(
        e.context
            .iter()
            .any(|(k, v)| k == "tracked-by" && v == "SRV-013"),
        "the refusal must name the follow-up ID: {:?}",
        e.context
    );
}

/// A certificate and key that are not a pair are refused by rustls, and the
/// error says how to check — rather than producing a server that fails on the
/// first client.
#[test]
fn a_mismatched_certificate_and_key_are_refused() {
    let a = CertFiles::generate("first");
    let b = CertFiles::generate("second");
    let config = TlsConfig::new(CertificateSource::Files {
        cert: a.cert.clone(),
        key: b.key.clone(),
    });

    let e = config
        .build()
        .expect_err("a mismatched pair must be refused");
    assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
    let remediation = e.remediation.unwrap_or_default();
    assert!(
        remediation.contains("openssl"),
        "the remediation must name a way to compare them: {remediation}"
    );
}

// ---------------------------------------------------------------------------
// SRV-008 — mTLS
// ---------------------------------------------------------------------------

/// **The mTLS `Required` refusal.** A client presenting no certificate cannot
/// complete the handshake when the server requires one.
///
/// This is the security-relevant half of `SRV-008`: `Required` must actually
/// reject, not merely request.
#[tokio::test]
async fn required_client_auth_refuses_a_client_with_no_certificate() {
    let server_cert = CertFiles::generate(SERVER_CN);
    let ca = CertFiles::generate("qqq-test-ca");

    let config = TlsConfig::new(server_cert.source())
        .with_required_client_auth(ca.cert.clone())
        .build()
        .expect("builds");

    // The client trusts the server but presents **no** certificate.
    let handshake = handshake(
        config,
        client_config(roots_trusting(server_cert.cert_der()), &[], CLIENT_VERSIONS),
    )
    .await;

    assert_eq!(
        handshake.negotiated.version, "none",
        "a server requiring a client certificate must not complete a handshake \
         with a client that presents none"
    );
    assert!(
        handshake.peer.is_none(),
        "there must be no peer identity without a peer certificate"
    );
}

/// **[`ClientAuth::Optional`] accepts a client that presents no certificate**, and
/// the resulting connection has no peer identity — which is distinct from an
/// anonymous identity.
///
/// This is the assertion that stops `Optional` from being implemented as
/// `Required`, and the `peer.is_none()` half stops it from being implemented as
/// "accept anything and invent an identity".
#[tokio::test]
async fn optional_client_auth_accepts_a_client_with_no_certificate() {
    let server_cert = CertFiles::generate(SERVER_CN);
    let ca = CertFiles::generate("qqq-test-ca");

    let config = TlsConfig::new(server_cert.source())
        .with_optional_client_auth(ca.cert.clone())
        .build()
        .expect("builds");

    let handshake = handshake(
        config,
        client_config(roots_trusting(server_cert.cert_der()), &[], CLIENT_VERSIONS),
    )
    .await;
    assert_connected!(handshake);

    assert_eq!(
        handshake.negotiated.version, "TLSv1.3",
        "Optional must not reject a client that declines to authenticate"
    );
    assert!(
        handshake.peer.is_none(),
        "a client that presented nothing has no identity — and that is not the \
         same as an anonymous one"
    );
}

/// **`PeerIdentity` extraction from a real presented certificate.**
///
/// The client presents a certificate and the server reads its subject and
/// fingerprint back from the verified chain. This is the whole of `SRV-008`'s
/// identity half: the value a handler would use to attribute a request.
#[tokio::test]
async fn a_presented_client_certificate_yields_a_peer_identity() {
    let server_cert = CertFiles::generate(SERVER_CN);
    let client_cert = CertFiles::generate(CLIENT_CN);

    // The server trusts exactly the client's self-signed certificate, so the
    // chain verifies and the handshake completes.
    let config = TlsConfig::new(server_cert.source())
        .with_required_client_auth(client_cert.cert.clone())
        .build()
        .expect("builds");

    let handshake = handshake(
        config,
        client_config_with_identity(
            roots_trusting(server_cert.cert_der()),
            &client_cert,
            CLIENT_VERSIONS,
        ),
    )
    .await;
    assert_connected!(handshake);

    assert_eq!(
        handshake.negotiated.version, "TLSv1.3",
        "a client presenting a trusted certificate must connect"
    );

    let peer = handshake
        .peer
        .expect("a presented client certificate must produce an identity");
    assert_eq!(
        peer.subject(),
        CLIENT_CN,
        "the extracted subject must be the certificate's common name"
    );
    assert!(
        !peer.subject_der().is_empty(),
        "the leaf DER must be retained for a caller that needs structured fields"
    );

    // The fingerprint is the SHA-256 of the leaf, rendered like openssl.
    let parts: Vec<&str> = peer.fingerprint().split(':').collect();
    assert_eq!(parts.len(), 32, "SHA-256 is 32 bytes");
    // And it matches the certificate the client actually holds, which is what
    // makes the fingerprint an audit identifier rather than a decoration.
    let expected = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(client_cert.cert_der().as_ref());
        digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    assert_eq!(
        peer.fingerprint(),
        expected,
        "the fingerprint must be the SHA-256 of the presented certificate"
    );
}

/// A client certificate signed by a CA the server does **not** trust is refused
/// under `Required`, even though one is presented.
///
/// Without this, `Required` would only prove "a certificate was presented",
/// which an attacker can satisfy with any self-signed certificate.
#[tokio::test]
async fn required_client_auth_refuses_an_untrusted_client_certificate() {
    let server_cert = CertFiles::generate(SERVER_CN);
    let trusted_ca = CertFiles::generate("trusted-ca");
    let rogue = CertFiles::generate("rogue-client");

    let config = TlsConfig::new(server_cert.source())
        .with_required_client_auth(trusted_ca.cert.clone())
        .build()
        .expect("builds");

    let handshake = handshake(
        config,
        client_config_with_identity(
            roots_trusting(server_cert.cert_der()),
            &rogue,
            CLIENT_VERSIONS,
        ),
    )
    .await;

    assert_eq!(
        handshake.negotiated.version, "none",
        "a certificate that does not chain to the configured trust root must be \
         refused; otherwise `Required` only means 'presented something'"
    );
}

/// The verifier configuration distinguishes the two modes at the trait level,
/// which is the property `client_auth_mandatory` encodes. Asserted alongside the
/// handshake tests because a handshake can only show one mode at a time.
#[test]
fn the_two_client_auth_modes_differ_in_mandatory_status() {
    assert!(!ClientAuth::None.is_required());
    assert!(!ClientAuth::None.requests_certificate());
    assert!(ClientAuth::Required {
        ca_file: "ca.pem".into()
    }
    .is_required());
    assert!(!ClientAuth::Optional {
        ca_file: "ca.pem".into()
    }
    .is_required());
}

// ---------------------------------------------------------------------------
// SEC-017 — no silent defaults
// ---------------------------------------------------------------------------

/// An unspecified version or suite list is an error through the public API, not
/// a silent substitution. `SEC-017`'s "no silent defaults", observed.
#[test]
fn an_unspecified_policy_field_is_refused_not_defaulted() {
    let cert = CertFiles::generate(SERVER_CN);

    let mut no_versions = TlsConfig::new(cert.source());
    no_versions.versions = &[];
    let e = no_versions.build().expect_err("an empty version list");
    assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
    assert!(e.message.contains("protocol version"), "got: {}", e.message);

    let mut no_suites = TlsConfig::new(cert.source());
    no_suites.cipher_suites = &[];
    let e = no_suites.build().expect_err("an empty suite list");
    assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
    assert!(e.message.contains("cipher suite"), "got: {}", e.message);
}

/// The policy constants are non-empty and 1.3-first, so a build with the
/// documented defaults is impossible to get silently wrong.
#[test]
fn the_documented_policy_is_complete() {
    assert!(!CIPHER_SUITES.is_empty());
    assert_eq!(
        PROTOCOL_VERSIONS.first().map(|v| v.version),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A temporary directory that removes itself.
///
/// Hand-rolled rather than using `tempfile`, which is not in this workspace's
/// dependency set: adding a crate for one helper that a test file needs is not a
/// trade worth making, and the implementation is a `Drop` and a counter.
mod tempdir {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A unique directory, deleted on drop.
    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        /// Create a uniquely named directory under the system temp dir.
        ///
        /// Named from the process id and a process-wide counter, so two tests in
        /// one binary cannot collide — which matters because these tests write
        /// files and run concurrently.
        pub fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("qqq-tls-it-{}-{}", std::process::id(), n));
            std::fs::create_dir_all(&path).expect("create the temp dir");
            Self { path }
        }

        /// The directory path.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Write a file into the directory, returning its path.
        pub fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.path.join(name);
            std::fs::write(&p, bytes).expect("write the fixture file");
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// A handshake helper that writes and reads a byte, used to prove the negotiated
/// stream is genuinely usable rather than merely established.
///
/// Kept separate from [`handshake`] so a test can assert on the transcript after
/// the fact. Included because a handshake that completes but cannot carry a byte
/// is not a working connection.
#[allow(dead_code)]
async fn round_trip(server: Arc<rustls::ServerConfig>, client: Arc<ClientConfig>) -> Vec<u8> {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let acceptor = TlsAcceptor::from(server);
    let connector = TlsConnector::from(client);

    let server_task = tokio::spawn(async move {
        let mut stream = acceptor.accept(server_io).await?;
        let mut buf = vec![0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
        Ok::<_, std::io::Error>(buf)
    });

    let server_name = ServerName::try_from("localhost").expect("valid");
    if let Ok(mut stream) = connector.connect(server_name, client_io).await {
        stream.write_all(b"ping").await.expect("write");
        stream.flush().await.expect("flush");
        let mut buf = [0u8; 4];
        let _ = tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await;
        return buf.to_vec();
    }
    let _ = server_task.await;
    Vec::new()
}

/// The `ResolvedCertificate` type is part of the public API; this proves it is
/// reachable and usable from outside the crate.
#[test]
fn a_certificate_can_be_resolved_through_the_public_api() {
    let generated = CertFiles::generate(SERVER_CN);
    let resolved: ResolvedCertificate = generated
        .source()
        .resolve()
        .expect("a real certificate must resolve");
    assert!(!resolved.chain.is_empty());
}
