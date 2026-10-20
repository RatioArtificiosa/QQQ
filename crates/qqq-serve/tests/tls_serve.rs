// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! TLS termination in the in-house accept loop (`SRV-021`).
//!
//! # Why these drive a real socket through `serve`
//!
//! `src/tls.rs` proves the configuration negotiates (over a duplex pipe)
//! and `tests/hyper_tls.rs` proves the hyper drivers route the negotiated
//! session. Neither proves the **in-house** loop — the one `qqqai serve`
//! runs — decrypts before its first parse, because neither runs it. These
//! tests bind the real `serve` with a rustls configuration, complete real
//! handshakes against it, and assert on the HTTP the decrypted stream
//! carries. A test that only inspected `ServerConfig.tls` could not see a
//! loop that never reads the field.
//!
//! # The certificates are generated, not committed
//!
//! Like `tests/tls.rs`: every certificate comes from `rcgen` inside the
//! test. The SAN is `localhost`, because the client verifies the name.
//! The server is built from the in-memory `Platform` source rather than
//! files: the file loader is `SRV-007`'s tested path, and this file tests
//! the accept loop's contract — an `Arc<rustls::ServerConfig>` — not the
//! loader's.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_io::listener::{ListenAddr, Shutdown};
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::server::{Dispatch, Handler, ServerConfig, serve};
use qqq_serve::tls::{CertificateSource, TlsConfig};
use qqq_serve::{Response, RouteMatch};

/// A port nobody is using.
///
/// Bound and released, accepting a microsecond race, for the reason
/// `tests/access.rs` states: the alternative is a fixed port that races
/// every parallel run instead of one microsecond.
fn free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("listener address")
}

fn hello_handler() -> Handler {
    Arc::new(|_head, m: &RouteMatch| Response::text(200, format!("hello from {}", m.handler)))
}

fn table() -> RouteTable {
    let mut t = RouteTable::new();
    t.insert(Route::new(Method::Get, "/hello", "hello").expect("route"))
        .expect("insert");
    t
}

/// A rustls server configuration from a generated self-signed certificate.
///
/// In-memory `Platform` source, deliberately: the contract under test is
/// "the loop terminates what it is given", and the file loader has its own
/// tests. Returns the config plus the certificate DER so the client can
/// trust exactly this server and no other.
fn server_config_with_tls() -> (Arc<rustls::ServerConfig>, Vec<u8>) {
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("rcgen accepts the SAN");
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "qqq-test-server");
        dn
    };
    let key = rcgen::KeyPair::generate().expect("rcgen generates a key");
    let cert = params
        .self_signed(&key)
        .expect("rcgen self-signs with the generated key");
    let der = cert.der().to_vec();
    let key_der = key.serialize_der();
    let source = CertificateSource::Platform {
        chain: vec![CertificateDer::from(der.clone())],
        key: PrivateKeyDer::Pkcs8(key_der.into()),
    };
    let config = TlsConfig::new(source)
        .build()
        .expect("a generated certificate builds");
    (config, der)
}

/// A TLS client trusting exactly `der`, offering HTTP/1.1.
///
/// `Result`, not panicking: the readiness poll connects while the server
/// is still starting, and a failed connect there is routine, not a test
/// failure. Only the tests themselves unwrap.
async fn try_connect_tls(
    addr: SocketAddr,
    der: &[u8],
) -> std::io::Result<(tokio_rustls::client::TlsStream<TcpStream>, String)> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(der.to_vec()))
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await?;
    let name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let stream = connector
        .connect(name, tcp)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let version = stream
        .get_ref()
        .1
        .protocol_version()
        .map_or_else(|| "none".to_owned(), |v| format!("{v:?}"));
    Ok((stream, version))
}

/// A TLS client trusting exactly `der`, offering HTTP/1.1.
async fn connect_tls(
    addr: SocketAddr,
    der: &[u8],
) -> (tokio_rustls::client::TlsStream<TcpStream>, String) {
    try_connect_tls(addr, der)
        .await
        .expect("the handshake must complete")
}

/// A running in-house server with TLS, stopped when dropped.
struct TlsServer {
    addr: SocketAddr,
    shutdown: Shutdown,
    metrics: Arc<qqq_serve::metrics::HttpMetrics>,
}

impl TlsServer {
    async fn start() -> (Self, Vec<u8>) {
        Self::start_with(|_| {}).await
    }

    /// Start with a configuration edit: short timeouts for the refusal
    /// tests, a ceiling of one for the ledger test. The TLS identity and
    /// the metrics registry are always installed — a test that disabled
    /// either would stop testing the production shape.
    async fn start_with(modify: impl FnOnce(&mut ServerConfig)) -> (Self, Vec<u8>) {
        let addr = free_addr();
        let listen = ListenAddr::parse(&addr.to_string()).expect("address parses");
        let (tls, der) = server_config_with_tls();
        let mut config = ServerConfig::for_addr(listen);
        config.tls = Some(tls);
        let metrics = Arc::new(qqq_serve::metrics::HttpMetrics::new());
        config.metrics = Some(Arc::clone(&metrics));
        modify(&mut config);
        let shutdown = Shutdown::new();
        let local = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(
                config,
                table(),
                Dispatch::flat(hello_handler()),
                local,
                Logger::new(Format::Json, Level::Error),
            )
            .await
            {
                eprintln!("server stopped early: {}", e.render());
            }
        });
        let server = Self {
            addr,
            shutdown,
            metrics,
        };
        server.wait_until_accepting(&der).await;
        (server, der)
    }

    /// Wait until the listener terminates TLS, with real handshakes.
    ///
    /// A plaintext connect would complete TCP and then fail the handshake,
    /// consuming an accept and recording a protocol error — polling with one
    /// would test the server by failing against it. The TLS handshake is the
    /// property that matters here. Tolerant: a connect that fails is a
    /// server still starting, not a test failure — panicking on the first
    /// refused connect made this flaky under load.
    async fn wait_until_accepting(&self, der: &[u8]) {
        for _ in 0..200 {
            match try_connect_tls(self.addr, der).await {
                Ok((mut stream, _)) => {
                    let _ = stream.shutdown().await;
                    return;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        panic!("the TLS listener never accepted");
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        self.shutdown.signal();
    }
}

async fn request(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    target: &str,
    connection: &str,
) {
    let req =
        format!("GET {target} HTTP/1.1\r\nhost: localhost\r\nconnection: {connection}\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("the request must write");
}

async fn read_response(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> (String, Vec<u8>) {
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.expect("server answers");
        head.push(byte[0]);
        assert!(head.len() <= 64 * 1024, "response head bounded");
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut length = 0usize;
    for line in text.split("\r\n") {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().expect("content-length parses");
        }
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.expect("body arrives");
    let status = text.lines().next().unwrap_or("").to_owned();
    (status, body)
}

/// **TLS terminates in the in-house loop and the decrypted stream serves.**
///
/// Two sequential requests on one connection, so keep-alive survives the
/// decryption — a handshake followed by a close would prove the acceptor
/// and nothing about the serving path. The negotiated version is asserted
/// client-side: it is the only observation point that sees encryption
/// rather than assuming it.
#[tokio::test]
async fn tls_terminates_and_serves_http_in_house() {
    let (server, der) = TlsServer::start().await;
    let addr = server.addr;
    let (mut stream, version) = connect_tls(addr, &der).await;
    assert!(
        version.contains("TLSv1_3"),
        "the session must negotiate TLS 1.3, not cleartext: {version}"
    );

    request(&mut stream, "/hello", "keep-alive").await;
    let (status, body) = read_response(&mut stream).await;
    assert!(status.contains("200"), "first request serves: {status}");
    assert_eq!(body, b"hello from hello");

    // Same connection, second request: keep-alive through the TLS stream.
    request(&mut stream, "/hello", "close").await;
    let (status, body) = read_response(&mut stream).await;
    assert!(status.contains("200"), "second request serves: {status}");
    assert_eq!(body, b"hello from hello");
}

/// **A failed handshake gets no HTTP response — never a cleartext fallback.**
///
/// Garbage bytes cannot complete a handshake, and what comes back must not
/// parse as HTTP. A server that fell back to cleartext on handshake failure
/// would answer `400` here; the assertion that nothing HTTP arrives is the
/// downgrade protection. The server must also close rather than hang: the
/// test expects the close, so a hang fails instead of passing.
///
/// The header timeout is shortened, which shortens the handshake bound with
/// it — the bound reads the header timeout by design, so this also proves
/// the timeout fires. The gauge must return to zero: an open without its
/// protocol-error close would leak a connection count.
#[tokio::test]
async fn a_failed_handshake_gets_no_http_response() {
    let (server, _der) = TlsServer::start_with(|config| {
        config.connection.header_timeout = Duration::from_millis(300);
    })
    .await;
    let addr = server.addr;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    tcp.write_all(b"\x00\x01\x02\x03not-tls-at-all")
        .await
        .expect("garbage writes");
    let mut first = [0u8; 5];
    // The server closes; it must not hang. `expect` on the timeout makes a
    // hang a failure, not a pass.
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut first))
        .await
        .expect("the server must close a failed handshake, not hang it")
        .expect("the close must arrive");
    assert_ne!(
        &first, b"HTTP/",
        "a handshake failure must never answer HTTP"
    );
    // The open is recorded before the handshake and the protocol-error close
    // after it: the gauge returning to zero proves both ran.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while server.metrics.open_connections() != 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the failed handshake leaked an open connection"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// **Cleartext HTTP to a TLS port is refused, not served.**
///
/// A client speaking plain HTTP to the TLS listener cannot complete a
/// handshake; the bytes it gets back (a TLS alert) or the close must not be
/// a served response. This is the user-visible shape of the fail-closed rule.
#[tokio::test]
async fn cleartext_http_to_a_tls_port_is_refused() {
    let (server, _der) = TlsServer::start_with(|config| {
        config.connection.header_timeout = Duration::from_millis(300);
    })
    .await;
    let addr = server.addr;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    tcp.write_all(b"GET /hello HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("the request must write");
    let mut buf = Vec::new();
    // Completion, not abandonment: a server that hangs the connection would
    // pass an assertion on an empty buffer.
    tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut buf))
        .await
        .expect("the server must end a cleartext connection, not hang it")
        .expect("the read must complete");
    assert!(
        !buf.starts_with(b"HTTP/"),
        "cleartext to a TLS port must not be served HTTP ({} bytes)",
        buf.len()
    );
}

/// **An idle handshake is closed by the timeout, freeing its slot.**
///
/// A client that connects and sends nothing is the slow-loris the header
/// timeout exists to bound — the handshake bound reads it by design. Without
/// the bound this test hangs: the `expect` on the close turns "waits
/// forever" into a failure. A subsequent real handshake proves the slot
/// released rather than leaking with the task.
#[tokio::test]
async fn an_idle_handshake_is_closed_by_the_timeout() {
    let (server, der) = TlsServer::start_with(|config| {
        config.connection.header_timeout = Duration::from_millis(300);
    })
    .await;
    let addr = server.addr;
    let mut idle = TcpStream::connect(addr).await.expect("connect");
    let mut byte = [0u8; 1];
    // EOF, not a byte: the server sends nothing before a handshake, so the
    // close arrives as end-of-stream. `read_exact` would report the EOF as
    // an error and misname a clean close a failure.
    let n = tokio::time::timeout(Duration::from_secs(10), idle.read(&mut byte))
        .await
        .expect("an idle handshake must be closed, not held")
        .expect("the close must arrive");
    assert_eq!(n, 0, "an idle handshake ends in EOF");

    let (mut stream, version) = connect_tls(addr, &der).await;
    assert!(
        version.contains("TLSv1_3"),
        "after the timeout the slot must serve: {version}"
    );
    request(&mut stream, "/hello", "close").await;
    let (status, _) = read_response(&mut stream).await;
    assert!(status.contains("200"), "the freed slot serves: {status}");
}

/// **A refused ledger slot on a TLS port closes quietly and releases.**
///
/// With a ceiling of one held by an open TLS connection, the next
/// connection is refused before any handshake — and the refusal sends no
/// plaintext body, because the peer expects a `ServerHello`. The slot
/// releases when the holder goes away: a third connection then handshakes,
/// proving the refusal consumed nothing permanent.
#[tokio::test]
async fn a_refused_tls_connection_closes_quietly_and_releases() {
    let (server, der) = TlsServer::start_with(|config| {
        config.connections_per_tenant = 1;
    })
    .await;
    let addr = server.addr;
    let (mut held, _) = connect_tls(addr, &der).await;

    let mut second = TcpStream::connect(addr).await.expect("connect");
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), second.read_to_end(&mut buf))
        .await
        .expect("a refused connection must end, not hang")
        .expect("the read must complete");
    assert!(
        !buf.starts_with(b"HTTP/"),
        "a ledger refusal on a TLS port must not answer HTTP ({} bytes)",
        buf.len()
    );

    // Release: the holder going away frees the slot for a full handshake.
    held.shutdown().await.expect("holder closes");
    drop(held);
    let (mut third, version) = connect_tls(addr, &der).await;
    assert!(
        version.contains("TLSv1_3"),
        "after release the next connection must handshake: {version}"
    );
    request(&mut third, "/hello", "close").await;
    let (status, _) = read_response(&mut third).await;
    assert!(status.contains("200"), "the released slot serves: {status}");
}
