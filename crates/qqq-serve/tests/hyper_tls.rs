// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! TLS termination in front of the hyper drivers (`F-16` parity).
//!
//! The seam commit made `serve_hyper_h1/h2` accept any stream; this
//! proves a server-side `TlsStream` flows through it: handshake with
//! the documented cipher policy, ALPN route to the matching driver,
//! mTLS peer identity reported. Fails to compile until
//! `serve_hyper_tls` exists — the accept loop has no TLS today, and
//! a test that drove `TlsConfig::build` alone would pass with no
//! byte ever served.
//!
//! Certificates are generated, not committed (the `tests/tls.rs`
//! rule): rcgen inside the test, SAN `localhost`, nothing under
//! `tests/fixtures/`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use qqq_io::listener::Shutdown;
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::h2::hpack::{Decoder, Encoder, HeaderField};
use qqq_serve::metrics::TenantLabels;
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::serve_hyper::serve_hyper_tls;
use qqq_serve::server::{ConnectionContext, ConnectionId, Dispatch, Handler, RouteMatch};
use qqq_serve::tls::{
    ALPN_H2, ALPN_HTTP11, CIPHER_SUITES, PROTOCOL_VERSIONS, PeerIdentity, TlsConfig,
};
use qqq_serve::transport::{HyperLimits, hyper_limits_for};
use qqq_serve::ws::WsConfig;
use qqq_serve::{ConnectionConfig, Response};

/// A unique directory, deleted on drop, for PEM fixtures.
mod tempdir {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("qqq-hyper-tls-it-{}-{}", std::process::id(), n));
            std::fs::create_dir_all(&path).expect("create the temp dir");
            Self { path }
        }

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

/// A self-signed server certificate for `localhost`, written as PEM.
struct ServerCert {
    _dir: tempdir::TempDir,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    der: Vec<u8>,
}

impl ServerCert {
    fn generate() -> Self {
        // SAN (not DN) is what the client verifies: rcgen leaves the
        // subject common name at its default, so the DN is set
        // explicitly for the identity assertions while `localhost`
        // rides in the SAN list (the `tests/tls.rs` pitfall).
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("rcgen SANs");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "qqq-test-server");
        params.distinguished_name = dn;
        let key = rcgen::KeyPair::generate().expect("rcgen key");
        let cert = params.self_signed(&key).expect("rcgen self-sign");
        let dir = tempdir::TempDir::new();
        let cert_path = dir.write("server.pem", cert.pem().as_bytes());
        let key_path = dir.write("server-key.pem", key.serialize_pem().as_bytes());
        let der = cert.der().to_vec();
        Self {
            _dir: dir,
            cert: cert_path,
            key: key_path,
            der,
        }
    }

    fn source(&self) -> qqq_serve::tls::CertificateSource {
        qqq_serve::tls::CertificateSource::files(self.cert.clone(), self.key.clone())
    }
}

/// A client identity: self-signed certificate the server can trust
/// directly, for the mTLS test.
struct ClientCert {
    _dir: tempdir::TempDir,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

impl ClientCert {
    fn generate() -> Self {
        let mut params =
            rcgen::CertificateParams::new(vec!["qqq-test-client".to_owned()]).expect("rcgen SANs");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "qqq-test-client");
        params.distinguished_name = dn;
        let key = rcgen::KeyPair::generate().expect("rcgen key");
        let cert = params.self_signed(&key).expect("rcgen self-sign");
        let dir = tempdir::TempDir::new();
        let cert_path = dir.write("client.pem", cert.pem().as_bytes());
        let key_path = dir.write("client-key.pem", key.serialize_pem().as_bytes());
        Self {
            _dir: dir,
            cert: cert_path,
            key: key_path,
        }
    }
}

/// Owned context pieces for one TLS connection in tests.
struct Pieces {
    shutdown: Shutdown,
    logger: Logger,
    cors: Option<qqq_serve::cors::Cors>,
    metrics_path: Option<String>,
    auth: Option<Arc<qqq_serve::auth::AuthPolicy>>,
    idle: Option<Duration>,
    metrics: Option<Arc<qqq_serve::metrics::HttpMetrics>>,
    limits: Option<Arc<qqq_serve::limits::TenantLimits>>,
    global_requests: Option<Arc<qqq_serve::limits::GlobalBucket>>,
    ws: WsConfig,
    loopback_only: bool,
    ws_buffer: Arc<tokio::sync::Semaphore>,
    tenant_labels: Arc<TenantLabels>,
}

impl Pieces {
    fn bare() -> Self {
        Self {
            shutdown: Shutdown::new(),
            logger: Logger::new(Format::Json, Level::Error),
            cors: None,
            metrics_path: None,
            auth: None,
            idle: None,
            metrics: None,
            limits: None,
            global_requests: None,
            ws: WsConfig::default(),
            loopback_only: false,
            ws_buffer: Arc::new(tokio::sync::Semaphore::new(16)),
            tenant_labels: Arc::new(TenantLabels::new()),
        }
    }
}

fn table_with(routes: &[(Method, &str, &str)]) -> RouteTable {
    let mut t = RouteTable::new();
    for (method, pattern, handler) in routes {
        t.insert(Route::new(*method, pattern, handler).expect("route"))
            .expect("insert");
    }
    t
}

fn hello_handler() -> Handler {
    Arc::new(|_head, m: &RouteMatch| Response::text(200, format!("hello from {}", m.handler)))
}

fn default_limits() -> HyperLimits {
    hyper_limits_for(&ConnectionConfig::default())
}

/// One TLS-terminating accept: handshake, ALPN route, serve. The
/// server task ends when the client goes away, like the plaintext
/// harness, so every exchange is observable end to end.
struct TlsServer {
    addr: SocketAddr,
    driver: JoinHandle<std::io::Result<qqq_serve::serve_hyper::TlsServed>>,
}

impl TlsServer {
    async fn start(
        tls: Arc<rustls::ServerConfig>,
        table: RouteTable,
        dispatch: Dispatch,
        limits: HyperLimits,
        pieces: Pieces,
        peer: SocketAddr,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("listener address");
        let table = Arc::new(table);
        let driver = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let id = ConnectionId::new(peer, 1);
            let ctx = ConnectionContext {
                id: &id,
                shutdown: &pieces.shutdown,
                logger: &pieces.logger,
                cors: pieces.cors.as_ref(),
                metrics_path: pieces.metrics_path.as_deref(),
                sampler: None,
                auth: pieces.auth.as_ref(),
                idle_timeout: pieces.idle,
                metrics: pieces.metrics.as_ref(),
                limits: pieces.limits.as_ref(),
                global_requests: pieces.global_requests.as_ref(),
                ws: &pieces.ws,
                loopback_only: pieces.loopback_only,
                ws_buffer: &pieces.ws_buffer,
                tenant_labels: &pieces.tenant_labels,
            };
            serve_hyper_tls(stream, tls, Arc::clone(&table), dispatch, limits, &ctx).await
        });
        Self { addr, driver }
    }
}

/// A TLS client trusting exactly `der`, offering `alpn`.
async fn connect(
    addr: SocketAddr,
    der: &[u8],
    alpn: &[&[u8]],
    identity: Option<(&[u8], &[u8])>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(der.to_vec()))
        .expect("server cert is a root here");
    // The client offers the same suite policy the server does, so a
    // mutual choice is possible (mirrors `tests/tls.rs`).
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = CIPHER_SUITES.to_vec();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider));
    let builder = builder
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .expect("versions and suites are compatible");
    let mut config = if let Some((cert_pem, key_pem)) = identity {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("client chain parses");
        let key = PrivateKeyDer::from_pem_slice(key_pem).expect("client key parses");
        builder
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .expect("client identity usable")
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    connector.connect(name, tcp).await.expect("handshake")
}

/// Read one response head off a stream, then its body.
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
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or("").to_owned();
    let mut length = 0usize;
    for line in lines {
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
    (status, body)
}

fn frame(ftype: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("test frames are small");
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push(u8::try_from(len >> 16).expect("length fits 24 bits"));
    out.push(u8::try_from((len >> 8) & 0xff).expect("length fits 24 bits"));
    out.push(u8::try_from(len & 0xff).expect("length fits 24 bits"));
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

const SETTINGS: u8 = 0x4;
const HEADERS: u8 = 0x1;
const DATA: u8 = 0x0;
const ACK: u8 = 0x1;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// An ALPN-`h2` client gets the h2 driver over TLS: preface,
/// SETTINGS, one `GET` stream, 200 + body, and the negotiated
/// protocol reported as `h2`.
#[tokio::test]
async fn tls_alpn_h2_routes_to_the_h2_driver() {
    let server_cert = ServerCert::generate();
    let tls = TlsConfig::new(server_cert.source())
        .with_alpn(&[ALPN_H2, ALPN_HTTP11])
        .build()
        .expect("policy builds");
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let server = TlsServer::start(
        tls,
        table_with(&[(Method::Get, "/hello", "h")]),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
        peer,
    )
    .await;
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        let mut client = connect(server.addr, &server_cert.der, &[ALPN_H2], None).await;
        let mut hello = PREFACE.to_vec();
        hello.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
        client.write_all(&hello).await.expect("preface writes");
        // Settle: server SETTINGS, then ack.
        loop {
            let mut head = [0u8; 9];
            client.read_exact(&mut head).await.expect("server settings");
            if head[3] == SETTINGS && (head[4] & ACK) == 0 {
                let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
                let mut rest = vec![0u8; len];
                if len > 0 {
                    client.read_exact(&mut rest).await.expect("settings body");
                }
                break;
            }
        }
        client
            .write_all(&frame(SETTINGS, ACK, 0, &[]))
            .await
            .expect("ack writes");
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new();
        let block = encoder.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", "/hello"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":authority", "localhost"),
        ]);
        client
            .write_all(&frame(HEADERS, END_HEADERS | END_STREAM, 1, &block))
            .await
            .expect("headers write");
        let mut status = 0u16;
        let mut body = Vec::new();
        loop {
            let mut head = [0u8; 9];
            client.read_exact(&mut head).await.expect("response frame");
            let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
            let mut payload = vec![0u8; len];
            if len > 0 {
                client.read_exact(&mut payload).await.expect("frame body");
            }
            let sid = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            if sid == 0 {
                continue;
            }
            if head[3] == HEADERS {
                for field in decoder.decode(&payload).expect("decode") {
                    if field.name == ":status" {
                        status = field.value.parse().expect("numeric status");
                    }
                }
            } else if head[3] == DATA {
                body.extend_from_slice(&payload);
                if (head[4] & END_STREAM) != 0 {
                    break;
                }
            }
        }
        assert_eq!(status, 200, "h2 over TLS answers");
        assert_eq!(body, b"hello from h");
        drop(client);
        server
            .driver
            .await
            .expect("server task joins")
            .expect("handshake and serve succeed")
    })
    .await
    .expect("server answers over TLS");
    assert_eq!(
        outcome.negotiated.alpn.as_deref(),
        Some("h2"),
        "ALPN h2 reported"
    );
    assert!(
        outcome.peer.is_none(),
        "no client certificate means no peer identity"
    );
}

/// An ALPN-`http/1.1` client gets the h1 driver over TLS: raw GET,
/// 200 + body, negotiated protocol reported as `http/1.1`.
#[tokio::test]
async fn tls_alpn_http11_routes_to_the_h1_driver() {
    let server_cert = ServerCert::generate();
    let tls = TlsConfig::new(server_cert.source())
        .with_alpn(&[ALPN_H2, ALPN_HTTP11])
        .build()
        .expect("policy builds");
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let server = TlsServer::start(
        tls,
        table_with(&[(Method::Get, "/hello", "h")]),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
        peer,
    )
    .await;
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        let mut client = connect(server.addr, &server_cert.der, &[ALPN_HTTP11], None).await;
        client
            .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("request writes");
        client.flush().await.expect("flush");
        let response = read_response(&mut client).await;
        drop(client);
        let done = server
            .driver
            .await
            .expect("server task joins")
            .expect("handshake and serve succeed");
        (response, done)
    })
    .await
    .expect("server answers over TLS");
    let ((status, body), done) = outcome;
    assert_eq!(status, "HTTP/1.1 200 OK", "h1 over TLS answers");
    assert_eq!(body, b"hello from h");
    assert_eq!(
        done.negotiated.alpn.as_deref(),
        Some("http/1.1"),
        "ALPN http/1.1 reported"
    );
}

/// mTLS: a required client certificate surfaces as peer identity
/// on the served outcome, with the subject the certificate names.
#[tokio::test]
async fn tls_required_client_auth_reports_peer_identity() {
    let server_cert = ServerCert::generate();
    let client_cert = ClientCert::generate();
    let client_pem = std::fs::read(&client_cert.cert).expect("client cert reads");
    let client_key = std::fs::read(&client_cert.key).expect("client key reads");
    let tls = TlsConfig::new(server_cert.source())
        .with_alpn(&[ALPN_HTTP11])
        .with_required_client_auth(client_cert.cert.clone())
        .build()
        .expect("policy builds");
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer");
    let server = TlsServer::start(
        tls,
        table_with(&[(Method::Get, "/hello", "h")]),
        Dispatch::flat(hello_handler()),
        default_limits(),
        Pieces::bare(),
        peer,
    )
    .await;
    let done = tokio::time::timeout(Duration::from_secs(60), async {
        let mut client = connect(
            server.addr,
            &server_cert.der,
            &[ALPN_HTTP11],
            Some((&client_pem, &client_key)),
        )
        .await;
        client
            .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("request writes");
        client.flush().await.expect("flush");
        let (status, body) = read_response(&mut client).await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(body, b"hello from h");
        drop(client);
        server
            .driver
            .await
            .expect("server task joins")
            .expect("handshake and serve succeed")
    })
    .await
    .expect("mTLS round trip completes");
    let peer: Option<PeerIdentity> = done.peer;
    let peer = peer.expect("required client auth yields an identity");
    assert_eq!(
        peer.subject(),
        "qqq-test-client",
        "identity names the certificate subject"
    );
    assert_eq!(
        done.negotiated.alpn.as_deref(),
        Some("http/1.1"),
        "ALPN still reported alongside identity"
    );
}
