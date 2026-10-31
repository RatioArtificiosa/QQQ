// SPDX-License-Identifier: Apache-2.0

//! HTTP/2 on the production accept loop (`SRV-023`).
//!
//! The in-house loop terminates TLS and routes by negotiated ALPN: `h2`
//! goes to the hyper HTTP/2 driver with the same table, dispatch, limits
//! and tenant context as every other connection; anything else stays on
//! the in-house HTTP/1.1 path. These tests drive that branch live: a real
//! TLS handshake with an ALPN offer, then real H2 frames, asserting the
//! response that comes back.
//!
//! The client here speaks H2 the way `hyper_h2.rs` does — hand-rolled
//! frames over the in-house HPACK codec, which is the shared vocabulary,
//! not a second implementation. What is *not* reused is the server side:
//! `hyper_h2.rs` drives `serve_hyper_h2` directly, bypassing the accept
//! loop, the TLS termination, and the ALPN routing this file exists to
//! prove. A test that called the driver would pass with the branch
//! missing.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use qqq_io::listener::Shutdown;
use qqq_serve::Response;
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::h2::hpack::{Decoder, Encoder, HeaderField};
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::server::{Dispatch, Handler, RouteMatch, TenantDispatch, serve};
use qqq_serve::tls::{ALPN_H2, ALPN_HTTP11, CIPHER_SUITES, PROTOCOL_VERSIONS, TlsConfig};

// -- wire constants (RFC 9113 §6) ------------------------------------------

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;

const ACK: u8 = 0x1;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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

struct H2Frame {
    ftype: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

async fn read_frame<S>(stream: &mut S, secs: u64) -> Option<H2Frame>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut hdr = [0u8; 9];
    if tokio::time::timeout(Duration::from_secs(secs), stream.read_exact(&mut hdr))
        .await
        .is_err()
    {
        return None;
    }
    let len = ((u32::from(hdr[0]) << 16) | (u32::from(hdr[1]) << 8) | u32::from(hdr[2])) as usize;
    let mut payload = vec![0u8; len];
    if tokio::time::timeout(Duration::from_secs(secs), stream.read_exact(&mut payload))
        .await
        .is_err()
    {
        return None;
    }
    Some(H2Frame {
        ftype: hdr[3],
        flags: hdr[4],
        stream: u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff,
        payload,
    })
}

// -- fixture: in-house accept loop with TLS -----------------------------------

/// A self-signed server certificate for `localhost`, written as PEM.
///
/// Certificates are generated, not committed. The directory is removed on
/// drop so concurrent tests (and repeated runs) never share files.
struct TlsFixture {
    dir: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    der: Vec<u8>,
}

impl TlsFixture {
    fn generate() -> Self {
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("rcgen SANs");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "qqq-test-server");
        params.distinguished_name = dn;
        let key = rcgen::KeyPair::generate().expect("rcgen key");
        let cert = params.self_signed(&key).expect("rcgen self-sign");
        let dir = std::env::temp_dir().join(format!(
            "qqq-h2-prod-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let cert_path = dir.join("server.pem");
        let key_path = dir.join("server-key.pem");
        std::fs::write(&cert_path, cert.pem().as_bytes()).expect("write cert");
        std::fs::write(&key_path, key.serialize_pem().as_bytes()).expect("write key");
        let der = cert.der().to_vec();
        Self {
            dir,
            cert: cert_path,
            key: key_path,
            der,
        }
    }
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
}

impl Server {
    async fn start(tls: Option<Arc<rustls::ServerConfig>>, der: &[u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let shutdown = Shutdown::new();
        let local = shutdown.clone();
        let mut config = qqq_serve::server::ServerConfig::for_addr(
            qqq_io::listener::ListenAddr::parse(&addr.to_string()).expect("loopback addr parses"),
        );
        config.tls = tls;
        let mut table = RouteTable::new();
        table
            .insert(Route::new(Method::Get, "/", "hello").expect("route"))
            .expect("insert");
        let handler: Handler =
            Arc::new(|_head: &RequestHead, _m: &RouteMatch| Response::text(200, "hello-h2"));
        let dispatch = TenantDispatch::new(Dispatch::flat(handler));
        let logger = Logger::new(Format::Human, Level::Error);
        tokio::spawn(async move {
            let _ = serve(config, table, dispatch, local, logger).await;
        });
        let s = Self { addr, shutdown };
        // Readiness is a completed handshake, not a bound port and not a
        // fixed sleep: the approve-then-serve gap is the server's, and a
        // sleep that is long enough today is a flake report tomorrow.
        for _ in 0..200 {
            if try_connect_tls(s.addr, der, &[ALPN_HTTP11]).await.is_some() {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("server never served TLS on {addr}");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.signal();
    }
}

use qqq_serve::RequestHead;

async fn connect_tls(
    addr: SocketAddr,
    der: &[u8],
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    try_connect_tls(addr, der, alpn).await.expect("handshake")
}

/// One TLS handshake attempt: `None` is a server that is bound but not
/// yet serving TLS (or a closed door), which the readiness poll, not the
/// test, decides about. `expect` stays only on fixture construction —
/// roots and names the test controls — never on the network.
async fn try_connect_tls(
    addr: SocketAddr,
    der: &[u8],
    alpn: &[&[u8]],
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    use rustls::pki_types::CertificateDer;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(der.to_vec()))
        .expect("server cert is a root here");
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = CIPHER_SUITES.to_vec();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider));
    let builder = builder
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .expect("versions and suites are compatible");
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await.ok()?;
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    connector.connect(name, tcp).await.ok()
}

/// Read one H2 response: HEADERS (decoded) then DATA to `END_STREAM`.
async fn read_h2_response<S>(
    stream: &mut S,
    decoder: &mut Decoder,
    want_stream: u32,
) -> (u16, Vec<u8>)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut status = 0u16;
    let mut body = Vec::new();
    loop {
        let frame = read_frame(stream, 10)
            .await
            .expect("the server must answer the H2 request");
        match frame.ftype {
            SETTINGS | PING if frame.flags & ACK == 0 => {}
            HEADERS if frame.stream == want_stream => {
                for field in decoder.decode(&frame.payload).expect("decode") {
                    if field.name == ":status" {
                        status = field.value.parse().expect("numeric status");
                    }
                }
                if frame.flags & END_STREAM != 0 {
                    break;
                }
            }
            DATA if frame.stream == want_stream => {
                body.extend_from_slice(&frame.payload);
                if frame.flags & END_STREAM != 0 {
                    break;
                }
            }
            GOAWAY => panic!("the server must not kill a well-formed H2 stream"),
            _ => {}
        }
    }
    (status, body)
}

/// H2 negotiated by ALPN is served by the HTTP/2 driver on the production
/// listener — not refused, not downgraded, not hung.
#[tokio::test]
async fn h2_upgrades_over_tls_alpn() {
    let fixture = TlsFixture::generate();
    let tls = TlsConfig::new(qqq_serve::tls::CertificateSource::files(
        fixture.cert.clone(),
        fixture.key.clone(),
    ))
    .build()
    .expect("fixture TLS builds");
    let server = Server::start(Some(tls), &fixture.der).await;

    let mut stream = connect_tls(server.addr, &fixture.der, &[ALPN_H2]).await;
    let (_, connection) = stream.get_ref();
    assert_eq!(
        connection.alpn_protocol(),
        Some(ALPN_H2),
        "the server must negotiate h2 when the client offers it"
    );

    // Client preface: magic, empty SETTINGS, then ACK the server's.
    stream.write_all(PREFACE).await.expect("preface sends");
    stream
        .write_all(&frame(SETTINGS, 0, 0, &[]))
        .await
        .expect("settings send");
    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();
    // Swallow SETTINGS (and any WINDOW_UPDATE/PING preamble) first.
    loop {
        let fr = read_frame(&mut stream, 10)
            .await
            .expect("server settings arrive");
        if fr.ftype == SETTINGS && fr.flags & ACK == 0 {
            stream
                .write_all(&frame(SETTINGS, ACK, 0, &[]))
                .await
                .expect("settings ack");
            break;
        }
    }
    let block = encoder.encode(&[
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/"),
        HeaderField::new(":scheme", "https"),
        HeaderField::new(":authority", "localhost"),
    ]);
    stream
        .write_all(&frame(HEADERS, END_HEADERS | END_STREAM, 1, &block))
        .await
        .expect("headers send");
    let (status, body) = read_h2_response(&mut stream, &mut decoder, 1).await;
    assert_eq!(
        status, 200,
        "H2 GET / must answer 200 on the production listener"
    );
    assert_eq!(
        &body, b"hello-h2",
        "the H2 response must carry the guest body"
    );
}

/// Offering only HTTP/1.1 still serves HTTP/1.1: the H2 opt-in never
/// downgrades a client that did not ask for it.
#[tokio::test]
async fn http11_still_served_when_h2_not_offered() {
    let fixture = TlsFixture::generate();
    let tls = TlsConfig::new(qqq_serve::tls::CertificateSource::files(
        fixture.cert.clone(),
        fixture.key.clone(),
    ))
    .build()
    .expect("fixture TLS builds");
    let server = Server::start(Some(tls), &fixture.der).await;

    let mut stream = connect_tls(server.addr, &fixture.der, &[ALPN_HTTP11]).await;
    let (_, connection) = stream.get_ref();
    assert_eq!(
        connection.alpn_protocol(),
        Some(ALPN_HTTP11),
        "an http/1.1-only offer must negotiate http/1.1"
    );
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request sends");
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await
    .expect("the server must answer");
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "H1 over TLS must still answer 200: {text:?}"
    );
}
