// SPDX-License-Identifier: Apache-2.0

//! Host-to-tenant attribution on the in-house accept loop (`ARCH-017`,
//! narrowed scope).
//!
//! A `[server.tenants]` hosts table maps request `Host` values to tenant
//! labels for access records, metrics, and audit. A request whose host is
//! unmapped is refused with 421 rather than served under a guessed tenant;
//! without a table every request keeps its peer-derived tenant, exactly as
//! before. The per-connection ledger stays peer-keyed throughout — the
//! header arrives after admission, so it can attribute but never gate.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use qqq_io::listener::Shutdown;
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::server::{Dispatch, Handler, RouteMatch, ServerConfig, serve};
use qqq_serve::{RequestHead, Response};

fn table() -> RouteTable {
    let mut t = RouteTable::new();
    t.insert(Route::new(Method::Get, "/", "root").expect("route"))
        .expect("insert");
    t
}

fn flat_handler() -> Handler {
    Arc::new(|_head: &RequestHead, _m: &RouteMatch| Response::text(200, "flat"))
}

struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
}

impl Server {
    async fn start(
        tenants: Option<BTreeMap<String, String>>,
        limits: Option<Arc<qqq_serve::limits::TenantLimits>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let shutdown = Shutdown::new();
        let local = shutdown.clone();
        let mut config = ServerConfig::for_addr(
            qqq_io::listener::ListenAddr::parse(&addr.to_string()).expect("addr"),
        );
        config.tenant_hosts = tenants.map(Arc::new);
        config.limits = limits;
        let table = table();
        let dispatch = Dispatch::flat(flat_handler());
        let logger = Logger::new(Format::Human, Level::Error);
        let probe = tokio::spawn(async move {
            if let Err(e) = serve(config, table, dispatch, local, logger).await {
                eprintln!("server stopped early: {}", e.render());
            }
        });
        let s = Self { addr, shutdown };
        for _ in 0..200 {
            if TcpStream::connect(s.addr).await.is_ok() {
                let mut probe_stream = TcpStream::connect(s.addr).await.expect("connect");
                probe_stream
                    .write_all(
                        b"GET / HTTP/1.1\r\nHost: probe.invalid\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("probe");
                let mut head = Vec::new();
                loop {
                    let mut one = [0u8; 1];
                    if probe_stream.read(&mut one).await.unwrap_or(0) == 0 {
                        break;
                    }
                    head.push(one[0]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                // Any complete response — 200 or 421 — proves the loop serves.
                if head.starts_with(b"HTTP/1.1 ") {
                    return s;
                }
            }
            assert!(!probe.is_finished(), "server task ended before binding");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("server never answered on {addr}");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.signal();
    }
}

async fn get(addr: SocketAddr, host: &str) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("send");
    let mut out = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
        }
        if out.len() > 1_000_000 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_owned(), b.as_bytes().to_vec()),
        None => (text.clone(), Vec::new()),
    };
    (head, body)
}

/// An unmapped host with a configured table is refused with 421 naming
/// the tenant table, not served under a guessed tenant.
#[tokio::test]
async fn unknown_host_is_refused_with_421() {
    let tenants = BTreeMap::from([("shop.example.com".to_owned(), "shop".to_owned())]);
    let server = Server::start(Some(tenants), None).await;
    let (head, _) = get(server.addr, "evil.example.com").await;
    assert!(
        head.starts_with("HTTP/1.1 421"),
        "an unmapped host must be refused, got: {head:?}"
    );
    assert!(
        head.contains("tenant-unknown-host") || head.contains("421"),
        "the refusal must name itself: {head:?}"
    );
}

/// A mapped host is served: the table admits the name.
#[tokio::test]
async fn mapped_host_is_served() {
    let tenants = BTreeMap::from([("shop.example.com".to_owned(), "shop".to_owned())]);
    let server = Server::start(Some(tenants), None).await;
    let (head, body) = get(server.addr, "shop.example.com").await;
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "a mapped host must be served: {head:?}"
    );
    assert_eq!(&body, b"flat", "the flat handler answers: {body:?}");
}

/// Case and port do not change the deployment named.
#[tokio::test]
async fn mapped_host_matching_ignores_case_and_port() {
    let tenants = BTreeMap::from([("shop.example.com".to_owned(), "shop".to_owned())]);
    let server = Server::start(Some(tenants), None).await;
    let (head, _) = get(server.addr, "SHOP.EXAMPLE.COM:8443").await;
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "case and port must not matter: {head:?}"
    );
}

/// Without a hosts table every loopback name keeps the peer-derived
/// tenant: no mapping, no tenant refusal. (A non-loopback host is still
/// refused with 421 by the loopback allow-list itself — `F-14` — which
/// is unchanged behavior, not a tenant decision.)
#[tokio::test]
async fn no_table_means_no_tenant_refusal() {
    let server = Server::start(None, None).await;
    let (head, _) = get(server.addr, "localhost").await;
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "without a table, a loopback host is served as before: {head:?}"
    );
    let (head, _) = get(server.addr, "anything.example.com").await;
    assert!(
        head.starts_with("HTTP/1.1 421"),
        "the loopback allow-list still refuses foreign hosts: {head:?}"
    );
}

/// Rotating `Host` across mapped tenants shares one rate bucket.
///
/// Limits stay peer-keyed: the connection's tenant key (peer prefix)
/// feeds the limiter, so renaming the host cannot mint fresh allowance.
/// Two mapped names, one peer, allowance two — the third request is
/// refused no matter which mapped name it carries.
#[tokio::test]
async fn rotating_mapped_hosts_shares_one_rate_bucket() {
    let tenants = BTreeMap::from([
        ("a.example.com".to_owned(), "a".to_owned()),
        ("b.example.com".to_owned(), "b".to_owned()),
    ]);
    let limits = Arc::new(qqq_serve::limits::TenantLimits::new(
        Vec::new(),
        qqq_serve::limits::Limits {
            max_requests_per_window: Some(2),
            window: std::time::Duration::from_secs(60),
            ..qqq_serve::limits::Limits::none()
        },
    ));
    let server = Server::start(Some(tenants), Some(limits)).await;
    let (first, _) = get(server.addr, "a.example.com").await;
    assert!(
        first.starts_with("HTTP/1.1 200"),
        "first request serves: {first:?}"
    );
    let (second, _) = get(server.addr, "b.example.com").await;
    assert!(
        second.starts_with("HTTP/1.1 200"),
        "a second mapped name serves from the same peer: {second:?}"
    );
    let (third, body) = get(server.addr, "a.example.com").await;
    assert!(
        third.starts_with("HTTP/1.1 429"),
        "rotating the host must not mint fresh allowance: {third:?}"
    );
    assert!(
        body.windows(6).any(|w| w == b"exceed"),
        "the refusal must name the spent allowance: {body:?}"
    );
}
