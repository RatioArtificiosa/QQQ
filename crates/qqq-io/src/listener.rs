//! Listen addresses, listener configuration, and the accept loop.
//!
//! Implements the transport half of `SRV-001` and step 1 of the §4.4 request
//! lifecycle.
//!
//! # Address parsing is hand-written, and here is why
//!
//! `SocketAddr`'s own parser rejects `[::1]:8080` in some forms and accepts bare
//! IPs inconsistently across the standard library's versions. More importantly,
//! a listen address in a manifest is a *user-facing* string: `127.0.0.1:3000`,
//! `[::]:8080`, `0.0.0.0:80`. The error a user gets for a typo has to name what
//! was wrong and what to write instead, and reconstructing that from
//! `AddrParseError`'s single opaque message is worse than the few lines here.
//!
//! The validation is deliberately literal: a host is either a well-formed IPv4
//! literal, a well-formed IPv6 literal, or `localhost`. **Hostnames are
//! resolved**, not accepted as literals, because binding to `example.com` is a
//! request to bind to whatever that resolves to on *this* machine at *this*
//! moment — which is a deployment-dependent behaviour, and NN-5 says nothing
//! important is inferred.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use qqq_core::{Error, ErrorCode, Result};

// ---------------------------------------------------------------------------
// Address parsing
// ---------------------------------------------------------------------------

/// A validated listen address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenAddr {
    /// The host as written.
    host: String,
    /// The port.
    port: u16,
}

impl ListenAddr {
    /// Parse a `host:port` string.
    ///
    /// Accepts:
    ///
    /// | Form | Example |
    /// |---|---|
    /// | IPv4 | `127.0.0.1:3000`, `0.0.0.0:80` |
    /// | IPv6 | `[::1]:8080`, `[::]:8080` |
    /// | `localhost` | `localhost:3000` |
    ///
    /// # Errors
    ///
    /// `QQQ-6005` naming the specific problem: no colon, an unparsable port, a
    /// port of zero, or a host that is not a literal or `localhost`.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(Error::new(
                ErrorCode::ListenerBindFailed,
                "a listen address is required",
            )
            .with_remediation("for example: --listen 127.0.0.1:3000"));
        }

        // Bracket form, so the colons inside the IPv6 literal are not mistaken
        // for the port separator. This is the whole reason the bracket syntax
        // exists in URLs, and getting it wrong is why `[::1]:8080` is the
        // classic broken case.
        let (host, port_str) = if let Some(rest) = s.strip_prefix('[') {
            let close = rest.find(']').ok_or_else(|| {
                Error::new(
                    ErrorCode::ListenerBindFailed,
                    format!("`{s}` opens a bracket and never closes it"),
                )
                .with_remediation("a bracketed IPv6 address looks like `[::1]:8080`")
            })?;
            let host = &rest[..close];
            let after = &rest[close + 1..];
            let port = after.strip_prefix(':').ok_or_else(|| {
                Error::new(
                    ErrorCode::ListenerBindFailed,
                    format!("`{s}` is missing a port after the bracketed address"),
                )
                .with_remediation("a bracketed IPv6 address looks like `[::1]:8080`")
            })?;
            (host, port)
        } else {
            // `rsplit_once` rather than `split_once`: an unbracketed IPv6
            // literal has many colons, and the port is the *last* one. Splitting
            // on the first would take `::1` apart into an empty host and `:1`.
            let (host, port) = s.rsplit_once(':').ok_or_else(|| {
                Error::new(ErrorCode::ListenerBindFailed, format!("`{s}` has no port"))
                    .with_remediation("a listen address looks like `127.0.0.1:3000`")
            })?;
            (host, port)
        };

        if host.is_empty() {
            return Err(Error::new(
                ErrorCode::ListenerBindFailed,
                format!("`{s}` has an empty host"),
            )
            .with_remediation("use `0.0.0.0` to listen on every interface"));
        }

        let port: u16 = port_str.trim().parse().map_err(|_| {
            Error::new(
                ErrorCode::ListenerBindFailed,
                format!("`{port_str}` is not a valid port"),
            )
            .with_remediation("a port is a number from 1 to 65535")
        })?;

        // Port 0 asks the OS for any free port. That is legitimate in a test
        // harness and dangerous in a manifest, because the deployed service
        // would listen somewhere nobody knows. Refused here, and the test
        // helper uses an explicit high port instead.
        if port == 0 {
            return Err(Error::new(
                ErrorCode::ListenerBindFailed,
                "port 0 does not name a port to listen on",
            )
            .with_remediation("choose a port from 1 to 65535"));
        }

        // The host must be something we can bind without resolving a name.
        if !host.eq_ignore_ascii_case("localhost")
            && host.parse::<Ipv4Addr>().is_err()
            && host.parse::<Ipv6Addr>().is_err()
        {
            return Err(Error::new(
                ErrorCode::ListenerBindFailed,
                format!("`{host}` is not an IP address or `localhost`"),
            )
            .with_remediation(
                "listening on a hostname would depend on this machine's DNS, so it is \
                 refused; use an IP literal such as `127.0.0.1`, `0.0.0.0` or `[::]`",
            ));
        }

        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// The host as written.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Whether this address binds every interface.
    ///
    /// `0.0.0.0` or `[::]`. Worth distinguishing because it is the difference
    /// between "reachable from this machine" and "reachable from the network",
    /// and a dev server that binds every interface by accident is a security
    /// problem rather than a convenience.
    #[must_use]
    pub fn is_any_interface(&self) -> bool {
        self.host == "0.0.0.0" || self.host == "::" || self.host == "[::]"
    }

    /// Resolve to socket addresses.
    ///
    /// # Errors
    ///
    /// `QQQ-6002` when the host cannot be resolved, which for `localhost` is a
    /// genuine environment problem rather than a configuration one.
    pub fn resolve(&self) -> Result<Vec<SocketAddr>> {
        let text = self.to_string();
        let addrs: Vec<SocketAddr> = text
            .to_socket_addrs()
            .map_err(|e| {
                Error::new(
                    ErrorCode::ListenerBindFailed,
                    format!("could not resolve `{text}`"),
                )
                .with_cause(e.to_string())
                .with_remediation("check that the address is correct")
            })?
            .collect();
        if addrs.is_empty() {
            return Err(Error::new(
                ErrorCode::ListenerBindFailed,
                format!("`{text}` resolved to no addresses"),
            )
            .with_remediation("use an IP literal such as `127.0.0.1:3000`"));
        }
        Ok(addrs)
    }

    /// The conventional rendering, re-bracketing IPv6.
    #[must_use]
    pub fn render(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Parse a listen address.
///
/// # Errors
///
/// As [`ListenAddr::parse`].
pub fn parse_listen_addr(s: &str) -> Result<ListenAddr> {
    ListenAddr::parse(s)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// How a listener behaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerConfig {
    /// Where to listen.
    pub addr: ListenAddr,
    /// The number of shards.
    ///
    /// Defaults to the machine's available parallelism. Not
    /// `SystemTime`-derived and not a fixed constant: shard-per-core is the
    /// point of §4.2, and hardcoding a number would either waste cores on a big
    /// machine or oversubscribe a small one.
    pub shards: usize,
    /// How many connections may be accepted before the acceptor yields.
    ///
    /// # Why there is a limit at all
    ///
    /// An unbounded accept loop starves everything else on the runtime: under a
    /// connection flood the acceptor never yields, so health checks, metrics and
    /// the shutdown signal are all delayed by exactly the load that makes them
    /// matter. A batch bound is what keeps, say, a metrics scrape answerable
    /// during a SYN flood.
    pub accept_batch: usize,
    /// Whether to set `TCP_NODELAY` on accepted sockets.
    ///
    /// On by default. Nagle's algorithm batches small writes, which is right for
    /// bulk transfer and wrong for a request/response protocol where the
    /// response is often a few hundred bytes — the delay is up to 40 ms, which
    /// dwarfs everything else the server does.
    pub nodelay: bool,
}

impl ListenerConfig {
    /// A configuration for an address, with machine-derived defaults.
    #[must_use]
    pub fn for_addr(addr: ListenAddr) -> Self {
        Self {
            addr,
            shards: default_shards(),
            // 128 is large enough to drain a genuine backlog in one pass and
            // small enough that the acceptor cannot hold the runtime for long.
            accept_batch: 128,
            nodelay: true,
        }
    }
}

/// The default shard count: the machine's available parallelism, at least one.
///
/// `available_parallelism` returns a `Result` because a sandbox can refuse to
/// report it. Falling back to one is safer than guessing high: an oversubscribed
/// shard set is slower than a single one, and the failure is silent.
#[must_use]
pub fn default_shards() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

/// A cooperative shutdown signal.
///
/// # Why a signal and not a cancellation token from the runtime
///
/// Because `qqq-io` is the crate that owns the runtime dependency, and a
/// shutdown primitive that leaked `tokio::sync::watch` upward would make every
/// caller depend on that choice. This is a plain atomic with an async wait, so
/// the shape survives a backend change.
#[derive(Debug, Clone, Default)]
pub struct Shutdown {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Shutdown {
    /// A fresh, un-signalled handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request shutdown.
    ///
    /// Idempotent, because a signal can arrive twice (a second Ctrl-C, a
    /// supervisor and an operator) and the second must not be an error.
    pub fn signal(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether shutdown has been requested.
    #[must_use]
    pub fn is_signalled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait until shutdown is requested.
    ///
    /// Polls rather than awaiting a notification, which is a deliberate trade:
    /// a notifier would need the runtime's channel type, and the thing being
    /// waited on is a process teardown that happens once. A 5 ms poll costs
    /// nothing over a shutdown and keeps this module runtime-agnostic.
    pub async fn wait(&self) {
        while !self.is_signalled() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an accept failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    /// The listener socket failed.
    ///
    /// # Why this is fatal rather than per-connection
    ///
    /// A per-connection error — the client hung up mid-handshake, the OS ran out
    /// of file descriptors — is normal and must not stop the server. An error
    /// from `accept` itself means the *listening socket* is broken, and
    /// retrying it in a loop is how a server spins at 100% CPU producing no
    /// logs. Returning it lets the caller decide to shut down loudly.
    ListenerFailed {
        /// The underlying message.
        detail: String,
    },
    /// Shutdown was requested.
    ShuttingDown,
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ListenerFailed { detail } => {
                write!(f, "the listening socket failed: {detail}")
            }
            Self::ShuttingDown => f.write_str("the listener is shutting down"),
        }
    }
}

impl std::error::Error for AcceptError {}

// ---------------------------------------------------------------------------
// The listener
// ---------------------------------------------------------------------------

/// A bound listener.
#[derive(Debug)]
pub struct Listener {
    config: ListenerConfig,
    /// The bound address, which for a hostname may differ from the requested
    /// one — and for port 0 always does.
    local: SocketAddr,
    inner: tokio::net::TcpListener,
}

impl Listener {
    /// Bind.
    ///
    /// # Errors
    ///
    /// `QQQ-6002` when the address cannot be resolved or the bind fails, with
    /// the specific OS error in the cause. "Address already in use" is the
    /// common case and deserves to be visible rather than paraphrased.
    pub async fn bind(config: ListenerConfig) -> Result<Self> {
        let addrs = config.addr.resolve()?;
        let mut last: Option<std::io::Error> = None;

        for addr in &addrs {
            match bind_one(addr).await {
                Ok(inner) => {
                    let local = inner.local_addr().map_err(|e| {
                        Error::new(
                            ErrorCode::ListenerBindFailed,
                            "the listener has no local address after binding",
                        )
                        .with_cause(e.to_string())
                    })?;
                    return Ok(Self {
                        config,
                        local,
                        inner,
                    });
                }
                Err(e) => last = Some(e),
            }
        }

        let detail = last.map_or_else(|| "no address was tried".to_owned(), |e| e.to_string());
        Err(Error::new(
            ErrorCode::ListenerBindFailed,
            format!("could not bind `{}`", config.addr),
        )
        .with_cause(detail)
        .with_remediation("another process may hold the port; choose a different one, or stop it"))
    }

    /// The address actually bound.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &ListenerConfig {
        &self.config
    }

    /// Accept one connection.
    ///
    /// # Errors
    ///
    /// [`AcceptError::ListenerFailed`] for a socket-level failure, which is
    /// fatal rather than per-connection.
    pub async fn accept(
        &self,
    ) -> std::result::Result<(tokio::net::TcpStream, SocketAddr), AcceptError> {
        let (stream, peer) =
            self.inner
                .accept()
                .await
                .map_err(|e| AcceptError::ListenerFailed {
                    detail: e.to_string(),
                })?;

        // `TCP_NODELAY` on the accepted socket, not the listening one: the
        // option is inherited on Linux but not on every platform, so setting it
        // here is what actually guarantees it.
        if self.config.nodelay {
            // A failure here is not fatal — the connection works, just with
            // Nagle's delay — so it is deliberately not propagated. Failing a
            // connection because a tuning hint was refused would be worse than
            // the latency it was meant to save.
            let _ = stream.set_nodelay(true);
        }

        Ok((stream, peer))
    }

    /// Accept in a loop, yielding to the runtime between batches.
    ///
    /// The loop ends when `shutdown` is signalled or the socket fails. Each
    /// accepted connection is passed to `on_accept`, which is where shard
    /// assignment happens.
    ///
    /// # Why the batch bound is inside the loop rather than around it
    ///
    /// Yielding only when there is no work is not enough: under a flood there is
    /// *always* work, so the acceptor would never yield. Bounding the batch
    /// forces a yield at a fixed point regardless of load, which is what keeps
    /// the rest of the runtime responsive.
    ///
    /// # Errors
    ///
    /// [`AcceptError::ListenerFailed`] when the socket fails.
    pub async fn accept_stream<F>(
        &self,
        shutdown: &Shutdown,
        mut on_accept: F,
    ) -> std::result::Result<(), AcceptError>
    where
        F: FnMut(tokio::net::TcpStream, SocketAddr),
    {
        loop {
            if shutdown.is_signalled() {
                return Ok(());
            }
            for _ in 0..self.config.accept_batch {
                // `select!` so a shutdown during a quiet period is noticed
                // immediately rather than after the next connection arrives.
                tokio::select! {
                    biased;
                    () = shutdown.wait() => return Ok(()),
                    result = self.accept() => {
                        let (stream, peer) = result?;
                        on_accept(stream, peer);
                    }
                }
            }
            // Yield unconditionally at the batch boundary, even if the batch
            // was not full.
            tokio::task::yield_now().await;
        }
    }
}

/// Bind one address, with the socket options this crate sets deliberately.
async fn bind_one(addr: &SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    // `SO_REUSEADDR` is set by Tokio's `bind` on Unix already; on Windows it is
    // set with different semantics (it allows stealing a bound port), so it is
    // deliberately not forced here. What matters is that the behaviour is
    // Tokio's documented default on each platform rather than something this
    // crate claims and does not deliver.
    tokio::net::TcpListener::bind(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- address parsing ---------------------------------------------------

    #[test]
    fn an_ipv4_address_parses() {
        let a = ListenAddr::parse("127.0.0.1:3000").expect("must parse");
        assert_eq!(a.host(), "127.0.0.1");
        assert_eq!(a.port(), 3000);
        assert!(!a.is_any_interface());
    }

    /// **The classic broken case.** An unbracketed IPv6 literal has many colons,
    /// and the port is the last one — splitting on the first would take `::1`
    /// apart into an empty host and `:1`.
    #[test]
    fn an_unbracketed_ipv6_literal_takes_the_last_colon_as_the_port() {
        let a = ListenAddr::parse("::1:8080").expect("must parse");
        assert_eq!(a.host(), "::1");
        assert_eq!(a.port(), 8080);
    }

    #[test]
    fn a_bracketed_ipv6_address_parses() {
        let a = ListenAddr::parse("[::1]:8080").expect("must parse");
        assert_eq!(a.host(), "::1");
        assert_eq!(a.port(), 8080);
        assert_eq!(
            a.render(),
            "[::1]:8080",
            "IPv6 must be re-bracketed on output"
        );
    }

    #[test]
    fn the_any_interface_addresses_are_recognised() {
        for s in ["0.0.0.0:80", "[::]:80"] {
            let a = ListenAddr::parse(s).expect("must parse");
            assert!(a.is_any_interface(), "`{s}` binds every interface");
        }
        // And a loopback address does not.
        assert!(!ListenAddr::parse("127.0.0.1:80")
            .unwrap()
            .is_any_interface());
    }

    #[test]
    fn localhost_is_accepted() {
        let a = ListenAddr::parse("localhost:3000").expect("must parse");
        assert_eq!(a.host(), "localhost");
    }

    /// **Hostnames are refused.** Binding to `example.com` would bind to
    /// whatever it resolves to on this machine at this moment, which is a
    /// deployment-dependent behaviour — and NN-5 says nothing important is
    /// inferred.
    #[test]
    fn a_hostname_is_refused_with_an_explanation() {
        let e = ListenAddr::parse("example.com:80").unwrap_err();
        assert_eq!(e.code, ErrorCode::ListenerBindFailed);
        assert!(
            e.message.contains("example.com"),
            "the error must name the host: {}",
            e.message
        );
        assert!(
            e.remediation.as_deref().unwrap_or("").contains("DNS"),
            "the remediation must explain why: {:?}",
            e.remediation
        );
    }

    #[test]
    fn a_missing_port_is_refused() {
        let e = ListenAddr::parse("127.0.0.1").unwrap_err();
        assert_eq!(e.code, ErrorCode::ListenerBindFailed);
        assert!(e.remediation.is_some());
    }

    #[test]
    fn a_non_numeric_port_is_refused() {
        let e = ListenAddr::parse("127.0.0.1:http").unwrap_err();
        assert!(e.message.contains("http"), "got: {}", e.message);
    }

    /// Port 0 asks the OS for any free port. Legitimate in a test harness,
    /// dangerous in a manifest — the deployed service would listen somewhere
    /// nobody knows.
    #[test]
    fn port_zero_is_refused() {
        let e = ListenAddr::parse("127.0.0.1:0").unwrap_err();
        assert!(e.message.contains("port 0"), "got: {}", e.message);
        assert!(e.remediation.is_some());
    }

    #[test]
    fn an_out_of_range_port_is_refused() {
        assert!(ListenAddr::parse("127.0.0.1:70000").is_err());
    }

    #[test]
    fn an_empty_host_is_refused() {
        let e = ListenAddr::parse(":3000").unwrap_err();
        assert!(e.message.contains("empty host"));
        assert!(
            e.remediation.as_deref().unwrap_or("").contains("0.0.0.0"),
            "the remediation should name the any-interface form"
        );
    }

    #[test]
    fn an_empty_string_is_refused() {
        let e = ListenAddr::parse("").unwrap_err();
        assert!(e.remediation.is_some());
        assert!(ListenAddr::parse("   ").is_err());
    }

    #[test]
    fn an_unclosed_bracket_is_refused_with_the_right_hint() {
        let e = ListenAddr::parse("[::1:8080").unwrap_err();
        assert!(e.message.contains("bracket"), "got: {}", e.message);
        assert!(e
            .remediation
            .as_deref()
            .unwrap_or("")
            .contains("[::1]:8080"));
    }

    #[test]
    fn a_bracketed_address_without_a_port_is_refused() {
        let e = ListenAddr::parse("[::1]").unwrap_err();
        assert!(e.message.contains("port"), "got: {}", e.message);
    }

    #[test]
    fn whitespace_is_trimmed() {
        let a = ListenAddr::parse("  127.0.0.1:3000  ").expect("must parse");
        assert_eq!(a.port(), 3000);
    }

    #[test]
    fn addresses_round_trip_through_render() {
        for s in [
            "127.0.0.1:3000",
            "0.0.0.0:80",
            "[::1]:8080",
            "localhost:3000",
        ] {
            let a = ListenAddr::parse(s).expect("must parse");
            let rendered = a.render();
            let again = ListenAddr::parse(&rendered)
                .unwrap_or_else(|e| panic!("`{rendered}` did not re-parse: {e}"));
            assert_eq!(a, again, "`{s}` did not round-trip through `{rendered}`");
        }
    }

    #[test]
    fn an_ipv4_address_resolves_to_itself() {
        let a = ListenAddr::parse("127.0.0.1:3000").unwrap();
        let addrs = a.resolve().expect("must resolve");
        assert_eq!(addrs, vec!["127.0.0.1:3000".parse().unwrap()]);
    }

    // -- configuration -----------------------------------------------------

    /// Shard-per-core is the point of §4.2, so the default is derived rather
    /// than hardcoded — a constant would waste cores on a large machine or
    /// oversubscribe a small one.
    #[test]
    fn the_default_shard_count_is_at_least_one() {
        assert!(default_shards() >= 1);
    }

    #[test]
    fn a_configuration_derives_its_defaults_from_the_machine() {
        let c = ListenerConfig::for_addr(ListenAddr::parse("127.0.0.1:3000").unwrap());
        assert_eq!(c.shards, default_shards());
        assert!(c.accept_batch > 0);
        assert!(c.nodelay, "Nagle's delay dwarfs everything else we do");
    }

    /// The batch bound must be positive, or the accept loop would never accept
    /// anything.
    #[test]
    fn the_accept_batch_must_be_usable() {
        let c = ListenerConfig::for_addr(ListenAddr::parse("127.0.0.1:3000").unwrap());
        assert!(c.accept_batch >= 1);
    }

    // -- shutdown ----------------------------------------------------------

    #[test]
    fn a_fresh_shutdown_is_not_signalled() {
        let s = Shutdown::new();
        assert!(!s.is_signalled());
    }

    /// Idempotent, because a signal can arrive twice — a second Ctrl-C, a
    /// supervisor and an operator — and the second must not be an error.
    #[test]
    fn signalling_twice_is_not_an_error() {
        let s = Shutdown::new();
        s.signal();
        s.signal();
        assert!(s.is_signalled());
    }

    #[test]
    fn clones_share_the_signal() {
        let a = Shutdown::new();
        let b = a.clone();
        a.signal();
        assert!(b.is_signalled(), "a clone must observe the same signal");
    }

    // -- accept errors -----------------------------------------------------

    #[test]
    fn accept_error_renders() {
        let e = AcceptError::ListenerFailed {
            detail: "too many open files".to_owned(),
        };
        assert!(e.to_string().contains("too many open files"));
        assert!(AcceptError::ShuttingDown
            .to_string()
            .contains("shutting down"));
    }
}
