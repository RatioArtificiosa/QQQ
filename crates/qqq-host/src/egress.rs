// SPDX-License-Identifier: Apache-2.0

//! The SSRF-safe egress connector (`I-01`): the only guest-reachable path
//! that turns a URL into a connected socket.
//!
//! The capability engine (`qqq_cap::egress`) decides *whether* a tenant may
//! reach a destination. This module decides *how* a permitted destination is
//! reached without letting the network answer change the question: parse
//! strictly, resolve once, vet every address, and connect to the vetted
//! address — never re-resolve, never filter-and-continue past a forbidden
//! address, never follow a redirect without re-vetting.
//!
//! # What lives here and what does not
//!
//! The pure vetting half comes first: the forbidden-IP tables, the
//! injectable [`Resolver`], and [`vet`], which reduces a URL string to a
//! [`Vetted`] address or a [`Refusal`]. The I/O half below builds on it:
//! [`Transport::open`] dials only a [`Vetted`] address, [`exchange`]
//! speaks one HTTP/1.1 round trip with caps, and [`request`] ties
//! vet-transport-exchange-audit together. Vetting first means the I/O
//! layer cannot be written to skip it, because there is no other
//! constructor for the address it dials.
//!
//! # Why canonical mapping comes first
//!
//! An IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) is *textually* IPv6 and
//! *routably* IPv4 loopback. Checking the v6 table first would pass it —
//! `::ffff:0:0/96` is not in any forbidden v6 range — and the loopback
//! would sail through. [`IpAddr::to_canonical`] maps it to IPv4 before any
//! table sees it, so every textual disguise of a forbidden address lands
//! in the table that forbids it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use qqq_cap::egress::TenantEgress;

/// Whether an address may never be dialled for a guest (`I-01`).
///
/// Canonical mapping first, then the family table: see the module docs for
/// why the order is the property, not an optimisation.
///
/// ```
/// use std::net::IpAddr;
/// use qqq_host::egress::is_forbidden_ip;
///
/// // The classics are forbidden ...
/// assert!(is_forbidden_ip("127.0.0.1".parse().unwrap()));
/// assert!(is_forbidden_ip("169.254.169.254".parse().unwrap()));
/// // ... and the disguises land in the same tables.
/// let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
/// assert!(is_forbidden_ip(mapped));
/// ```
///
/// ```
/// use qqq_host::egress::is_forbidden_ip;
///
/// // Public addresses pass: the connector must still be able to dial
/// // the public internet for a permitted tenant.
/// assert!(!is_forbidden_ip("8.8.8.8".parse().unwrap()));
/// assert!(!is_forbidden_ip("2606:4700:4700::1111".parse().unwrap()));
/// ```
#[must_use]
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    // Destructured, never indexed: `indexing_slicing` is deny in this
    // crate, and an octet read is exactly what destructuring is for.
    let [a, b, c, _d] = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (b & 0xC0) == 64)
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b & 0xFE) == 18)
        || a >= 240
}

fn forbidden_v6(ip: Ipv6Addr) -> bool {
    let [s0, s1, ..] = ip.segments();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s0 & 0xFFC0) == 0xFE80
        || (s0 & 0xFE00) == 0xFC00
        || (s0 == 0x2001 && s1 == 0x0DB8)
        || (s0 == 0x2001 && s1 == 0)
        || s0 == 0x2002
        || (s0 == 0x0064 && s1 == 0xFF9B)
}

/// How the connector learns addresses: one call, behind a trait (`I-01`).
///
/// The trait exists so tests prove resolve-once with a counting fake
/// instead of needing DNS: a fake that returns a public address first and
/// a private address on a *second* lookup must never see that second call,
/// because the connector resolves once and vets every answer.
///
/// ```
/// use qqq_host::egress::Resolver;
///
/// struct Never;
///
/// impl Resolver for Never {
///     async fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
///         Ok(Vec::new())
///     }
/// }
/// ```
pub trait Resolver {
    /// Resolve `host` to its addresses, exactly once per vetting.
    fn resolve(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = std::io::Result<Vec<IpAddr>>>;
}

/// A URL reduced to the one address the connector may dial (`I-01`).
///
/// There is no other constructor for a diallable address: the I/O layer
/// takes [`Vetted`], so vetting cannot be skipped by construction.
///
/// ```
/// use qqq_host::egress::{Resolver, vet};
/// use qqq_cap::egress::TenantEgress;
///
/// struct Localhost;
///
/// impl Resolver for Localhost {
///     async fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
///         Ok(vec!["93.184.216.34".parse().unwrap()])
///     }
/// }
///
/// let policy = TenantEgress::allowing_hosts(&["example.com"]).unwrap();
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .enable_all()
///     .build()
///     .unwrap();
/// let vetted = rt.block_on(vet(&policy, "https://example.com/", &Localhost)).unwrap();
/// assert_eq!(vetted.addr.ip().to_string(), "93.184.216.34");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vetted {
    /// The one vetted address, with the URL's port.
    ///
    /// ```
    /// use qqq_host::egress::{Resolver, vet};
    /// use qqq_cap::egress::TenantEgress;
    ///
    /// struct Localhost;
    ///
    /// impl Resolver for Localhost {
    ///     async fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
    ///         Ok(vec!["93.184.216.34".parse().unwrap()])
    ///     }
    /// }
    ///
    /// let policy = TenantEgress::allowing_hosts(&["example.com"]).unwrap();
    /// let rt = tokio::runtime::Builder::new_current_thread()
    ///     .enable_all()
    ///     .build()
    ///     .unwrap();
    /// let vetted = rt.block_on(vet(&policy, "https://example.com/", &Localhost)).unwrap();
    /// assert_eq!(vetted.addr.port(), 443);
    /// ```
    pub addr: SocketAddr,
    /// The normalised host the address was vetted for (lower-cased ASCII,
    /// IDNA already applied by the URL parser) — the SNI and audit value.
    ///
    /// ```
    /// use qqq_host::egress::{Resolver, vet};
    /// use qqq_cap::egress::TenantEgress;
    ///
    /// struct Localhost;
    ///
    /// impl Resolver for Localhost {
    ///     async fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
    ///         Ok(vec!["93.184.216.34".parse().unwrap()])
    ///     }
    /// }
    ///
    /// let policy = TenantEgress::allowing_hosts(&["example.com"]).unwrap();
    /// let rt = tokio::runtime::Builder::new_current_thread()
    ///     .enable_all()
    ///     .build()
    ///     .unwrap();
    /// let vetted = rt.block_on(vet(&policy, "https://EXAMPLE.com/", &Localhost)).unwrap();
    /// assert_eq!(vetted.host, "example.com");
    /// ```
    pub host: String,
    /// Whether the URL demanded TLS — the I/O layer's branch condition.
    ///
    /// ```
    /// use qqq_host::egress::{Resolver, vet};
    /// use qqq_cap::egress::TenantEgress;
    ///
    /// struct Localhost;
    ///
    /// impl Resolver for Localhost {
    ///     async fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
    ///         Ok(vec!["93.184.216.34".parse().unwrap()])
    ///     }
    /// }
    ///
    /// let policy = TenantEgress::allowing_hosts(&["example.com"]).unwrap();
    /// let rt = tokio::runtime::Builder::new_current_thread()
    ///     .enable_all()
    ///     .build()
    ///     .unwrap();
    /// let vetted = rt.block_on(vet(&policy, "https://example.com/", &Localhost)).unwrap();
    /// assert!(vetted.tls);
    /// ```
    pub tls: bool,
}

/// Why a URL was refused before any socket opened (`I-01`).
///
/// The messages name the *reason*, never the URL: a URL routinely carries
/// credentials (userinfo, presigned queries) and refusals reach logs.
/// Where the host is safe to name (it matched or failed an allowlist of
/// names), the variant carries it; otherwise only the kind travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The string is not a parseable URL.
    Malformed,
    /// A `user:pass@` authority — credentials never travel.
    Userinfo,
    /// A scheme outside the grant (`http` without the cleartext opt-in,
    /// anything else always).
    Scheme,
    /// No host to vet (empty authority).
    EmptyHost,
    /// A literal IP the grant does not cover with `allowing_ip_literals`.
    IpLiteral,
    /// A name (or literal) outside the tenant's allowlist.
    NotAllowed,
    /// The single resolution failed.
    Dns,
    /// At least one resolved address is forbidden — the whole request is
    /// refused, never filtered-and-continued, because a rebinding attacker
    /// mixes addresses. Carries the offending address, which is safe: it
    /// is an address, never a credential.
    Forbidden {
        /// The forbidden address that refused the request.
        ip: IpAddr,
    },
    /// The resolver answered, but with no addresses at all.
    NoAddresses,
}

/// Reduce a URL string to the one address the connector may dial (`I-01`).
///
/// Parse strictly, check the grant, resolve once, vet every address, and
/// refuse on any forbidden one. The single resolution is the rebinding
/// defence: the socket this returns is built from these exact bytes, and
/// a second lookup — which could answer differently — never happens.
///
/// # Errors
///
/// Returns the [`Refusal`] for the first vetting step that fails, in the
/// order documented on the type: malformed URL, userinfo, scheme, host
/// shape, grant, DNS, forbidden address, or empty answer. No socket opens
/// on any path — every error returns before resolution except [`Refusal::Dns`],
/// [`Refusal::Forbidden`], and [`Refusal::NoAddresses`], which return after
/// the single lookup.
///
/// ```
/// use qqq_host::egress::{Refusal, Resolver, vet};
/// use qqq_cap::egress::TenantEgress;
///
/// struct Poisoned;
///
/// impl Resolver for Poisoned {
///     async fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
///         // A rebinding attacker mixing a public address with a private one.
///         Ok(vec!["93.184.216.34".parse().unwrap(), "10.0.0.1".parse().unwrap()])
///     }
/// }
///
/// let policy = TenantEgress::allowing_hosts(&["example.com"]).unwrap();
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .enable_all()
///     .build()
///     .unwrap();
/// let err = rt.block_on(vet(&policy, "https://example.com/", &Poisoned)).unwrap_err();
/// // Refused, not filtered: the public address does not save the request.
/// assert!(matches!(err, Refusal::Forbidden { .. }));
/// ```
///
/// ```
/// use qqq_host::egress::{Resolver, vet};
/// use qqq_cap::egress::TenantEgress;
///
/// struct Never;
///
/// impl Resolver for Never {
///     async fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
///         Ok(Vec::new())
///     }
/// }
///
/// // Userinfo never travels, even to an allowed host.
/// let policy = TenantEgress::allowing_hosts(&["example.com"]).unwrap();
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .enable_all()
///     .build()
///     .unwrap();
/// let err = rt
///     .block_on(vet(&policy, "https://user:pass@example.com/", &Never))
///     .unwrap_err();
/// assert_eq!(format!("{err:?}"), "Userinfo");
/// ```
pub async fn vet(
    policy: &TenantEgress,
    url: &str,
    resolver: &impl Resolver,
) -> Result<Vetted, Refusal> {
    let parsed = url::Url::parse(url).map_err(|_| Refusal::Malformed)?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Refusal::Userinfo);
    }
    let tls = match parsed.scheme() {
        "https" => true,
        "http" if policy.allows_cleartext() => false,
        _ => return Err(Refusal::Scheme),
    };
    let host = parsed.host_str().ok_or(Refusal::EmptyHost)?;
    // The url crate already lower-cased the domain and applied IDNA: what
    // `host` holds is the normalised ASCII form the allowlist matches on.
    // A homograph not in the allowlist fails the match below — punycode is
    // compared, never decoded for display. Numeric shorthand (`https://12345/`,
    // `https://0x7f.1/`) never reaches this string test as written: WHATWG
    // parsing already normalised it to dotted IPv4, so it takes the literal
    // path below — which never touches DNS at all.
    let port = parsed.port_or_known_default().ok_or(Refusal::Scheme)?;
    match parsed.host() {
        Some(url::Host::Domain(_)) => {
            if policy.permits(host, port).is_none() {
                return Err(Refusal::NotAllowed);
            }
        }
        // A literal bypasses DNS and therefore the allowlist: it needs the
        // explicit opt-in, and even then the address below still passes the
        // forbidden table (a granted loopback stays refused). Literals are
        // vetted WITHOUT resolving — passing a literal to DNS would let
        // search domains expand it into a different host than written.
        Some(url::Host::Ipv4(v4)) => {
            if !policy.allows_ip_literals() {
                return Err(Refusal::IpLiteral);
            }
            let ip = IpAddr::V4(v4);
            if is_forbidden_ip(ip) {
                return Err(Refusal::Forbidden { ip });
            }
            return Ok(Vetted {
                addr: SocketAddr::new(ip, port),
                host: host.to_owned(),
                tls,
            });
        }
        Some(url::Host::Ipv6(v6)) => {
            if !policy.allows_ip_literals() {
                return Err(Refusal::IpLiteral);
            }
            let ip = IpAddr::V6(v6);
            if is_forbidden_ip(ip) {
                return Err(Refusal::Forbidden { ip });
            }
            return Ok(Vetted {
                addr: SocketAddr::new(ip, port),
                host: host.to_owned(),
                tls,
            });
        }
        None => return Err(Refusal::EmptyHost),
    }
    // Resolve ONCE. Everything after this line works from `addrs`, and no
    // second lookup exists to answer differently mid-request.
    let addrs = resolver.resolve(host).await.map_err(|_| Refusal::Dns)?;
    if addrs.is_empty() {
        return Err(Refusal::NoAddresses);
    }
    // EVERY address is vetted and ANY forbidden one refuses the request.
    // Filtering-and-continuing would let a rebinding attacker mix one
    // public address (to pass) with one private address (to hit).
    if let Some(ip) = addrs.iter().find(|ip| is_forbidden_ip(**ip)) {
        return Err(Refusal::Forbidden { ip: *ip });
    }
    let first = addrs.into_iter().next().ok_or(Refusal::NoAddresses)?;
    Ok(Vetted {
        addr: SocketAddr::new(first, port),
        host: host.to_owned(),
        tls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit's forbidden table, verbatim: every row must refuse.
    #[test]
    fn i01_forbidden_addresses() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "198.18.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "64:ff9b::7f00:1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            let ip: IpAddr = s.parse().expect("the table holds parseable addresses");
            assert!(is_forbidden_ip(ip), "{s} must be forbidden");
        }
    }

    /// The audit's allowed table, verbatim: public addresses must pass.
    #[test]
    fn i01_public_addresses_are_allowed() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2a00:1450:4001:81a::200e",
        ] {
            let ip: IpAddr = s.parse().expect("the table holds parseable addresses");
            assert!(!is_forbidden_ip(ip), "{s} must be allowed");
        }
    }

    struct Fake {
        answers: Vec<IpAddr>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Fake {
        fn answering(addrs: &[&str]) -> Self {
            Self {
                answers: addrs
                    .iter()
                    .map(|s| s.parse().expect("fake answers parse"))
                    .collect(),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl Resolver for Fake {
        // Synchronous body behind the async trait: a fake has no I/O to
        // await, and manufacturing a timer just to satisfy the lint would
        // be theater — the `async` is the trait's contract, not this impl's.
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "fake resolver has no I/O to await; async satisfies the Resolver contract"
        )]
        async fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.answers.clone())
        }
    }

    fn policy() -> TenantEgress {
        TenantEgress::allowing_hosts(&["example.com"]).expect("the fixture parses")
    }

    /// Mixed answers refuse: the public address does not launder the private one.
    #[tokio::test]
    async fn mixed_public_and_private_answers_are_refused() {
        let fake = Fake::answering(&["93.184.216.34", "10.0.0.1"]);
        let err = vet(&policy(), "https://example.com/", &fake)
            .await
            .expect_err("a mixed answer must refuse");
        assert_eq!(
            err,
            Refusal::Forbidden {
                ip: "10.0.0.1".parse().expect("fixture parses")
            }
        );
        // And the refusal cost exactly one resolution: a second lookup that
        // could answer differently never happens.
        assert_eq!(fake.calls(), 1, "the connector resolves once");
    }

    /// A second lookup that answers differently is never consulted, period:
    /// even when every answer is forbidden, the count stays one.
    #[tokio::test]
    async fn a_forbidden_answer_costs_no_second_lookup() {
        let fake = Fake::answering(&["10.0.0.1"]);
        let _ = vet(&policy(), "https://example.com/", &fake).await;
        assert_eq!(fake.calls(), 1, "the connector resolves once");
    }

    /// The happy path vets to the first allowed address with the URL's port.
    #[tokio::test]
    async fn an_allowed_host_vets_to_its_address() {
        let fake = Fake::answering(&["93.184.216.34"]);
        let vetted = vet(&policy(), "https://example.com/", &fake)
            .await
            .expect("an allowed host vets");
        assert_eq!(
            vetted.addr,
            "93.184.216.34:443".parse().expect("fixture parses")
        );
        assert_eq!(vetted.host, "example.com");
        assert!(vetted.tls);
    }

    /// Userinfo never travels, even to an allowed host.
    #[tokio::test]
    async fn userinfo_is_refused() {
        let fake = Fake::answering(&["93.184.216.34"]);
        let err = vet(&policy(), "https://user:pass@example.com/", &fake)
            .await
            .expect_err("userinfo must refuse");
        assert_eq!(err, Refusal::Userinfo);
        assert_eq!(fake.calls(), 0, "refusal precedes resolution");
    }

    /// An IDN homograph not in the allowlist is refused: punycode is compared.
    #[tokio::test]
    async fn an_ungranted_homograph_is_refused() {
        let fake = Fake::answering(&["93.184.216.34"]);
        let err = vet(&policy(), "https://xn--exmple-cua.com/", &fake)
            .await
            .expect_err("an ungranted homograph must refuse");
        assert_eq!(err, Refusal::NotAllowed);
    }

    /// The metadata endpoint is refused three ways: cleartext without the
    /// opt-in stops at the scheme, a literal without the literals opt-in
    /// stops at the literal check, and with both opt-ins the address itself
    /// is still forbidden — a granted loopback stays refused.
    #[tokio::test]
    async fn metadata_literal_is_refused_all_ways() {
        let fake = Fake::answering(&["169.254.169.254"]);
        let err = vet(&policy(), "http://169.254.169.254/", &fake)
            .await
            .expect_err("cleartext needs the opt-in");
        assert_eq!(err, Refusal::Scheme);
        let err = vet(&policy(), "https://169.254.169.254/", &fake)
            .await
            .expect_err("a literal needs the opt-in");
        assert_eq!(err, Refusal::IpLiteral);
        let open = TenantEgress::allowing_hosts(&["example.com"])
            .expect("fixture parses")
            .allowing_ip_literals()
            .allowing_cleartext();
        let err = vet(&open, "http://169.254.169.254/", &fake)
            .await
            .expect_err("link-local stays forbidden");
        assert_eq!(
            err,
            Refusal::Forbidden {
                ip: "169.254.169.254".parse().expect("fixture parses")
            }
        );
    }

    /// A port overflow is malformed, not a destination.
    #[tokio::test]
    async fn a_cap_overflow_port_is_malformed() {
        let fake = Fake::answering(&["93.184.216.34"]);
        let err = vet(&policy(), "https://example.com:99999/", &fake)
            .await
            .expect_err("port 99999 must refuse");
        assert_eq!(err, Refusal::Malformed);
        assert_eq!(fake.calls(), 0, "refusal precedes resolution");
    }

    /// Numeric shorthand normalises to a literal and refuses without the
    /// opt-in — `https://12345/` is WHATWG-parsed to `0.0.48.57`, which
    /// takes the literal path (never DNS, so no search-domain expansion
    /// into a different host than written). With the opt-in it is still
    /// forbidden (`0.0.0.0/8`).
    #[tokio::test]
    async fn numeric_shorthand_is_a_literal_and_refuses() {
        let fake = Fake::answering(&["93.184.216.34"]);
        let err = vet(&policy(), "https://12345/", &fake)
            .await
            .expect_err("numeric shorthand must refuse");
        assert_eq!(err, Refusal::IpLiteral);
        assert_eq!(fake.calls(), 0, "literals never touch DNS");
        let open = TenantEgress::allowing_hosts(&["example.com"])
            .expect("fixture parses")
            .allowing_ip_literals();
        let err = vet(&open, "https://12345/", &fake)
            .await
            .expect_err("0.0.48.57 stays forbidden");
        assert_eq!(
            err,
            Refusal::Forbidden {
                ip: "0.0.48.57".parse().expect("fixture parses")
            }
        );
        assert_eq!(fake.calls(), 0, "literals never touch DNS");
    }

    /// An empty answer is its own refusal, distinct from forbidden.
    #[tokio::test]
    async fn an_empty_answer_is_refused() {
        let fake = Fake::answering(&[]);
        let err = vet(&policy(), "https://example.com/", &fake)
            .await
            .expect_err("no addresses must refuse");
        assert_eq!(err, Refusal::NoAddresses);
    }
}

// ---------------------------------------------------------------------------
// I/O half: dial the vetted address, speak one capped round trip, audit it.
// ---------------------------------------------------------------------------

/// Budgets for one egress call (`I-01`).
///
/// Every number bounds a distinct attacker-controlled resource: hangs
/// (timeouts), header bombs (counts and bytes), and body bombs (bytes).
/// Redirects are gated twice: the tenant grant
/// (`TenantEgress::max_redirect_hops`) authorises and this
/// `max_redirects` operates — [`request`] follows the minimum of the
/// two under [`REDIRECT_HOP_LIMIT`], re-vetting every hop.
///
/// ```
/// use qqq_host::egress::Limits;
///
/// let limits = Limits::default();
/// assert_eq!(limits.max_redirects, 0, "redirects stay off until a grant exists");
/// assert!(limits.max_body_bytes > 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// TCP connect timeout.
    ///
    /// ```
    /// use qqq_host::egress::Limits;
    ///
    /// assert!(Limits::default().connect_timeout.as_secs() > 0);
    /// ```
    pub connect_timeout: std::time::Duration,
    /// TLS handshake timeout.
    ///
    /// ```
    /// use qqq_host::egress::Limits;
    ///
    /// assert!(Limits::default().tls_timeout.as_secs() > 0);
    /// ```
    pub tls_timeout: std::time::Duration,
    /// Total timeout around the whole call (connect through body).
    ///
    /// ```
    /// use qqq_host::egress::Limits;
    ///
    /// assert!(Limits::default().total_timeout >= Limits::default().connect_timeout);
    /// ```
    pub total_timeout: std::time::Duration,
    /// Maximum request headers the connector will write.
    ///
    /// ```
    /// use qqq_host::egress::Limits;
    ///
    /// assert!(Limits::default().max_request_headers > 0);
    /// ```
    pub max_request_headers: usize,
    /// Maximum request bytes (head plus body) the connector will write.
    ///
    /// ```
    /// use qqq_host::egress::Limits;
    ///
    /// assert!(Limits::default().max_request_bytes > 0);
    /// ```
    pub max_request_bytes: u64,
    /// Maximum response headers the connector will read.
    ///
    /// ```
    /// use qqq_host::egress::Limits;
    ///
    /// assert!(Limits::default().max_response_headers > 0);
    /// ```
    pub max_response_headers: usize,
    /// Maximum response head bytes (status line plus header block).
    ///
    /// ```
    /// use qqq_host::egress::Limits;
    ///
    /// assert!(Limits::default().max_response_head_bytes > 0);
    /// ```
    pub max_response_head_bytes: u64,
    /// Maximum response body bytes; larger bodies are an error, not a cut.
    ///
    /// ```
    /// use qqq_host::egress::Limits;
    ///
    /// assert_eq!(Limits::default().max_body_bytes, 1 << 20);
    /// ```
    pub max_body_bytes: u64,
    /// Redirect hops followed: the operational half of the redirect
    /// budget. [`request`] follows the minimum of this, the tenant
    /// grant, and [`REDIRECT_HOP_LIMIT`]; [`exchange`] surfaces any
    /// `3xx` with a `Location` as a response while this is non-zero
    /// and refuses it as [`CallError::Redirect`] while it is zero.
    ///
    /// ```
    /// use qqq_host::egress::Limits;
    ///
    /// assert_eq!(Limits::default().max_redirects, 0);
    /// ```
    pub max_redirects: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout: std::time::Duration::from_secs(10),
            tls_timeout: std::time::Duration::from_secs(10),
            total_timeout: std::time::Duration::from_secs(30),
            max_request_headers: 100,
            max_request_bytes: 1 << 20,
            max_response_headers: 100,
            max_response_head_bytes: 64 << 10,
            max_body_bytes: 1 << 20,
            max_redirects: 0,
        }
    }
}

/// An HTTP method the connector can write (`I-01`).
///
/// Closed on purpose: the connector writes requests, and these three cover
/// what a guest capability needs without verb-tampering surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `HEAD` (no body is read, whatever the headers claim).
    Head,
    /// `POST` with a caller-supplied body.
    Post,
}

impl Method {
    /// The method as written on the request line.
    ///
    /// ```
    /// use qqq_host::egress::Method;
    ///
    /// assert_eq!(Method::Get.as_str(), "GET");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
        }
    }
}

/// A request to send through the connector (`I-01`).
///
/// Headers are caller-supplied pairs; hop-by-hop headers (`connection`,
/// `keep-alive`, `proxy-authenticate`, `proxy-authorization`,
/// `proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade`)
/// are stripped at write time, and a body over the limit is refused
/// before any byte is written. Connector-owned `host` and
/// `content-length` are refused outright, never overridden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The URL, vetted by [`vet`] inside [`request`].
    pub url: String,
    /// Header pairs. Names and values must be ASCII-visible; anything else
    /// is refused rather than sanitised.
    pub headers: Vec<(String, String)>,
    /// The body (POST only; non-empty elsewhere is refused).
    pub body: Vec<u8>,
}

/// A response read through the connector (`I-01`).
///
/// Bodies are complete, never truncated: over-cap bodies are
/// [`CallError::BodyTooLarge`], so a caller cannot mistake a prefix for
/// the whole. Trailers are parsed-and-dropped under the header cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The numeric status.
    pub status: u16,
    /// Response headers (hop-by-hop framing already consumed: content
    /// length honoured, chunks decoded, trailers dropped).
    pub headers: Vec<(String, String)>,
    /// The complete body (empty for HEAD, whatever the headers claimed).
    pub body: Vec<u8>,
}

/// How one egress call ended, for the audit row (`I-01`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The call completed; carries the status.
    Success {
        /// The response status.
        status: u16,
    },
    /// Vetting refused before any socket opened; carries the refusal.
    Refused {
        /// The vetting refusal.
        reason: Refusal,
    },
    /// The call failed after vetting; carries the failure.
    Failed {
        /// The I/O failure.
        reason: CallError,
    },
}

/// One audit row per visited hop (plus one for a terminal chain
/// refusal): host, port, outcome, byte counts — never the body
/// (`I-01`, Phase 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// The normalised host that was vetted (SNI value on TLS calls).
    pub host: String,
    /// The port that was dialled.
    pub port: u16,
    /// How the call ended.
    pub outcome: Outcome,
    /// Request bytes written on the wire.
    pub request_bytes: u64,
    /// Response bytes read off the wire (head plus body).
    pub response_bytes: u64,
}

/// What can go wrong after vetting passed (`I-01`).
///
/// Messages name limits and kinds, never URLs or bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// Nothing completed within the total timeout.
    Timeout,
    /// The TLS handshake failed or the peer was unverifiable.
    Tls,
    /// A redirect was answered but no hop chain is granted — or the
    /// granted chain is exhausted.
    Redirect,
    /// An `https` hop redirected to `http`: downgrades always refuse,
    /// under every grant. A separate variant (rather than folding
    /// into `Redirect`) because the remedy differs — fix the peer,
    /// not the grant.
    Downgrade,
    /// The request breached its own caps (too many headers, too many bytes,
    /// a body on GET/HEAD, or a non-ASCII-visible header).
    RequestTooLarge,
    /// The response head exceeded its count or byte cap.
    ResponseHeadTooLarge,
    /// The response body exceeded `max_body_bytes` — an error, never a cut.
    BodyTooLarge {
        /// The configured limit.
        limit: u64,
    },
    /// The bytes were not a response (bad status line, bad chunk, early EOF).
    Protocol,
    /// The transport failed below HTTP (reset, refused, unreachable).
    Transport,
}

/// A call that failed at either half: vetting or I/O (`I-01`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Vetting refused before any socket opened.
    Refused(Refusal),
    /// I/O failed after vetting passed.
    Failed(CallError),
}

/// How the connector opens streams: the seam every test fakes (`I-01`).
///
/// The production impl dials TCP with the connect timeout and upgrades to
/// TLS with SNI plus verification against the vetted host. The fake serves
/// scripted bytes over an in-memory duplex, so every exchange behaviour —
/// caps, redirects, timeouts, audit rows — is proven without a network.
pub trait Transport {
    /// The stream, ready to exchange HTTP (post-TLS for the real impl).
    type Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send;

    /// Open the stream for a vetted destination.
    fn open(
        &self,
        vetted: &Vetted,
        limits: &Limits,
    ) -> impl std::future::Future<Output = Result<Self::Stream, CallError>> + Send;
}

/// The OS root store for outbound TLS (`I-01`).
///
/// Every system root the platform reports, or an error when none parses:
/// an empty store would make every handshake fail with a confusing alert,
/// so "no verifiable roots" fails here, loudly, before any dial.
fn system_roots() -> Result<rustls::RootCertStore, CallError> {
    let result = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(result.certs);
    // Empty means unverifiable-everything: fail here, loudly, rather than
    // failing every handshake later with a confusing alert. Partial load
    // errors ride along only when roots did load — the store that results
    // is exactly what verification runs against, named in no log.
    if added == 0 {
        return Err(CallError::Tls);
    }
    Ok(roots)
}

/// Upgrade a connected stream to TLS for the vetted host (`I-01`).
///
/// SNI and verification both use `host` — the vetted, normalised name from
/// [`Vetted`], which [`request`] re-vets on every redirect hop, so each
/// hop's own hostname is the only one that reaches verification here.
/// The handshake returning `Ok` IS the verification: rustls refuses
/// unverifiable chains inside the handshake, so no separate check can be
/// forgotten.
///
/// # Errors
///
/// [`CallError::Tls`] when the name is unusable or the peer is
/// unverifiable; [`CallError::Timeout`] when the handshake stalls.
pub async fn upgrade_tls<S>(
    stream: S,
    host: &str,
    roots: std::sync::Arc<rustls::RootCertStore>,
    timeout: std::time::Duration,
) -> Result<tokio_rustls::client::TlsStream<S>, CallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let config = rustls::ClientConfig::builder()
        .with_root_certificates((*roots).clone())
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    // Owned: the name must be `'static` for the connector future. Brackets
    // stripped: URL-form IPv6 literals would otherwise fail to parse as a
    // server name and every HTTPS IPv6 literal would TLS-error.
    let name = rustls_pki_types::ServerName::try_from(sni_name(host).to_owned())
        .map_err(|_| CallError::Tls)?;
    tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .map_err(|_| CallError::Timeout)?
        .map_err(|_| CallError::Tls)
}

/// The name TLS verifies: the vetted host without IPv6 brackets (`I-01`).
///
/// `Vetted.host` carries the URL form, where IPv6 literals wear brackets
/// (`[::1]`); rustls `ServerName` takes the bare address, and bracketed
/// input fails to parse — which would turn every HTTPS IPv6 literal into
/// a TLS error. DNS names and IPv4 pass through untouched.
fn sni_name(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
}

/// The production transport: TCP plus TLS against OS roots (`I-01`).
///
/// SNI is the vetted host and verification runs against it — the hop's
/// own hostname, which [`request`] re-vets on every redirect before it
/// can reach verification.
pub struct SystemTransport;

/// The protocol ceiling on redirect hops: no chain follows more
/// than three, whatever any grant or limit allows. Three is the
/// mandate's number — enough for login flows and canonicalization
/// chains, small enough that a redirect loop is a short walk, not
/// an unbounded one.
pub const REDIRECT_HOP_LIMIT: u8 = 3;

/// The production cleartext transport: plain TCP, no TLS (`I-01`,
/// Phase 3).
///
/// Serves ONLY cleartext-vetted destinations. A `tls` destination
/// reaching this transport is a wiring bug, not a fallback case —
/// it refuses rather than connecting, because connecting would be
/// a silent downgrade and refusing loudly is the property the
/// selection test pins. `SystemTransport` mirrors it from the
/// other side (cleartext refused before dialling).
pub struct PlainTransport;

impl Transport for PlainTransport {
    type Stream = tokio::net::TcpStream;

    async fn open(&self, vetted: &Vetted, limits: &Limits) -> Result<Self::Stream, CallError> {
        use tokio::io::AsyncWriteExt as _;
        if vetted.tls {
            // Wrong transport for a TLS destination: refuse, never
            // silently downgrade. Reachable only through miswiring —
            // `EgressTransport` selects by `vetted.tls`.
            return Err(CallError::Transport);
        }
        let mut tcp = tokio::time::timeout(
            limits.connect_timeout,
            tokio::net::TcpStream::connect(vetted.addr),
        )
        .await
        .map_err(|_| CallError::Timeout)?
        .map_err(|_| CallError::Transport)?;
        // Flushing here surfaces a dead peer before the request,
        // mirroring the TLS path.
        tcp.flush().await.map_err(|_| CallError::Transport)?;
        Ok(tcp)
    }
}

/// Route each hop to its transport by scheme (`I-01`, Phase 3).
///
/// `request` stays generic over one `Transport`, so this struct is
/// the seam: TLS destinations open through `secure`, cleartext
/// through `plain`, chosen per hop from the freshly vetted
/// destination — never from the original URL, which is how a
/// redirect could otherwise smuggle a scheme change past the
/// selection. Each hop opens as [`EgressStream::Secure`] or
/// [`EgressStream::Plain`]; the bytes cross the enum, not copies of it.
pub struct EgressTransport<T, P> {
    /// Opened for `https` (vetted `tls`) destinations.
    pub secure: T,
    /// Opened for `http` (cleartext-vetted) destinations.
    pub plain: P,
}

impl<T, P> EgressTransport<T, P> {
    /// Build the selector from its two transports.
    pub fn new(secure: T, plain: P) -> Self {
        Self { secure, plain }
    }
}

/// The stream [`EgressTransport`] opens: exactly one of its two
/// transports' streams.
///
/// An enum rather than a boxed trait object because two non-auto
/// traits (`AsyncRead` + `AsyncWrite`) cannot share one `dyn` — and
/// the enum keeps the selection visible in the type instead of
/// behind a vtable. Both arms implement the stream traits by
/// delegation, so [`exchange`] never branches on security posture.
pub enum EgressStream<S, P> {
    /// Opened by the secure transport for a TLS-vetted destination.
    Secure(S),
    /// Opened by the plain transport for a cleartext-vetted destination.
    Plain(P),
}

impl<S, P> tokio::io::AsyncRead for EgressStream<S, P>
where
    S: tokio::io::AsyncRead + Unpin,
    P: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            EgressStream::Secure(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            EgressStream::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<S, P> tokio::io::AsyncWrite for EgressStream<S, P>
where
    S: tokio::io::AsyncWrite + Unpin,
    P: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            EgressStream::Secure(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            EgressStream::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            EgressStream::Secure(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            EgressStream::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            EgressStream::Secure(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            EgressStream::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl<T, P> Transport for EgressTransport<T, P>
where
    T: Transport + Sync,
    P: Transport + Sync,
{
    type Stream = EgressStream<T::Stream, P::Stream>;

    async fn open(&self, vetted: &Vetted, limits: &Limits) -> Result<Self::Stream, CallError> {
        if vetted.tls {
            Ok(EgressStream::Secure(
                self.secure.open(vetted, limits).await?,
            ))
        } else {
            Ok(EgressStream::Plain(self.plain.open(vetted, limits).await?))
        }
    }
}

/// The production resolver: one OS lookup per vetted host (`I-01`).
///
/// A unit struct because there is nothing to configure — and because a
/// resolver with options would be a place to smuggle in a second DNS
/// path that bypasses the forbidden table. `vet` calls it exactly
/// once per call and screens every returned address, so rebinding
/// attackers gain nothing from mixed answers.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
        let mut out = Vec::new();
        for addr in tokio::net::lookup_host((host, 0)).await? {
            out.push(addr.ip());
        }
        Ok(out)
    }
}

impl Transport for SystemTransport {
    type Stream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

    async fn open(&self, vetted: &Vetted, limits: &Limits) -> Result<Self::Stream, CallError> {
        use tokio::io::AsyncWriteExt as _;
        if !vetted.tls {
            // Refused BEFORE dialling: vet permits cleartext when granted,
            // so this branch is reachable — and a refused destination must
            // never see even a SYN. Cleartext destinations are served by
            // `PlainTransport` (selected per hop by `EgressTransport`),
            // not by a flag here: a second stream type and a branch at
            // every exchange would be the shape that smuggles an
            // unencrypted path in later.
            return Err(CallError::Transport);
        }
        let tcp = tokio::time::timeout(
            limits.connect_timeout,
            tokio::net::TcpStream::connect(vetted.addr),
        )
        .await
        .map_err(|_| CallError::Timeout)?
        .map_err(|_| CallError::Transport)?;
        let roots = std::sync::Arc::new(system_roots()?);
        let mut tls = upgrade_tls(tcp, &vetted.host, roots, limits.tls_timeout).await?;
        // Flushing here surfaces a dead peer before the request.
        tls.flush().await.map_err(|_| CallError::Transport)?;
        Ok(tls)
    }
}

/// Wire byte counters: what actually moved, for audit rows that tell the
/// truth about partial calls (`I-01`).
///
/// A failed or timed-out call still moved bytes — a row that says zero
/// when 900 KiB crossed is a lie the audit cannot afford. Every write and
/// read below charges these saturating counters, and [`request`] reads
/// them in all three audit arms instead of hard-coding zeros.
///
/// ```
/// use qqq_host::egress::IoCount;
///
/// // The shape audit rows read: two saturating counters, no behaviour.
/// let counts = IoCount {
///     written: 100,
///     read: 50,
/// };
/// assert_eq!((counts.written, counts.read), (100, 50));
/// ```
#[derive(Debug, Default, Clone)]
pub struct IoCount {
    /// Request bytes written.
    pub written: u64,
    /// Response bytes read.
    pub read: u64,
}

/// A redirect target when the response is one: 3xx status plus a
/// `Location` header value. Shared by [`exchange`] (which refuses
/// when the operational switch is off) and [`request`] (which
/// follows when the grant allows), so the two cannot disagree about
/// what counts as a redirect.
fn redirect_location(status: u16, headers: &[(String, String)]) -> Option<&str> {
    if !(300..400).contains(&status) {
        return None;
    }
    headers
        .iter()
        .find(|(name, _)| name == "location")
        .map(|(_, value)| value.as_str())
}

/// Vet one chain hop under the shared deadline.
///
/// Every hop — first or fifth — passes the full policy, so a
/// redirect cannot smuggle a destination past the allowlist. Both
/// refusal shapes audit their row here, keeping [`request`]'s loop
/// to the exchange arms.
async fn vet_hop(
    policy: &TenantEgress,
    url: &str,
    resolver: &impl Resolver,
    deadline: tokio::time::Instant,
    audit: &mut impl FnMut(AuditRow),
) -> Result<Vetted, Failure> {
    match tokio::time::timeout_at(deadline, vet(policy, url, resolver)).await {
        Ok(Ok(vetted)) => Ok(vetted),
        Ok(Err(reason)) => {
            audit(AuditRow {
                host: safe_host(url),
                port: 0,
                outcome: Outcome::Refused {
                    reason: reason.clone(),
                },
                request_bytes: 0,
                response_bytes: 0,
            });
            Err(Failure::Refused(reason))
        }
        Err(_) => {
            audit(AuditRow {
                host: safe_host(url),
                port: 0,
                outcome: Outcome::Failed {
                    reason: CallError::Timeout,
                },
                request_bytes: 0,
                response_bytes: 0,
            });
            Err(Failure::Failed(CallError::Timeout))
        }
    }
}

/// Audit a terminal chain refusal against the hop that answered it.
///
/// The refused target was never vetted, so the row names the current
/// hop — every row names a vetted destination, with zero byte counts
/// because the refusal moved none.
fn refuse_chain(vetted: &Vetted, reason: CallError, audit: &mut impl FnMut(AuditRow)) -> Failure {
    audit(AuditRow {
        host: vetted.host.clone(),
        port: vetted.addr.port(),
        outcome: Outcome::Failed {
            reason: reason.clone(),
        },
        request_bytes: 0,
        response_bytes: 0,
    });
    Failure::Failed(reason)
}

/// Open one hop's stream and exchange the current request over it.
///
/// Thin glue keeping [`request`]'s loop readable: open, then
/// [`exchange`], with transport failures mapped at the seam.
async fn exchange_hop<T: Transport>(
    transport: &T,
    vetted: &Vetted,
    current: &Request,
    hop_limits: &Limits,
    counts: &std::sync::Mutex<IoCount>,
) -> Result<Response, Failure> {
    let mut stream = transport
        .open(vetted, hop_limits)
        .await
        .map_err(Failure::Failed)?;
    exchange(vetted, current, hop_limits, &mut stream, counts)
        .await
        .map_err(Failure::Failed)
}

/// Speak one capped HTTP/1.1 round trip over an open stream (`I-01`).
///
/// Pure exchange logic over any stream, which is what makes it testable
/// over in-memory duplexes: request validation and stripping, head
/// reading under count and byte caps, redirect refusal, body reading
/// under the byte cap with chunk decoding, and byte accounting for the
/// audit row. Timeouts live in [`request`], not here, so tests control
/// the clock by controlling the stream.
///
/// ```
/// use qqq_host::egress::{Method, Request, Vetted, exchange};
///
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .enable_all()
///     .build()
///     .unwrap();
/// rt.block_on(async {
///     let (mut client, mut server) = tokio::io::duplex(65536);
///     tokio::spawn(async move {
///         use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
///         let mut buf = [0u8; 4096];
///         let n = server.read(&mut buf).await.unwrap();
///         assert!(buf[..n].starts_with(b"GET / HTTP/1.1\r\n"));
///         server
///             .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
///             .await
///             .unwrap();
///     });
///     let vetted = Vetted {
///         addr: "93.184.216.34:443".parse().unwrap(),
///         host: "example.com".to_owned(),
///         tls: true,
///     };
///     let request = Request {
///         method: Method::Get,
///         url: "https://example.com/".to_owned(),
///         headers: Vec::new(),
///         body: Vec::new(),
///     };
///     let counts = std::sync::Mutex::new(qqq_host::egress::IoCount::default());
///     let response =
///         exchange(&vetted, &request, &Default::default(), &mut client, &counts)
///             .await
///             .unwrap();
///     assert_eq!(response.status, 200);
///     assert_eq!(response.body, b"hello");
///     let moved = counts.lock().unwrap();
///     assert!(moved.written > 0 && moved.read > 0);
/// });
/// ```
///
/// ```
/// use qqq_host::egress::{CallError, Method, Request, Vetted, exchange};
///
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .enable_all()
///     .build()
///     .unwrap();
/// rt.block_on(async {
///     let (mut client, mut server) = tokio::io::duplex(65536);
///     tokio::spawn(async move {
///         use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
///         let mut buf = [0u8; 4096];
///         let _ = server.read(&mut buf).await.unwrap();
///         server
///             .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n")
///             .await
///             .unwrap();
///     });
///     let vetted = Vetted {
///         addr: "93.184.216.34:443".parse().unwrap(),
///         host: "example.com".to_owned(),
///         tls: true,
///     };
///     let request = Request {
///         method: Method::Get,
///         url: "https://example.com/".to_owned(),
///         headers: Vec::new(),
///         body: Vec::new(),
///     };
///     let limits = qqq_host::egress::Limits {
///         max_body_bytes: 10,
///         ..Default::default()
///     };
///     let counts = std::sync::Mutex::new(qqq_host::egress::IoCount::default());
///     let err = exchange(&vetted, &request, &limits, &mut client, &counts)
///         .await
///         .unwrap_err();
///     assert_eq!(err, CallError::BodyTooLarge { limit: 10 });
/// });
/// ```
///
/// # Errors
///
/// [`CallError::RequestTooLarge`], [`CallError::ResponseHeadTooLarge`],
/// [`CallError::BodyTooLarge`], [`CallError::Redirect`],
/// [`CallError::Protocol`], or [`CallError::Transport`] as named.
pub async fn exchange<S>(
    vetted: &Vetted,
    request: &Request,
    limits: &Limits,
    stream: &mut S,
    counts: &std::sync::Mutex<IoCount>,
) -> Result<Response, CallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;

    if request.headers.len() > limits.max_request_headers {
        return Err(CallError::RequestTooLarge);
    }
    if !request.body.is_empty() && !matches!(request.method, Method::Post) {
        return Err(CallError::RequestTooLarge);
    }
    let mut head = format!(
        "{} {} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n",
        request.method.as_str(),
        request_path(&request.url).ok_or(CallError::RequestTooLarge)?,
        host_header(vetted),
    );
    for (name, value) in &request.headers {
        // Names are RFC 9110 tokens, full stop: anything else (spaces,
        // CTLs, CR/LF) is an injection attempt, not a header. Values stay
        // visible-ASCII for the same reason.
        if !is_token(name) || !is_visible_ascii(value) {
            return Err(CallError::RequestTooLarge);
        }
        let lower = name.to_ascii_lowercase();
        // Connector-owned headers are refused, never overridden: the
        // connector writes exactly one `host` (the vetted name) and one
        // `content-length` (the actual body), and a caller copy would put
        // two on the wire — the duplicate-header shape behind request
        // smuggling.
        if lower == "host" || lower == "content-length" {
            return Err(CallError::RequestTooLarge);
        }
        if is_hop_by_hop(&lower) {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if matches!(request.method, Method::Post) {
        use std::fmt::Write as _;
        head.write_fmt(format_args!("content-length: {}\r\n", request.body.len()))
            .map_err(|_| CallError::RequestTooLarge)?;
    }
    head.push_str("\r\n");
    let head_bytes = head.into_bytes();
    let request_len = u64::try_from(head_bytes.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(request.body.len()).unwrap_or(u64::MAX));
    if request_len > limits.max_request_bytes {
        return Err(CallError::RequestTooLarge);
    }
    stream
        .write_all(&head_bytes)
        .await
        .map_err(|_| CallError::Transport)?;
    charge(counts, head_bytes.len(), 0);
    stream
        .write_all(&request.body)
        .await
        .map_err(|_| CallError::Transport)?;
    charge(counts, request.body.len(), 0);
    stream.flush().await.map_err(|_| CallError::Transport)?;

    let (status, headers, rest) = read_final_head(stream, limits, counts).await?;
    let mut rest: &[u8] = &rest;
    if redirect_location(status, &headers).is_some() && limits.max_redirects == 0 {
        return Err(CallError::Redirect);
    }
    let body = read_body(
        &headers,
        &mut rest,
        stream,
        limits,
        // HEAD answers nothing, and 204/304 carry nothing by definition
        // (RFC 9110) no matter what the headers claim — reading would wait
        // for bytes that must never come.
        matches!(request.method, Method::Head) || matches!(status, 204 | 304),
        counts,
    )
    .await?;
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Read response heads until the final one, skipping interim 1xx.
///
/// Returns the final status, its headers, and the bytes after the final
/// head end (the body's first bytes, possibly). A 101 that promises an
/// upgrade is refused: this connector speaks one HTTP/1.1 round trip and
/// upgrades to nothing. The byte cap spans all heads together, and the
/// head end is checked before every read — a buffered complete head never
/// costs a read that could meet EOF.
async fn read_final_head<S>(
    stream: &mut S,
    limits: &Limits,
    counts: &std::sync::Mutex<IoCount>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), CallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    // Interim 1xx heads (103 Early Hints and friends) are consumed here so
    // the body reader only ever sees the final head.
    //
    // Drained interim heads count against the cap too (`consumed`): without
    // it, ten just-under-cap interim heads would each pass while
    // collectively blowing the budget they were given.
    let mut consumed: u64 = 0;
    loop {
        loop {
            // The cap first, the head second: after draining an interim
            // head the final head may already sit buffered, and checking
            // the head first would skip the cumulative cap exactly when it
            // matters. While the head end is absent the whole buffer counts
            // (nothing is known to be body yet); once present, only the
            // bytes through the end count, so body bytes sharing the read
            // are never charged to the head budget.
            if let Some(end) = find_head_end(&raw) {
                let total = consumed.saturating_add(u64::try_from(end).unwrap_or(u64::MAX));
                if total > limits.max_response_head_bytes {
                    return Err(CallError::ResponseHeadTooLarge);
                }
                break;
            }
            let total = consumed.saturating_add(u64::try_from(raw.len()).unwrap_or(u64::MAX));
            if total > limits.max_response_head_bytes {
                return Err(CallError::ResponseHeadTooLarge);
            }
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|_| CallError::Transport)?;
            if n == 0 {
                return Err(CallError::Protocol);
            }
            charge(counts, 0, n);
            {
                let (chunk, _) = buf.split_at(n);
                raw.extend_from_slice(chunk);
            }
        }
        let end = find_head_end(&raw).ok_or(CallError::Protocol)?;
        let (head_bytes, _) = raw.split_at(end);
        let (status, headers) = parse_head(head_bytes, limits)?;
        if (100..200).contains(&status) {
            // 101 Switching Protocols is a refusal, not a skip: this
            // connector speaks one HTTP/1.1 round trip and upgrades to
            // nothing. Any other 1xx is consumed — its bytes drained — and
            // the next head parsed from what follows.
            if status == 101 {
                return Err(CallError::Protocol);
            }
            consumed = consumed.saturating_add(u64::try_from(end).unwrap_or(u64::MAX));
            raw.drain(..end);
            continue;
        }
        let (_, rest) = raw.split_at(end);
        return Ok((status, headers, rest.to_vec()));
    }
}

/// Charge wire bytes to the audit counters (saturating; poison recovers
/// rather than failing the call, for the same reason every registry lock
/// recovers: a counter must never break the path it measures).
fn charge(counts: &std::sync::Mutex<IoCount>, written: usize, read: usize) {
    let mut guard = counts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.written = guard
        .written
        .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
    guard.read = guard
        .read
        .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
}

/// One vetted call, end to end: vet, open, exchange, audit (`I-01`,
/// Phase 3).
///
/// The audit callback runs once per visited hop plus once for a
/// terminal chain refusal, on every path — including vetting
/// refusals, which produce a row with zero byte counts rather than
/// no row: a refusal that leaves no trace is un-auditable, and the
/// sink (not this function) decides what to persist. Failed and
/// timed-out rows carry the bytes that hop actually moved (deltas
/// off the shared counters), never cumulative totals and never
/// hard-coded zeros.
///
/// One deadline bounds everything: it is computed once from
/// `total_timeout` and covers vetting *and* every hop's exchange, so
/// a hanging resolver fails the call with [`CallError::Timeout`]
/// instead of outliving the budget the operator set.
///
/// # The redirect chain, and why the budget is a three-way minimum
///
/// Each followed hop is re-vetted through [`vet`] — policy, scheme,
/// forbidden addresses, fresh DNS — so a redirect cannot smuggle a
/// destination past the allowlist. The followed budget is the minimum
/// of the tenant grant (`TenantEgress::max_redirect_hops`), the
/// operational switch (`Limits::max_redirects`), and
/// [`REDIRECT_HOP_LIMIT`]: the grant authorises, the switch operates,
/// the ceiling contains, and no one of the three can widen the other
/// two. `https` to `http` downgrades refuse under every grant, before
/// the next hop is even resolved.
///
/// # Errors
///
/// [`Failure::Refused`] before any socket opens, [`Failure::Failed`]
/// after. A [`CallError::Timeout`] covers the whole call via the total
/// timeout, so a hanging peer fails the call instead of the test suite.
pub async fn request<T: Transport>(
    policy: &TenantEgress,
    request: &Request,
    resolver: &impl Resolver,
    limits: &Limits,
    transport: &T,
    audit: &mut impl FnMut(AuditRow),
) -> Result<Response, Failure> {
    let deadline = tokio::time::Instant::now() + limits.total_timeout;
    let counts = std::sync::Mutex::new(IoCount::default());
    let snapshot = || {
        counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    };
    // The 3xx that [`exchange`] would refuse must stay visible here:
    // each visited hop gets its own `Success` row (the 302 happened),
    // and the chain decision below gets its own refusal row. The
    // per-hop switch says "surface", the budget below says "follow".
    let mut hop_limits = *limits;
    hop_limits.max_redirects = 1;
    let budget = policy
        .max_redirect_hops()
        .min(limits.max_redirects)
        .min(REDIRECT_HOP_LIMIT);
    let mut current = request.clone();
    let mut hops_followed: u8 = 0;
    loop {
        let before = snapshot();
        let vetted = vet_hop(policy, &current.url, resolver, deadline, audit).await?;
        let outcome = exchange_hop(transport, &vetted, &current, &hop_limits, &counts);
        // Deltas, not totals: the counters accumulate across hops, and
        // a row that repeats the running total would charge every
        // earlier hop's bytes to the latest one.
        let delta = |moved: &IoCount| {
            (
                moved.written.saturating_sub(before.written),
                moved.read.saturating_sub(before.read),
            )
        };
        match tokio::time::timeout_at(deadline, outcome).await {
            Ok(Ok(response)) => {
                let moved = snapshot();
                let (written, read) = delta(&moved);
                audit(AuditRow {
                    host: vetted.host.clone(),
                    port: vetted.addr.port(),
                    outcome: Outcome::Success {
                        status: response.status,
                    },
                    request_bytes: written,
                    response_bytes: read,
                });
                let Some(location) = redirect_location(response.status, &response.headers) else {
                    return Ok(response);
                };
                if hops_followed >= budget {
                    return Err(refuse_chain(&vetted, CallError::Redirect, audit));
                }
                let Some(next_url) = join_location(&current.url, location) else {
                    return Err(refuse_chain(&vetted, CallError::Protocol, audit));
                };
                if is_downgrade(&current.url, &next_url) {
                    return Err(refuse_chain(&vetted, CallError::Downgrade, audit));
                }
                if is_cross_origin(&current.url, &next_url) {
                    strip_credentials(&mut current.headers);
                    // A cross-origin hop never carries the first
                    // origin's body: the guest entrusted it to one
                    // allowed origin, and a redirect — even between
                    // two allowed origins — is not consent to deliver
                    // it to another. The follow continues as a GET
                    // (HEAD stays HEAD); ordinary headers still travel
                    // so tracing and negotiation survive the hop.
                    // Same-origin chains keep method and body: login
                    // flows must not lose their POST.
                    if current.method == Method::Post {
                        current.method = Method::Get;
                        current.body.clear();
                    }
                }
                current.url = next_url;
                hops_followed = hops_followed.saturating_add(1);
            }
            Ok(Err(failure)) => {
                let moved = snapshot();
                let (written, read) = delta(&moved);
                let reason = match &failure {
                    Failure::Refused(reason) => Outcome::Refused {
                        reason: reason.clone(),
                    },
                    Failure::Failed(reason) => Outcome::Failed {
                        reason: reason.clone(),
                    },
                };
                audit(AuditRow {
                    host: vetted.host.clone(),
                    port: vetted.addr.port(),
                    outcome: reason,
                    request_bytes: written,
                    response_bytes: read,
                });
                return Err(failure);
            }
            Err(_) => {
                let moved = snapshot();
                let (written, read) = delta(&moved);
                audit(AuditRow {
                    host: vetted.host.clone(),
                    port: vetted.addr.port(),
                    outcome: Outcome::Failed {
                        reason: CallError::Timeout,
                    },
                    request_bytes: written,
                    response_bytes: read,
                });
                return Err(Failure::Failed(CallError::Timeout));
            }
        }
    }
}

/// Resolve a `Location` value against the hop that answered it.
///
/// Absolute URLs stand alone; origin-relative paths (`/next`) and
/// bare relative references inherit the answering hop's origin. An
/// unusable value yields `None` — the peer spoke a malformed
/// redirect, and [`request`] fails it as [`CallError::Protocol`]
/// rather than guessing a destination.
fn join_location(current_url: &str, location: &str) -> Option<String> {
    url::Url::parse(current_url)
        .ok()?
        .join(location)
        .ok()
        .map(Into::into)
}

/// Whether following `next_url` from `current_url` would downgrade an
/// encrypted hop to cleartext.
///
/// Origin-relative locations inherit the current scheme through
/// [`join_location`], so they can never downgrade; only an absolute
/// `http:` target from an `https:` hop refuses. Unparseable input
/// refuses safe (not a downgrade — the join already failed those).
fn is_downgrade(current_url: &str, next_url: &str) -> bool {
    let (Some(current), Some(next)) = (
        url::Url::parse(current_url).ok(),
        url::Url::parse(next_url).ok(),
    ) else {
        return false;
    };
    current.scheme() == "https" && next.scheme() == "http"
}

/// Whether two URLs have different origins (scheme, host, or port).
///
/// Unparseable input counts as cross-origin: stripping a credential
/// that turns out to be same-origin costs nothing, while forwarding
/// one that turns out cross-origin is the breach.
fn is_cross_origin(current_url: &str, next_url: &str) -> bool {
    let (Some(current), Some(next)) = (
        url::Url::parse(current_url).ok(),
        url::Url::parse(next_url).ok(),
    ) else {
        return true;
    };
    current.scheme() != next.scheme()
        || current.host_str() != next.host_str()
        || current.port_or_known_default() != next.port_or_known_default()
}

/// Strip credential headers before a cross-origin hop.
///
/// Forward-only: nothing restores a credential once it leaves its
/// origin, and same-origin hops keep theirs. The set is the
/// request-side secrets a redirect must never carry elsewhere —
/// `authorization`, `proxy-authorization`, `cookie` — matched
/// case-insensitively because header names are. Ordinary headers
/// (tracing IDs, content negotiation) travel untouched.
fn strip_credentials(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| {
        !matches!(
            name.to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization" | "cookie"
        )
    });
}

fn safe_host(url: &str) -> String {
    // The refusal row must not echo the URL (credentials travel in URLs);
    // the host alone is allowlist-shaped and safe. Unparseable input yields
    // the empty string rather than the input.
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}

fn is_visible_ascii(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

/// An RFC 9110 token (`tchar`): the only shape a header name may have.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_hop_by_hop(lower_name: &str) -> bool {
    // Takes the already-lowercased name: every caller lowercases once, so
    // the comparison cannot disagree about case. `proxy-connection` is
    // listed though no other proxy-* needs naming — it is the one proxies
    // actually send, and the general prefix is NOT matched (a `proxy-foo`
    // allowlist-by-prefix would be a policy by substring).
    matches!(
        lower_name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn request_path(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let mut path = parsed.path().to_owned();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    Some(path)
}

fn host_header(vetted: &Vetted) -> String {
    // The port travels when it is not the scheme default: virtual hosts
    // behind one address route on it, and omitting it misroutes.
    let default = if vetted.tls { 443 } else { 80 };
    if vetted.addr.port() == default {
        vetted.host.clone()
    } else {
        format!("{}:{}", vetted.host, vetted.addr.port())
    }
}

fn find_head_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_head(head: &[u8], limits: &Limits) -> Result<(u16, Vec<(String, String)>), CallError> {
    let text = std::str::from_utf8(head).map_err(|_| CallError::Protocol)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(CallError::Protocol)?;
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().ok_or(CallError::Protocol)?;
    let status: u16 = parts
        .next()
        .ok_or(CallError::Protocol)?
        .parse()
        .map_err(|_| CallError::Protocol)?;
    if !(100..600).contains(&status) {
        return Err(CallError::Protocol);
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if headers.len() >= limits.max_response_headers {
            return Err(CallError::ResponseHeadTooLarge);
        }
        let (raw_name, value) = line.split_once(':').ok_or(CallError::Protocol)?;
        // The name is validated BEFORE trimming: trimming first would launder
        // `"X : v"` into `"x"`, accepting whitespace before the colon that a
        // strict parser refuses (and that desyncs lenient/tolerant pairs).
        if !is_token(raw_name) {
            return Err(CallError::Protocol);
        }
        let name = raw_name.to_ascii_lowercase();
        // Values admit empty (a bare `x-flag:` is legal), visible ASCII,
        // spaces, and HTAB (OWS around the field value is legal HTTP);
        // anything else — CR, LF, other CTLs — is an injection attempt.
        if !value
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ' || b == b'\t')
        {
            return Err(CallError::Protocol);
        }
        let value = value.trim().to_owned();
        headers.push((name, value));
    }
    Ok((status, headers))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

async fn read_body<S>(
    headers: &[(String, String)],
    rest: &mut &[u8],
    stream: &mut S,
    limits: &Limits,
    head_only: bool,
    counts: &std::sync::Mutex<IoCount>,
) -> Result<Vec<u8>, CallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    if head_only {
        return Ok(Vec::new());
    }
    if let Some(te) = header(headers, "transfer-encoding") {
        if te.split(',').any(|v| v.trim() == "chunked") {
            return read_chunked(rest, stream, limits, counts).await;
        }
        return Err(CallError::Protocol);
    }
    if let Some(len) = header(headers, "content-length") {
        let len: u64 = len.trim().parse().map_err(|_| CallError::Protocol)?;
        if len > limits.max_body_bytes {
            return Err(CallError::BodyTooLarge {
                limit: limits.max_body_bytes,
            });
        }
        let mut body = Vec::new();
        let mut remaining = len;
        drain_rest(rest, &mut body, &mut remaining);
        while remaining > 0 {
            let mut buf = [0u8; 4096];
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|_| CallError::Transport)?;
            if n == 0 {
                return Err(CallError::Protocol);
            }
            charge(counts, 0, n);
            let n_u64 = u64::try_from(n).unwrap_or(u64::MAX);
            let take = n_u64.min(remaining);
            let take_usize = usize::try_from(take).map_err(|_| CallError::Protocol)?;
            {
                let (chunk, _) = buf.split_at(take_usize);
                body.extend_from_slice(chunk);
            }
            remaining -= take;
        }
        return Ok(body);
    }
    // Close-delimited: read to EOF under the cap.
    let mut body = rest.to_vec();
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > limits.max_body_bytes {
        return Err(CallError::BodyTooLarge {
            limit: limits.max_body_bytes,
        });
    }
    loop {
        let mut buf = [0u8; 4096];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|_| CallError::Transport)?;
        if n == 0 {
            return Ok(body);
        }
        charge(counts, 0, n);
        {
            let (chunk, _) = buf.split_at(n);
            body.extend_from_slice(chunk);
        }
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > limits.max_body_bytes {
            return Err(CallError::BodyTooLarge {
                limit: limits.max_body_bytes,
            });
        }
    }
}

/// Move already-read bytes into the body, charging them against `remaining`.
fn drain_rest(rest: &mut &[u8], body: &mut Vec<u8>, remaining: &mut u64) {
    let take = rest
        .len()
        .min(usize::try_from(*remaining).unwrap_or(usize::MAX));
    {
        let (take_part, rest_part) = rest.split_at(take);
        body.extend_from_slice(take_part);
        *rest = rest_part;
    }
    *remaining -= u64::try_from(take).unwrap_or(u64::MAX);
}

async fn read_chunked<S>(
    rest: &mut &[u8],
    stream: &mut S,
    limits: &Limits,
    counts: &std::sync::Mutex<IoCount>,
) -> Result<Vec<u8>, CallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buffered = rest.to_vec();
    *rest = &[];
    let mut body = Vec::new();
    loop {
        let line = read_crlf_line(&mut buffered, stream, limits, counts).await?;
        let size = u64::from_str_radix(line.split(';').next().unwrap_or(""), 16)
            .map_err(|_| CallError::Protocol)?;
        if size == 0 {
            drain_trailers(&mut buffered, stream, limits, counts).await?;
            return Ok(body);
        }
        let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
        let total = body_len.checked_add(size).ok_or(CallError::BodyTooLarge {
            limit: limits.max_body_bytes,
        })?;
        if total > limits.max_body_bytes {
            return Err(CallError::BodyTooLarge {
                limit: limits.max_body_bytes,
            });
        }
        fill_exact(&mut buffered, stream, size, counts).await?;
        let size_usize = usize::try_from(size).map_err(|_| CallError::Protocol)?;
        {
            let (chunk, _) = buffered.split_at(size_usize);
            body.extend_from_slice(chunk);
        }
        buffered.drain(..size_usize);
        // Every chunk is followed by its own CRLF.
        let crlf = read_exact_2(&mut buffered, stream, counts).await?;
        if crlf != *b"\r\n" {
            return Err(CallError::Protocol);
        }
    }
}

/// Read one CRLF-terminated line, charging the head byte cap.
async fn read_crlf_line<S>(
    buffered: &mut Vec<u8>,
    stream: &mut S,
    limits: &Limits,
    counts: &std::sync::Mutex<IoCount>,
) -> Result<String, CallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    loop {
        if let Some(end) = buffered.windows(2).position(|w| w == b"\r\n") {
            let line: Vec<u8> = buffered.drain(..end).collect();
            buffered.drain(..2);
            return std::str::from_utf8(&line)
                .map(str::to_owned)
                .map_err(|_| CallError::Protocol);
        }
        if u64::try_from(buffered.len()).unwrap_or(u64::MAX) > limits.max_response_head_bytes {
            return Err(CallError::ResponseHeadTooLarge);
        }
        let mut buf = [0u8; 4096];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|_| CallError::Transport)?;
        if n == 0 {
            return Err(CallError::Protocol);
        }
        charge(counts, 0, n);
        {
            let (chunk, _) = buf.split_at(n);
            buffered.extend_from_slice(chunk);
        }
    }
}

/// Read exactly `size` bytes into `buffered`.
///
/// No cap check here: the caller proved `body + size <= max` with checked
/// arithmetic before calling, so the final body cannot exceed the limit,
/// and the transient overshoot of one partial read is bounded by
/// construction. A second check would be defence-in-theatre, not depth.
async fn fill_exact<S>(
    buffered: &mut Vec<u8>,
    stream: &mut S,
    size: u64,
    counts: &std::sync::Mutex<IoCount>,
) -> Result<(), CallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let size_usize = usize::try_from(size).map_err(|_| CallError::Protocol)?;
    while buffered.len() < size_usize {
        let mut buf = [0u8; 4096];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|_| CallError::Transport)?;
        if n == 0 {
            return Err(CallError::Protocol);
        }
        charge(counts, 0, n);
        {
            let (chunk, _) = buf.split_at(n);
            buffered.extend_from_slice(chunk);
        }
    }
    Ok(())
}

/// Read exactly two bytes (a chunk's trailing CRLF).
async fn read_exact_2<S>(
    buffered: &mut Vec<u8>,
    stream: &mut S,
    counts: &std::sync::Mutex<IoCount>,
) -> Result<[u8; 2], CallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    // One byte at a time, destructured rather than indexed: `indexing_slicing`
    // is deny in this crate, and at most one byte is ever missing here.
    while buffered.len() < 2 {
        let mut one = [0u8; 1];
        if stream
            .read(&mut one)
            .await
            .map_err(|_| CallError::Transport)?
            == 0
        {
            return Err(CallError::Protocol);
        }
        charge(counts, 0, 1);
        let [byte] = one;
        buffered.push(byte);
    }
    let mut pair = buffered.drain(..2);
    match (pair.next(), pair.next()) {
        (Some(a), Some(b)) => Ok([a, b]),
        // Unreachable: the loop above guarantees two bytes, and `drain`
        // yields exactly what it removes. Returning `Protocol` instead of
        // panicking keeps the failure a wire error on every build.
        _ => Err(CallError::Protocol),
    }
}

/// Trailers after the zero chunk: parsed-and-dropped under the header cap.
async fn drain_trailers<S>(
    buffered: &mut Vec<u8>,
    stream: &mut S,
    limits: &Limits,
    counts: &std::sync::Mutex<IoCount>,
) -> Result<(), CallError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut count = 0;
    loop {
        let line = read_crlf_line(buffered, stream, limits, counts).await?;
        if line.is_empty() {
            return Ok(());
        }
        count += 1;
        if count > limits.max_response_headers {
            return Err(CallError::ResponseHeadTooLarge);
        }
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;

    /// A transport whose server half records every client byte and serves a
    /// script, over one duplex pair per open.
    struct SnoopTransport {
        script: Vec<u8>,
        seen: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        /// Deliver the script in two writes with a pause between, so tests
        /// can force split reads. `None` writes at once (existing tests).
        /// The pause only costs time, never correctness: coalesced reads
        /// take the same code path with the same verdict.
        split_at: Option<usize>,
    }

    impl SnoopTransport {
        fn new(script: &str) -> (Self, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
            Self::split(script, None)
        }

        fn split(
            script: &str,
            split_at: Option<usize>,
        ) -> (Self, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
            let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    script: script.as_bytes().to_vec(),
                    seen: std::sync::Arc::clone(&seen),
                    split_at,
                },
                seen,
            )
        }
    }

    impl Transport for SnoopTransport {
        type Stream = tokio::io::DuplexStream;

        // No `.await` inside: the open only spawns the server task; the
        // `async` is the trait's contract, not this impl's.
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "open only spawns the scripted server; async satisfies the Transport contract"
        )]
        async fn open(
            &self,
            _vetted: &Vetted,
            _limits: &Limits,
        ) -> Result<Self::Stream, CallError> {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let (client, mut server) = tokio::io::duplex(1 << 16);
            let script = self.script.clone();
            let split_at = self.split_at;
            let seen = std::sync::Arc::clone(&self.seen);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                // Read the request head first (up to the blank line), so the
                // exchange never blocks on a full duplex buffer, then serve.
                let mut head = Vec::new();
                loop {
                    let Ok(n) = server.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    {
                        let (chunk, _) = buf.split_at(n.min(4096));
                        head.extend_from_slice(chunk);
                    }
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                if let Ok(mut seen) = seen.lock() {
                    seen.extend_from_slice(&head);
                }
                match split_at {
                    Some(at) => {
                        let (first, rest) = script.split_at(at.min(script.len()));
                        let _ = server.write_all(first).await;
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        let _ = server.write_all(rest).await;
                    }
                    None => {
                        let _ = server.write_all(&script).await;
                    }
                }
            });
            Ok(client)
        }
    }

    struct FakeResolver;

    impl Resolver for FakeResolver {
        // Like `Fake` above: no I/O to await in a canned answer.
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "canned answers involve no I/O; async satisfies the Resolver contract"
        )]
        async fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(vec!["93.184.216.34".parse().expect("fixture parses")])
        }
    }

    fn policy() -> TenantEgress {
        TenantEgress::allowing_hosts(&["example.com"]).expect("the fixture parses")
    }

    fn get(url: &str) -> Request {
        Request {
            method: Method::Get,
            url: url.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A content-length response round-trips with byte counts, and the
    /// request on the wire carries host, close, and no hop-by-hop.
    #[tokio::test]
    async fn exchange_happy_path_counts_bytes() {
        let (transport, seen) =
            SnoopTransport::new("HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-note: hi\r\n\r\nhello");
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let response = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect("exchange works");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        let moved = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            moved.written > 0 && moved.read > 0,
            "the counters observe the wire, not the decoded body"
        );
        let seen = seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let seen = String::from_utf8(seen).expect("the request is ASCII");
        assert!(
            seen.starts_with("GET / HTTP/1.1\r\n"),
            "request line first, got {seen:?}"
        );
        assert!(
            seen.contains("\r\nhost: example.com\r\n"),
            "host header, got {seen:?}"
        );
        assert!(
            seen.contains("\r\nconnection: close\r\n"),
            "close semantics, got {seen:?}"
        );
    }

    /// Hop-by-hop headers never reach the wire, whatever the caller passes.
    #[tokio::test]
    async fn hop_by_hop_headers_are_stripped() {
        let (transport, seen) = SnoopTransport::new("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let mut request = get("https://example.com/");
        request.headers = vec![
            (
                "proxy-authorization".to_owned(),
                "Basic c2VjcmV0".to_owned(),
            ),
            ("proxy-connection".to_owned(), "keep-alive".to_owned()),
            ("te".to_owned(), "trailers".to_owned()),
            ("x-keep".to_owned(), "yes".to_owned()),
        ];
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        exchange(&vetted, &request, &limits, &mut stream, &counts)
            .await
            .expect("exchange works");
        let seen = String::from_utf8(
            seen.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .expect("ASCII");
        assert!(
            !seen.contains("proxy-authorization"),
            "stripped, got {seen:?}"
        );
        assert!(!seen.contains("proxy-connection"), "stripped, got {seen:?}");
        assert!(!seen.contains("\r\nte:"), "stripped, got {seen:?}");
        assert!(seen.contains("x-keep: yes"), "kept, got {seen:?}");
    }

    /// An over-cap body is an error with the limit, never a prefix.
    #[tokio::test]
    async fn an_over_cap_body_is_an_error() {
        let (transport, _seen) =
            SnoopTransport::new("HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n");
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits {
            max_body_bytes: 10,
            ..Limits::default()
        };
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let err = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect_err("over-cap bodies error");
        assert_eq!(err, CallError::BodyTooLarge { limit: 10 });
    }

    /// Chunked bodies decode; trailers drop; the cap charges decoded bytes.
    #[tokio::test]
    async fn chunked_bodies_decode_under_the_cap() {
        let (transport, _seen) = SnoopTransport::new(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx-t: v\r\n\r\n",
        );
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let response = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect("chunks decode");
        assert_eq!(response.body, b"hello");
    }

    /// A redirect with no hop chain granted is refused, not followed.
    #[tokio::test]
    async fn a_redirect_without_a_grant_is_refused() {
        let (transport, _seen) = SnoopTransport::new(
            "HTTP/1.1 301 Moved\r\nlocation: https://example.com/other\r\ncontent-length: 0\r\n\r\n",
        );
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let err = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect_err("redirects refuse");
        assert_eq!(err, CallError::Redirect);
    }

    /// HEAD reads no body, whatever the headers claim.
    #[tokio::test]
    async fn head_reads_no_body() {
        let (transport, _seen) =
            SnoopTransport::new("HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n");
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let request = Request {
            method: Method::Head,
            url: "https://example.com/".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let response = exchange(&vetted, &request, &limits, &mut stream, &counts)
            .await
            .expect("HEAD works");
        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
    }

    /// Too many request headers refuse before any byte is written — proven
    /// by reading the server half to EOF, not by racing a recorder task.
    #[tokio::test]
    async fn too_many_request_headers_refuse() {
        use tokio::io::AsyncReadExt as _;
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits {
            max_request_headers: 2,
            ..Limits::default()
        };
        let mut request = get("https://example.com/");
        request.headers = vec![
            ("a".to_owned(), "1".to_owned()),
            ("b".to_owned(), "2".to_owned()),
            ("c".to_owned(), "3".to_owned()),
        ];
        let counts = std::sync::Mutex::new(IoCount::default());
        let err = exchange(&vetted, &request, &limits, &mut client, &counts)
            .await
            .expect_err("header count refuses");
        assert_eq!(err, CallError::RequestTooLarge);
        drop(client);
        let mut wire = Vec::new();
        server
            .read_to_end(&mut wire)
            .await
            .expect("the server half ends");
        assert!(wire.is_empty(), "refusal precedes the first byte: {wire:?}");
    }

    /// A body on GET refuses; non-ASCII headers refuse; CR/LF in names or
    /// values refuses; caller `host` and `content-length` refuse (the
    /// connector owns both — a caller copy would put two on the wire).
    #[tokio::test]
    async fn bodies_on_get_and_dirty_headers_refuse() {
        let (transport, _seen) =
            SnoopTransport::new("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let mut bad = get("https://example.com/");
        bad.body = vec![1, 2, 3];
        let err = exchange(&vetted, &bad, &limits, &mut stream, &counts)
            .await
            .expect_err("GET with a body refuses");
        assert_eq!(err, CallError::RequestTooLarge);
        let mut dirty = get("https://example.com/");
        dirty.headers = vec![("x-bad".to_owned(), "snowman ☃".to_owned())];
        let err = exchange(&vetted, &dirty, &limits, &mut stream, &counts)
            .await
            .expect_err("non-ASCII refuses");
        assert_eq!(err, CallError::RequestTooLarge);
        for (name, value, why) in [
            (
                "x-bad\r\ninjected: yes",
                "v",
                "a CR/LF name smuggles a header",
            ),
            (
                "x-bad",
                "v\r\ninjected: yes",
                "a CR/LF value smuggles a header",
            ),
            ("x bad", "v", "a space is not a token char"),
            ("host", "evil.example", "the connector owns Host"),
            ("content-length", "5", "the connector owns Content-Length"),
            ("HOST", "evil.example", "ownership is case-insensitive"),
        ] {
            let mut injected = get("https://example.com/");
            injected.headers = vec![(name.to_owned(), value.to_owned())];
            let err = exchange(&vetted, &injected, &limits, &mut stream, &counts)
                .await
                .expect_err("injection refuses");
            assert_eq!(err, CallError::RequestTooLarge, "{why}");
        }
    }

    /// `request` audits success with byte counts.
    #[tokio::test]
    async fn request_audits_success() {
        let (transport, _seen) =
            SnoopTransport::new("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello");
        let limits = Limits::default();
        let mut rows = Vec::new();
        let response = request(
            &policy(),
            &get("https://example.com/"),
            &FakeResolver,
            &limits,
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect("the call works");
        assert_eq!(response.status, 200);
        assert_eq!(rows.len(), 1, "exactly one row per call");
        let row = rows.first().expect("exactly one row");
        assert_eq!(row.host, "example.com");
        assert_eq!(row.port, 443);
        assert_eq!(row.outcome, Outcome::Success { status: 200 });
        assert!(row.request_bytes > 0 && row.response_bytes > 0);
    }

    /// `request` audits vetting refusals with zero byte counts — a refusal
    /// that leaves no trace is un-auditable.
    #[tokio::test]
    async fn request_audits_refusals() {
        let (transport, _seen) =
            SnoopTransport::new("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        let limits = Limits::default();
        let mut rows = Vec::new();
        let err = request(
            &policy(),
            &get("https://user:pass@example.com/"),
            &FakeResolver,
            &limits,
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("userinfo refuses");
        assert_eq!(err, Failure::Refused(Refusal::Userinfo));
        assert_eq!(rows.len(), 1, "refusals audit too");
        let row = rows.first().expect("exactly one row");
        assert_eq!(
            row.outcome,
            Outcome::Refused {
                reason: Refusal::Userinfo
            }
        );
        assert_eq!(row.request_bytes, 0);
        assert_eq!(row.response_bytes, 0);
    }

    struct HangTransport;

    impl Transport for HangTransport {
        type Stream = tokio::io::DuplexStream;

        async fn open(
            &self,
            _vetted: &Vetted,
            _limits: &Limits,
        ) -> Result<Self::Stream, CallError> {
            // Never resolves: the total timeout must fail the call.
            std::future::pending().await
        }
    }

    /// A hanging peer fails the call via the total timeout, with an audit row.
    #[tokio::test]
    async fn a_hanging_peer_times_out_with_an_audit_row() {
        let limits = Limits {
            total_timeout: std::time::Duration::from_millis(50),
            ..Limits::default()
        };
        let mut rows = Vec::new();
        let err = request(
            &policy(),
            &get("https://example.com/"),
            &FakeResolver,
            &limits,
            &HangTransport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("a hang must time out");
        assert_eq!(err, Failure::Failed(CallError::Timeout));
        assert_eq!(rows.len(), 1);
        let row = rows.first().expect("exactly one row");
        assert_eq!(
            row.outcome,
            Outcome::Failed {
                reason: CallError::Timeout
            }
        );
    }

    struct HangResolver;

    impl Resolver for HangResolver {
        async fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            std::future::pending().await
        }
    }

    /// A hanging resolver fails the call under the same deadline — the
    /// total timeout covers vetting, not just the exchange.
    #[tokio::test]
    async fn a_hanging_resolver_times_out_with_an_audit_row() {
        let (transport, _seen) =
            SnoopTransport::new("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        let limits = Limits {
            total_timeout: std::time::Duration::from_millis(50),
            ..Limits::default()
        };
        let mut rows = Vec::new();
        let err = request(
            &policy(),
            &get("https://example.com/"),
            &HangResolver,
            &limits,
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("a hanging resolver must time out");
        assert_eq!(err, Failure::Failed(CallError::Timeout));
        assert_eq!(rows.len(), 1, "timeouts audit too");
        let row = rows.first().expect("exactly one row");
        assert_eq!(
            row.outcome,
            Outcome::Failed {
                reason: CallError::Timeout
            }
        );
        // The row names the host but never the URL: credentials travel in
        // URLs and rows reach logs.
        assert_eq!(row.host, "example.com");
    }

    /// A failed call audits the bytes that actually moved: the head was
    /// read before the over-cap body refused, so the row says so.
    #[tokio::test]
    async fn a_failed_call_audits_partial_bytes() {
        let script = "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n";
        let (transport, _seen) = SnoopTransport::new(script);
        let limits = Limits {
            max_body_bytes: 10,
            ..Limits::default()
        };
        let mut rows = Vec::new();
        let err = request(
            &policy(),
            &get("https://example.com/"),
            &FakeResolver,
            &limits,
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("over-cap bodies error");
        assert_eq!(err, Failure::Failed(CallError::BodyTooLarge { limit: 10 }));
        let row = rows.first().expect("exactly one row");
        assert_eq!(
            row.outcome,
            Outcome::Failed {
                reason: CallError::BodyTooLarge { limit: 10 }
            }
        );
        assert!(row.request_bytes > 0, "the request went out whole");
        let script_len = u64::try_from(script.len()).expect("the script fits");
        assert_eq!(
            row.response_bytes, script_len,
            "the head was read before the body refused"
        );
    }

    /// The OS root store loads non-empty: an empty store would fail every
    /// handshake with a confusing alert, so "no verifiable roots" fails
    /// here instead.
    #[test]
    fn system_roots_load() {
        let roots = system_roots().expect("the test machine has roots");
        assert!(
            !roots.is_empty(),
            "an empty store verifies nothing — fail loudly, not later"
        );
    }

    /// TLS verification is real in both directions: the test PKI's own name
    /// succeeds and any other name fails. Loopback here is test plumbing,
    /// not the connector — `vet` never sees these sockets.
    #[tokio::test]
    async fn tls_verifies_the_vetted_name() {
        let mut params = rcgen::CertificateParams::new(vec!["test.example".to_owned()])
            .expect("rcgen accepts the SAN");
        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "test.example");
            dn
        };
        let key = rcgen::KeyPair::generate().expect("rcgen generates");
        let cert = params.self_signed(&key).expect("self-signs");
        let key_der = rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der())
            .expect("rcgen emits a parseable private key");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .expect("server config builds");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(cert.der().clone())
            .expect("the test PKI trusts itself");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback binds");
        let addr = listener.local_addr().expect("addr known");
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("a client comes");
            let _ = acceptor.accept(tcp).await;
        });

        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("loopback connects");
        let roots = std::sync::Arc::new(roots);
        let ok = upgrade_tls(
            tcp,
            "test.example",
            std::sync::Arc::clone(&roots),
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(ok.is_ok(), "the vetted name verifies");

        // The server task finished after one accept; bind a second server
        // for the negative half.
        server.await.expect("server done");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback binds again");
        let addr = listener.local_addr().expect("addr known");
        let acceptor2 = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der())
                        .expect("rcgen emits a parseable private key"),
                )
                .expect("server config builds"),
        ));
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("a client comes");
            let _ = acceptor2.accept(tcp).await;
        });
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("loopback connects");
        let err = upgrade_tls(
            tcp,
            "other.example",
            roots,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect_err("another name must not verify");
        assert_eq!(err, CallError::Tls);
        server.await.expect("server done");
    }

    /// Interim 1xx heads are consumed; the final head decides. A 101 that
    /// promises an upgrade is refused instead.
    #[tokio::test]
    async fn interim_heads_are_skipped_and_101_refuses() {
        let (transport, _seen) = SnoopTransport::new(
            "HTTP/1.1 103 Early Hints\r\nlink: </style.css>\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi",
        );
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let response = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect("the final head wins");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hi");

        let (transport, _seen) =
            SnoopTransport::new("HTTP/1.1 101 Switching\r\nupgrade: h2c\r\n\r\n");
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let err = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect_err("101 refuses");
        assert_eq!(err, CallError::Protocol);
    }

    /// A chunk exactly at the body cap succeeds: the bound is inclusive,
    /// and the terminating zero chunk in the same read changes nothing.
    #[tokio::test]
    async fn a_chunk_exactly_at_cap_succeeds() {
        let (transport, _seen) = SnoopTransport::new(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n",
        );
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits {
            max_body_bytes: 10,
            ..Limits::default()
        };
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let response = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect("exactly-at-cap succeeds");
        assert_eq!(response.body, b"0123456789");
    }

    /// `sni_name` strips one bracket pair and nothing else.
    #[test]
    fn sni_strips_brackets_only() {
        assert_eq!(sni_name("[::1]"), "::1");
        assert_eq!(sni_name("[2606:4700:4700::1111]"), "2606:4700:4700::1111");
        assert_eq!(sni_name("example.com"), "example.com");
        assert_eq!(sni_name("93.184.216.34"), "93.184.216.34");
        assert_eq!(sni_name("[oops"), "[oops");
    }

    /// An HTTPS IPv6 literal vets with brackets intact — the form
    /// `upgrade_tls` strips before the server name.
    #[tokio::test]
    async fn an_https_ipv6_literal_vets() {
        struct V6;

        impl Resolver for V6 {
            // Canned answer, like `Fake` above.
            #[expect(
                clippy::unused_async_trait_impl,
                reason = "canned answers involve no I/O; async satisfies the Resolver contract"
            )]
            async fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
                Ok(vec![
                    "2606:4700:4700::1111".parse().expect("fixture parses"),
                ])
            }
        }

        let open = TenantEgress::allowing_hosts(&["example.com"])
            .expect("fixture parses")
            .allowing_ip_literals();
        let vetted = vet(&open, "https://[2606:4700:4700::1111]/", &V6)
            .await
            .expect("a public IPv6 literal vets with the opt-in");
        assert_eq!(vetted.host, "[2606:4700:4700::1111]");
        assert!(vetted.tls);
    }

    /// Cleartext is refused before dialling: the listener below accepts
    /// anything, so a dial would complete — the refusal must come first.
    #[tokio::test]
    async fn cleartext_is_refused_before_dialling() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback binds");
        let addr = listener.local_addr().expect("addr known");
        let vetted = Vetted {
            addr,
            host: "example.com".to_owned(),
            tls: false,
        };
        let transport = SystemTransport;
        let err = transport
            .open(&vetted, &Limits::default())
            .await
            .expect_err("cleartext refuses");
        assert_eq!(err, CallError::Transport);
        // And nothing arrived: the accept below must time out, proving no
        // SYN ever left. (A dial-first implementation would complete the
        // handshake here and fail this line instead.)
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "no connection may arrive for a refused destination"
        );
    }

    /// A response head with whitespace before the colon refuses: trimming
    /// first would launder `"X : v"` into a header the peer never sent.
    #[tokio::test]
    async fn whitespace_before_the_colon_refuses() {
        let (transport, _seen) =
            SnoopTransport::new("HTTP/1.1 200 OK\r\nx-bad : v\r\ncontent-length: 0\r\n\r\n");
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let err = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect_err("space before colon refuses");
        assert_eq!(err, CallError::Protocol);
    }

    /// Drained interim heads count against the head cap: two heads each
    /// under a 60-byte cap still refuse when they total past it. The heads
    /// arrive in separate reads, so the test exercises the cumulative
    /// accounting (`consumed`) rather than one fat buffer — removing
    /// `consumed` lets the second head through and fails this test.
    /// (If the reads ever coalesce, the verdict is the same refusal via
    /// the single-buffer path; the split only sharpens the attribution.)
    #[tokio::test]
    async fn interim_heads_share_one_cap() {
        let script =
            "HTTP/1.1 103 Early\r\nlink: </a>\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        // The interim head is exactly 34 bytes (20 + 12 + 2): split there
        // so the first read holds one complete head and nothing else.
        let interim: usize = 34;
        let (transport, _seen) = SnoopTransport::split(script, Some(interim));
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits {
            max_response_head_bytes: 60,
            ..Limits::default()
        };
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let err = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect_err("collective heads refuse");
        assert_eq!(err, CallError::ResponseHeadTooLarge);
    }

    /// 204 carries nothing no matter what the headers claim: the body is
    /// empty without reading, so a lying content-length cannot hang the call.
    #[tokio::test]
    async fn no_content_means_no_body() {
        let (transport, _seen) =
            SnoopTransport::new("HTTP/1.1 204 No Content\r\ncontent-length: 100\r\n\r\n");
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let response = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect("204 reads no body");
        assert_eq!(response.status, 204);
        assert!(response.body.is_empty());
    }

    /// Empty values and HTAB-adjacent values are legal HTTP and pass;
    /// anything else in a value refuses.
    #[tokio::test]
    async fn empty_and_tab_values_pass() {
        let (transport, _seen) = SnoopTransport::new(
            "HTTP/1.1 200 OK\r\nx-empty:\r\nx-tab:\t v\t\r\ncontent-length: 0\r\n\r\n",
        );
        let vetted = vet(&policy(), "https://example.com/", &FakeResolver)
            .await
            .expect("vets");
        let limits = Limits::default();
        let mut stream = transport.open(&vetted, &limits).await.expect("fake opens");
        let counts = std::sync::Mutex::new(IoCount::default());
        let response = exchange(
            &vetted,
            &get("https://example.com/"),
            &limits,
            &mut stream,
            &counts,
        )
        .await
        .expect("empty and tab values are legal");
        assert_eq!(response.status, 200);
    }
}

// ---------------------------------------------------------------------------
// Redirect hop chains + cleartext transports (Phase 3, red-first)
// ---------------------------------------------------------------------------
//
// These fail to compile until the wiring lands (`PlainTransport`,
// `EgressTransport`, `CallError::Downgrade`,
// `TenantEgress::allowing_redirects`, manifest `cleartext` /
// `redirects` fields) — then prove the chain: re-vet every hop,
// never downgrade, fourth hop refused, per-hop audit rows.

#[cfg(test)]
mod redirect_tests {
    use super::*;

    /// One canned address for every test host, counting calls in order
    /// so tests prove each hop was re-vetted (and refused hops never
    /// reached DNS at all).
    struct CountingResolver {
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl CountingResolver {
        fn new() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("test mutex held").clone()
        }
    }

    impl Resolver for CountingResolver {
        // No I/O to await in a canned answer; the `async` is the
        // trait's contract, not this impl's.
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "canned answers involve no I/O; async satisfies the Resolver contract"
        )]
        async fn resolve(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
            self.calls
                .lock()
                .expect("test mutex held")
                .push(host.to_owned());
            Ok(vec!["93.184.216.34".parse().expect("fixture parses")])
        }
    }

    /// A transport serving per-host scripts over duplex, recording
    /// opened hosts in order — so tests prove each hop dialled its
    /// own vetted address, and refused hops dialled nothing.
    ///
    /// The alias keeps the log's type below the complexity lint: the
    /// shape (host plus the raw head bytes the server half saw) is
    /// the assertion surface, not an abstraction worth a struct.
    type SeenLog = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;
    struct RouteTransport {
        routes: std::collections::HashMap<String, Vec<u8>>,
        opens: std::sync::Mutex<Vec<String>>,
        seen: SeenLog,
    }

    impl RouteTransport {
        fn new(routes: &[(&str, Vec<u8>)]) -> Self {
            Self {
                routes: routes
                    .iter()
                    .map(|(host, script)| ((*host).to_owned(), script.clone()))
                    .collect(),
                opens: std::sync::Mutex::new(Vec::new()),
                seen: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn opens(&self) -> Vec<String> {
            self.opens.lock().expect("test mutex held").clone()
        }

        /// Request bytes the server half saw for one host, concatenated.
        fn seen_for(&self, host: &str) -> Vec<u8> {
            self.seen
                .lock()
                .expect("test mutex held")
                .iter()
                .filter(|(h, _)| h == host)
                .flat_map(|(_, bytes)| bytes.clone())
                .collect()
        }
    }

    impl Transport for RouteTransport {
        type Stream = tokio::io::DuplexStream;

        // No `.await` in this impl: setup only, I/O in the task.
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "duplex setup involves no I/O to await; async satisfies the Transport contract"
        )]
        async fn open(&self, vetted: &Vetted, _limits: &Limits) -> Result<Self::Stream, CallError> {
            self.opens
                .lock()
                .expect("test mutex held")
                .push(vetted.host.clone());
            let script = self.routes.get(&vetted.host).cloned().unwrap_or_else(|| {
                b"HTTP/1.1 500 No Script\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec()
            });
            let seen = std::sync::Arc::clone(&self.seen);
            let host = vetted.host.clone();
            let (client, mut server) = tokio::io::duplex(1 << 16);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut head = Vec::new();
                loop {
                    let mut byte = [0u8; 1];
                    if server.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    if head.len() > 8192 {
                        return;
                    }
                }
                // Drain a declared body so the exchange never blocks on
                // a full duplex buffer; content comes from Content-Length.
                let text = String::from_utf8_lossy(&head).into_owned();
                let mut content_length = 0usize;
                for line in text.split("\r\n") {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_length.min(1 << 20)];
                let mut read = 0usize;
                while read < body.len() {
                    // `get_mut` with the loop invariant rather than
                    // slicing: the cursor only advances by bytes read.
                    let Some(slot) = body.get_mut(read..) else {
                        break;
                    };
                    match server.read(slot).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => read += n,
                    }
                }
                if let Ok(mut seen) = seen.lock() {
                    seen.push((host, head));
                }
                let _ = server.write_all(&script).await;
                let _ = server.flush().await;
            });
            Ok(client)
        }
    }

    fn redirect_to(url: &str) -> Vec<u8> {
        format!("HTTP/1.1 302 Found\r\nlocation: {url}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .into_bytes()
    }

    fn ok(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn policy_allowing(hosts: &[&str]) -> TenantEgress {
        TenantEgress::allowing_hosts(hosts).expect("fixture policy parses")
    }

    fn redirect_limits(hops: u8) -> Limits {
        Limits {
            max_redirects: hops,
            ..Limits::default()
        }
    }

    fn get(url: &str) -> Request {
        Request {
            method: Method::Get,
            url: url.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Cleartext without the opt-in refuses at vetting: no DNS, no
    /// dial, one refusal row.
    #[tokio::test]
    async fn cleartext_refused_without_the_opt_in() {
        let transport = RouteTransport::new(&[]);
        let resolver = CountingResolver::new();
        let mut rows = Vec::new();
        let err = request(
            &policy_allowing(&["example.com"]),
            &get("http://example.com/"),
            &resolver,
            &Limits::default(),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("cleartext without the grant refuses");
        assert_eq!(err, Failure::Refused(Refusal::Scheme));
        assert!(transport.opens().is_empty(), "refused before any dial");
        assert!(resolver.calls().is_empty(), "refused before any DNS");
        assert_eq!(rows.len(), 1);
        assert!(matches!(
            rows.first().expect("one refusal row").outcome,
            Outcome::Refused { .. }
        ));
    }

    /// Granted cleartext connects over the plain transport: the TLS
    /// side panics if touched, proving selection, and the body proves
    /// the bytes.
    #[tokio::test]
    async fn granted_cleartext_connects() {
        struct PanicTls;
        impl Transport for PanicTls {
            type Stream = tokio::io::DuplexStream;
            // No `.await`: refusal needs none. The `async` is the
            // trait's contract, not this impl's. (No `#[expect]`:
            // a body that only panics never trips the unused-async
            // lint, so expecting it would itself fail.)
            async fn open(&self, _: &Vetted, _: &Limits) -> Result<Self::Stream, CallError> {
                panic!("cleartext must never reach the TLS transport");
            }
        }
        let plain = RouteTransport::new(&[("example.com", ok("plain hello"))]);
        let transport = EgressTransport::new(PanicTls, plain);
        let policy = policy_allowing(&["example.com"]).allowing_cleartext();
        let mut rows = Vec::new();
        let response = request(
            &policy,
            &get("http://example.com/"),
            &CountingResolver::new(),
            &Limits::default(),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect("granted cleartext connects");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"plain hello");
        assert_eq!(rows.len(), 1);
        assert!(matches!(
            rows.first().expect("one success row").outcome,
            Outcome::Success { status: 200 }
        ));
    }

    /// TLS destinations route to the secure transport: the plain side
    /// panics if touched, proving selection the other way.
    #[tokio::test]
    async fn tls_destinations_route_to_the_secure_transport() {
        struct PanicPlain;
        impl Transport for PanicPlain {
            type Stream = tokio::io::DuplexStream;
            // No `.await`: refusal needs none (see `PanicTls` above
            // for why there is no `#[expect]` here).
            async fn open(&self, _: &Vetted, _: &Limits) -> Result<Self::Stream, CallError> {
                panic!("TLS must never reach the plain transport");
            }
        }
        let secure = RouteTransport::new(&[("example.com", ok("secure hello"))]);
        let transport = EgressTransport::new(secure, PanicPlain);
        let mut rows = Vec::new();
        let response = request(
            &policy_allowing(&["example.com"]),
            &get("https://example.com/"),
            &CountingResolver::new(),
            &Limits::default(),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect("https routes to the secure transport");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"secure hello");
        assert_eq!(rows.len(), 1);
    }

    fn redirect_policy() -> TenantEgress {
        policy_allowing(&["hop1.test", "hop2.test", "hop3.test", "final.test"])
            .allowing_redirects(3)
    }

    /// A redirect without the grant refuses after the first hop: one
    /// hop dialled and vetted, the second never resolved, two rows
    /// (the visited hop plus the refusal).
    #[tokio::test]
    async fn redirect_refused_without_the_grant() {
        let transport =
            RouteTransport::new(&[("hop1.test", redirect_to("https://hop2.test/next"))]);
        let resolver = CountingResolver::new();
        let mut rows = Vec::new();
        let err = request(
            &policy_allowing(&["hop1.test", "hop2.test"]),
            &get("https://hop1.test/start"),
            &resolver,
            &Limits::default(),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("redirect without a grant refuses");
        assert_eq!(err, Failure::Failed(CallError::Redirect));
        assert_eq!(transport.opens(), ["hop1.test"]);
        assert_eq!(resolver.calls(), ["hop1.test"]);
        assert_eq!(rows.len(), 2, "visited hop plus refusal");
        assert!(matches!(
            rows.first().expect("visited hop row").outcome,
            Outcome::Success { status: 302 }
        ));
        assert!(matches!(
            rows.get(1).expect("refusal row").outcome,
            Outcome::Failed { .. }
        ));
    }

    /// A three-hop chain succeeds with every hop re-vetted: opens and
    /// resolver calls arrive in hop order, and four rows name the
    /// four destinations.
    #[tokio::test]
    async fn three_hop_chain_succeeds() {
        let transport = RouteTransport::new(&[
            ("hop1.test", redirect_to("https://hop2.test/next")),
            ("hop2.test", redirect_to("https://hop3.test/next")),
            ("hop3.test", redirect_to("https://final.test/end")),
            ("final.test", ok("chain done")),
        ]);
        let resolver = CountingResolver::new();
        let mut rows = Vec::new();
        let response = request(
            &redirect_policy(),
            &get("https://hop1.test/start"),
            &resolver,
            &redirect_limits(3),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect("three granted hops succeed");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"chain done");
        assert_eq!(
            transport.opens(),
            ["hop1.test", "hop2.test", "hop3.test", "final.test"]
        );
        assert_eq!(
            resolver.calls(),
            ["hop1.test", "hop2.test", "hop3.test", "final.test"]
        );
        let hosts: Vec<&str> = rows.iter().map(|row| row.host.as_str()).collect();
        assert_eq!(hosts, ["hop1.test", "hop2.test", "hop3.test", "final.test"]);
    }

    /// An https-to-http hop refuses as a downgrade before the second
    /// dial: the new URL is never resolved, let alone opened.
    #[tokio::test]
    async fn downgrade_refused() {
        let transport = RouteTransport::new(&[("hop1.test", redirect_to("http://hop2.test/next"))]);
        let resolver = CountingResolver::new();
        let mut rows = Vec::new();
        let err = request(
            &redirect_policy(),
            &get("https://hop1.test/start"),
            &resolver,
            &redirect_limits(3),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("https-to-http downgrade refuses");
        assert_eq!(err, Failure::Failed(CallError::Downgrade));
        assert_eq!(transport.opens(), ["hop1.test"]);
        assert_eq!(resolver.calls(), ["hop1.test"]);
        assert_eq!(rows.len(), 2);
    }

    /// The fourth follow refuses when three are granted: a grant of N
    /// authorises N followed redirects (N + 1 visits), so the fourth
    /// redirect — `final.test` back to `hop1.test` — is the chain
    /// error. Four opens, four resolutions, five rows (four visited
    /// hops plus the refusal): the refused follow is never resolved,
    /// let alone opened.
    #[tokio::test]
    async fn fourth_hop_refused() {
        let transport = RouteTransport::new(&[
            ("hop1.test", redirect_to("https://hop2.test/2")),
            ("hop2.test", redirect_to("https://hop3.test/3")),
            ("hop3.test", redirect_to("https://final.test/4")),
            ("final.test", redirect_to("https://hop1.test/again")),
        ]);
        let resolver = CountingResolver::new();
        let mut rows = Vec::new();
        let err = request(
            &redirect_policy(),
            &get("https://hop1.test/start"),
            &resolver,
            &redirect_limits(3),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("the fourth follow refuses");
        assert_eq!(err, Failure::Failed(CallError::Redirect));
        assert_eq!(
            transport.opens(),
            ["hop1.test", "hop2.test", "hop3.test", "final.test"]
        );
        assert_eq!(
            resolver.calls(),
            ["hop1.test", "hop2.test", "hop3.test", "final.test"]
        );
        assert_eq!(rows.len(), 5, "four visited hops plus the refusal");
        assert!(matches!(
            rows.get(4).expect("refusal row").outcome,
            Outcome::Failed { .. }
        ));
    }

    /// The hard ceiling holds regardless of the grant: five granted
    /// hops still stop at three follows — four visits, then the
    /// fourth redirect refuses even though the grant allows five.
    #[tokio::test]
    async fn hard_ceiling_holds_past_the_grant() {
        let transport = RouteTransport::new(&[
            ("hop1.test", redirect_to("https://hop2.test/2")),
            ("hop2.test", redirect_to("https://hop3.test/3")),
            ("hop3.test", redirect_to("https://final.test/4")),
            ("final.test", redirect_to("https://hop1.test/5")),
        ]);
        let policy = policy_allowing(&["hop1.test", "hop2.test", "hop3.test", "final.test"])
            .allowing_redirects(5);
        let resolver = CountingResolver::new();
        let mut rows = Vec::new();
        let err = request(
            &policy,
            &get("https://hop1.test/start"),
            &resolver,
            &redirect_limits(5),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("the protocol ceiling stops at three");
        assert_eq!(err, Failure::Failed(CallError::Redirect));
        assert_eq!(transport.opens().len(), 4, "three follows, four visits");
        assert_eq!(resolver.calls().len(), 4);
        assert_eq!(rows.len(), 5, "four visited hops plus the refusal");
    }

    /// Credentials stay at their origin: an `authorization` header
    /// forwarded to the first hop is stripped before a cross-origin
    /// second hop, while ordinary headers travel — and stay stripped
    /// on the third. Stripping moves forward only: nothing restores
    /// a credential once it leaves its origin.
    #[tokio::test]
    async fn sensitive_headers_stripped_cross_origin() {
        let transport = RouteTransport::new(&[
            ("a.test", redirect_to("https://b.test/mid")),
            ("b.test", redirect_to("https://c.test/end")),
            ("c.test", ok("done")),
        ]);
        let policy = policy_allowing(&["a.test", "b.test", "c.test"]).allowing_redirects(3);
        let post = Request {
            method: Method::Post,
            url: "https://a.test/start".to_owned(),
            headers: vec![
                ("authorization".to_owned(), "Bearer secret".to_owned()),
                ("x-keep".to_owned(), "yes".to_owned()),
            ],
            body: b"data".to_vec(),
        };
        let mut rows = Vec::new();
        let response = request(
            &policy,
            &post,
            &CountingResolver::new(),
            &redirect_limits(3),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect("chain succeeds");
        assert_eq!(response.status, 200);
        for host in ["b.test", "c.test"] {
            let seen = transport.seen_for(host);
            let seen = String::from_utf8_lossy(&seen).into_owned();
            assert!(
                !seen.to_ascii_lowercase().contains("authorization"),
                "credential stripped before {host}: {seen:?}"
            );
            assert!(
                seen.contains("x-keep: yes"),
                "ordinary headers travel to {host}: {seen:?}"
            );
        }
        assert_eq!(rows.len(), 3, "one row per hop");
    }

    /// A cross-origin hop never carries the first origin's body: a
    /// POST that meets a cross-origin redirect continues as a GET
    /// with an empty body, so a secret the guest entrusted to one
    /// allowed origin is not delivered to another. Ordinary headers
    /// still travel (pinned above); only the body is dropped.
    #[tokio::test]
    async fn cross_origin_hop_drops_the_body() {
        let transport = RouteTransport::new(&[
            ("a.test", redirect_to("https://b.test/mid")),
            ("b.test", ok("landed")),
        ]);
        let policy = policy_allowing(&["a.test", "b.test"]).allowing_redirects(1);
        let post = Request {
            method: Method::Post,
            url: "https://a.test/start".to_owned(),
            headers: vec![("x-keep".to_owned(), "yes".to_owned())],
            body: b"secret-body".to_vec(),
        };
        let mut rows = Vec::new();
        let response = request(
            &policy,
            &post,
            &CountingResolver::new(),
            &redirect_limits(1),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect("chain succeeds as a bodyless follow");
        assert_eq!(response.status, 200);
        let seen = transport.seen_for("b.test");
        let seen = String::from_utf8_lossy(&seen).into_owned();
        assert!(
            seen.starts_with("GET /mid "),
            "cross-origin follow is a GET: {seen:?}"
        );
        assert!(
            !seen.contains("secret-body"),
            "first origin's body never reaches the second: {seen:?}"
        );
        assert_eq!(rows.len(), 2, "one row per hop");
    }

    /// A same-origin hop keeps method and body: the follow is the
    /// same trust domain, so the POST continues as a POST with its
    /// bytes — login flows must not lose their payload to the chain.
    /// Both hops' heads carry the method and the full content
    /// length; the second 302 then exhausts the grant of one and
    /// refuses, which is also what bounds the self-redirect.
    #[tokio::test]
    async fn same_origin_hop_keeps_method_and_body() {
        let transport = RouteTransport::new(&[("a.test", redirect_to("https://a.test/again"))]);
        let policy = policy_allowing(&["a.test"]).allowing_redirects(1);
        let post = Request {
            method: Method::Post,
            url: "https://a.test/start".to_owned(),
            headers: Vec::new(),
            body: b"secret-body".to_vec(),
        };
        let mut rows = Vec::new();
        let err = request(
            &policy,
            &post,
            &CountingResolver::new(),
            &redirect_limits(1),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect_err("the second redirect exhausts the grant of one");
        assert_eq!(err, Failure::Failed(CallError::Redirect));
        let seen = transport.seen_for("a.test");
        let seen = String::from_utf8_lossy(&seen).to_ascii_lowercase();
        assert!(seen.contains("post /start "), "first hop posts: {seen:?}");
        assert!(
            seen.contains("post /again "),
            "same-origin follow stays a post: {seen:?}"
        );
        assert_eq!(
            seen.matches("content-length: 11").count(),
            2,
            "both hops carry the full body: {seen:?}"
        );
        assert_eq!(rows.len(), 3, "two visited hops plus the refusal");
    }

    /// A cross-origin HEAD stays a HEAD: there is no body to drop,
    /// so the follow changes nothing — pinning that the conversion
    /// touches POST alone.
    #[tokio::test]
    async fn cross_origin_head_stays_head() {
        let transport = RouteTransport::new(&[
            ("a.test", redirect_to("https://b.test/mid")),
            ("b.test", ok("landed")),
        ]);
        let policy = policy_allowing(&["a.test", "b.test"]).allowing_redirects(1);
        let head = Request {
            method: Method::Head,
            url: "https://a.test/start".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut rows = Vec::new();
        let response = request(
            &policy,
            &head,
            &CountingResolver::new(),
            &redirect_limits(1),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect("chain succeeds");
        assert_eq!(response.status, 200);
        let seen = transport.seen_for("b.test");
        let seen = String::from_utf8_lossy(&seen).into_owned();
        assert!(
            seen.starts_with("HEAD /mid "),
            "cross-origin follow keeps head: {seen:?}"
        );
        assert_eq!(rows.len(), 2, "one row per hop");
    }

    /// The manifest is the grants' single source: cleartext plus one
    /// redirect hop declared in TOML enforces both through a store
    /// built from that manifest.
    #[tokio::test]
    async fn manifest_derivation_covers_cleartext_and_redirects() {
        use qqq_cap::manifest::Manifest;
        let manifest = Manifest::parse(
            "[package]\nname = \"acme\"\nversion = \"1.0.0\"\n\
             [capabilities.http]\nclient = [\"example.com\", \"plain.example.com\"]\ncleartext = true\nredirects = 1\n",
        )
        .expect("fixture manifest parses");
        let policy = TenantEgress::from_manifest(&manifest);
        assert!(policy.allows_cleartext(), "cleartext declared");
        let transport = RouteTransport::new(&[
            ("example.com", redirect_to("http://plain.example.com/plain")),
            ("plain.example.com", ok("plain done")),
        ]);
        let mut rows = Vec::new();
        let response = request(
            &policy,
            &get("http://example.com/start"),
            &CountingResolver::new(),
            &redirect_limits(1),
            &transport,
            &mut |row| rows.push(row),
        )
        .await
        .expect("declared cleartext plus one hop works");
        assert_eq!(response.status, 200);
        assert_eq!(rows.len(), 2, "start hop plus followed hop");
    }
}
