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
//! This commit holds the pure vetting half: the forbidden-IP tables, the
//! injectable [`Resolver`], and [`vet`], which reduces a URL string to a
//! [`Vetted`] address or a [`Refusal`]. Socket I/O (connect, TLS, timeouts,
//! caps, audit rows) builds on [`Vetted`] in the follow-up commit —
//! vetting first means the I/O layer cannot be written to skip it, because
//! there is no other constructor for the address it dials.
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
