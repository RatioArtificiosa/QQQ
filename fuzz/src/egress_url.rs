//! URL-string harness for the egress connector (`I-01`), as pure functions
//! the fuzz target calls and the tests below pin.
//!
//! # What this proves, and what it does not
//!
//! It proves two properties over arbitrary byte strings: vetting never
//! panics, and vetting never yields a forbidden address — the firewall
//! property, checked on the `Vetted` value rather than on the code path,
//! so a future refactor that keeps the type keeps the proof. It does not
//! prove the exchange half (framing is covered by unit tests over
//! scripted streams) and it does not touch the network: the resolver is
//! a canned mixed answer, which is also what makes the rebinding case
//! (public + private together) reachable on every input.

use qqq_cap::egress::TenantEgress;
use qqq_host::egress::{Resolver, is_forbidden_ip, vet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A canned mixed answer: one public address, one private. Every granted
/// host vets against both, so the rebinding shape (an attacker mixing
/// addresses) is exercised on every input rather than only on the inputs
/// a resolver would really return.
struct Mixed {
    calls: AtomicUsize,
}

impl Mixed {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl Resolver for Mixed {
    async fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(vec![
            "93.184.216.34".parse().expect("fixture parses"),
            "10.0.0.1".parse().expect("fixture parses"),
        ])
    }
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    // One runtime per fuzz process: building one per input would spend
    // more time constructing executors than vetting URLs.
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a test runtime builds")
    })
}

fn policy() -> TenantEgress {
    TenantEgress::allowing_hosts(&["example.com", "*.example.net"])
        .expect("the fixture parses")
        .allowing_ip_literals()
        .allowing_cleartext()
}

/// Check one URL string: no panic, and no forbidden address ever vets.
///
/// A policy that grants broadly (literals, cleartext, a wildcard) is
/// deliberate: a narrow policy would refuse everything before the tables
/// matter, and the property under test is that the *tables* hold on every
/// input the parser accepts.
pub fn check(data: &[u8]) {
    let url = String::from_utf8_lossy(data);
    let rt = runtime();
    let resolver = Mixed::new();
    // `vet` must not panic on any input — including the non-UTF-8 the
    // lossy conversion replaced, the empty string, and multi-megabyte
    // strings (libFuzzer explores all three).
    match rt.block_on(vet(&policy(), &url, &resolver)) {
        Ok(vetted) => assert!(
            !is_forbidden_ip(vetted.addr.ip()),
            "vetted a forbidden address for {url:?}: {:?}",
            vetted.addr.ip(),
        ),
        Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interesting shapes, each pinned: grants, refusals, literals,
    /// userinfo, IDN, numeric shorthand, port overflow, and garbage.
    #[test]
    fn seed_urls_hold_the_property() {
        for url in [
            "https://example.com/",
            "https://example.com:8443/a?b=c",
            "http://example.com/",
            "https://sub.example.net/",
            "https://user:pass@example.com/",
            "https://93.184.216.34/",
            "https://10.0.0.1/",
            "https://169.254.169.254/",
            "https://[::1]/",
            "https://xn--exmple-cua.com/",
            "https://12345/",
            "https://0x7f.1/",
            "https://example.com:99999/",
            "https://example.com:0/",
            "not a url at all",
            "",
            "https://",
            "ftp://example.com/",
            "https://example.com/%ff",
            "HTTPS://EXAMPLE.COM/",
        ] {
            check(url.as_bytes());
        }
        // Non-UTF-8 input reaches the lossy path, not a panic.
        check(b"https://example.com/\xff\xfe");
    }

    /// A granted public host against the mixed resolver refuses (the
    /// private half poisons the answer) — and resolved exactly once.
    #[test]
    fn mixed_answers_refuse_once() {
        let rt = runtime();
        let resolver = Mixed::new();
        let err = rt
            .block_on(vet(&policy(), "https://example.com/", &resolver))
            .expect_err("mixed answers refuse");
        assert!(matches!(
            err,
            qqq_host::egress::Refusal::Forbidden { .. }
        ));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
    }
}
