// SPDX-License-Identifier: Apache-2.0

//! Resolve `qqq:secrets` material at the deploy layer — `HOST-028`.
//!
//! The host (`qqq-host`) holds and uses secret bytes but never resolves them:
//! resolution reads the process environment, which is ambient state that
//! `§2.5` forbids inside the runtime (`tools/check_no_ambient.py` enforces
//! it). So the edge — `qqq-run`, a CLI that is entitled to inspect its own
//! process — resolves once, at startup, and hands the runtime material.
//!
//! A missing variable fails the command with `SecretUnresolvable`, naming the
//! variable but never echoing a value. Refusing to start is the fail-closed
//! direction: a guest whose secret never resolves would otherwise fail at
//! first use, after the operator believed the deploy healthy. An unknown
//! scheme (`vault:`, `file:`) fails the same way — silently ignoring it
//! would deploy a guest whose secret never resolves.
//!
//! The lookup is a parameter rather than `std::env` directly so the rule is
//! testable without mutating the process environment (which would race every
//! other test in the binary).

use qqq_cap::manifest::Manifest;
use qqq_cap::normalize::SecretRef;
use qqq_core::{Error, ErrorCode};
use qqq_host::host_secrets::{PermittedOp, SecretMaterial, SecretStore};

/// Resolve every secret the manifest grants into a store the host can serve.
///
/// Reads each `env:` reference through `lookup` and grants the logical name.
/// Production passes the process environment; tests pass a map. Material
/// carries every operation — the crypto grants intersect at call time (see
/// `host_secrets::register`), so a use grant cannot smuggle a primitive the
/// operator did not also grant.
///
/// # Errors
///
/// `SecretUnresolvable` naming the reference when the scheme is unknown or
/// the variable is unset. The value is never echoed.
pub fn resolve_secret_store(
    manifest: &Manifest,
    lookup: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Result<SecretStore, Error> {
    let mut refs: Vec<&String> = Vec::new();
    if let Some(secret) = manifest.capabilities.secret.as_ref() {
        refs.extend(secret.secrets.iter());
    }
    if let Some(crypto) = manifest.capabilities.crypto.as_ref() {
        refs.extend(crypto.secrets.iter());
    }
    let mut granted: Vec<String> = Vec::new();
    let mut material: Vec<SecretMaterial> = Vec::new();
    for r in refs {
        let parsed = SecretRef::parse(r).map_err(|reason| {
            Error::new(
                ErrorCode::SecretUnresolvable,
                format!("secret reference `{r}` is not usable: {reason}"),
            )
            .with_remediation("use the `env:NAME` scheme, e.g. `secrets = [\"env:DB_URL\"]`")
        })?;
        granted.push(parsed.logical_name.clone());
        match lookup(&parsed.env_var) {
            Some(value) => material.push(SecretMaterial::new(
                parsed.logical_name,
                value,
                PermittedOp::all().to_vec(),
            )),
            None => {
                return Err(Error::new(
                    ErrorCode::SecretUnresolvable,
                    format!(
                        "secret `{}` needs environment variable `{}` which is not set",
                        parsed.logical_name, parsed.env_var
                    ),
                )
                .with_remediation("set the named environment variable, or correct the reference"));
            }
        }
    }
    granted.sort();
    granted.dedup();
    Ok(SecretStore::with_grants(granted, material))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with(secrets: &str) -> Manifest {
        Manifest::parse(&format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n{secrets}\n"
        ))
        .expect("fixture manifest parses")
    }

    fn lookup<'a>(pairs: &'a [(&'a str, &'a [u8])]) -> impl Fn(&str) -> Option<Vec<u8>> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_vec())
        }
    }

    /// Resolution grants the logical name and carries the bytes.
    #[test]
    fn env_reference_resolves_to_material() {
        let m = manifest_with("[capabilities.secret]\nsecrets = [\"env:K\"]\n");
        let store =
            resolve_secret_store(&m, &lookup(&[("K", b"0123456789abcdef0123456789abcdef")]))
                .expect("set variable resolves");
        assert!(store.is_granted("K"));
        assert!(store.exists("K"));
        assert!(!store.is_granted("OTHER"));
    }

    /// A missing variable fails the deploy, naming the variable — not the guest's first call.
    #[test]
    fn missing_variable_fails_closed() {
        let m = manifest_with("[capabilities.secret]\nsecrets = [\"env:MISSING\"]\n");
        let err = resolve_secret_store(&m, &lookup(&[])).expect_err("unset must fail");
        assert_eq!(err.code, ErrorCode::SecretUnresolvable);
        assert!(
            err.message.contains("MISSING"),
            "names the variable: {}",
            err.message
        );
        assert!(!err.message.contains("super"), "never echoes a value");
    }

    /// Unknown schemes fail rather than deploying an unresolvable grant.
    #[test]
    fn unknown_scheme_fails_closed() {
        let m = manifest_with("[capabilities.secret]\nsecrets = [\"vault:x\"]\n");
        let err = resolve_secret_store(&m, &lookup(&[])).expect_err("unknown scheme must fail");
        assert_eq!(err.code, ErrorCode::SecretUnresolvable);
    }

    /// Both spellings union: the legacy nested table resolves identically.
    #[test]
    fn legacy_spelling_resolves() {
        let m = manifest_with("[capabilities.crypto]\nsecrets = [\"env:K\"]\n");
        let store = resolve_secret_store(&m, &lookup(&[("K", b"x")])).expect("legacy resolves");
        assert!(store.is_granted("K"));
    }
}
