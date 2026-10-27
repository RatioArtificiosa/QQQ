// SPDX-License-Identifier: Apache-2.0

//! `qqq:env/environment` — individually named variables, never a blanket inherit.
//!
//! The manifest names variables; the deploy layer resolves their values once
//! and hands this module a map. Nothing here touches the process environment
//! (`CON-010`): the WASI baseline context is built from injected pairs for
//! the same reason, and this interface is the `qqq:`-namespaced equivalent.
//!
//! Two denials look identical on purpose: `not-allowed` covers both "not
//! granted" and "not in the allowlist", because distinguishing them would let
//! a guest enumerate which variables exist. `unset` is a separate, honest
//! state — allowed but absent — which `get-or` turns into the fallback.

use qqq_cap::capability::Capability::EnvRead;

/// The WIT package this module implements.
pub const INTERFACE: &str = "qqq:env@1.0.0";

/// The environment interface, as a component imports it.
pub const ENVIRONMENT: &str = "qqq:env/environment@1.0.0";

mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-env.wit",
        interfaces: "import qqq:env/environment@1.0.0;",
    });
}

/// The WIT `env-error`, re-exported rather than re-declared: the WIT variant
/// is the definition. (Same rule as `host_test.rs` and `host_secrets.rs`.)
pub use bindings::qqq::env::environment::EnvError as WitEnvError;

/// Register the environment interface for the granted capability.
///
/// Links `qqq:env/environment` only when `env.read` is granted; every
/// function re-checks at call time.
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects a signature.
pub fn register(
    linker: &mut wasmtime::component::Linker<crate::linker::StoreData>,
    grants: &qqq_cap::resolve::GrantSet,
) -> wasmtime::Result<()> {
    if !grants.grants(EnvRead) {
        return Ok(());
    }
    let mut inst = linker.instance(ENVIRONMENT)?;
    register_get(&mut inst)?;
    register_get_or(&mut inst)?;
    register_allowed_names(&mut inst)?;
    Ok(())
}

/// `get(name) -> result<string, env-error>`.
fn register_get(
    inst: &mut wasmtime::component::LinkerInstance<'_, crate::linker::StoreData>,
) -> wasmtime::Result<()> {
    inst.func_wrap(
        "get",
        |store: wasmtime::StoreContextMut<'_, crate::linker::StoreData>,
         (name,): (String,)|
         -> wasmtime::Result<(std::result::Result<String, WitEnvError>,)> {
            crate::guard::guard("qqq:env/environment.get", || {
                let out = match lookup(store.data(), &name) {
                    Err(e) => Err(e),
                    Ok(None) => Err(WitEnvError::Unset),
                    Ok(Some(bytes)) => {
                        String::from_utf8(bytes).map_err(|_| WitEnvError::InvalidUtf8)
                    }
                };
                Ok((out,))
            })
        },
    )?;
    Ok(())
}

/// `get-or(name, default) -> result<string, env-error>`.
///
/// The fallback applies to `unset` only: substituting a default for a denied
/// capability would hide a misconfiguration.
fn register_get_or(
    inst: &mut wasmtime::component::LinkerInstance<'_, crate::linker::StoreData>,
) -> wasmtime::Result<()> {
    inst.func_wrap(
        "get-or",
        |store: wasmtime::StoreContextMut<'_, crate::linker::StoreData>,
         (name, default): (String, String)|
         -> wasmtime::Result<(std::result::Result<String, WitEnvError>,)> {
            crate::guard::guard("qqq:env/environment.get-or", || {
                let out = match lookup(store.data(), &name) {
                    Err(e) => Err(e),
                    Ok(None) => Ok(default),
                    Ok(Some(bytes)) => {
                        String::from_utf8(bytes).map_err(|_| WitEnvError::InvalidUtf8)
                    }
                };
                Ok((out,))
            })
        },
    )?;
    Ok(())
}

/// `allowed-names() -> list<string>`: the manifest set, sorted.
///
/// Disclosing the names is safe (they ship in `qqq.toml`); the values never
/// cross. Sorted because the source is a map, and map order must not leak
/// into anything a guest can observe (`DET-006`).
fn register_allowed_names(
    inst: &mut wasmtime::component::LinkerInstance<'_, crate::linker::StoreData>,
) -> wasmtime::Result<()> {
    inst.func_wrap(
        "allowed-names",
        |store: wasmtime::StoreContextMut<'_, crate::linker::StoreData>,
         ()|
         -> wasmtime::Result<(Vec<String>,)> {
            crate::guard::guard("qqq:env/environment.allowed-names", || {
                if !store.data().grants.grants(EnvRead) {
                    return Ok((Vec::new(),));
                }
                Ok((store.data().env.keys().cloned().collect(),))
            })
        },
    )?;
    Ok(())
}

/// Look a name up: the grant, then the allowlist, then the value.
///
/// The map carries every allowed name (`None` for listed-but-unset), so a
/// missing *key* is unlisted (`not-allowed`) while a `None` *value* is
/// `unset`. Collapsing the two would let a guest enumerate the allowlist
/// by probing names — the precise leak the single `not-allowed` error for
/// "ungranted or unlisted" exists to prevent.
fn lookup(
    data: &crate::linker::StoreData,
    name: &str,
) -> std::result::Result<Option<Vec<u8>>, WitEnvError> {
    if !data.grants.grants(EnvRead) {
        return Err(WitEnvError::NotAllowed);
    }
    match data.env.get(name) {
        None => Err(WitEnvError::NotAllowed),
        Some(None) => Ok(None),
        Some(Some(value)) => Ok(Some(value.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_with(granted: bool, pairs: &[(&str, Option<&[u8]>)]) -> crate::linker::StoreData {
        use qqq_cap::resolve::GrantSet;
        let grants = if granted {
            let m = qqq_cap::manifest::Manifest::parse(
                "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.env]\nallow = [\"A\", \"B\"]\n",
            )
            .expect("manifest parses");
            GrantSet::from_manifest(&m)
        } else {
            GrantSet::empty()
        };
        let mut data = crate::linker::StoreData::new(grants);
        data.env = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.map(<[u8]>::to_vec)))
            .collect();
        data
    }

    /// Lookups distinguish the three states.
    #[test]
    fn lookup_states_are_distinct() {
        let data = data_with(true, &[("A", Some(b"1".as_slice())), ("B", None)]);
        assert_eq!(
            lookup(&data, "A").expect("allowed").as_deref(),
            Some(b"1".as_slice())
        );
        assert_eq!(lookup(&data, "B").expect("allowed but unset"), None);
        assert!(matches!(lookup(&data, "C"), Err(WitEnvError::NotAllowed)));
        let data = data_with(false, &[("A", Some(b"1".as_slice()))]);
        assert!(matches!(lookup(&data, "A"), Err(WitEnvError::NotAllowed)));
    }

    /// The register links exactly when granted.
    #[test]
    fn register_links_only_when_granted() {
        use qqq_cap::resolve::GrantSet;
        const NAMED: &str = r#"(component
          (import "qqq:env/environment@1.0.0" (instance $e
            (export "get" (func (param "a" string)))))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        const EMPTY: &str = r#"(component
          (import "qqq:env/environment@1.0.0" (instance $e))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        fn link(grants: &GrantSet, wat: &str) -> wasmtime::Result<()> {
            let mut config = wasmtime::Config::new();
            config.wasm_component_model(true);
            let engine = wasmtime::Engine::new(&config).expect("engine builds");
            let mut linker = wasmtime::component::Linker::new(&engine);
            register(&mut linker, grants)?;
            let bytes = wat::parse_str(wat).expect("fixture assembles");
            let component =
                wasmtime::component::Component::new(&engine, &bytes).expect("fixture compiles");
            let mut store =
                wasmtime::Store::new(&engine, crate::linker::StoreData::new(grants.clone()));
            linker.instantiate(&mut store, &component).map(|_| ())
        }
        let err = link(&GrantSet::empty(), NAMED).expect_err("no grant means no instance");
        assert!(
            format!("{err:#}").contains("qqq:env/environment"),
            "the refusal must name the import: {err:#}"
        );
        let m = qqq_cap::manifest::Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.env]\nallow = [\"A\"]\n",
        )
        .expect("manifest parses");
        link(&GrantSet::from_manifest(&m), EMPTY).expect("a granted import links");
    }
}
