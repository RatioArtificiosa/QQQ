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
//!
//! ```
//! assert!(qqq_host::host_env::ENVIRONMENT.contains("environment"));
//! ```

use qqq_cap::capability::Capability::EnvRead;

/// The WIT package this module implements.
///
/// ```
/// assert_eq!(qqq_host::host_env::INTERFACE, "qqq:env@1.0.0");
/// ```
pub const INTERFACE: &str = "qqq:env@1.0.0";

/// The environment interface, as a component imports it.
///
/// ```
/// assert_eq!(
///     qqq_host::host_env::ENVIRONMENT,
///     "qqq:env/environment@1.0.0"
/// );
/// ```
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
/// ```
/// let engine = wasmtime::Engine::default();
/// let mut linker = wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
/// qqq_host::host_env::register(&mut linker, &qqq_cap::resolve::GrantSet::empty())
///     .expect("empty grants register nothing");
/// ```
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
///
/// The grant re-check is inline (not delegated to `lookup`), so the audit
/// sees the re-check in the body that enforces it (`ARCH-012`). The WIT has
/// no `not-granted` case — an ungranted call is `not-allowed`, which is also
/// what an unlisted name gets, so a guest cannot probe the allowlist.
fn register_get(
    inst: &mut wasmtime::component::LinkerInstance<'_, crate::linker::StoreData>,
) -> wasmtime::Result<()> {
    inst.func_wrap(
        "get",
        |store: wasmtime::StoreContextMut<'_, crate::linker::StoreData>,
         (name,): (String,)|
         -> wasmtime::Result<(std::result::Result<String, WitEnvError>,)> {
            crate::guard::guard("qqq:env/environment.get", || {
                let data = store.data();
                if !data.grants.grants(EnvRead) {
                    return Ok((Err(WitEnvError::NotAllowed),));
                }
                match lookup(data, &name) {
                    None => Ok((Err(WitEnvError::NotAllowed),)),
                    Some(None) => Ok((Err(WitEnvError::Unset),)),
                    Some(Some(bytes)) => {
                        Ok((String::from_utf8(bytes).map_err(|_| WitEnvError::InvalidUtf8),))
                    }
                }
            })
        },
    )?;
    Ok(())
}

/// `get-or(name, default) -> result<string, env-error>`.
///
/// The fallback applies to `unset` only: substituting a default for a denied
/// capability would hide a misconfiguration. Grant and allowlist re-checked
/// inline, as above; `not-allowed` covers ungranted and unlisted alike.
fn register_get_or(
    inst: &mut wasmtime::component::LinkerInstance<'_, crate::linker::StoreData>,
) -> wasmtime::Result<()> {
    inst.func_wrap(
        "get-or",
        |store: wasmtime::StoreContextMut<'_, crate::linker::StoreData>,
         (name, default): (String, String)|
         -> wasmtime::Result<(std::result::Result<String, WitEnvError>,)> {
            crate::guard::guard("qqq:env/environment.get-or", || {
                let data = store.data();
                if !data.grants.grants(EnvRead) {
                    return Ok((Err(WitEnvError::NotAllowed),));
                }
                match lookup(data, &name) {
                    None => Ok((Err(WitEnvError::NotAllowed),)),
                    Some(None) => Ok((Ok(default),)),
                    Some(Some(bytes)) => {
                        Ok((String::from_utf8(bytes).map_err(|_| WitEnvError::InvalidUtf8),))
                    }
                }
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

/// Look a name up in the allowlist map.
///
/// Returns [None] for an unlisted name and [Some(None)] for a listed-but-
/// unset one. The grant check lives in the callers, visibly: this helper is
/// pure lookup, so the audit ([ARCH-012]) sees the re-check in the body that
/// enforces it rather than behind a call.
///
/// `Option<Option<..>>` is the model, not laziness: three states need three
/// values, and a custom enum would rename exactly what the nesting says.
#[allow(
    clippy::option_option,
    reason = "three states need three values; see above"
)]
fn lookup(data: &crate::linker::StoreData, name: &str) -> Option<Option<Vec<u8>>> {
    data.env.get(name).cloned()
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
        let map: std::collections::BTreeMap<String, Option<Vec<u8>>> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.map(<[u8]>::to_vec)))
            .collect();
        crate::linker::StoreData::new(grants).with_env(map)
    }

    /// Lookups distinguish the three states.
    #[test]
    fn lookup_states_are_distinct() {
        let data = data_with(true, &[("A", Some(b"1".as_slice())), ("B", None)]);
        assert_eq!(
            lookup(&data, "A").flatten().as_deref(),
            Some(b"1".as_slice())
        );
        assert_eq!(lookup(&data, "B"), Some(None), "listed but unset");
        assert_eq!(lookup(&data, "C"), None, "unlisted is absent");
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
