// SPDX-License-Identifier: Apache-2.0

//! Resolve `qqq:sql` configuration at the deploy layer — `HOST-036`.
//!
//! The manifest names databases; this module turns that list into the
//! [`SqlConfig`] the host enforces. No I/O, no ambient reads, no
//! connections: the allowlist is data, and data resolves without touching
//! anything the guest could observe — which is what makes it unit-testable
//! without a database.
//!
//! Only the `sqlite` driver is served: any other driver name resolves to
//! nothing, so its databases fail `database-not-configured` at the host —
//! refused by name, the same shape as an unlisted database, because from
//! the guest's side an unservable database *is* an unconfigured one. The
//! `host` and `secret` manifest fields are network-driver concerns and are
//! ignored for `sqlite`, which dials nothing and holds no credentials.
//!
//! For `sqlite`, the manifest's `host` field names the database file: it is
//! deploy-controlled (the manifest author writes it), never guest-controlled
//! (the guest only names the database), so a guest cannot pick paths. The
//! path is stored verbatim and resolves against the host process's working
//! directory at open when relative; an absolute path pins the file.
//! Cross-request state lives in the files, so `serve` shares them across
//! requests exactly as `run` shares nothing — each request opens its own
//! connections either way.

use qqq_cap::manifest::Manifest;
use qqq_host::host_sql::{SqlConfig, SqlDatabase, SqlView};

/// The deploy-time SQL configuration: exactly what the manifest configures.
///
/// An absent `[capabilities.sql]` (or one with no servable entry) resolves
/// to empty: no databases, no opens — the same deny-by-default the host
/// applies to an instance built without the stanza. Entries keep
/// declaration order; duplicate names keep the first, so `find` and the
/// configured list can never disagree about which file a name means.
///
/// Only `sqlite` entries resolve, and `:memory:` does not: a
/// private-per-connection database breaks the "files are the shared state"
/// contract — no second request could ever see it — so it resolves to
/// nothing and fails `database-not-configured` by name.
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
/// )
/// .expect("manifest parses");
/// let config = qqq_run::sql::resolve_sql_config(&manifest);
/// assert!(config.databases.is_empty());
/// ```
#[must_use]
pub fn resolve_sql_config(manifest: &Manifest) -> SqlConfig {
    let mut seen: Vec<String> = Vec::new();
    let databases: Vec<SqlDatabase> = manifest
        .capabilities
        .sql
        .iter()
        .filter(|db| db.driver == "sqlite" && db.host != ":memory:")
        .filter(|db| {
            if seen.contains(&db.name) {
                false
            } else {
                seen.push(db.name.clone());
                true
            }
        })
        .map(|db| {
            SqlDatabase::new(
                db.name.clone(),
                std::path::PathBuf::from(&db.host),
                db.execute,
            )
        })
        .collect();
    SqlConfig::new(databases)
}

/// The per-deployment SQL view: resolved config, no shared backend.
///
/// One call site for both `run` (fresh view per execution, like the
/// instance) and `serve` (one view shared across every request the
/// deployment serves). There is no backend to share — the files are the
/// shared state, and each request opens its own connections to them — so
/// the view is just the config, cloned per request.
///
/// ```
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
///      [[capabilities.sql]]\nname = \"orders\"\ndriver = \"sqlite\"\n\
///      host = \"/var/lib/app/orders.db\"\nexecute = true\n",
/// )
/// .expect("manifest parses");
/// let view = qqq_run::sql::view_for_manifest(&manifest);
/// assert!(view.config.allows("orders"));
/// assert!(!view.config.allows("ledger"));
/// ```
#[must_use]
pub fn view_for_manifest(manifest: &Manifest) -> SqlView {
    SqlView::new(std::sync::Arc::new(resolve_sql_config(manifest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with(body: &str) -> Manifest {
        Manifest::parse(&format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n{body}"
        ))
        .expect("manifest parses")
    }

    /// Absent sql resolves empty: deny by default.
    #[test]
    fn absent_sql_resolves_empty() {
        let config = resolve_sql_config(&manifest_with(""));
        assert!(config.databases.is_empty());
        assert!(!config.allows("anything"));
    }

    /// Only `sqlite` entries resolve: a `postgres` entry is not served, so
    /// it resolves to nothing rather than to a database the host cannot open.
    #[test]
    fn non_sqlite_drivers_resolve_to_nothing() {
        let config = resolve_sql_config(&manifest_with(
            "[[capabilities.sql]]\nname = \"pg\"\ndriver = \"postgres\"\n\
             host = \"db.internal:5432\"\n\
             [[capabilities.sql]]\nname = \"orders\"\ndriver = \"sqlite\"\n\
             host = \"/tmp/orders.db\"\n",
        ));
        assert_eq!(config.databases.len(), 1);
        assert!(config.allows("orders"));
        assert!(!config.allows("pg"));
        let db = config.find("orders").expect("sqlite entry resolves");
        assert!(
            db.path.as_os_str() == "/tmp/orders.db" && db.read_only(),
            "for sqlite, host names the file and the default is read-only"
        );
    }

    /// `execute = true` widens to read-write; the default stays read-only.
    #[test]
    fn execute_flag_widens_to_read_write() {
        let config = resolve_sql_config(&manifest_with(
            "[[capabilities.sql]]\nname = \"ro\"\ndriver = \"sqlite\"\n\
             host = \"/tmp/ro.db\"\n\
             [[capabilities.sql]]\nname = \"rw\"\ndriver = \"sqlite\"\n\
             host = \"/tmp/rw.db\"\nexecute = true\n",
        ));
        assert!(config.find("ro").expect("ro resolves").read_only());
        assert!(!config.find("rw").expect("rw resolves").read_only());
    }

    /// `:memory:` resolves to nothing: a private-per-connection database
    /// breaks the "files are the shared state" contract, so it fails
    /// `database-not-configured` by name rather than serving a database no
    /// second request could ever see.
    #[test]
    fn memory_databases_resolve_to_nothing() {
        let config = resolve_sql_config(&manifest_with(
            "[[capabilities.sql]]\nname = \"ghost\"\ndriver = \"sqlite\"\n\
             host = \":memory:\"\n\
             [[capabilities.sql]]\nname = \"orders\"\ndriver = \"sqlite\"\n\
             host = \"/tmp/orders.db\"\n",
        ));
        assert_eq!(config.databases.len(), 1);
        assert!(config.allows("orders"));
        assert!(!config.allows("ghost"));
    }

    /// Duplicate names keep the first: `find` and `databases` then agree,
    /// so a name never means two files depending on who asks.
    #[test]
    fn duplicate_names_keep_first() {
        let config = resolve_sql_config(&manifest_with(
            "[[capabilities.sql]]\nname = \"orders\"\ndriver = \"sqlite\"\n\
             host = \"/tmp/first.db\"\n\
             [[capabilities.sql]]\nname = \"orders\"\ndriver = \"sqlite\"\n\
             host = \"/tmp/second.db\"\n",
        ));
        assert_eq!(config.databases.len(), 1);
        assert_eq!(
            config
                .find("orders")
                .expect("orders resolves")
                .path
                .as_os_str(),
            "/tmp/first.db"
        );
        assert_eq!(config.databases.len(), 1);
    }
}
