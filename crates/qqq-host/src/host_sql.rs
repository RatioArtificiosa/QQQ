// SPDX-License-Identifier: Apache-2.0

//! `qqq:sql/database` and `qqq:sql/transaction` — typed queries against
//! process-local SQLite databases.
//!
//! The manifest names databases; the deploy layer resolves that list once
//! and hands this module a [`SqlConfig`]. Nothing here reads the manifest
//! or the environment per call: membership in the config is the allowlist,
//! exactly as `host_env`'s map is.
//!
//! Each configured database is one file-backed SQLite database, opened once
//! per instance and closed with it. One connection per instance — never
//! shared, never pooled — is what makes transactions sound without a lock
//! manager: every call in a request runs against the same connection, and
//! concurrent requests hold different connections while SQLite's own
//! locking (plus a busy timeout) serializes the file. Cross-request state
//! lives in the files, not in the host.
//!
//! Only the `sqlite` driver is served: any other driver name resolves to
//! nothing, so its databases fail `database-not-configured` — refused by
//! name, the same shape as an unlisted database, because from the guest's
//! side an unservable database *is* an unconfigured one. The `host` and
//! `secret` manifest fields are network-driver concerns and are ignored
//! for `sqlite`, which dials nothing and holds no credentials.
//!
//! Read-only is enforced from the statement itself: `prepare` records
//! whether SQLite considers the statement read-only, and `execute` refuses
//! a writing statement unless the manifest granted `execute` on that
//! database. Enforcement reads the database's own answer rather than
//! pattern-matching the SQL text, which a comment could defeat.
//!
//! ```
//! let config = qqq_host::host_sql::SqlConfig::new(vec![
//!     qqq_host::host_sql::SqlDatabase::new("orders".to_owned(), std::path::PathBuf::from(":memory:"), false),
//! ]);
//! assert!(config.allows("orders"));
//! assert!(!config.allows("ledger"));
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

/// The WIT package this module implements.
///
/// ```
/// assert_eq!(qqq_host::host_sql::INTERFACE, "qqq:sql@1.0.0");
/// ```
pub const INTERFACE: &str = "qqq:sql@1.0.0";

/// The generated bindings carry no doc comments of their own, and re-exporting
/// them would fail `missing_docs` on the WIT's definition rather than on any
/// prose this crate wrote. The allow is scoped to the generated module so
/// hand-written items keep the lint.
#[allow(missing_docs)]
mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-sql.wit",
        interfaces: "import qqq:sql/database@1.0.0; import qqq:sql/transaction@1.0.0;",
    });
}

/// The WIT `sql-error`, re-exported rather than re-declared: the WIT variant
/// is the definition. (Same rule as `host_log` and `host_kv`.)
pub use bindings::qqq::sql::database::SqlError as WitSqlError;
use bindings::qqq::sql::database::{Row as WitRow, Value as WitValue};

/// The longest single SQL statement the host accepts, in bytes.
///
/// A statement is text the guest fully controls; without a bound one call
/// can hand the parser megabytes. 64 KiB holds any statement a guest should
/// be generating — longer ones are built, not written, and belong in a
/// migration, not a request.
pub(crate) const MAX_SQL_STATEMENT_BYTES: usize = 64 * 1024;

/// The most rows one call returns before it must paginate.
///
/// A `SELECT *` on a large table is how a guest turns the host's heap into
/// its result buffer. The cap fails the call with `result-too-large`
/// instead, which names the fix.
pub(crate) const MAX_SQL_ROWS: usize = 1000;

/// The largest single value the host accepts or returns, in bytes.
///
/// Applies both directions: an argument larger than this never reaches the
/// database (`argument-mismatch`, because the value cannot be what the
/// placeholder permits), and a stored value larger than this never crosses
/// back (`result-too-large`). 64 KiB matches the kv value bound — one
/// number to learn.
pub(crate) const MAX_SQL_VALUE_BYTES: usize = 64 * 1024;

/// The most bound arguments one call may carry.
///
/// Placeholders are positional, so the count is bounded by the statement —
/// but the argument *list* is guest-controlled allocation independent of
/// any statement. 1024 binds is far past any real query's arity.
pub(crate) const MAX_SQL_ARGS: usize = 1024;

/// The longest single database name the host accepts, in bytes.
///
/// Names become map keys and file names on every call, so an unbounded name
/// is an unbounded host allocation for one lookup. 256 bytes names any
/// reasonable database.
pub(crate) const MAX_SQL_NAME_BYTES: usize = 256;

/// How long a lock wait lasts before SQLite gives up, in milliseconds.
///
/// Concurrent requests hold different connections to the same files; the
/// busy timeout is what turns a momentary lock conflict into a brief wait
/// instead of an immediate failure. Five seconds is long enough for a
/// request-scoped transaction and short enough that a wedged holder does
/// not pin every other request behind it.
pub(crate) const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

/// The most bytes one call's result may carry.
///
/// Rows are capped in count, values in size, and this caps their product:
/// a thousand full-size rows would otherwise still be tens of megabytes
/// for one call.
pub(crate) const MAX_SQL_RESULT_BYTES: u64 = 4 * 1024 * 1024;

/// The most open handles (statements, transactions, and transaction
/// statements together) one instance may hold.
///
/// Each entry holds up to 64 KiB of SQL text, so an unbounded table is a
/// memory-exhaustion primitive any guest can drive. 256 matches the span
/// table's precedent (`host_trace`) — past it, new handles fail
/// `pool-exhausted`, which names the exhaustion.
pub(crate) const MAX_SQL_HANDLES: usize = 256;

/// One configured database: its name, its file, and whether it may be written.
///
/// ```
/// let db = qqq_host::host_sql::SqlDatabase::new(
///     "orders".to_owned(),
///     std::path::PathBuf::from("/var/lib/app/orders.db"),
///     true,
/// );
/// assert_eq!(db.name, "orders");
/// assert!(!db.read_only());
/// ```
#[derive(Debug, Clone)]
pub struct SqlDatabase {
    /// The manifest's logical name, used in diagnostics and audit rows.
    pub name: String,
    /// The file holding this database. Created on first open.
    pub path: PathBuf,
    /// Whether `execute` is permitted (`execute = true` in the manifest).
    pub read_write: bool,
}

impl SqlDatabase {
    /// A configured database at `path`.
    ///
    /// ```
    /// let db = qqq_host::host_sql::SqlDatabase::new(
    ///     "orders".to_owned(),
    ///     std::path::PathBuf::from(":memory:"),
    ///     false,
    /// );
    /// assert!(db.read_only());
    /// ```
    #[must_use]
    pub fn new(name: String, path: PathBuf, read_write: bool) -> Self {
        Self {
            name,
            path,
            read_write,
        }
    }

    /// Whether this database refuses writes. The manifest-facing vocabulary
    /// is `read-only` / `read-write`; storing the positive flag and
    /// answering the enforcement question keeps call sites reading intent
    /// (`if db.read_only()`) rather than negating a flag.
    ///
    /// ```
    /// let db = qqq_host::host_sql::SqlDatabase::new(
    ///     "orders".to_owned(),
    ///     std::path::PathBuf::from(":memory:"),
    ///     true,
    /// );
    /// assert!(!db.read_only());
    /// ```
    #[must_use]
    pub fn read_only(&self) -> bool {
        !self.read_write
    }
}

/// Which databases the guest may open, and in which mode.
///
/// Resolved once at deploy from the manifest; cloned per request, never
/// re-resolved per call.
///
/// ```
/// let config = qqq_host::host_sql::SqlConfig::new(Vec::new());
/// assert!(!config.allows("anything"));
/// assert!(config.find("orders").is_none());
/// ```
#[derive(Debug, Clone, Default)]
pub struct SqlConfig {
    /// Databases the manifest configures, in declaration order.
    pub databases: Vec<SqlDatabase>,
}

impl SqlConfig {
    /// The deploy-time resolution: exactly what the manifest configures.
    ///
    /// ```
    /// let config = qqq_host::host_sql::SqlConfig::new(Vec::new());
    /// assert!(config.databases.is_empty());
    /// ```
    #[must_use]
    pub fn new(databases: Vec<SqlDatabase>) -> Self {
        Self { databases }
    }

    /// Whether `name` names a configured database. Membership is the
    /// allowlist: an unlisted name is `database-not-configured`, never an
    /// empty database the guest conjured into existence.
    ///
    /// ```
    /// let config = qqq_host::host_sql::SqlConfig::new(Vec::new());
    /// assert!(!config.allows("orders"));
    /// ```
    #[must_use]
    pub fn allows(&self, name: &str) -> bool {
        self.databases.iter().any(|db| db.name == name)
    }

    /// The configured entry for `name`, if any.
    ///
    /// ```
    /// let config = qqq_host::host_sql::SqlConfig::new(Vec::new());
    /// assert!(config.find("orders").is_none());
    /// ```
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&SqlDatabase> {
        self.databases.iter().find(|db| db.name == name)
    }
}

/// The per-instance view: deploy-resolved config, no shared state.
///
/// Unlike kv and queues there is no in-memory backend to share: the files
/// are the shared state, and each instance opens its own connections to
/// them. The view is therefore just the config, cloned per request.
///
/// ```
/// let view = qqq_host::host_sql::SqlView::new(
///     std::sync::Arc::new(qqq_host::host_sql::SqlConfig::new(Vec::new())),
/// );
/// assert!(view.config.databases.is_empty());
/// ```
#[derive(Debug, Clone, Default)]
pub struct SqlView {
    /// The deploy-resolved allowlist, modes, and file paths.
    pub config: Arc<SqlConfig>,
}

impl SqlView {
    /// A view over `config`.
    ///
    /// ```
    /// let view = qqq_host::host_sql::SqlView::new(
    ///     std::sync::Arc::new(qqq_host::host_sql::SqlConfig::new(Vec::new())),
    /// );
    /// assert!(view.config.databases.is_empty());
    /// ```
    #[must_use]
    pub fn new(config: Arc<SqlConfig>) -> Self {
        Self { config }
    }
}

/// Per-instance SQL state: connections, prepared statements, and open
/// transactions for this request.
///
/// Created fresh per instance (`prepare` never carries it over): a
/// statement handle from a previous request must not resolve here, and a
/// transaction must not outlive the request that began it. Handles are
/// host-minted indices, monotonic and never reused within the instance, so
/// a stale handle cannot resolve to a newer statement — the same discipline
/// as `host_trace`'s span table.
///
/// ```
/// let state = qqq_host::host_sql::SqlInstanceState::default();
/// assert!(state.statements.is_empty());
/// assert!(state.transactions.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct SqlInstanceState {
    /// One connection per configured database touched this request, opened
    /// lazily so a request that never touches SQL pays nothing.
    pub connections: BTreeMap<String, rusqlite::Connection>,
    /// Prepared statements: `(database, sql, sqlite-reported read-only)`.
    /// The SQL text is stored rather than the prepared statement because a
    /// `rusqlite::Statement` borrows its connection, and the map owns both.
    /// Re-preparing per execution keeps lifetimes tractable; SQLite parses
    /// are cheap next to a guest call.
    pub statements: BTreeMap<u32, (String, String, bool)>,
    /// Open transactions: id to database name.
    pub transactions: BTreeMap<u32, String>,
    /// Prepared statements bound to a transaction: id to
    /// `(transaction, database, sql, sqlite-reported read-only)`. Kept
    /// separate from `statements` so closing a transaction can invalidate
    /// exactly the statements prepared inside it.
    pub txn_statements: BTreeMap<u32, (u32, String, String, bool)>,
    /// Next handle to mint, shared across the three tables so ids never
    /// collide between a statement and a transaction.
    pub next: u32,
}

/// Whether a database name is safe to use as a map key and file stem.
///
/// Unbounded names are unbounded host allocation; empty names would render
/// as structure without identity. Whitespace and control characters can
/// never appear in a configured name, so they can never be allowlisted.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SQL_NAME_BYTES
        && !name
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}

/// Register the SQL interfaces for the granted capabilities.
///
/// Links `qqq:sql/database` and `qqq:sql/transaction` when `sql.query` or
/// `sql.execute` is granted; every function re-checks at call time.
///
/// ```
/// let engine = wasmtime::Engine::default();
/// let mut linker = wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
/// qqq_host::host_sql::register(&mut linker, &qqq_cap::resolve::GrantSet::empty())
///     .expect("empty grants register nothing");
/// ```
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects an interface.
pub fn register(
    linker: &mut wasmtime::component::Linker<crate::linker::StoreData>,
    grants: &qqq_cap::resolve::GrantSet,
) -> wasmtime::Result<()> {
    use qqq_cap::capability::Capability::{SqlExecute, SqlQuery};
    use wasmtime::component::HasSelf;
    if !(grants.grants(SqlQuery) || grants.grants(SqlExecute)) {
        return Ok(());
    }
    bindings::qqq::sql::database::add_to_linker::<
        crate::linker::StoreData,
        HasSelf<crate::linker::StoreData>,
    >(linker, |state| state)?;
    bindings::qqq::sql::transaction::add_to_linker::<
        crate::linker::StoreData,
        HasSelf<crate::linker::StoreData>,
    >(linker, |state| state)?;
    Ok(())
}

/// Check a read: the direction grant, then the database membership.
///
/// Grant first (an ungranted call fails before its name is judged), then
/// membership. `sql.query` alone gates reads.
fn check_read(data: &crate::linker::StoreData, name: &str) -> std::result::Result<(), WitSqlError> {
    use qqq_cap::capability::Capability::SqlQuery;
    if !data.grants.grants(SqlQuery) {
        return Err(WitSqlError::NotGranted);
    }
    if !valid_name(name) || !data.sql.config.allows(name) {
        return Err(WitSqlError::DatabaseNotConfigured);
    }
    Ok(())
}

/// Check a write: either grant missing, the database membership, then the direction.
///
/// `not-granted` means *neither* direction was granted. A read-only
/// database (no `execute = true`) refuses writes as `read-only-connection`,
/// not as ungranted — the guest is allowed to *see* the database, just not
/// to change it.
fn check_write(
    data: &crate::linker::StoreData,
    name: &str,
) -> std::result::Result<(), WitSqlError> {
    use qqq_cap::capability::Capability::{SqlExecute, SqlQuery};
    if !data.grants.grants(SqlQuery) && !data.grants.grants(SqlExecute) {
        return Err(WitSqlError::NotGranted);
    }
    let Some(db) = data.sql.config.find(name) else {
        return Err(WitSqlError::DatabaseNotConfigured);
    };
    if !data.grants.grants(SqlExecute) || db.read_only() {
        // The grant without the config (or the reverse) is a mis-built
        // instance: the manifest grants both or neither per database, so a
        // split means the deploy path and the link path disagree — and the
        // safe direction is refusal, named read-only.
        return Err(WitSqlError::ReadOnlyConnection);
    }
    Ok(())
}

/// Refuse plain calls while a transaction is open on `db`.
///
/// Every path in one request shares the one connection, so a plain call
/// during an open transaction would read uncommitted rows and commit or
/// roll back with it. Refusing keeps statement and transaction scopes
/// separate; the guest routes through the transaction's own handles
/// instead. Smuggled transaction-control statements (`COMMIT` through
/// plain SQL) desynchronize the host record the same way a second `begin`
/// does; the safe recovery is dropping the transaction handle.
fn check_no_open_transaction(
    data: &crate::linker::StoreData,
    db: &SqlDatabase,
) -> std::result::Result<(), WitSqlError> {
    if data
        .sql_state
        .transactions
        .values()
        .any(|name| name == &db.name)
    {
        return Err(WitSqlError::ExecutionFailed(format!(
            "transaction is open on database '{}'",
            db.name
        )));
    }
    Ok(())
}

/// Convert a guest value to a SQLite value, bounding text and blobs.
fn to_sql(value: WitValue) -> std::result::Result<rusqlite::types::Value, WitSqlError> {
    use rusqlite::types::Value as SqlValue;
    match value {
        WitValue::Null => Ok(SqlValue::Null),
        WitValue::Boolean(flag) => Ok(SqlValue::Integer(i64::from(flag))),
        WitValue::Integer(number) => Ok(SqlValue::Integer(number)),
        WitValue::Float(number) => Ok(SqlValue::Real(number)),
        WitValue::Text(text) => {
            if text.len() > MAX_SQL_VALUE_BYTES {
                return Err(WitSqlError::ArgumentMismatch(format!(
                    "text argument of {} bytes exceeds the host limit of {MAX_SQL_VALUE_BYTES}",
                    text.len()
                )));
            }
            Ok(SqlValue::Text(text))
        }
        WitValue::Blob(bytes) => {
            if bytes.len() > MAX_SQL_VALUE_BYTES {
                return Err(WitSqlError::ArgumentMismatch(format!(
                    "blob argument of {} bytes exceeds the host limit of {MAX_SQL_VALUE_BYTES}",
                    bytes.len()
                )));
            }
            Ok(SqlValue::Blob(bytes))
        }
    }
}

/// Convert one SQLite row to guest values, bounding text and blobs.
fn from_row(row: &rusqlite::Row<'_>) -> std::result::Result<WitRow, WitSqlError> {
    use rusqlite::types::Value as SqlValue;
    let mut out: WitRow = Vec::with_capacity(row.as_ref().column_count());
    for index in 0..row.as_ref().column_count() {
        let value: SqlValue = row.get(index).map_err(|error| {
            WitSqlError::ExecutionFailed(format!("cannot read column {index}: {error}"))
        })?;
        out.push(match value {
            SqlValue::Null => WitValue::Null,
            SqlValue::Integer(number) => WitValue::Integer(number),
            SqlValue::Real(number) => WitValue::Float(number),
            SqlValue::Text(text) => {
                if text.len() > MAX_SQL_VALUE_BYTES {
                    return Err(WitSqlError::ResultTooLarge);
                }
                WitValue::Text(text)
            }
            SqlValue::Blob(bytes) => {
                if bytes.len() > MAX_SQL_VALUE_BYTES {
                    return Err(WitSqlError::ResultTooLarge);
                }
                WitValue::Blob(bytes)
            }
        });
    }
    Ok(out)
}

/// Convert guest arguments to bound SQLite values, capping the count.
fn bind_args(args: Vec<WitValue>) -> std::result::Result<Vec<rusqlite::types::Value>, WitSqlError> {
    if args.len() > MAX_SQL_ARGS {
        return Err(WitSqlError::ArgumentMismatch(format!(
            "call binds {} arguments, above the host limit of {MAX_SQL_ARGS}",
            args.len()
        )));
    }
    args.into_iter().map(to_sql).collect()
}

/// Check the bound argument count against the statement's placeholders.
///
/// A mismatch is the guest's bug — one bind per placeholder — and it fails
/// `argument-mismatch` here, naming the fix, instead of surfacing as
/// SQLite's `execution-failed` at first use.
fn check_arity(
    statement: &rusqlite::Statement<'_>,
    bound: &[rusqlite::types::Value],
) -> std::result::Result<(), WitSqlError> {
    if statement.parameter_count() != bound.len() {
        return Err(WitSqlError::ArgumentMismatch(format!(
            "statement takes {} arguments but {} were bound",
            statement.parameter_count(),
            bound.len()
        )));
    }
    Ok(())
}

/// Create the database file's parent directories, if it names any.
///
/// Only for writable databases: a missing read-only file fails at open
/// rather than materializing directories for a database that can never
/// be created.
fn create_parent_dirs(name: &str, path: &std::path::Path) -> std::result::Result<(), WitSqlError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|error| {
        WitSqlError::ExecutionFailed(format!(
            "cannot create directory for database '{name}': {error}"
        ))
    })
}

/// Open the database file read-only, and hand back this request's
/// connection to it.
///
/// The refusal path's opener: calls that cannot write open read-only, so a
/// refused write never creates directories or files. A missing file fails
/// instead of materializing.
fn connection_for_readonly<'a>(
    data: &'a mut crate::linker::StoreData,
    db: &SqlDatabase,
) -> std::result::Result<&'a mut rusqlite::Connection, WitSqlError> {
    if !data.sql_state.connections.contains_key(&db.name) {
        let connection = rusqlite::Connection::open_with_flags(
            &db.path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|error| {
            WitSqlError::ExecutionFailed(format!("cannot open database '{}': {error}", db.name))
        })?;
        connection
            .busy_timeout(std::time::Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
            .map_err(|error| {
                WitSqlError::ExecutionFailed(format!(
                    "cannot set busy timeout on database '{}': {error}",
                    db.name
                ))
            })?;
        data.sql_state
            .connections
            .insert(db.name.clone(), connection);
    }
    let Some(connection) = data.sql_state.connections.get_mut(&db.name) else {
        return Err(WitSqlError::PoolExhausted);
    };
    Ok(connection)
}

/// Open (creating) the database file for `db`, and hand back this request's
/// connection to it.
///
/// One connection per database per request: reusing it across calls is what
/// makes transactions span calls, and never sharing it across requests is
/// what keeps per-request isolation total. SQLite's own file locking plus
/// a busy timeout serializes concurrent requests.
///
/// A read-only database opens read-only: opening it read-write would create
/// a missing file and let SQLite write recovery artifacts into a database
/// the manifest says never changes. A missing read-only file therefore
/// fails instead of materializing.
///
/// I/O failures name the database and the cause (`execution-failed`): a bad
/// path or denied permission is a configuration error, not load, and
/// `pool-exhausted` is reserved for handle exhaustion and lock contention.
///
/// The returned borrow ties the connection to the store, so callers finish
/// every `&mut self` use first: the borrow checker then enforces that a
/// connection never outlives the call that opened it.
fn connection_for<'a>(
    data: &'a mut crate::linker::StoreData,
    db: &SqlDatabase,
) -> std::result::Result<&'a mut rusqlite::Connection, WitSqlError> {
    if !data.sql_state.connections.contains_key(&db.name) {
        if !db.read_only() {
            create_parent_dirs(&db.name, &db.path)?;
        }
        let flags = if db.read_only() {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        };
        let connection =
            rusqlite::Connection::open_with_flags(&db.path, flags).map_err(|error| {
                WitSqlError::ExecutionFailed(format!("cannot open database '{}': {error}", db.name))
            })?;
        connection
            .busy_timeout(std::time::Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
            .map_err(|error| {
                WitSqlError::ExecutionFailed(format!(
                    "cannot set busy timeout on database '{}': {error}",
                    db.name
                ))
            })?;
        data.sql_state
            .connections
            .insert(db.name.clone(), connection);
    }
    let Some(connection) = data.sql_state.connections.get_mut(&db.name) else {
        return Err(WitSqlError::PoolExhausted);
    };
    Ok(connection)
}

/// Mint a fresh handle id, or fail when the space is exhausted.
///
/// Monotonic and never reused within the instance, so a stale handle cannot
/// resolve to a newer statement — the same discipline as `host_trace`'s
/// span table. Wrapping would reuse an id a stale handle names, so the
/// counter saturates into `pool-exhausted` instead.
fn mint_id(data: &mut crate::linker::StoreData) -> std::result::Result<u32, WitSqlError> {
    let id = data.sql_state.next;
    data.sql_state.next = id.checked_add(1).ok_or(WitSqlError::PoolExhausted)?;
    Ok(id)
}

/// Refuse new handles past the table cap, before minting.
///
/// Checked after validation and before any open, so the entry order is
/// grant, membership, isolation, validation, cap, open, mint on every
/// path that mints: a refused call fails before any file effect.
fn check_handles(data: &crate::linker::StoreData) -> std::result::Result<(), WitSqlError> {
    let open = data.sql_state.statements.len()
        + data.sql_state.transactions.len()
        + data.sql_state.txn_statements.len();
    if open >= MAX_SQL_HANDLES {
        return Err(WitSqlError::PoolExhausted);
    }
    Ok(())
}

/// Look a statement handle up, or fail the call that needs it.
///
/// Returns the cloned entry so the caller holds no borrow on the table
/// while opening the connection: the map owns the entry, and the lookup
/// ends before any `&mut` work begins.
fn lookup_statement(
    data: &crate::linker::StoreData,
    handle: &wasmtime::component::Resource<bindings::qqq::sql::database::Statement>,
) -> std::result::Result<(String, String, bool), WitSqlError> {
    data.sql_state
        .statements
        .get(&handle.rep())
        .cloned()
        .ok_or_else(|| WitSqlError::ExecutionFailed("unknown statement".to_owned()))
}

/// Look a transaction handle up, or fail the call that needs it.
fn lookup_transaction(
    data: &crate::linker::StoreData,
    handle: &wasmtime::component::Resource<bindings::qqq::sql::transaction::Txn>,
) -> std::result::Result<String, WitSqlError> {
    data.sql_state
        .transactions
        .get(&handle.rep())
        .cloned()
        .ok_or_else(|| WitSqlError::ExecutionFailed("unknown transaction".to_owned()))
}

/// Look a transaction-statement handle up, or fail the call that needs it.
#[allow(clippy::type_complexity)]
fn lookup_txn_statement(
    data: &crate::linker::StoreData,
    handle: &wasmtime::component::Resource<bindings::qqq::sql::transaction::TxnStatement>,
) -> std::result::Result<(u32, String, String, bool), WitSqlError> {
    data.sql_state
        .txn_statements
        .get(&handle.rep())
        .cloned()
        .ok_or_else(|| WitSqlError::ExecutionFailed("unknown statement".to_owned()))
}

/// Run rows for one call, capping count and total bytes.
///
/// Reads at most one row past the cap so an uncapped result fails instead
/// of truncating silently: a guest that asked for everything and got the
/// first thousand rows would never know.
fn collect_rows(mut rows: rusqlite::Rows<'_>) -> std::result::Result<Vec<WitRow>, WitSqlError> {
    let mut out: Vec<WitRow> = Vec::new();
    let mut bytes: u64 = 0;
    loop {
        match rows.next() {
            Err(error) => return Err(WitSqlError::ExecutionFailed(error.to_string())),
            Ok(None) => break,
            Ok(Some(row)) => {
                if out.len() >= MAX_SQL_ROWS {
                    return Err(WitSqlError::ResultTooLarge);
                }
                let converted = from_row(row)?;
                bytes += converted
                    .iter()
                    .map(|value| match value {
                        WitValue::Text(text) => text.len() as u64,
                        WitValue::Blob(blob) => blob.len() as u64,
                        _ => 8,
                    })
                    .sum::<u64>();
                // Same ceiling as the per-call budget the other interfaces
                // enforce through their own bounds: one call's result stays
                // a bounded allocation even when every row is at its cap.
                if bytes > MAX_SQL_RESULT_BYTES {
                    return Err(WitSqlError::ResultTooLarge);
                }
                out.push(converted);
            }
        }
    }
    Ok(out)
}

/// Reject an over-long statement before it reaches the parser.
///
/// The guest controls the text; without a bound one call hands SQLite
/// megabytes to parse. Every entry point that prepares — `prepare`,
/// `query-once`, `txn prepare` — calls this first, so the cap cannot be
/// bypassed by choosing the one-shot path.
fn check_sql_size(sql: &str) -> std::result::Result<(), WitSqlError> {
    if sql.len() > MAX_SQL_STATEMENT_BYTES {
        return Err(WitSqlError::PrepareFailed(format!(
            "statement of {} bytes exceeds the host limit of {MAX_SQL_STATEMENT_BYTES}",
            sql.len()
        )));
    }
    check_forbidden_leading(sql)
}

/// Reject statements that reach files outside the named database.
///
/// `ATTACH`/`DETACH` open arbitrary SQLite files under the host's
/// authority — `sqlite3_stmt_readonly` reports them as reads, so the
/// read-only enforcement cannot see the escape — and `VACUUM INTO` writes
/// one. Text matching is deliberate here rather than the engine's own
/// answer: the engine exposes no per-statement attachment flag, and the
/// check is a conservative policy gate, not a semantic classification.
/// Leading comments and case are skipped; an unterminated comment matches
/// nothing and SQLite refuses the statement itself, which is the safe
/// direction either way.
fn check_forbidden_leading(sql: &str) -> std::result::Result<(), WitSqlError> {
    let keyword = leading_keyword(sql);
    if keyword.eq_ignore_ascii_case("attach")
        || keyword.eq_ignore_ascii_case("detach")
        || keyword.eq_ignore_ascii_case("vacuum")
    {
        return Err(WitSqlError::PrepareFailed(format!(
            "{keyword} statements are not allowed: queries address only the named database"
        )));
    }
    Ok(())
}

/// The statement's first keyword, skipping whitespace and comments.
///
/// Returns an empty string when no keyword is visible (empty input, comment
/// only, unterminated comment): callers treat that as "no policy match"
/// and SQLite reports the syntax error itself.
fn leading_keyword(sql: &str) -> &str {
    let mut rest = sql.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("--") {
            match after.find('\n') {
                Some(index) => rest = after[index + 1..].trim_start(),
                None => return "",
            }
        } else if let Some(after) = rest.strip_prefix("/*") {
            match after.find("*/") {
                Some(index) => rest = after[index + 2..].trim_start(),
                None => return "",
            }
        } else {
            break;
        }
    }
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .unwrap_or(rest.len());
    &rest[..end]
}

/// Prepare on a live connection: validates the SQL now (so `prepare` fails
/// `prepare-failed` at prepare time, not first use) and reports whether
/// SQLite considers the statement read-only.
fn prepare_on(
    connection: &rusqlite::Connection,
    sql: &str,
) -> std::result::Result<bool, WitSqlError> {
    check_sql_size(sql)?;
    let statement = connection
        .prepare(sql)
        .map_err(|error| WitSqlError::PrepareFailed(error.to_string()))?;
    Ok(statement.readonly())
}

/// The host implementation of `qqq:sql/database`.
///
/// # Why every method re-checks both the grant and the config
///
/// Registration is conditional on the grant AND the body re-checks it, so a
/// mis-built linker still denies (`ARCH-012`). The config check is separate
/// because grants are capability-level while databases are named:
/// `sql.query` says the guest may query *some* database, and only the
/// config says which.
impl bindings::qqq::sql::database::Host for crate::linker::StoreData {
    fn prepare(
        &mut self,
        database: String,
        sql: String,
    ) -> std::result::Result<
        wasmtime::component::Resource<bindings::qqq::sql::database::Statement>,
        WitSqlError,
    > {
        use qqq_cap::capability::Capability::{SqlExecute, SqlQuery};
        use wasmtime::component::Resource;
        // Either direction grant opens the call; the direction check happens
        // after the statement's own nature is known, so an execute-only
        // grant (reachable through a narrowing overlay) prepares writes.
        if !self.grants.grants(SqlQuery) && !self.grants.grants(SqlExecute) {
            return Err(WitSqlError::NotGranted);
        }
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        check_no_open_transaction(self, &db)?;
        // Validation before cap before open: grant, membership, isolation,
        // validation, cap, open, mint on every minting path.
        check_sql_size(&sql)?;
        check_handles(self)?;
        let read_only = {
            let connection = connection_for(self, &db)?;
            prepare_on(connection, &sql)?
        };
        // Direction follows the statement, not the call: a read prepares
        // under the query grant, a write under the execute grant.
        if read_only {
            if !self.grants.grants(SqlQuery) {
                return Err(WitSqlError::NotGranted);
            }
        } else if !self.grants.grants(SqlExecute) {
            return Err(WitSqlError::ReadOnlyConnection);
        }
        let id = mint_id(self)?;
        self.sql_state
            .statements
            .insert(id, (db.name, sql, read_only));
        Ok(Resource::new_own(id))
    }

    fn query_once(
        &mut self,
        database: String,
        sql: String,
        args: Vec<WitValue>,
    ) -> std::result::Result<Vec<WitRow>, WitSqlError> {
        use qqq_cap::capability::Capability::SqlExecute;
        check_read(self, &database)?;
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        check_no_open_transaction(self, &db)?;
        check_sql_size(&sql)?;
        let bound = bind_args(args)?;
        // Read before borrowing the connection: the borrow checker then
        // enforces that the grant decision predates the effect. A call that
        // cannot write opens read-only, so a refused write never creates
        // directories or files.
        let can_write = self.grants.grants(SqlExecute) && !db.read_only();
        let connection = if can_write {
            connection_for(self, &db)?
        } else {
            connection_for_readonly(self, &db)?
        };
        let mut statement = connection
            .prepare(&sql)
            .map_err(|error| WitSqlError::PrepareFailed(error.to_string()))?;
        check_arity(&statement, &bound)?;
        if statement.readonly() {
            let rows = statement
                .query(rusqlite::params_from_iter(bound.iter()))
                .map_err(|error| WitSqlError::ExecutionFailed(error.to_string()))?;
            let rows = collect_rows(rows)?;
            require_autocommit(connection)?;
            Ok(rows)
        } else if can_write {
            let count = statement
                .execute(rusqlite::params_from_iter(bound.iter()))
                .map_err(|error| WitSqlError::ExecutionFailed(error.to_string()))?;
            let _ = count;
            require_autocommit(connection)?;
            Ok(Vec::new())
        } else {
            Err(WitSqlError::ReadOnlyConnection)
        }
    }

    fn databases(&mut self) -> Vec<String> {
        // Infallible by WIT design (the manifest set is public), so the
        // grant re-check fails closed by answering empty rather than by
        // erroring: an ungranted caller learns nothing, including membership.
        use qqq_cap::capability::Capability::{SqlExecute, SqlQuery};
        if !(self.grants.grants(SqlQuery) || self.grants.grants(SqlExecute)) {
            return Vec::new();
        }
        self.sql
            .config
            .databases
            .iter()
            .map(|db| db.name.clone())
            .collect()
    }
}

/// The host implementation of `qqq:sql/database/statement`.
impl bindings::qqq::sql::database::HostStatement for crate::linker::StoreData {
    fn query(
        &mut self,
        handle: wasmtime::component::Resource<bindings::qqq::sql::database::Statement>,
        args: Vec<WitValue>,
    ) -> std::result::Result<Vec<WitRow>, WitSqlError> {
        use qqq_cap::capability::Capability::SqlQuery;
        if !self.grants.grants(SqlQuery) {
            return Err(WitSqlError::NotGranted);
        }
        let (database, sql, _) = lookup_statement(self, &handle)?;
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        check_no_open_transaction(self, &db)?;
        let bound = bind_args(args)?;
        let connection = connection_for(self, &db)?;
        let mut statement = connection
            .prepare(&sql)
            .map_err(|error| WitSqlError::PrepareFailed(error.to_string()))?;
        check_arity(&statement, &bound)?;
        if !statement.readonly() {
            return Err(WitSqlError::ReadOnlyConnection);
        }
        let rows = statement
            .query(rusqlite::params_from_iter(bound.iter()))
            .map_err(|error| WitSqlError::ExecutionFailed(error.to_string()))?;
        let rows = collect_rows(rows)?;
        require_autocommit(connection)?;
        Ok(rows)
    }

    fn execute(
        &mut self,
        handle: wasmtime::component::Resource<bindings::qqq::sql::database::Statement>,
        args: Vec<WitValue>,
    ) -> std::result::Result<u64, WitSqlError> {
        use qqq_cap::capability::Capability::{SqlExecute, SqlQuery};
        if !self.grants.grants(SqlQuery) && !self.grants.grants(SqlExecute) {
            return Err(WitSqlError::NotGranted);
        }
        let (database, sql, _) = lookup_statement(self, &handle)?;
        // Membership and direction: neither grant was refused above, so
        // this names an unlisted database or a read-only one — never a
        // missing grant.
        check_write(self, &database)?;
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        check_no_open_transaction(self, &db)?;
        let bound = bind_args(args)?;
        let connection = connection_for(self, &db)?;
        let count = {
            let mut statement = connection
                .prepare(&sql)
                .map_err(|error| WitSqlError::PrepareFailed(error.to_string()))?;
            check_arity(&statement, &bound)?;
            // Fresh, not stored: the statement is re-prepared per execution,
            // so the database's own current answer decides.
            if statement.readonly() {
                return Err(WitSqlError::ReadOnlyConnection);
            }
            statement
                .execute(rusqlite::params_from_iter(bound.iter()))
                .map_err(|error| WitSqlError::ExecutionFailed(error.to_string()))?
        };
        require_autocommit(connection)?;
        Ok(count as u64)
    }

    fn close(
        &mut self,
        handle: wasmtime::component::Resource<bindings::qqq::sql::database::Statement>,
    ) {
        // Idempotent: the end state — the handle is gone — is what was
        // asked for, so closing twice is not an error.
        self.sql_state.statements.remove(&handle.rep());
    }

    fn drop(
        &mut self,
        rep: wasmtime::component::Resource<bindings::qqq::sql::database::Statement>,
    ) -> wasmtime::Result<()> {
        self.sql_state.statements.remove(&rep.rep());
        Ok(())
    }
}

/// Require either direction grant: beginning a transaction neither reads
/// nor writes by itself, so either grant opens one — the direction checks
/// happen when statements inside it execute.
fn check_any(data: &crate::linker::StoreData) -> std::result::Result<(), WitSqlError> {
    use qqq_cap::capability::Capability::{SqlExecute, SqlQuery};
    if data.grants.grants(SqlQuery) || data.grants.grants(SqlExecute) {
        Ok(())
    } else {
        Err(WitSqlError::NotGranted)
    }
}

/// Fail when the connection left autocommit mode.
///
/// Transaction control belongs to the transaction interface: a plain call
/// that smuggles `BEGIN` would open a hidden SQLite transaction no host
/// handle names, defeating the open-transaction refusal. Rolling back and
/// failing keeps the host record — which never opened one — truthful.
fn require_autocommit(connection: &rusqlite::Connection) -> std::result::Result<(), WitSqlError> {
    if connection.is_autocommit() {
        Ok(())
    } else {
        let _ = connection.execute_batch("ROLLBACK");
        Err(WitSqlError::ExecutionFailed(
            "transaction control statements are not allowed outside transactions".to_owned(),
        ))
    }
}

/// Run `BEGIN` on the database's connection.
///
/// Immediate for writers, deferred otherwise: `BEGIN IMMEDIATE` takes the
/// write lock up front so a write conflict fails here — before the guest
/// does work it will discard — rather than at the first statement. A guest
/// that cannot write (no `execute` grant, or a read-only database) gets
/// deferred instead, so a read-only transaction never holds the write lock
/// writers wait on.
fn begin_on(
    connection: &rusqlite::Connection,
    immediate: bool,
) -> std::result::Result<(), WitSqlError> {
    let sql = if immediate {
        "BEGIN IMMEDIATE"
    } else {
        "BEGIN"
    };
    connection
        .execute_batch(sql)
        .map_err(|error| WitSqlError::ExecutionFailed(format!("cannot begin transaction: {error}")))
}

/// Roll back an open transaction without failing when there is nothing to
/// roll back.
///
/// Best-effort by design: `drop` is infallible, and a missing handle, a
/// missing database, or a missing connection all mean the transaction is
/// already gone — which is the end state the caller asked for.
fn rollback_open(data: &mut crate::linker::StoreData, id: u32) {
    let Some(database) = data.sql_state.transactions.get(&id).cloned() else {
        return;
    };
    let Some(db) = data.sql.config.find(&database).cloned() else {
        return;
    };
    let Some(connection) = data.sql_state.connections.get(&db.name) else {
        return;
    };
    let _ = connection.execute_batch("ROLLBACK");
}

/// Close a transaction's handle and invalidate its statements.
///
/// Called on commit, rollback, and drop alike: the end state — the
/// transaction is gone and its statements resolve to nothing — is the same
/// whichever path closed it.
fn close_transaction(data: &mut crate::linker::StoreData, id: u32) {
    data.sql_state.transactions.remove(&id);
    data.sql_state
        .txn_statements
        .retain(|_, (txn, _, _, _)| *txn != id);
}

/// The host implementation of `qqq:sql/transaction`.
///
/// One transaction per database per request (V1): a second `begin` on the
/// same connection fails with `execution-failed` naming the lock — the
/// guest serializes, the host does not queue. Writers take the lock at
/// `BEGIN IMMEDIATE`; readers defer it, so a read-only transaction never
/// starves them. A transaction holds its connection's lock until commit,
/// rollback, or drop, and the request's end drops the store with it, so no
/// transaction outlives its request.
impl bindings::qqq::sql::transaction::Host for crate::linker::StoreData {
    fn begin(
        &mut self,
        database: String,
    ) -> std::result::Result<
        wasmtime::component::Resource<bindings::qqq::sql::transaction::Txn>,
        WitSqlError,
    > {
        use qqq_cap::capability::Capability::SqlExecute;
        use wasmtime::component::Resource;
        check_any(self)?;
        if !valid_name(&database) {
            return Err(WitSqlError::DatabaseNotConfigured);
        }
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        // Writers take the lock up front; readers defer it, so a read-only
        // transaction never starves writers. Read before borrowing.
        let immediate = self.grants.grants(SqlExecute) && !db.read_only();
        // Cap before begin: minting nothing after `BEGIN` would strand a
        // SQLite transaction with no handle to resolve it.
        check_handles(self)?;
        begin_on(connection_for(self, &db)?, immediate)?;
        let id = mint_id(self)?;
        self.sql_state.transactions.insert(id, db.name);
        Ok(Resource::new_own(id))
    }
}

/// The host implementation of `qqq:sql/transaction/txn`.
impl bindings::qqq::sql::transaction::HostTxn for crate::linker::StoreData {
    fn prepare(
        &mut self,
        handle: wasmtime::component::Resource<bindings::qqq::sql::transaction::Txn>,
        sql: String,
    ) -> std::result::Result<
        wasmtime::component::Resource<bindings::qqq::sql::transaction::TxnStatement>,
        WitSqlError,
    > {
        use wasmtime::component::Resource;
        check_any(self)?;
        check_sql_size(&sql)?;
        let database = lookup_transaction(self, &handle)?;
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        check_handles(self)?;
        let read_only = {
            let connection = connection_for(self, &db)?;
            prepare_on(connection, &sql)?
        };
        let txn = handle.rep();
        let id = mint_id(self)?;
        self.sql_state
            .txn_statements
            .insert(id, (txn, db.name, sql, read_only));
        Ok(Resource::new_own(id))
    }

    fn commit(
        &mut self,
        handle: wasmtime::component::Resource<bindings::qqq::sql::transaction::Txn>,
    ) -> std::result::Result<(), WitSqlError> {
        check_any(self)?;
        let database = lookup_transaction(self, &handle)?;
        let id = handle.rep();
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        let connection = connection_for(self, &db)?;
        let outcome = connection
            .execute_batch("COMMIT")
            .map_err(|error| WitSqlError::ExecutionFailed(format!("cannot commit: {error}")));
        // Only on success: a failed `COMMIT` leaves the SQLite transaction
        // open, and closing the handle would strand it with no handle to
        // retry or roll back. The guest keeps the handle and decides.
        if outcome.is_ok() {
            close_transaction(self, id);
        }
        outcome
    }

    fn rollback(
        &mut self,
        handle: wasmtime::component::Resource<bindings::qqq::sql::transaction::Txn>,
    ) -> std::result::Result<(), WitSqlError> {
        check_any(self)?;
        let database = lookup_transaction(self, &handle)?;
        let id = handle.rep();
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        let connection = connection_for(self, &db)?;
        let outcome = connection
            .execute_batch("ROLLBACK")
            .map_err(|error| WitSqlError::ExecutionFailed(format!("cannot roll back: {error}")));
        // Only on success, for the same reason as `commit`: a failed
        // `ROLLBACK` (for example after the guest smuggled `COMMIT` through
        // plain SQL) keeps its handle so the guest can still drop it.
        if outcome.is_ok() {
            close_transaction(self, id);
        }
        outcome
    }

    fn drop(
        &mut self,
        rep: wasmtime::component::Resource<bindings::qqq::sql::transaction::Txn>,
    ) -> wasmtime::Result<()> {
        // Dropping without committing rolls back: a guest that panics
        // mid-transaction must not leave a partial write committed. The
        // rollback's own failure is swallowed — the WIT `drop` is
        // infallible, and the cleanup (invalidating the handle and its
        // statements) happens regardless.
        let id = rep.rep();
        rollback_open(self, id);
        close_transaction(self, id);
        Ok(())
    }
}

/// The host implementation of `qqq:sql/transaction/txn-statement`.
impl bindings::qqq::sql::transaction::HostTxnStatement for crate::linker::StoreData {
    fn query(
        &mut self,
        handle: wasmtime::component::Resource<bindings::qqq::sql::transaction::TxnStatement>,
        args: Vec<WitValue>,
    ) -> std::result::Result<Vec<WitRow>, WitSqlError> {
        use qqq_cap::capability::Capability::SqlQuery;
        if !self.grants.grants(SqlQuery) {
            return Err(WitSqlError::NotGranted);
        }
        let (txn, database, sql, _) = lookup_txn_statement(self, &handle)?;
        if !self.sql_state.transactions.contains_key(&txn) {
            return Err(WitSqlError::ExecutionFailed(
                "transaction is closed".to_owned(),
            ));
        }
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        let bound = bind_args(args)?;
        let connection = connection_for(self, &db)?;
        let mut statement = connection
            .prepare(&sql)
            .map_err(|error| WitSqlError::PrepareFailed(error.to_string()))?;
        check_arity(&statement, &bound)?;
        if !statement.readonly() {
            return Err(WitSqlError::ReadOnlyConnection);
        }
        let rows = statement
            .query(rusqlite::params_from_iter(bound.iter()))
            .map_err(|error| WitSqlError::ExecutionFailed(error.to_string()))?;
        collect_rows(rows)
    }

    fn execute(
        &mut self,
        handle: wasmtime::component::Resource<bindings::qqq::sql::transaction::TxnStatement>,
        args: Vec<WitValue>,
    ) -> std::result::Result<u64, WitSqlError> {
        use qqq_cap::capability::Capability::{SqlExecute, SqlQuery};
        if !self.grants.grants(SqlQuery) && !self.grants.grants(SqlExecute) {
            return Err(WitSqlError::NotGranted);
        }
        let (txn, database, sql, _) = lookup_txn_statement(self, &handle)?;
        if !self.sql_state.transactions.contains_key(&txn) {
            return Err(WitSqlError::ExecutionFailed(
                "transaction is closed".to_owned(),
            ));
        }
        check_write(self, &database)?;
        let Some(db) = self.sql.config.find(&database).cloned() else {
            return Err(WitSqlError::DatabaseNotConfigured);
        };
        let bound = bind_args(args)?;
        let connection = connection_for(self, &db)?;
        let count = {
            let mut statement = connection
                .prepare(&sql)
                .map_err(|error| WitSqlError::PrepareFailed(error.to_string()))?;
            check_arity(&statement, &bound)?;
            // Fresh, not stored: same reason as the non-transaction path.
            if statement.readonly() {
                return Err(WitSqlError::ReadOnlyConnection);
            }
            statement
                .execute(rusqlite::params_from_iter(bound.iter()))
                .map_err(|error| WitSqlError::ExecutionFailed(error.to_string()))?
        };
        Ok(count as u64)
    }

    fn drop(
        &mut self,
        rep: wasmtime::component::Resource<bindings::qqq::sql::transaction::TxnStatement>,
    ) -> wasmtime::Result<()> {
        self.sql_state.txn_statements.remove(&rep.rep());
        Ok(())
    }
}

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::bindings::qqq::sql::database::{Statement, Value as TestValue};
    use super::bindings::qqq::sql::transaction::{Txn, TxnStatement};
    use super::*;
    use crate::linker::StoreData;
    use qqq_cap::manifest::Manifest;
    use qqq_cap::resolve::GrantSet;

    /// A fresh database file for one test. Unique per test name so parallel
    /// tests never share a file, and removed up front so a rerun after a
    /// crash starts clean rather than inheriting another run's tables.
    fn test_path(name: &str) -> PathBuf {
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("qqq-sql-test-{pid}-{name}.db"));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn view_for(path: &std::path::Path, read_write: bool) -> SqlView {
        SqlView::new(Arc::new(SqlConfig::new(vec![SqlDatabase::new(
            "orders".to_owned(),
            path.to_path_buf(),
            read_write,
        )])))
    }

    fn manifest_for(path: &std::path::Path, execute: bool) -> Manifest {
        // Forward slashes: a Windows display path carries backslashes,
        // which TOML would read as escapes. The view uses the `PathBuf`
        // directly; the manifest only carries the grant derivation.
        let host = path.display().to_string().replace('\\', "/");
        let suffix = if execute { "\nexecute = true\n" } else { "" };
        Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
             [[capabilities.sql]]\nname = \"orders\"\ndriver = \"sqlite\"\n\
             host = \"{host}\"{suffix}",
        ))
        .expect("probe manifest parses")
    }

    fn store_for(path: &std::path::Path, read_write: bool, execute: bool) -> StoreData {
        let manifest = manifest_for(path, execute);
        StoreData::new(GrantSet::from_manifest(&manifest)).with_sql(view_for(path, read_write))
    }

    fn ungranted_store() -> StoreData {
        StoreData::new(GrantSet::empty())
    }

    /// One-shot query without importing the database trait: transaction
    /// tests already import the transaction traits (whose `prepare` would
    /// collide), so they reach `query-once` through this helper instead.
    fn query_once(
        data: &mut StoreData,
        database: String,
        sql: String,
        args: Vec<TestValue>,
    ) -> std::result::Result<Vec<WitRow>, WitSqlError> {
        use super::bindings::qqq::sql::database::Host as _;
        data.query_once(database, sql, args)
    }

    /// Grant first, membership second: an ungranted call fails before its
    /// database name is judged, so it learns nothing about the config.
    #[test]
    fn ungranted_prepare_fails_before_membership() {
        use super::bindings::qqq::sql::database::Host as _;
        let mut data = ungranted_store();
        let err = data
            .prepare("orders".to_owned(), "SELECT 1".to_owned())
            .expect_err("no grant means no statement");
        assert!(matches!(err, WitSqlError::NotGranted));
        assert!(data.databases().is_empty());
    }

    /// A granted call against an unlisted name fails `database-not-configured`
    /// — refused by name, never conjured into existence.
    #[test]
    fn unlisted_database_is_not_configured() {
        use super::bindings::qqq::sql::database::Host as _;
        let path = test_path("unlisted");
        let mut data = store_for(&path, true, true);
        let err = data
            .prepare("ledger".to_owned(), "SELECT 1".to_owned())
            .expect_err("unlisted names never open");
        assert!(matches!(err, WitSqlError::DatabaseNotConfigured));
        let err = data
            .query_once("ledger".to_owned(), "SELECT 1".to_owned(), vec![])
            .expect_err("one-shot path checks too");
        assert!(matches!(err, WitSqlError::DatabaseNotConfigured));
    }

    /// `prepare` validates syntax now, not at first use: a bad statement
    /// fails `prepare-failed` before any handle exists.
    #[test]
    fn prepare_validates_syntax_eagerly() {
        use super::bindings::qqq::sql::database::Host as _;
        let path = test_path("syntax");
        let mut data = store_for(&path, true, true);
        let err = data
            .prepare("orders".to_owned(), "SELEC nonsense FROM".to_owned())
            .expect_err("bad SQL fails at prepare");
        assert!(matches!(err, WitSqlError::PrepareFailed(_)));
        assert!(data.sql_state.statements.is_empty());
    }

    /// An over-long statement fails before it reaches the parser, through
    /// both the prepared and the one-shot path.
    #[test]
    fn oversize_statements_fail_prepare_failed() {
        use super::bindings::qqq::sql::database::Host as _;
        let path = test_path("oversize");
        let mut data = store_for(&path, true, true);
        let big = format!("SELECT {}", "1".repeat(MAX_SQL_STATEMENT_BYTES));
        let err = data
            .prepare("orders".to_owned(), big.clone())
            .expect_err("oversize fails");
        assert!(matches!(err, WitSqlError::PrepareFailed(_)));
        let err = data
            .query_once("orders".to_owned(), big, vec![])
            .expect_err("one-shot path caps too");
        assert!(matches!(err, WitSqlError::PrepareFailed(_)));
    }

    /// More placeholders than the host allows fails `argument-mismatch`
    /// before any value is converted.
    #[test]
    fn too_many_args_fail_argument_mismatch() {
        let path = test_path("args");
        let mut data = store_for(&path, true, true);
        let args = vec![TestValue::Integer(1); MAX_SQL_ARGS + 1];
        let err = query_once(&mut data, "orders".to_owned(), "SELECT 1".to_owned(), args)
            .expect_err("1025 binds fail");
        assert!(matches!(err, WitSqlError::ArgumentMismatch(_)));
    }

    /// Files outside the named database stay outside: `ATTACH`, `DETACH`
    /// and `VACUUM` reach other files, so every prepare site refuses them
    /// by leading keyword — including through comments and mixed case.
    /// `VACUUM INTO` writes an arbitrary path; plain `VACUUM` rewrites the
    /// file outside the host's accounting. Neither is needed for the V1
    /// query/execute contract, so both stay out.
    #[test]
    fn attachment_statements_are_rejected() {
        let path = test_path("no-attach");
        let mut data = store_for(&path, true, true);
        for sql in [
            "ATTACH 'other.db' AS other",
            "attach 'other.db' AS other",
            "  /*\nmulti\n*/\tDETACH other",
            "-- line comment\nVACUUM",
            "VACUUM INTO 'backup.db'",
        ] {
            let err = query_once(&mut data, "orders".to_owned(), sql.to_owned(), vec![])
                .expect_err("attachment never prepares");
            assert!(
                matches!(err, WitSqlError::PrepareFailed(_)),
                "policy refusal, not execution: {err:?}"
            );
        }
    }

    /// An oversize argument never reaches the database.
    #[test]
    fn oversize_values_fail_argument_mismatch() {
        let path = test_path("values");
        let mut data = store_for(&path, true, true);
        let args = vec![TestValue::Text("x".repeat(MAX_SQL_VALUE_BYTES + 1))];
        let err = query_once(&mut data, "orders".to_owned(), "SELECT ?1".to_owned(), args)
            .expect_err("oversize text fails");
        assert!(matches!(err, WitSqlError::ArgumentMismatch(_)));
    }

    /// The full round trip: create, insert, select — values cross both
    /// directions with types intact, except boolean: SQLite has no native
    /// boolean, so `true` is stored as integer 1 and reads back as
    /// `Integer(1)` — SQLite's dynamic typing, not a host conversion.
    #[test]
    fn statement_round_trip_preserves_values() {
        use super::bindings::qqq::sql::database::{Host as _, HostStatement as _};
        let path = test_path("round-trip");
        let mut data = store_for(&path, true, true);
        query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER, name TEXT, active BOOLEAN, score REAL)".to_owned(),
            vec![],
        )
        .expect("create runs");
        let insert = data
            .prepare(
                "orders".to_owned(),
                "INSERT INTO t VALUES (?1, ?2, ?3, ?4)".to_owned(),
            )
            .expect("insert prepares");
        let changed = data
            .execute(
                insert,
                vec![
                    TestValue::Integer(7),
                    TestValue::Text("seven".to_owned()),
                    TestValue::Boolean(true),
                    TestValue::Float(1.5),
                ],
            )
            .expect("insert executes");
        assert_eq!(changed, 1);
        let select = data
            .prepare("orders".to_owned(), "SELECT * FROM t".to_owned())
            .expect("select prepares");
        let rows = data.query(select, vec![]).expect("select runs");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.len(), 4);
        assert!(matches!(row[0], TestValue::Integer(7)));
        assert!(matches!(row[1], TestValue::Text(ref text) if text == "seven"));
        assert!(matches!(row[2], TestValue::Integer(1)));
        assert!(matches!(row[3], TestValue::Float(number) if (number - 1.5).abs() < f64::EPSILON));
    }

    /// Query-only cannot write: direction follows the statement, so a
    /// writing prepare fails `read-only` — the caller may see the database,
    /// just not change it. The one-shot path opens read-only, so on a
    /// missing file the open fails first; direction fires once the file
    /// exists. A read still prepares and runs.
    #[test]
    fn query_only_grant_cannot_write() {
        use super::bindings::qqq::sql::database::{Host as _, HostStatement as _};
        let path = test_path("query-only");
        let mut data = store_for(&path, true, false);
        // A missing file fails before direction is known: the read-only
        // open cannot prepare, so existence precedes direction here.
        let err = query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect_err("query-only cannot create");
        assert!(matches!(err, WitSqlError::ExecutionFailed(_)));
        let write = data
            .prepare(
                "orders".to_owned(),
                "CREATE TABLE t (id INTEGER)".to_owned(),
            )
            .expect_err("prepare itself enforces direction");
        assert!(matches!(write, WitSqlError::ReadOnlyConnection));
        let read = data
            .prepare("orders".to_owned(), "SELECT 1".to_owned())
            .expect("reads still prepare");
        let rows = data.query(read, vec![]).expect("reads still run");
        assert_eq!(rows.len(), 1);
    }

    /// A read-only database refuses writes even when the grant allows them:
    /// the manifest grants both or neither per database, and a split means
    /// the deploy path and the link path disagree — refused, read-only.
    #[test]
    fn read_only_database_refuses_execute() {
        use super::bindings::qqq::sql::database::{Host as _, HostStatement as _};
        let path = test_path("read-only-db");
        // Seed the file through a writable store: a read-only database
        // opens read-only, so the file must already exist.
        let mut seed = store_for(&path, true, true);
        query_once(
            &mut seed,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect("seed creates");
        let mut data = store_for(&path, false, true);
        let err = query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE u (id INTEGER)".to_owned(),
            vec![],
        )
        .expect_err("read-only database refuses create");
        assert!(matches!(err, WitSqlError::ReadOnlyConnection));
        let write = data
            .prepare("orders".to_owned(), "SELECT * FROM t".to_owned())
            .expect("prepare needs only the read grant");
        let err = data
            .execute(write, vec![])
            .expect_err("read-only database refuses execute");
        assert!(matches!(err, WitSqlError::ReadOnlyConnection));
    }

    /// A read through an `execute` handle fails `read-only`: the statement's
    /// own answer, not the SQL text, decides.
    #[test]
    fn statement_query_refuses_writing_statements() {
        use super::bindings::qqq::sql::database::{Host as _, HostStatement as _};
        let path = test_path("write-query");
        let mut data = store_for(&path, true, true);
        let write = data
            .prepare(
                "orders".to_owned(),
                "CREATE TABLE t (id INTEGER)".to_owned(),
            )
            .expect("write prepares");
        let err = data
            .query(write, vec![])
            .expect_err("query on a write fails read-only");
        assert!(matches!(err, WitSqlError::ReadOnlyConnection));
    }

    /// A thousand and one rows fail `result-too-large` instead of
    /// truncating silently at a thousand.
    #[test]
    fn row_cap_fails_instead_of_truncating() {
        use super::bindings::qqq::sql::database::{Host as _, HostStatement as _};
        let path = test_path("row-cap");
        let mut data = store_for(&path, true, true);
        query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect("create runs");
        let max = i64::try_from(MAX_SQL_ROWS).unwrap_or(i64::MAX);
        for id in 0..=max {
            let handle = data
                .prepare("orders".to_owned(), "INSERT INTO t VALUES (?1)".to_owned())
                .expect("insert prepares");
            // Handles are bounded, so the test closes what it opens: the
            // cap under test is the row cap, not the handle cap.
            let rep = handle.rep();
            data.execute(handle, vec![TestValue::Integer(id)])
                .expect("insert runs");
            data.close(wasmtime::component::Resource::<Statement>::new_own(rep));
        }
        let select = data
            .prepare("orders".to_owned(), "SELECT * FROM t".to_owned())
            .expect("select prepares");
        let err = data.query(select, vec![]).expect_err("1001 rows fail");
        assert!(matches!(err, WitSqlError::ResultTooLarge));
    }

    /// A stale handle resolves to nothing: fabricated ids fail
    /// `execution-failed`, never another statement.
    #[test]
    fn unknown_statement_fails_execution_failed() {
        use super::bindings::qqq::sql::database::HostStatement as _;
        let path = test_path("stale");
        let mut data = store_for(&path, true, true);
        let stale = wasmtime::component::Resource::<Statement>::new_own(999);
        let err = data.query(stale, vec![]).expect_err("stale handle fails");
        assert!(matches!(err, WitSqlError::ExecutionFailed(_)));
    }

    /// `close` is idempotent: closing twice is not an error, and the
    /// closed handle resolves to nothing afterwards.
    #[test]
    fn close_is_idempotent() {
        use super::bindings::qqq::sql::database::{Host as _, HostStatement as _};
        let path = test_path("close");
        let mut data = store_for(&path, true, true);
        let first = data
            .prepare("orders".to_owned(), "SELECT 1".to_owned())
            .expect("select prepares");
        let id = first.rep();
        data.close(first);
        let second = wasmtime::component::Resource::<Statement>::new_own(id);
        data.close(second);
        let third = wasmtime::component::Resource::<Statement>::new_own(id);
        let err = data
            .query(third, vec![])
            .expect_err("closed handle resolves to nothing");
        assert!(matches!(err, WitSqlError::ExecutionFailed(_)));
    }

    /// Commit persists: rows written inside the transaction survive it.
    #[test]
    fn committed_rows_survive() {
        use super::bindings::qqq::sql::transaction::{
            Host as _, HostTxn as _, HostTxnStatement as _,
        };
        let path = test_path("commit");
        let mut data = store_for(&path, true, true);
        query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect("create runs");
        let txn = data.begin("orders".to_owned()).expect("begin runs");
        let insert = data
            .prepare(txn, "INSERT INTO t VALUES (1)".to_owned())
            .expect("txn insert prepares");
        data.execute(insert, vec![]).expect("txn insert runs");
        // A fresh statement sees the uncommitted row on the same connection;
        // the commit is what publishes it to every connection after this one.
        let commit_txn = {
            let id = data.sql_state.transactions.keys().next().copied().unwrap();
            wasmtime::component::Resource::<Txn>::new_own(id)
        };
        data.commit(commit_txn).expect("commit runs");
        let rows = query_once(
            &mut data,
            "orders".to_owned(),
            "SELECT * FROM t".to_owned(),
            vec![],
        )
        .expect("select runs");
        assert_eq!(rows.len(), 1);
    }

    /// Rollback discards: rows written inside the transaction vanish.
    #[test]
    fn rolled_back_rows_vanish() {
        use super::bindings::qqq::sql::transaction::{
            Host as _, HostTxn as _, HostTxnStatement as _,
        };
        let path = test_path("rollback");
        let mut data = store_for(&path, true, true);
        query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect("create runs");
        let txn = data.begin("orders".to_owned()).expect("begin runs");
        let insert = data
            .prepare(txn, "INSERT INTO t VALUES (1)".to_owned())
            .expect("txn insert prepares");
        data.execute(insert, vec![]).expect("txn insert runs");
        let id = data.sql_state.transactions.keys().next().copied().unwrap();
        data.rollback(wasmtime::component::Resource::<Txn>::new_own(id))
            .expect("rollback runs");
        let rows = query_once(
            &mut data,
            "orders".to_owned(),
            "SELECT * FROM t".to_owned(),
            vec![],
        )
        .expect("select runs");
        assert!(rows.is_empty());
    }

    /// Dropping without committing rolls back: the safe default for a
    /// guest that panics mid-transaction.
    #[test]
    fn dropped_transaction_rolls_back() {
        use super::bindings::qqq::sql::transaction::{
            Host as _, HostTxn as _, HostTxnStatement as _,
        };
        let path = test_path("drop-rolls-back");
        let mut data = store_for(&path, true, true);
        query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect("create runs");
        let txn = data.begin("orders".to_owned()).expect("begin runs");
        let id = txn.rep();
        let insert = data
            .prepare(txn, "INSERT INTO t VALUES (1)".to_owned())
            .expect("txn insert prepares");
        data.execute(insert, vec![]).expect("txn insert runs");
        <StoreData as super::bindings::qqq::sql::transaction::HostTxn>::drop(
            &mut data,
            wasmtime::component::Resource::<Txn>::new_own(id),
        )
        .expect("drop runs");
        let rows = query_once(
            &mut data,
            "orders".to_owned(),
            "SELECT * FROM t".to_owned(),
            vec![],
        )
        .expect("select runs");
        assert!(rows.is_empty());
        assert!(!data.sql_state.transactions.contains_key(&id));
    }

    /// A second `begin` on the same database fails: one transaction per
    /// database per request, and the lock names the conflict.
    #[test]
    fn second_begin_on_one_database_fails() {
        use super::bindings::qqq::sql::transaction::Host as _;
        let path = test_path("second-begin");
        let mut data = store_for(&path, true, true);
        let _first = data.begin("orders".to_owned()).expect("first begins");
        let err = data
            .begin("orders".to_owned())
            .expect_err("second begin fails");
        assert!(matches!(err, WitSqlError::ExecutionFailed(_)));
    }

    /// Committing a closed transaction fails `execution-failed`, and a
    /// statement prepared inside it resolves to a closed transaction.
    #[test]
    fn statements_die_with_their_transaction() {
        use super::bindings::qqq::sql::transaction::{
            Host as _, HostTxn as _, HostTxnStatement as _,
        };
        let path = test_path("txn-closed");
        let mut data = store_for(&path, true, true);
        query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect("create runs");
        let txn = data.begin("orders".to_owned()).expect("begin runs");
        let txn_id = txn.rep();
        let insert = data
            .prepare(txn, "INSERT INTO t VALUES (1)".to_owned())
            .expect("txn insert prepares");
        let stmt_id = insert.rep();
        data.commit(wasmtime::component::Resource::<Txn>::new_own(txn_id))
            .expect("commit runs");
        let again = data
            .commit(wasmtime::component::Resource::<Txn>::new_own(txn_id))
            .expect_err("second commit fails");
        assert!(matches!(again, WitSqlError::ExecutionFailed(_)));
        let stale: wasmtime::component::Resource<TxnStatement> =
            wasmtime::component::Resource::<TxnStatement>::new_own(stmt_id);
        let err = data
            .query(stale, vec![])
            .expect_err("statement of a closed txn fails");
        assert!(matches!(err, WitSqlError::ExecutionFailed(_)));
    }

    /// Beginning without any grant fails closed; `databases` names the
    /// configured set only to granted callers.
    #[test]
    fn begin_needs_a_grant() {
        use super::bindings::qqq::sql::transaction::Host as _;
        let path = test_path("begin-grant");
        let mut data = ungranted_store();
        let _ = path;
        let err = data
            .begin("orders".to_owned())
            .expect_err("ungranted begin fails");
        assert!(matches!(err, WitSqlError::NotGranted));
    }

    /// `databases` lists the configured names to a granted caller.
    #[test]
    fn databases_lists_configured_names() {
        use super::bindings::qqq::sql::database::Host as _;
        let path = test_path("databases");
        let mut data = store_for(&path, true, true);
        assert_eq!(data.databases(), vec!["orders".to_owned()]);
    }

    /// A read-only database opens read-only: opening the file must never
    /// create it, so a missing file fails instead of materializing.
    #[test]
    fn read_only_database_never_creates_files() {
        use super::bindings::qqq::sql::database::Host as _;
        let path = test_path("ro-no-create");
        let _ = std::fs::remove_file(&path);
        let mut data = store_for(&path, false, true);
        let err = data
            .prepare("orders".to_owned(), "SELECT 1".to_owned())
            .expect_err("a missing read-only file fails");
        assert!(matches!(err, WitSqlError::ExecutionFailed(_)));
        assert!(!path.exists(), "a failed open creates nothing");
    }

    /// Non-transaction calls refuse while a transaction is open on that
    /// database: sharing the one connection would otherwise let them read
    /// uncommitted rows and commit or roll back with the transaction.
    #[test]
    fn non_txn_calls_refuse_while_transaction_open() {
        use super::bindings::qqq::sql::database::Host as DbHost;
        use super::bindings::qqq::sql::transaction::{Host as _, HostTxn as _};
        let path = test_path("txn-isolation");
        let mut data = store_for(&path, true, true);
        query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect("create runs");
        let txn = data.begin("orders".to_owned()).expect("begin runs");
        let err =
            <StoreData as DbHost>::prepare(&mut data, "orders".to_owned(), "SELECT 1".to_owned())
                .expect_err("prepare joins nothing while a txn is open");
        match err {
            WitSqlError::ExecutionFailed(message) => assert!(
                message.contains("transaction is open"),
                "the refusal names the open transaction: {message}"
            ),
            other => panic!("expected execution-failed, got {other:?}"),
        }
        let err = query_once(
            &mut data,
            "orders".to_owned(),
            "SELECT 1".to_owned(),
            vec![],
        )
        .expect_err("one-shot joins nothing either");
        assert!(matches!(err, WitSqlError::ExecutionFailed(_)));
        data.commit(txn).expect("commit runs");
        <StoreData as DbHost>::prepare(&mut data, "orders".to_owned(), "SELECT 1".to_owned())
            .expect("prepare works after commit");
    }

    /// A failed commit keeps its handle: closing it would strand the SQLite
    /// transaction with no handle to retry or roll back. A deferred foreign
    /// key fails at `COMMIT`, not at insert — so the commit fails, the
    /// handle stays, and the guest recovers with an explicit rollback.
    #[test]
    fn failed_commit_keeps_handle() {
        use super::bindings::qqq::sql::transaction::{
            Host as _, HostTxn as _, HostTxnStatement as _,
        };
        let path = test_path("kept-handle");
        let mut data = store_for(&path, true, true);
        query_once(
            &mut data,
            "orders".to_owned(),
            "PRAGMA foreign_keys = ON".to_owned(),
            vec![],
        )
        .expect("foreign keys enforce");
        query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE p (id INTEGER PRIMARY KEY)".to_owned(),
            vec![],
        )
        .expect("parent creates");
        query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE c (id INTEGER, pid INTEGER REFERENCES p(id) DEFERRABLE INITIALLY DEFERRED)".to_owned(),
            vec![],
        )
        .expect("child creates");
        let txn = data.begin("orders".to_owned()).expect("begin runs");
        let id = txn.rep();
        let insert = data
            .prepare(txn, "INSERT INTO c VALUES (1, 999)".to_owned())
            .expect("orphan insert prepares");
        data.execute(insert, vec![])
            .expect("orphan insert runs inside the txn");
        let err = data
            .commit(wasmtime::component::Resource::<Txn>::new_own(id))
            .expect_err("deferred key fails at commit");
        assert!(
            matches!(err, WitSqlError::ExecutionFailed(_)),
            "commit names the failure: {err:?}"
        );
        data.rollback(wasmtime::component::Resource::<Txn>::new_own(id))
            .expect("the kept handle rolls back");
        let err = data
            .rollback(wasmtime::component::Resource::<Txn>::new_own(id))
            .expect_err("rolled-back txn is gone");
        assert!(
            matches!(err, WitSqlError::ExecutionFailed(_)),
            "closed handles stay closed: {err:?}"
        );
    }

    /// Validation precedes any file effect: an oversize statement fails
    /// before the host creates a single directory or file.
    #[test]
    fn failed_prepare_creates_no_file() {
        use super::bindings::qqq::sql::database::Host as _;
        let path = test_path("no-file");
        let _ = std::fs::remove_file(&path);
        let mut data = store_for(&path, true, true);
        let big = format!("SELECT {}", "1".repeat(MAX_SQL_STATEMENT_BYTES));
        let err = data
            .prepare("orders".to_owned(), big)
            .expect_err("oversize fails");
        assert!(matches!(err, WitSqlError::PrepareFailed(_)));
        assert!(!path.exists(), "validation precedes any file effect");
    }

    /// A query-only guest can still transact reads: `begin` takes no write
    /// lock it cannot use, so reads inside proceed and commit succeeds.
    #[test]
    fn query_only_transaction_reads() {
        use super::bindings::qqq::sql::transaction::{
            Host as _, HostTxn as _, HostTxnStatement as _,
        };
        let path = test_path("qo-txn");
        let mut seed = store_for(&path, true, true);
        query_once(
            &mut seed,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect("create runs");
        query_once(
            &mut seed,
            "orders".to_owned(),
            "INSERT INTO t VALUES (1)".to_owned(),
            vec![],
        )
        .expect("insert runs");
        let mut data = store_for(&path, true, false);
        let txn = data.begin("orders".to_owned()).expect("begin runs");
        let select = data
            .prepare(txn, "SELECT * FROM t".to_owned())
            .expect("txn select prepares");
        let rows = data.query(select, vec![]).expect("txn select runs");
        assert_eq!(rows.len(), 1);
    }

    /// The handle tables are bounded: past the cap, new handles fail
    /// `pool-exhausted` instead of growing without limit.
    #[test]
    fn handle_table_is_bounded() {
        use super::bindings::qqq::sql::database::Host as _;
        let path = test_path("handles");
        let mut data = store_for(&path, true, true);
        for _ in 0..MAX_SQL_HANDLES {
            data.prepare("orders".to_owned(), "SELECT 1".to_owned())
                .expect("within the cap");
        }
        let err = data
            .prepare("orders".to_owned(), "SELECT 1".to_owned())
            .expect_err("past the cap");
        assert!(matches!(err, WitSqlError::PoolExhausted));
    }

    /// A cap-hit creates nothing: the cap is checked before any open, so a
    /// refused call leaves no file behind.
    #[test]
    fn capped_calls_create_nothing() {
        use super::bindings::qqq::sql::database::Host as _;
        let path = test_path("cap-clean");
        let _ = std::fs::remove_file(&path);
        let mut data = store_for(&path, true, true);
        // Fill the table without touching SQLite: no connection opens, no
        // file creates — only the cap under test can fire.
        for id in 0..u32::try_from(MAX_SQL_HANDLES).unwrap_or(u32::MAX) {
            data.sql_state
                .statements
                .insert(id, ("orders".to_owned(), "SELECT 1".to_owned(), true));
        }
        let err = data
            .prepare("orders".to_owned(), "SELECT 1".to_owned())
            .expect_err("a full table refuses");
        assert!(matches!(err, WitSqlError::PoolExhausted));
        assert!(!path.exists(), "a refused call creates nothing");
    }

    /// Arity is the host's answer, not SQLite's: binding the wrong number
    /// of arguments fails `argument-mismatch`, naming the fix.
    #[test]
    fn arity_mismatch_fails_argument_mismatch() {
        let path = test_path("arity");
        let mut data = store_for(&path, true, true);
        let err = query_once(
            &mut data,
            "orders".to_owned(),
            "SELECT ?1, ?2".to_owned(),
            vec![TestValue::Integer(1)],
        )
        .expect_err("one bind for two placeholders fails");
        assert!(matches!(err, WitSqlError::ArgumentMismatch(_)));
    }

    /// A refused write creates nothing: the one-shot path opens read-only
    /// when the call cannot write. On a missing file the open itself fails
    /// — existence precedes direction, and direction fires once the file
    /// exists — and still nothing is created.
    #[test]
    fn refused_writes_create_nothing() {
        let path = test_path("refused-write");
        let _ = std::fs::remove_file(&path);
        let mut data = store_for(&path, true, false);
        // A missing file fails before direction is known: the read-only
        // open cannot prepare, so existence precedes direction here —
        // direction fires once the file exists, below.
        let err = query_once(
            &mut data,
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
            vec![],
        )
        .expect_err("query-only cannot create");
        assert!(matches!(err, WitSqlError::ExecutionFailed(_)));
        assert!(!path.exists(), "a refused write creates nothing");
    }

    /// Transaction control stays in the transaction interface: `BEGIN`
    /// through a plain path fails instead of opening a hidden SQLite
    /// transaction no host handle names.
    #[test]
    fn plain_paths_reject_transaction_control() {
        let path = test_path("txn-control");
        let mut data = store_for(&path, true, true);
        let err = query_once(&mut data, "orders".to_owned(), "BEGIN".to_owned(), vec![])
            .expect_err("BEGIN outside a transaction fails");
        match err {
            WitSqlError::ExecutionFailed(message) => assert!(
                message.contains("transaction control"),
                "the refusal names the rule: {message}"
            ),
            other => panic!("expected execution-failed, got {other:?}"),
        }
    }

    /// An execute-only grant prepares writes: direction follows the
    /// statement's own nature, so a grant the narrowing overlay can produce
    /// is usable outside transactions too.
    #[test]
    fn execute_only_prepares_writes() {
        use super::bindings::qqq::sql::database::Host as _;
        use qqq_cap::capability::Capability::SqlExecute;
        use qqq_cap::resolve::Overlay;
        let path = test_path("execute-only");
        let manifest = manifest_for(&path, true);
        let grants = GrantSet::from_manifest(&manifest).narrow(&Overlay::allow_only(
            qqq_cap::resolve::Layer::Organization,
            [SqlExecute],
            "execute only",
        ));
        assert!(!grants.grants(qqq_cap::capability::Capability::SqlQuery));
        let mut data = StoreData::new(grants).with_sql(view_for(&path, true));
        data.prepare(
            "orders".to_owned(),
            "CREATE TABLE t (id INTEGER)".to_owned(),
        )
        .expect("execute-only prepares writes");
    }

    /// Handle ids never wrap: exhausting the `u32` space fails
    /// `pool-exhausted` instead of reusing an id a stale handle names.
    #[test]
    fn handle_ids_never_reused() {
        use super::bindings::qqq::sql::database::Host as _;
        let path = test_path("no-reuse");
        let mut data = store_for(&path, true, true);
        data.sql_state.next = u32::MAX;
        let err = data
            .prepare("orders".to_owned(), "SELECT 1".to_owned())
            .expect_err("a wrapped id never mints");
        assert!(matches!(err, WitSqlError::PoolExhausted));
        assert!(
            data.sql_state.statements.is_empty(),
            "a refused mint inserts nothing"
        );
    }
}
