// SPDX-License-Identifier: Apache-2.0

//! `qqqai serve` — the production server (`CLI-011`).
//!
//! # What this is, and what took so long
//!
//! Proposal §5.2 lists the command with `--listen`, `--workers`, `--tls` and
//! `--config`. Every part of the runtime it needs existed and was tested long
//! before this file did; what was missing was the **edges** between them, which no
//! checklist item owned because every item is scoped to one crate (`§O-146`). The
//! chain that had to exist first:
//!
//! ```text
//!   wit/app/app.wit   what a QQQ app *is*
//!   invoke            resolve the guest's handler export
//!   abi               the canonical types
//!   call              encode, call, decode
//!   guest_bridge      HTTP -> ABI
//!   guest_handler     GuestApp, a real Dispatch handler
//!   serve (this file) bind, route, dispatch, shut down
//! ```
//!
//! # What `--workers` sizes
//!
//! A worker in a component-per-request runtime is not a thread that owns a connection:
//! V1 runs async-single-threaded with one task per connection (§4.7), so the quantity an
//! operator is reaching for when they raise `--workers` is **how many requests may hold a
//! guest instance at once**. That is an instance-pool capacity, and
//! `qqq_host::pool::Pool` is the pool.
//!
//! Until that seam existed, `--workers` was parsed, validated, capped and **reported with
//! no effect** — `--workers 4` was accepted and the process ran one — and a refusal stood
//! in its place naming `[limits] max_instances` as the ceiling that did exist. The refusal
//! said what would end it: *"A refusal is the honest shape while the flag has nothing to
//! size; when a pool lands, the check is deleted and the number acquires its meaning."*
//!
//! The pool has landed, the check is deleted, and the number now sizes
//! `GuestApp::with_capacity`'s pool. `handle_request` acquires a slot **before**
//! instantiating, so a request that cannot get one is refused rather than paying for the
//! instantiation the bound exists to prevent — the rule `refuse_before_reading` states for
//! request bodies, one layer down.
//!
//! ## Why this is not `[limits] max_instances`
//!
//! They are different quantities, and conflating them was the earlier mistake. That limit
//! is the manifest's **per-store** ceiling: how many Wasmtime instances one instantiation
//! may create, which is a property of the artifact (§O-154 measured three core modules
//! and four instantiation sites in the reference application). This pool bounds how many
//! **requests** hold a guest at once, across the process. Both are real and neither
//! substitutes for the other.
//!
//! # Why `--tls` is refused
//!
//! `--tls` used to parse, set `ServeOutput::tls`, print `TLS: on` and serve cleartext: the
//! manifest has no `[server.tls]` section and there is no TLS-terminating accept path, so
//! the flag had nothing to turn on. A command that reports an active security feature it
//! does not provide is worse than one that has no such flag, because the operator's belief
//! is the thing being relied on.
//!
//! It is refused at parse time, naming what is missing and what to do instead, so the
//! failure lands while the user is looking at the command they typed.
//!
//! # Why `--config` names a manifest and is not an overlay format
//!
//! `--config <file>` selects which `qqq.toml` to serve, so a deployment can keep
//! one per environment. It is deliberately **not** a second configuration language:
//! narrowing-only overlays already exist in `qqq-cap`, and inventing another one
//! here would be a second answer to a question the capability model already
//! answers.

use std::path::Path;
use std::sync::Arc;

use qqq_cap::resolve::GrantSet;
use qqq_core::{Error, ErrorCode, Result};
use qqq_host::config::EngineConfig;
use qqq_host::LimitSet;
use qqq_io::{ListenAddr, Shutdown};
use qqq_serve::access_log::Logger;
use qqq_serve::access_log::{Format, Level};
use qqq_serve::response::Response;
use qqq_serve::server::{Dispatch, Handler, ServerConfig};

use crate::build::find_artifact;
use crate::guest_handler::GuestApp;
use crate::manifest_loader::LoadedManifest;
use crate::serve_routes::routes_from_manifest;

/// The largest worker count this command accepts.
///
/// A refusal rather than a clamp, for the reason `qqq-cap` refuses an incoherent
/// limit set: silently reducing 1000 to 128 means the operator's configuration and
/// the running system disagree, and nothing says so.
pub const MAX_WORKERS: u32 = 128;

/// The flags `qqqai serve` accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeOptions {
    /// `--listen <host:port>`.
    pub listen: String,
    /// `--workers <n>`. Only `1` is accepted; see the module documentation.
    pub workers: u32,
    /// `--tls`. Refused while no TLS configuration or accept path exists; see the module
    /// documentation.
    pub tls: bool,
    /// `--config <path>` — an alternate manifest to serve.
    pub config: Option<String>,
    /// Stop after accepting this many connections.
    ///
    /// `None` — the default — runs until interrupted, which is what production
    /// wants. Tests pass a bound, for the reason `dev`'s `--reload-limit` exists:
    /// **an unbounded loop that cannot be bounded is a loop that cannot be
    /// verified.**
    pub accept_limit: Option<u64>,
    /// `--audit-log <path>` — persist the capability-use record, resuming any history there.
    ///
    /// `None` keeps the record in memory, which is the honest default: a server that wrote an
    /// evidence file nobody asked for would be a surprise, and a silent one, because nothing in a
    /// response says a file was created.
    ///
    /// When set, the file is **loaded and verified before serving starts**. A malformed or
    /// chain-broken file refuses the start rather than being absorbed — see
    /// `GuestApp::attach_audit_file`.
    pub audit_log: Option<String>,
    /// `--redact-from <path>` — a `NAME=value` file of secret values to redact from every line.
    ///
    /// `None` redacts nothing, which is the honest default: the values are not available to the
    /// runtime by any other route (§2.5 forbids environment reads), so a server that silently
    /// redacted *nothing* while appearing configured is the failure this flag exists to make
    /// visible — an operator who wants redaction must supply the values.
    pub redact_from: Option<String>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3000".to_owned(),
            // One worker is the honest default: it is what V1 actually runs.
            workers: 1,
            tls: false,
            config: None,
            accept_limit: None,
            audit_log: None,
            redact_from: None,
        }
    }
}

/// What a serve run reports.
///
/// `Serialize` is not decoration: every `qqqai` command emits stable
/// machine-readable JSON, and `--json` is part of the CLI's contract. This type
/// carried no derive until `serve` was made reachable, because nothing had ever
/// tried to render it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServeOutput {
    /// The address served on.
    pub listen: String,
    /// How many routes the manifest declared.
    pub routes: usize,
    /// The workers configured.
    pub workers: u32,
    /// Whether TLS was requested.
    pub tls: bool,
    /// Whether a guest component was found and loaded.
    pub guest_loaded: bool,
}

/// Parse `qqqai serve`'s arguments.
///
/// # Errors
///
/// `QQQ-7001` for an unknown flag, a flag without a value, or a value that does not
/// parse. Every one is a *usage* error: the command names what was wrong and what
/// to write instead, because a server that starts with a flag silently ignored is
/// worse than one that refuses to start.
pub fn options(args: &[String]) -> Result<ServeOptions> {
    let mut opts = ServeOptions::default();
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--listen" => {
                opts.listen = value_of(args, i, "--listen")?;
                i += 2;
            }
            "--workers" => {
                let v = value_of(args, i, "--workers")?;
                let n: u32 = v.parse().map_err(|_| {
                    usage(format!("`--workers {v}` is not a number"))
                        .with_remediation("pass a whole number, for example `--workers 4`")
                })?;
                if n == 0 {
                    return Err(usage("`--workers 0` would serve nothing").with_remediation(
                        "pass at least 1; V1 runs one worker with one task per connection",
                    ));
                }
                if n > MAX_WORKERS {
                    return Err(usage(format!(
                        "`--workers {n}` exceeds the maximum of {MAX_WORKERS}"
                    ))
                    .with_remediation(
                        "the instance pool bounds concurrency; raise that rather than \
                         the worker count",
                    ));
                }
                opts.workers = n;
                i += 2;
            }
            "--tls" => {
                opts.tls = true;
                i += 1;
            }
            "--config" => {
                opts.config = Some(value_of(args, i, "--config")?);
                i += 2;
            }
            "--redact-from" => {
                let v = value_of(args, i, "--redact-from")?;
                if v.is_empty() {
                    return Err(usage("`--redact-from` needs a path").with_remediation(
                        "pass the `NAME=value` file holding the secret values to redact, for \
                         example `--redact-from /etc/qqq/secrets.env`",
                    ));
                }
                opts.redact_from = Some(v);
                i += 2;
            }
            "--audit-log" => {
                let v = value_of(args, i, "--audit-log")?;
                if v.is_empty() {
                    return Err(usage("`--audit-log` needs a path").with_remediation(
                        "pass the file the capability-use record is appended to, for example \
                         `--audit-log /var/log/qqq/audit.jsonl`",
                    ));
                }
                opts.audit_log = Some(v);
                i += 2;
            }
            "--accept-limit" => {
                let v = value_of(args, i, "--accept-limit")?;
                opts.accept_limit = Some(v.parse().map_err(|_| {
                    usage(format!("`--accept-limit {v}` is not a number"))
                        .with_remediation("pass a whole number of connections")
                })?);
                i += 2;
            }
            other => {
                return Err(usage(format!("`{other}` is not a flag `serve` accepts"))
                    .with_remediation(
                        "serve accepts --listen, --workers, --tls, --config and \
                         --accept-limit",
                    ))
            }
        }
    }

    // --- The one flag that would otherwise report something untrue -----------
    //
    // A *refusal at parse time* rather than a warning at startup, because the alternative
    // is a server that prints a security claim it cannot honour: `--tls` printed
    // `TLS: on` while serving cleartext, so an operator reading the command's own output
    // would conclude the listener was encrypted.
    //
    // Refusing is a smaller change than it looks, and a reversible one: when `[server.tls]`
    // is modelled and a TLS-terminating accept path exists, this check is deleted and
    // nothing else moves.
    if opts.tls {
        return Err(usage(
            "`--tls` is not implemented: the manifest has no `[server.tls]` section and \
             there is no TLS-terminating accept path, so this server would serve cleartext \
             while reporting TLS",
        )
        .with_remediation(
            "terminate TLS in front of `qqqai serve` (a reverse proxy or a service mesh). \
             `SRV-007` is **done** — it implemented `qqq-serve::tls`: rustls 0.23, the explicit \
             cipher policy, ALPN, and 21 end-to-end handshake tests. What has not landed is the \
             **manifest `[server.tls]` section** and the **accept path in this command that \
             would read it**, and no checklist item owns either. That is why this remediation \
             names the two missing pieces instead of a row to wait for",
        ));
    }
    // `--workers > 1` was refused here until the instance pool landed, and the refusal
    // said as much: *"A refusal is the honest shape while the flag has nothing to size;
    // when a pool lands, the check is deleted and the number acquires its meaning."*
    // The pool is `qqq_host::pool::Pool`, `GuestApp::with_capacity` installs it, and
    // `handle_request` acquires before instantiating — so the number now sizes something
    // and the check is gone.

    Ok(opts)
}

/// Read the value that follows a flag.
fn value_of(args: &[String], i: usize, flag: &str) -> Result<String> {
    args.get(i + 1).cloned().ok_or_else(|| {
        usage(format!("`{flag}` needs a value")).with_remediation(format!("write `{flag} <value>`"))
    })
}

/// A usage error — the invocation was wrong, not the project.
fn usage(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::McpArgumentInvalid, message)
}

/// Prepare a server from a loaded project, without binding.
///
/// # Why this is separate from [`run`]
///
/// So the *decisions* — is there a route table, is there a guest, is the address
/// valid — are testable without opening a socket. Binding is the one step that
/// needs a real port, and a test that needs one is a test that flakes on a busy
/// machine (`§O-144`).
///
/// # Errors
///
/// * `QQQ-2002` — the project declares no routes.
/// * `QQQ-6002` — the listen address is invalid.
/// * `QQQ-1002` — a component was found but is not a QQQ application.
pub fn prepare(loaded: &LoadedManifest, opts: &ServeOptions) -> Result<Prepared> {
    let server = &loaded.manifest.server;

    if server.routes.is_empty() {
        return Err(Error::new(
            ErrorCode::ManifestSchemaViolation,
            "this project declares no routes, so there is nothing to serve",
        )
        .with_context("manifest", loaded.path.display().to_string())
        .with_remediation("add at least one `[[server.routes]]` entry to `[server]`"));
    }

    // Parsing the address here rather than at bind time means a typo fails before
    // a socket is opened -- and names the flag the typo was in.
    let addr: ListenAddr = ListenAddr::parse(&opts.listen).map_err(|e| {
        Error::new(
            e.code,
            format!(
                "`--listen {}` is not a usable address: {}",
                opts.listen, e.message
            ),
        )
        .with_remediation("write `--listen <host>:<port>`, for example `--listen 0.0.0.0:8080`")
    })?;

    let routes = routes_from_manifest(server, &loaded.path.display().to_string())?;

    // --- The configuration the manifest asked for, attached ----------------
    //
    // Every field here was previously computed and then dropped: `routes_from_manifest`
    // built the per-route auth modes, the per-tenant limits and the CORS policy, and
    // `ServerConfig::for_addr` produced a config with all of them absent. The server ran,
    // answered, and enforced none of it — including `default_auth`, whose default is
    // `deny`. Attaching them is the whole of `§O-181`.
    let mut config = ServerConfig::for_addr(addr);

    // The authentication policy. Always attached, never optional on this path: a manifest
    // always has an opinion about authority (`default_auth`), so a server started from one
    // always has a policy. An empty route list is already refused above.
    config.auth = Some(Arc::new(routes.auth_policy));

    // The per-tenant request limits, or `None` when `[server.limits]` is absent — which is
    // the manifest saying "no limits", a different statement from "the server forgot to
    // install them".
    config.limits = routes.limits;

    // The cross-origin policy, or `None` when `[server.cors]` is absent.
    config.cors = build_cors(server)?;

    // Metrics, always on for the production command.
    //
    // No manifest switch exists for this, and inventing one would be a configuration
    // surface with a single value. §10.2 asks for the default metric set on a served
    // process, and the recording sites are `Option`-checked, so attaching the registry is
    // what turns `qqq-serve`'s counters from tested-and-unreachable into reachable. The
    // registry allocates nothing until a request is recorded.
    config.metrics = Some(Arc::new(qqq_serve::metrics::HttpMetrics::new()));

    // `--accept-limit`, which was parsed and ignored. `None` means run until signalled.
    config.accept_limit = opts.accept_limit;

    let (dispatch, guest_loaded, pool_capacity) = build_dispatch(loaded, opts)?;

    Ok(Prepared {
        config,
        table: routes.table,
        dispatch,
        routes: server.routes.len(),
        guest_loaded,
        pool_capacity,
    })
}

/// Build the cross-origin policy from the manifest's `[server.cors]`.
///
/// # Why the whole section is converted rather than only `allow_origins`
///
/// A policy with the right origin list and the wrong credentials flag is a policy that
/// behaves differently from the one the author wrote, in a way no test of the origin list
/// can see. Every field the manifest models is carried, and the two that V1 refuses
/// (`*` and a subdomain wildcard) are refused by `Cors::from_manifest` with a message
/// naming the reason — a refusal at startup rather than a policy that silently matches
/// nothing.
///
/// # Errors
///
/// `QQQ-2002` when an origin in `allow_origins` is not a valid origin, or is a wildcard.
fn build_cors(server: &qqq_cap::manifest::Server) -> Result<Option<qqq_serve::cors::Cors>> {
    let Some(declared) = server.cors.as_ref() else {
        return Ok(None);
    };

    let mut cors = qqq_serve::cors::Cors::from_manifest(&declared.allow_origins).map_err(|e| {
        Error::new(
            ErrorCode::ManifestSchemaViolation,
            format!("`[server.cors] allow_origins` is not usable: {e}"),
        )
        .with_remediation(
            "name each origin explicitly, for example \
             `allow_origins = [\"https://app.example.com\"]`",
        )
    })?;

    if declared.allow_credentials {
        cors = cors.with_credentials();
    }
    if !declared.allow_methods.is_empty() {
        cors = cors.with_methods(&declared.allow_methods);
    }
    if !declared.allow_headers.is_empty() {
        cors = cors.with_allowed_headers(&declared.allow_headers);
    }
    if !declared.expose_headers.is_empty() {
        cors = cors.with_exposed_headers(&declared.expose_headers);
    }
    if let Some(seconds) = declared.max_age {
        cors = cors.with_max_age(seconds);
    }

    Ok(Some(cors))
}

/// A server that is ready to bind.
pub struct Prepared {
    /// The server configuration, with the address already parsed.
    pub config: ServerConfig,
    /// The route table built from the manifest.
    pub table: qqq_serve::route::RouteTable,
    /// The dispatcher: the guest if there is one, a clear refusal otherwise.
    pub dispatch: Dispatch,
    /// How many routes the manifest declares.
    pub routes: usize,
    /// Whether a guest component was found.
    pub guest_loaded: bool,
    /// The guest pool's capacity, **as the pool reports it**.
    ///
    /// Read from `GuestApp::capacity()` rather than copied from `opts.workers`. The two
    /// agree today, and they stop agreeing the moment a clamp is added anywhere between
    /// the flag and the pool — at which point a report that echoed the flag would
    /// describe a server nobody is running.
    pub pool_capacity: Option<u64>,
}

/// Build the dispatcher, loading the guest when the project has been built.
///
/// # Why a missing component is a 503 and not a 404
///
/// "Not built yet" and "no such route" are different facts, and a 404 sends a
/// developer looking for a typo in their routes. The 503 says which command fixes
/// it.
///
/// # Errors
///
/// `QQQ-1002` when a component exists but is not a QQQ application, or cannot be
/// read or compiled. Failing here means the server refuses to start rather than
/// answering every request with an error nobody reads.
fn build_dispatch(
    loaded: &LoadedManifest,
    opts: &ServeOptions,
) -> Result<(Dispatch, bool, Option<u64>)> {
    let Some(artifact) = find_artifact(
        project_dir(loaded),
        "release",
        "wasm32-wasip2",
        loaded.name(),
    ) else {
        // No component means no `GuestApp` and therefore **no pool**. `None` rather than
        // `Some(0)`: `0` would read as "a pool with no capacity", which is a different
        // and false statement about a project that simply has not been built.
        return Ok((Dispatch::flat(unbuilt(loaded.name())), false, None));
    };

    let bytes = std::fs::read(&artifact).map_err(|e| {
        Error::new(
            ErrorCode::InvalidComponentArtifact,
            format!("could not read the component `{}`", artifact.display()),
        )
        .with_cause(e.to_string())
        .with_remediation("run `qqqai build` to produce it again")
    })?;

    // No debug_info: the server serves an untrusted artifact, and a source line
    // is not going to be read by anyone. run.rs sets it for exactly the opposite
    // reason -- see its comment there.
    let cfg = EngineConfig::default();
    let wasmtime_cfg = cfg.to_wasmtime_config()?;
    let engine = wasmtime::Engine::new(&wasmtime_cfg).map_err(|e| {
        Error::new(
            ErrorCode::InternalInvariantViolated,
            "could not construct the wasm engine",
        )
        .with_cause(e.to_string())
    })?;
    let grants = GrantSet::from_manifest(&loaded.manifest);
    let limits = LimitSet::from_manifest(&loaded.manifest.limits)?;

    // `--workers` sizes the pool that bounds concurrent guest instances. This is the
    // seam the flag was missing: it was parsed, capped and reported with nothing to act
    // on, and the number now reaches the component that enforces it.
    let mut app = GuestApp::with_capacity(
        engine,
        &bytes,
        grants,
        limits,
        opts.listen.clone(),
        opts.workers,
    )?;

    // `--audit-log` attaches the persisted capability-use record, **loading and verifying any
    // history before a single request is served**. A malformed or chain-broken file refuses the
    // start here rather than being absorbed, because a server that began serving and then
    // discovered its evidence file was unusable would have already produced records it cannot
    // keep.
    if let Some(path) = &opts.audit_log {
        app.attach_audit_file(std::path::Path::new(path))?;
    }

    let app = Arc::new(app);
    // Captured before the `Arc` is moved into the dispatcher closures, so the report can
    // name the capacity that is actually installed.

    // The flat handler stays the default, so a route with no entry behaves as it did.
    let mut dispatch = Dispatch::flat(app.dispatch());

    // The body-aware handler is registered for **every** declared route name.
    //
    // `Dispatch` resolves a handler by the route's `handler` name, and two rows can
    // share a name across methods, so gating on the method would make one of them
    // unreachable depending on table order. One entry per name removes the question, and
    // the guest decides what to do with the body -- `orders::create` reads it while
    // `orders::health` ignores it, so the host does not need to know which routes write.
    //
    // Without this the reference application answered every `POST` as though its body
    // were empty: `serve_connection` drained the bytes for the `body_bytes` metric and
    // then dispatched without them.
    for route in &loaded.manifest.server.routes {
        dispatch = dispatch.with_body(route.handler.clone(), app.dispatch_with_body());
    }

    Ok((dispatch, true, Some(app.capacity())))
}

/// The directory a project lives in — the manifest's parent.
fn project_dir(loaded: &LoadedManifest) -> &Path {
    loaded.path.parent().unwrap_or_else(|| Path::new("."))
}

/// The handler for a project with no built component.
fn unbuilt(name: &str) -> Handler {
    let name = name.to_owned();
    Arc::new(move |_head, _matched| {
        let mut r = Response::text(
            503,
            format!(
                "`{name}` has no built component. Run `qqqai build` first, or use \
                 `qqqai dev`, which builds on demand."
            ),
        );
        r.set_header("X-QQQ-Error", "not_built");
        r
    })
}

/// Serve a project until shutdown.
///
/// # Errors
///
/// As [`prepare`], plus `QQQ-6002` when the address cannot be bound.
pub async fn run(loaded: &LoadedManifest, opts: &ServeOptions) -> Result<ServeOutput> {
    let prepared = prepare(loaded, opts)?;

    // Shared with every connection and triggered by the drain path. Created here
    // rather than inside `serve` so a caller could signal it; in V1 the only
    // signal is process shutdown.
    let shutdown = Shutdown::new();
    // §10.3: redaction is applied by the HOST, using the manifest-declared secret names. The
    // values arrive from the file the operator named, read ONCE here -- §2.5 forbids the runtime
    // reading the environment, and a per-call read is what `host_secrets`' own doc rules out.
    //
    // A failure to read or parse the file REFUSES THE START. The alternative -- serving with an
    // empty redactor -- is a server that believes it redacts and does not, which is worse than one
    // that never claimed to: the operator has no signal, and the secret is in the logs.
    let logger = match &opts.redact_from {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| {
                usage(format!("`--redact-from {path}` could not be read: {e}")).with_remediation(
                    "point it at a readable `NAME=value` file, or remove the flag to redact nothing",
                )
            })?;
            let redactor = qqq_serve::access_log::Redactor::from_dotenv(&text).map_err(|e| {
                usage(format!("`--redact-from {path}` is malformed: {e}"))
                    .with_remediation("each non-comment line must be `NAME=value`")
            })?;
            // The COUNT is reported, never the values: a start-up message naming what is redacted
            // would be the leak the redactor exists to prevent.
            eprintln!(
                "redacting {} distinct secret value(s) from every log line",
                redactor.len()
            );
            Logger::new(Format::Human, Level::Info).with_redactor(redactor)
        }
        None => Logger::new(Format::Human, Level::Info),
    };

    let routes = prepared.routes;
    let guest_loaded = prepared.guest_loaded;

    qqq_serve::serve(
        prepared.config,
        prepared.table,
        prepared.dispatch,
        shutdown,
        logger,
    )
    .await?;

    Ok(ServeOutput {
        listen: opts.listen.clone(),
        routes,
        // The pool's own capacity when a guest is loaded, and the flag otherwise.
        //
        // A project with no built component has no `GuestApp` and therefore no pool, so
        // there is nothing to report but the number the operator asked for. That case is
        // already visible in the output as `guest: not built`, and reporting `0` would be
        // worse: it would read as "the pool has no capacity" rather than "there is no pool".
        workers: prepared
            .pool_capacity
            .and_then(|c| u32::try_from(c).ok())
            .unwrap_or(opts.workers),
        tls: opts.tls,
        guest_loaded,
    })
}

/// Serve a project until shutdown, from a synchronous caller.
///
/// # Why this exists as well as [`run`]
///
/// `qqqai serve`'s `main` is synchronous: it parses arguments, loads a manifest and
/// returns an `ExitCode`. The server is asynchronous. This function is the bridge,
/// and it exists so that `qqq-run` **does not depend on the async runtime**.
///
/// `qqq-io`'s documentation states that it is "the only crate in the workspace that
/// depends on the async runtime". A direct `tokio` edge here would make that
/// sentence false and give the workspace two answers to "which runtime is this
/// program built on". The bridge lives in `qqq-io` for exactly that reason, and this
/// function is a one-line call through it.
///
/// # Errors
///
/// As [`run`], plus `QQQ-6004` when the runtime cannot be constructed.
pub fn run_blocking(loaded: &LoadedManifest, opts: &ServeOptions) -> Result<ServeOutput> {
    qqq_io::block_on(run(loaded, opts))?
}

impl crate::output::CommandOutput for ServeOutput {
    fn command(&self) -> crate::output::CommandName {
        crate::output::CommandName::Serve
    }

    /// The one-line summary, in `dev`'s register.
    ///
    /// # Why the guest's state is in the summary
    ///
    /// "listening on 127.0.0.1:3000" alone is the summary of a server that will
    /// answer 503 to every request, which is a fact an operator needs in the first
    /// line rather than in the JSON. `dev` puts its reload count there for the same
    /// reason.
    ///
    /// # Why the number is described as a capacity rather than as "workers"
    ///
    /// This is the line an operator reads, and it said `4 worker(s)` while the flag had no
    /// effect at all — a true statement about a number and a false impression about what it
    /// did. It now names the quantity the pool enforces, which is the fact worth having: the
    /// reader learns how many requests may hold a guest **at once**, and that is what they
    /// were reaching for when they passed the flag.
    fn summary(&self) -> String {
        format!(
            "{}: {} route(s), {} concurrent instance(s), guest {}",
            self.listen,
            self.routes,
            self.workers,
            if self.guest_loaded {
                "loaded"
            } else {
                "not built (run `qqqai build`)"
            }
        )
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Render a serve result for a human.
#[must_use]
pub fn render(out: &ServeOutput) -> String {
    // `write!` into the `String` rather than `push_str(&format!(..))`: the second
    // allocates a temporary for every line, and clippy is right that it is noise.
    use std::fmt::Write as _;

    let mut s = format!("qqqai serve\n  listening on {}\n", out.listen);
    let _ = writeln!(s, "  {} route(s)", out.routes);
    let _ = writeln!(
        s,
        "  {} concurrent instance(s) — the --workers pool capacity",
        out.workers
    );
    let _ = writeln!(
        s,
        "  guest: {}",
        if out.guest_loaded {
            "loaded"
        } else {
            "not built (run `qqqai build`)"
        }
    );
    if out.tls {
        s.push_str("  TLS: on\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_defaults_are_a_loopback_address_and_one_worker() {
        let o = options(&[]).expect("no flags must parse");
        assert_eq!(o.listen, "127.0.0.1:3000");
        assert_eq!(o.workers, 1);
        assert!(!o.tls);
        assert_eq!(o.config, None);
        assert_eq!(o.accept_limit, None);
    }

    #[test]
    fn every_supported_flag_parses() {
        let o = options(&args(&[
            "--listen",
            "0.0.0.0:8080",
            "--workers",
            "1",
            "--config",
            "prod.toml",
            "--accept-limit",
            "3",
        ]))
        .expect("the supported flags must parse");
        assert_eq!(o.listen, "0.0.0.0:8080");
        assert_eq!(o.workers, 1);
        assert_eq!(o.config.as_deref(), Some("prod.toml"));
        assert_eq!(o.accept_limit, Some(3));
    }

    #[test]
    fn tls_is_refused_rather_than_reported_as_on() {
        // The defect this replaces: `--tls` parsed, `ServeOutput::tls` was true, the command
        // printed `TLS: on`, and the listener served cleartext. A flag that reports a
        // security feature it does not provide is worse than a flag that is absent, so the
        // refusal has to name what is missing rather than say "unsupported".
        let err = options(&args(&["--tls"])).expect_err("--tls must be refused");
        assert!(
            err.message.contains("not implemented"),
            "the message must say the flag is not implemented: {}",
            err.message
        );
        assert!(
            err.message.contains("cleartext"),
            "the message must say what would actually happen: {}",
            err.message
        );
        let remediation = err.remediation.as_deref().unwrap_or_default();
        assert!(
            remediation.contains("reverse proxy") || remediation.contains("terminate"),
            "the remediation must name a way to get TLS today: {remediation}"
        );
    }

    #[test]
    fn more_than_one_worker_is_accepted_now_that_a_pool_sizes_it() {
        // This test asserted the opposite until the instance pool landed, and the refusal it
        // checked said what would end it: *"when a pool lands, the check is deleted and the
        // number acquires its meaning."* `qqq_host::pool::Pool` is the pool,
        // `GuestApp::with_capacity` installs it, and `handle_request` acquires before
        // instantiating.
        //
        // The assertion is on the **parsed value**, because parsing is all this function does;
        // that the number reaches the pool is proved by `GuestApp`'s own tests, which construct
        // a real app. Keeping this test here rather than deleting it is the point: the flag is
        // still validated, capped and refused at zero, and those are three separate behaviours
        // that a deletion would have silently un-tested.
        let o = options(&args(&["--workers", "4"])).expect("--workers 4 now sizes a pool");
        assert_eq!(o.workers, 4);
    }

    #[test]
    fn one_worker_is_accepted_because_it_is_what_runs() {
        let o = options(&args(&["--workers", "1"])).expect("one worker is the truth");
        assert_eq!(o.workers, 1);
    }

    #[test]
    fn an_unknown_flag_is_refused_rather_than_ignored() {
        // A server that starts with a flag silently ignored is worse than one that
        // refuses: the operator's configuration and the running system disagree,
        // and nothing says so.
        let err = options(&args(&["--prot", "8080"])).expect_err("a typo must be refused");
        assert!(
            err.message.contains("--prot"),
            "the message must name the flag: {}",
            err.message
        );
        assert!(
            err.remediation
                .as_deref()
                .is_some_and(|r| r.contains("--listen")),
            "the fix must list what is accepted: {err:?}"
        );
    }

    #[test]
    fn a_missing_value_is_refused_by_name() {
        let err = options(&args(&["--listen"])).expect_err("a flag with no value must be refused");
        assert!(
            err.message.contains("--listen"),
            "the message must name the flag: {}",
            err.message
        );
    }

    #[test]
    fn zero_workers_is_refused_rather_than_defaulted() {
        let err = options(&args(&["--workers", "0"])).expect_err("zero must be refused");
        assert!(
            err.message.contains("would serve nothing"),
            "the message must say why zero is wrong: {}",
            err.message
        );
    }

    #[test]
    fn an_excessive_worker_count_is_refused_rather_than_clamped() {
        // A silent clamp means the operator's configuration and the running system
        // disagree — the failure the refusal exists to prevent.
        let err = options(&args(&["--workers", "1000"])).expect_err("must be refused");
        assert!(
            err.message.contains("exceeds the maximum"),
            "the message must say it is over the limit: {}",
            err.message
        );
        assert!(
            err.remediation
                .as_deref()
                .is_some_and(|r| r.contains("instance pool")),
            "the fix must say what actually bounds concurrency: {err:?}"
        );
    }

    #[test]
    fn a_non_numeric_worker_count_is_refused() {
        let err = options(&args(&["--workers", "many"])).expect_err("must be refused");
        assert!(err.message.contains("not a number"), "got: {}", err.message);
    }

    #[test]
    fn a_non_numeric_accept_limit_is_refused() {
        let err = options(&args(&["--accept-limit", "lots"])).expect_err("must be refused");
        assert!(err.message.contains("not a number"), "got: {}", err.message);
    }

    #[test]
    fn the_rendered_report_names_the_worker_meaning() {
        // The flag's honest meaning is part of the output, not only the docs: a
        // flag that looks like it does something and does nothing is the defect
        // this project keeps recording.
        let out = ServeOutput {
            listen: "127.0.0.1:3000".to_owned(),
            routes: 3,
            workers: 4,
            tls: false,
            guest_loaded: true,
        };
        let r = render(&out);
        assert!(r.contains("127.0.0.1:3000"), "{r}");
        assert!(r.contains("3 route(s)"), "{r}");
        assert!(
            r.contains("the --workers pool capacity"),
            "the worker count must say what it bounds: {r}"
        );
        assert!(r.contains("guest: loaded"), "{r}");
        assert!(!r.contains("TLS"), "TLS must not appear when off: {r}");
    }

    #[test]
    fn an_unbuilt_guest_is_reported_rather_than_implied() {
        let out = ServeOutput {
            listen: "127.0.0.1:3000".to_owned(),
            routes: 1,
            workers: 1,
            tls: true,
            guest_loaded: false,
        };
        let r = render(&out);
        assert!(r.contains("not built"), "{r}");
        assert!(r.contains("qqqai build"), "the fix must be named: {r}");
        assert!(r.contains("TLS: on"), "{r}");
    }

    /// The **summary** line describes the number as a capacity, not as "workers".
    ///
    /// # Why this test exists separately from the render test above
    ///
    /// They are two different renderers, and only one reaches an operator's terminal. Measured:
    /// `qqqai serve` prints the one-line `summary()` — `127.0.0.1:58795: 1 route(s), 4
    /// concurrent instance(s), guest loaded` — while `render()`'s multi-line block is not what
    /// the command emits. The first version of this change edited `render` and the integration
    /// test searched for that wording, so both the code change and its test passed while the line
    /// a user reads was untouched.
    ///
    /// The assertion is on the phrase rather than the number, because the number is already
    /// covered by the integration test against a running server; what this pins is that the
    /// summary names the quantity the pool bounds.
    #[test]
    fn the_summary_names_the_capacity_rather_than_workers() {
        let out = ServeOutput {
            listen: "127.0.0.1:3000".to_owned(),
            routes: 1,
            workers: 4,
            tls: false,
            guest_loaded: true,
        };
        let line = crate::output::CommandOutput::summary(&out);
        assert!(
            line.contains("concurrent instance(s)"),
            "the summary must name what the number bounds: {line}"
        );
        assert!(
            line.contains('4'),
            "the summary must carry the capacity: {line}"
        );
        // The vague term that let the flag go unnoticed for as long as it did.
        assert!(
            !line.contains("worker(s)"),
            "`worker(s)` describes nothing an operator can act on: {line}"
        );
    }
}
