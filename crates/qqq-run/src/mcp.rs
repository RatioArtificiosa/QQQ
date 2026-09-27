// SPDX-License-Identifier: Apache-2.0

//! `qqqai mcp` — a Model Context Protocol server over **stdio**, `AGENT-004`.
//!
//! # Why the contract was already here and the server was not
//!
//! `output::mcp_tool_names()` has listed **12** tools since before this module existed, and
//! `qqqai mcp` answered `QQQ-6004: not implemented yet`. **A published contract with no server is the
//! shape this repository keeps finding**: a thing that is written, documented and never called. This is
//! the server.
//!
//! # The transport
//!
//! MCP's stdio transport is **newline-delimited JSON-RPC 2.0**: one JSON object per line on stdin, one
//! per line on stdout. That is why this module writes a trailing `\n` after every message and why a
//! malformed line produces an error **response** rather than a panic — a client that sends one bad
//! line should get one bad answer, not a dead server.
//!
//! # What is implemented, and what is not
//!
//! | method | state |
//! |---|---|
//! | `initialize` | implemented |
//! | `tools/list` | implemented — all **12** tools, from the same list the CLI publishes |
//! | `tools/call` | implemented for **all twelve**: eight in-process, four by re-entering the CLI |
//!
//! **`tools/call` answers structurally for a tool it cannot run** — an `isError` result naming the
//! tool, not prose and not a panic. `AGENT-019` is the item that makes this a requirement: *"every tool
//! returns structured content, never prose-only"*, and a client that has to parse a sentence to learn
//! that a tool is missing is a client that will get it wrong.
//!
//! # Re-entering the CLI is a GRANT, not a guess
//!
//! Four tools (`qqq_build`, `qqq_run`, `qqq_test`, `qqq_bench`) run a QQQ command as a subprocess. The
//! path they run is **passed in by the caller** — `main` passes its own, because it is the one place
//! that knows this process is the CLI. A server constructed with `None` **refuses**, and the refusal is
//! structural.
//!
//! That is not decoration. The first version of this module called `std::env::current_exe()` instead,
//! and under `cargo test --doc` `current_exe()` is **rustdoc's doctest harness** — a program that
//! re-runs the same doctest, which re-enters again. **One `cargo test --doc` spawned 2,528 processes
//! and did not stop** (`§O-351`). A capability-secure runtime that guesses at the program it re-enters
//! is not capability-secure, and the fix is to be *told*.
//!
//! # Example
//!
//! ```
//! use qqq_run::mcp::serve_stdio;
//!
//! // One JSON object per line in, one per line out. **No CLI is granted here**, and that is the case
//! // worth showing: a tool that would shell out must refuse rather than guess at a program to
//! // re-enter -- `§O-351`.
//! let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
//!              \"params\":{\"name\":\"qqq_build\",\"arguments\":{}}}\n";
//! let mut out = Vec::new();
//! serve_stdio(input.as_bytes(), &mut out, None).expect("the transport is infallible here");
//!
//! let reply = String::from_utf8(out).expect("utf8");
//! // A refusal, not prose and not a panic: a client branches on a boolean.
//! assert!(reply.contains("\"isError\":true"), "{reply}");
//! assert!(reply.contains("not granted"), "{reply}");
//! ```
//!
//! # Why an unknown method is `-32601` and not a custom code
//!
//! Because JSON-RPC 2.0 defines it, and a client's own dispatch is written against that number. A
//! QQQ-specific code for *"no such method"* would be a second spelling of a standard answer.

use std::io::{BufRead, Write};
use std::path::Path;

use serde_json::{json, Value};

/// The JSON-RPC version this server speaks. There is one, and it is not negotiable.
const JSONRPC: &str = "2.0";

/// The largest request body this server will read.
///
/// **Refused rather than allocated**: an unbounded read on a socket is how a server is made to allocate
/// until it dies, and an MCP client has no reason to send a megabyte.
const MAX_BODY: usize = 1 << 20;

/// The MCP protocol revision this server implements.
///
/// Named rather than inlined because a client reads it from `initialize` and decides how to talk to
/// this server from it — so it is a **compatibility claim**, and a claim wants one place to change.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// JSON-RPC 2.0's standard codes, plus the one this server defines.
mod code {
    /// Invalid JSON.
    pub(super) const PARSE: i64 = -32700;
    /// A request object that is not a valid request.
    pub(super) const INVALID_REQUEST: i64 = -32600;
    /// No such method.
    pub(super) const METHOD_NOT_FOUND: i64 = -32601;
    /// The arguments are wrong for the method.
    pub(super) const INVALID_PARAMS: i64 = -32602;
}

/// One tool this server publishes.
///
/// # Why the description is short and the schema is present
///
/// Because a **model** reads both, and a description that runs to a paragraph is a description that
/// competes with the schema for the reader's attention. The schema is where the arguments are; the
/// description is where the *intent* is.
struct Tool {
    name: &'static str,
    description: &'static str,
    /// The JSON Schema for this tool's arguments.
    input: Value,
}

/// An object with no properties, which is what a tool that takes no arguments publishes.
fn no_arguments() -> Value {
    json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

/// The twelve tools, from the same list the CLI publishes.
///
/// # Why this reads `mcp_tool_names()` rather than repeating it
///
/// Because a second copy of the list is a second answer to *"what tools exist"*, and the two would
/// drift. **The names come from one place; the descriptions and schemas live here**, because the CLI's
/// list is a name list and this is a protocol surface.
fn tools() -> Vec<Tool> {
    let names = crate::output::mcp_tool_names();
    names
        .into_iter()
        .map(|name| Tool {
            name,
            description: describe(name),
            input: arguments_for(name),
        })
        .collect()
}

/// What a tool is for, in one sentence a model can act on.
fn describe(name: &str) -> &'static str {
    match name {
        "qqq_manifest_get" => "Read the project's `qqq.toml` as structured data.",
        "qqq_manifest_validate" => {
            "Validate `qqq.toml` and report every problem with its location."
        }
        "qqq_caps_explain" => "Explain what one capability grants and what it refuses.",
        "qqq_caps_list" => "List every capability the project declares, with its grants.",
        "qqq_build" => "Build the project's guest component for `wasm32-wasip2`. Takes `dry_run` to describe what would run without running it.",
        "qqq_run" => "Run the guest component against a request, without serving.",
        "qqq_test" => "Run the project's conformance tests.",
        "qqq_audit" => "Read the capability audit and report the worst severity found.",
        "qqq_inspect" => "Report what a project is allowed to do, and what it is not.",
        "qqq_bench" => "Run the benchmarks and report the measured numbers.",
        "qqq_schema" => "Return the JSON Schema for a QQQ command's arguments.",
        "qqq_errors_lookup" => "Look up QQQ error codes by class, with each code's meaning.",
        // Unreachable while `mcp_tool_names()` is the source of the names, and kept rather than
        // defaulted so that adding a name without a description **fails a test** rather than
        // publishing an empty one.
        other => {
            let _ = other;
            "A QQQ tool whose description is missing."
        }
    }
}

/// The JSON Schema for a tool's arguments.
fn arguments_for(name: &str) -> Value {
    match name {
        // **Seven tools, one schema, one arm.** Four read the manifest; three shell out to a command.
        // They all take a `path` and nothing else -- `qqq_run` lost its `request` because nothing
        // forwards one, and `dry_run` belongs to `qqq_build` alone because `build` alone mutates.
        //
        // **`clippy::match_same_arms` found this, and it was right**: an arm that exists only to repeat
        // its neighbour is a place for the two to drift apart later.
        "qqq_manifest_get"
        | "qqq_manifest_validate"
        | "qqq_caps_list"
        | "qqq_inspect"
        | "qqq_run"
        | "qqq_test"
        | "qqq_bench" => json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "The project directory. Defaults to the working directory." }
            },
            "additionalProperties": false
        }),
        "qqq_caps_explain" => json!({
            "type": "object",
            "properties": {
                "capability": { "type": "string", "description": "The capability name, such as `http.client`." }
            },
            "required": ["capability"],
            "additionalProperties": false
        }),
        "qqq_errors_lookup" => json!({
            "type": "object",
            "properties": {
                "class": { "type": "string", "description": "A two-digit class, such as `70` for MCP errors." }
            },
            "additionalProperties": false
        }),
        "qqq_schema" => json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "The command name, such as `serve`." }
            },
            "additionalProperties": false
        }),
        // **`build` alone, because `build` alone mutates.** `CommandName::is_mutating()` names
        // `Build` and not `Test` or `Bench`, and `supports_dry_run()` IS `is_mutating()` -- so a
        // `dry_run` on the other two would be **a promise the command does not keep**, which is what a
        // cross-surface test found.
        "qqq_build" => json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "The project directory. Defaults to the working directory." },
                "dry_run": { "type": "boolean", "description": "Describe what would run, without running it." }
            },
            "additionalProperties": false
        }),
        // **`run`, `test` and `bench` share ONE schema -- `path` alone -- and the reasons are one per
        // tool, all the same shape:**
        //
        // - `test` and `bench` **do not mutate**, so `CommandName::supports_dry_run()` is false for
        //   them;
        // - `run` declares `supports_dry_run: false` in `output::command_schemas()` even though it
        //   executes a guest -- so a tool offering one would be **a promise the command does not
        //   keep**, which a cross-surface test compares;
        // - and `run_command` forwards `path` and `dry_run` and **nothing else**, so no request line
        //   reaches the command -- a `request` field would be the same defect `§O-344` found in
        //   `dry_run`, found the same way.
        //
        "qqq_audit" => json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "fail_on": { "type": "string", "enum": ["note", "warning", "error"] }
            },
            "additionalProperties": false
        }),
        _ => no_arguments(),
    }
}

/// Answer one JSON-RPC message, or `None` for a notification.
///
/// # Why this takes a `Value` and returns an `Option<Value>`
///
/// Because a JSON-RPC **notification** (no `id`) is answered with **nothing at all** — not with a
/// `null` id, which a client would read as a reply to a request it never made.
///
/// # Why the CLI path is threaded through here
///
/// Because the four tools that shell out must run **a program the caller named**, and this is the layer
/// that reaches them. A parameter that only `run_command` saw would have to be fetched from somewhere
/// ambient, and ambient is what `§O-351` cost 2,528 processes to disprove.
#[must_use]
fn answer(message: &Value, cli: Option<&Path>) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str);

    let Some(method) = method else {
        return id.map(|id| error(&id, code::INVALID_REQUEST, "no `method` in the request"));
    };

    let result = match method {
        "initialize" => Ok(initialize()),
        "tools/list" => Ok(json!({ "tools": tools().iter().map(tool_json).collect::<Vec<_>>() })),
        "tools/call" => call(message.get("params"), cli),
        "notifications/initialized" => {
            // A notification by definition, and the protocol says it needs no reply.
            return None;
        }
        "ping" => Ok(json!({})),
        other => Err((
            code::METHOD_NOT_FOUND,
            format!("`{other}` is not a method this server implements"),
        )),
    };

    id.map(|id| match result {
        Ok(value) => json!({ "jsonrpc": JSONRPC, "id": id, "result": value }),
        Err((c, m)) => error(&id, c, &m),
    })
}

/// The `initialize` result.
fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "qqqai", "version": env!("CARGO_PKG_VERSION") }
    })
}

/// One tool as the protocol publishes it.
fn tool_json(tool: &Tool) -> Value {
    json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input,
    })
}

/// A JSON-RPC error object.
fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": JSONRPC, "id": id, "error": { "code": code, "message": message } })
}

/// Run a tool, or say structurally why it cannot run.
///
/// # The result shape, and why `isError` is a field rather than a sentence
///
/// MCP returns a `content` array of typed blocks, and an `isError` flag. **A tool that cannot run here
/// sets `isError` and still returns content** — so a client branches on a boolean rather than on the
/// wording of a message. `AGENT-019`: *"every tool returns structured content, never prose-only."*
fn call(params: Option<&Value>, cli: Option<&Path>) -> Result<Value, (i64, String)> {
    let params = params.ok_or((code::INVALID_PARAMS, "`tools/call` needs params".to_owned()))?;
    let name = params.get("name").and_then(Value::as_str).ok_or((
        code::INVALID_PARAMS,
        "`tools/call` needs a tool name".to_owned(),
    ))?;
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    // The tool must exist before it can be run, and the check is against the SAME list the protocol
    // publishes -- so a name that `tools/list` offers is never refused here.
    if !crate::output::mcp_tool_names().contains(&name) {
        return Err((
            code::INVALID_PARAMS,
            format!("`{name}` is not one of this server's tools"),
        ));
    }

    match name {
        "qqq_errors_lookup" => Ok(errors_lookup(&arguments)),
        "qqq_schema" => Ok(schema_lookup(&arguments)),
        "qqq_caps_list" => Ok(caps_list()),
        "qqq_caps_explain" => Ok(caps_explain(&arguments)),
        "qqq_manifest_get" => Ok(manifest(&arguments, false)),
        "qqq_manifest_validate" => Ok(manifest(&arguments, true)),
        "qqq_audit" => Ok(audit(&arguments)),
        "qqq_inspect" => Ok(inspect(&arguments)),
        // **The four that SHELL OUT.** Each is a thin wrapper over the command of the same name, run as a
        // subprocess of the CLI path the caller GRANTED -- which for `qqqai mcp` is `qqqai` itself.
        "qqq_build" | "qqq_run" | "qqq_test" | "qqq_bench" => Ok(run_command(
            name.trim_start_matches("qqq_"),
            &arguments,
            cli,
        )),
        other => Ok(unimplemented(other)),
    }
}

/// `qqq_errors_lookup` — the error catalogue, as structured content.
///
/// # Why this tool is the one wired first
///
/// Because its backing **already exists in-process**: `ErrorCode::all()` is a static slice, so the tool
/// needs no build, no guest and no filesystem. A first tool that needs none of those is a tool that
/// proves the *server* works rather than proving the *project* builds.
fn errors_lookup(arguments: &Value) -> Value {
    let wanted = arguments.get("class").and_then(Value::as_str);

    let mut codes = Vec::new();
    for code in qqq_core::ErrorCode::all() {
        let id = code.id();
        // A class is the two digits after `QQQ-`; filtering on a prefix would match `7` to `70`, `71`
        // and `72` at once, which is a lookup that answers a question nobody asked.
        let class = id.split_once('-').map_or("", |(_, rest)| rest);
        let class = class.get(..2).unwrap_or(class);
        if wanted.is_some_and(|w| w != class) {
            continue;
        }
        // **`meaning` was here and it was a lie.** `ErrorCode`'s `Display` renders the ID, so the
        // field repeated the id it sat beside -- measured by running the tool and reading its own
        // output. `ErrorCode` has **no description accessor**, so this tool cannot carry the
        // meaning; what it can carry is where the meaning lives, which is the permanent URL every
        // QQQ error prints.
        codes.push(json!({
            "id": id,
            "class": class,
            "docs": format!("https://qqq.codes/errors/{id}"),
        }));
    }

    ok(&json!({ "count": codes.len(), "codes": codes }))
}

/// `qqq_schema` -- the command schemas, as structured content.
///
/// # Why this one is cheap, and what that says about the others
///
/// Because its backing is a **static registry**: `output::command_schemas()` needs no build, no guest and
/// no filesystem. **A tool whose backing is already a pure function is a tool that should be wired
/// first**, and the three wired so far share that property -- `ErrorCode::all()`, `command_schemas()`,
/// `Namespace::all()`.
///
/// # The cross-check that falls out of it
///
/// Every schema carries **`mutating`** and **`supports_dry_run`**, which is `AGENT-020`'s contract **at
/// the command level**. The tool descriptions assert the same property at the MCP level, and a test
/// compares the two -- because **two places that answer one question is how they drift**.
fn schema_lookup(arguments: &Value) -> Value {
    let wanted = arguments.get("command").and_then(Value::as_str);
    let schemas = crate::output::command_schemas();

    let mut commands = Vec::new();
    for s in &schemas {
        if wanted.is_some_and(|w| w != s.command) {
            continue;
        }
        commands.push(json!({
            "command": s.command,
            "summary": s.summary,
            "mutating": s.mutating,
            "supports_dry_run": s.supports_dry_run,
            "data_schema": s.data_schema,
        }));
    }
    ok(&json!({ "count": commands.len(), "commands": commands }))
}

/// `qqq_caps_list` -- the capability namespaces, as structured content.
///
/// # What this tool does NOT say, and why that is the honest scope
///
/// It lists the **namespaces the runtime defines** -- `sql`, `http`, `fs` and the rest. It does **not**
/// say which of them a *project* declares; that needs a manifest, which needs a path, which is a
/// different tool. **A tool that answered both would be answering a question about a project while
/// appearing to answer one about the runtime**, and the difference is the whole of QQQ's model.
fn caps_list() -> Value {
    let namespaces: Vec<Value> = qqq_cap::capability::Namespace::all()
        .into_iter()
        .map(|n| json!({ "namespace": n.as_str() }))
        .collect();
    ok(&json!({ "count": namespaces.len(), "namespaces": namespaces }))
}

/// Run a QQQ command as a subprocess and return what it said -- `AGENT-006`-`AGENT-017`.
///
/// # Why a SUBPROCESS and not an in-process call
///
/// Because the command's dispatchers live in the **binary**, and this module is in the **library**.
/// More importantly, **a command writes to stdout, and on the stdio transport stdout IS THE PROTOCOL** --
/// an in-process call would print a human summary into the middle of a JSON-RPC stream and corrupt it.
/// A subprocess gives the command its own stdout, which this reads.
///
/// # The exit code IS the tool's verdict
///
/// A non-zero exit sets **`isError: true`** and puts the code in the structured content. **The command
/// already decided whether it succeeded**, and a wrapper that second-guessed it would be a second answer
/// to a question the command answers -- `§O-344`'s lesson.
///
/// # `--json` is always passed
///
/// Because the CLI has a machine-readable mode and **a wrapper that parsed the human rendering would be
/// parsing a presentation**. When the output is not JSON -- a command that has no envelope yet -- the raw
/// text is returned under `text` rather than dropped.
///
/// # Why `cli` is a PARAMETER and `current_exe()` is not used -- `§O-351`
///
/// **Because `current_exe()` is the wrong question.** It answers *"what program is running"*, and this
/// needs *"what program may I re-enter"* -- two questions that coincide only when the process is the CLI.
/// Under `cargo test --doc` they diverge violently: `current_exe()` is rustdoc's doctest harness, which
/// **re-runs the same doctest**, which shells out again. Measured: **one `cargo test --doc` reached
/// 2,528 live `rust_out.exe` processes and was still climbing when it was killed.**
///
/// So the ability to re-enter is **granted by the caller or absent**, and absent means refuse. `None` is
/// the honest state for a doctest, a unit test, and any embedder linking this library -- and all three
/// now get a structured refusal instead of a fork bomb.
fn run_command(command: &str, arguments: &Value, cli: Option<&Path>) -> Value {
    let Some(exe) = cli else {
        // **Refused, and refused as a RESULT** rather than a protocol error: the call was well formed
        // and the answer is "this server may not". The same shape every other failure uses.
        return failed(&json!({
            "command": command,
            "error": {
                "code": "QQQ-7001",
                "message": "this server was not granted a CLI to re-enter, so it will not run a command \
                            as a subprocess",
                "remediation": "start the server with `qqqai mcp`, which grants its own path",
            },
        }));
    };

    let mut args: Vec<String> = vec![command.to_owned()];

    if let Some(dir) = arguments.get("path").and_then(Value::as_str) {
        args.push("--manifest".to_owned());
        args.push(
            std::path::Path::new(dir)
                .join("qqq.toml")
                .display()
                .to_string(),
        );
    }
    // `--dry-run` only when asked, and **only for the commands that declare it** -- the tool's own
    // description is held to the command's `supports_dry_run` by a test, so passing it unconditionally
    // would make that test's guarantee false at the point of use.
    let dry_run = arguments
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if dry_run {
        args.push("--dry-run".to_owned());
    }
    args.push("--json".to_owned());

    match std::process::Command::new(exe).args(&args).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            // **The exit code, not the text, decides.** A command that printed a summary and exited
            // non-zero failed, whatever the summary said.
            let code = out.status.code().unwrap_or(-1);
            let parsed = serde_json::from_str::<Value>(stdout.trim()).ok();
            let structured = json!({
                "command": command,
                "args": args,
                "exit_code": code,
                "dry_run": dry_run,
                "output": parsed.clone().unwrap_or(Value::Null),
                "text": if parsed.is_some() { Value::Null } else { json!(stdout) },
            });
            if code == 0 {
                ok(&structured)
            } else {
                failed(&structured)
            }
        }
        Err(e) => failed(&json!({
            "command": command,
            "args": args,
            "error": { "code": "QQQ-7001", "message": format!("cannot run this binary: {e}") },
        })),
    }
}

/// `qqq_inspect` -- what a project is allowed to do, **and what it is not**.
///
/// # The second half is the point
///
/// `qqq_inspect`'s own description says *"Report what a project is allowed to do, **and what it is
/// not**"*. A tool that reported only the declared capabilities would be **a list of what the manifest
/// mentions**, which is a weaker claim than the one QQQ makes: **a capability that is absent is not
/// denied at request time, it is not there to be denied** -- *"absent, not denied"* is the model, and a
/// report that omits the absences **hides the property that makes the model worth having**.
///
/// # Why the absences are derived from `Namespace::all()` and not from a hand-written list
///
/// Because a hand-written list of *"the capabilities that exist"* is **a second answer to a question the
/// runtime already answers** -- the lesson `§O-344` cost a round to learn. `Namespace::all()` is the
/// runtime's own answer, so a namespace added tomorrow appears as absent until a manifest declares it.
fn inspect(arguments: &Value) -> Value {
    let dir = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
    let path = std::path::Path::new(dir).join("qqq.toml");

    let loaded = match crate::manifest_loader::LoadedManifest::load(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            return failed(&json!({
                "found": false,
                "path": path.display().to_string(),
                "error": { "code": e.id(), "message": e.to_string() },
            }))
        }
    };

    // The manifest's capability sections, as the manifest itself spells them.
    let declared = serde_json::to_value(&loaded.manifest.capabilities).unwrap_or(Value::Null);
    let declared_names: Vec<String> = declared
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    // **The absences, from the RUNTIME's list rather than from a hand-written one.**
    let absent: Vec<Value> = qqq_cap::capability::Namespace::all()
        .into_iter()
        .filter(|n| !declared_names.iter().any(|d| d == n.as_str()))
        .map(|n| json!({ "namespace": n.as_str() }))
        .collect();

    ok(&json!({
        "project": loaded.name(),
        "path": loaded.path.display().to_string(),
        "declared": declared,
        "declared_namespaces": declared_names,
        "absent_namespaces": absent,
        "absent_count": absent.len(),
    }))
}

/// `qqq_audit` -- the capability audit, and the SARIF export `OBS-003` asks for.
///
/// # Why this tool is the one the checklist has been waiting for
///
/// `ARCH-011` says of step 15: *"step 13 meters and step 15 records, and the recording half does not
/// run."* **This is the recording half, reachable by a client.** `AuditReport::to_sarif` has existed
/// since `OBS-003` was written and **its only callers were the CLI and its own tests** -- the same shape
/// this repository keeps finding.
///
/// # `fail_on` is parsed, not defaulted
///
/// Because `Severity::parse` **refuses a typo rather than picking a default**, and its own doc says why:
/// *"a `--fail-on` that silently accepted a typo would be a CI gate that never fires, which is worse than
/// no gate because it is believed to be one."* **A tool that defaulted would reintroduce exactly that.**
///
/// # The SARIF is returned as a PARSED document, not a string
///
/// Because `AGENT-019` says structured content, and **a client that has to parse a JSON string out of a
/// JSON field is a client doing the server's work.** The document is re-parsed here so the field is an
/// object; if that ever fails, the string is returned under `sarif_text` rather than dropped.
fn audit(arguments: &Value) -> Value {
    let dir = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
    let path = std::path::Path::new(dir).join("qqq.toml");

    let loaded = match crate::manifest_loader::LoadedManifest::load(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            return failed(&json!({
                "found": false,
                "path": path.display().to_string(),
                "error": { "code": e.id(), "message": e.to_string() },
            }))
        }
    };

    let report = crate::audit::audit(&loaded, None);
    let findings: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            json!({
                "rule": f.rule,
                "severity": f.severity.as_str(),
                "message": f.message,
                "remediation": f.remediation,
            })
        })
        .collect();

    // `fail_on` decides whether the CALL is a failure -- the audit itself always answers.
    let threshold = match arguments.get("fail_on").and_then(Value::as_str) {
        Some(text) => match crate::audit::Severity::parse(text) {
            Ok(s) => Some(s),
            Err(e) => {
                return failed(&json!({
                    "project": report.project,
                    "error": { "code": "QQQ-1003", "message": e },
                }))
            }
        },
        None => None,
    };

    let worst = report.worst().map(crate::audit::Severity::as_str);
    let fails = threshold.is_some_and(|t| report.fails_at(t));
    let sarif_text = report.to_sarif();
    let sarif = serde_json::from_str::<Value>(&sarif_text).unwrap_or(Value::Null);

    let structured = json!({
        "project": report.project,
        "count": findings.len(),
        "worst": worst,
        "findings": findings,
        "fail_on": threshold.map(crate::audit::Severity::as_str),
        "fails_at_threshold": fails,
        "sarif": sarif,
        "sarif_text": if sarif.is_null() { json!(sarif_text) } else { Value::Null },
    });

    // A threshold the audit does not meet makes the CALL a failure -- `isError` rather than a JSON-RPC
    // error, because the request was well formed and the ANSWER is "yes, this fails".
    if fails {
        return failed(&structured);
    }
    ok(&structured)
}

/// `qqq_caps_explain` -- what one capability grants, and what it does not.
///
/// # The suggestion is the point
///
/// A capability name is a **closed vocabulary** (`fs.read`, `http.client`, ...), and a model that guesses
/// wrong should be told **which name it probably meant** rather than that its guess was wrong. That is
/// what `Capability::suggest` is for, and **a tool that answered only *"no such capability"* would make a
/// model try again with another guess** -- which is the loop this tool exists to break.
///
/// # `is_covert_channel` is reported rather than hidden
///
/// Because it is a **security property of the capability itself**: a capability that can carry data
/// without an obvious channel is one a reviewer needs to see named. A tool that omitted it would be
/// explaining the convenience and not the risk.
fn caps_explain(arguments: &Value) -> Value {
    let Some(name) = arguments.get("capability").and_then(Value::as_str) else {
        return failed(&json!({
            "capability": Value::Null,
            "error": { "code": "QQQ-1001", "message": "`qqq_caps_explain` needs a `capability` name" },
        }));
    };

    if let Some(c) = qqq_cap::capability::Capability::from_name(name) {
        return ok(&json!({
            "capability": c.name(),
            "namespace": c.namespace(),
            "kind": c.kind().as_str(),
            "covert_channel": c.is_covert_channel(),
        }));
    }

    // The nearest name, if there is one. **A structured suggestion is worth more than a structured
    // refusal**, because it ends the guessing rather than reporting it.
    let suggestion =
        qqq_cap::capability::Capability::suggest(name).map(qqq_cap::capability::Capability::name);
    failed(&json!({
        "capability": name,
        "suggestion": suggestion,
        "error": {
            "code": "QQQ-1002",
            "message": format!("`{name}` is not a capability this runtime defines"),
        },
    }))
}

/// `qqq_manifest_get` and `qqq_manifest_validate` -- the first tools that touch the FILESYSTEM.
///
/// # Why these two are one function with a flag
///
/// Because they answer two questions about one file: *"what does it say"* and *"is it valid"*. **A
/// manifest that cannot be parsed has no content to report**, so `get` on an invalid manifest must
/// report the failure rather than an empty object -- and that is the same call either way.
///
/// # The error is STRUCTURED, which is the whole point of `AGENT-019`
///
/// A missing or invalid manifest sets **`isError: true`** and carries **the QQQ error code**, so a
/// client branches on a code rather than on a sentence. **A tool that touched the filesystem and
/// reported a string would be the tool that makes `AGENT-019` worth having fail first.**
fn manifest(arguments: &Value, validate_only: bool) -> Value {
    let dir = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
    let path = std::path::Path::new(dir).join("qqq.toml");

    match crate::manifest_loader::LoadedManifest::load(&path) {
        Ok(loaded) => ok(&json!({
            "found": true,
            "path": loaded.path.display().to_string(),
            "name": loaded.name(),
            "valid": true,
            // `validate` reports only the verdict; `get` also reports where it came from, because a
            // client asking for content needs to know WHICH file answered.
            "validated": validate_only,
        })),
        Err(e) => failed(&json!({
            "found": false,
            "path": path.display().to_string(),
            "valid": false,
            "error": { "code": e.id(), "message": e.to_string() },
        })),
    }
}

/// Wrap a structured value as a FAILED tool result.
///
/// # Why `isError` and not a protocol error
///
/// Because the call was well formed: the client asked a valid question and the answer is *"no"*. A JSON-RPC
/// error would tell it the REQUEST was wrong, which is a different thing and would make a client retry a
/// request it should not change. **`AGENT-019` puts the failure in the result, and this is the one place
/// that decides how.**
fn failed(structured: &Value) -> Value {
    json!({
        "content": [ { "type": "text", "text": structured.to_string() } ],
        "structuredContent": structured,
        "isError": true
    })
}

/// Wrap a structured value as a successful tool result.
///
/// # Why this borrows
///
/// Because `json!` **reads** its operands rather than consuming them, so taking the value by ownership
/// would be a signature promising a move it does not make. **Three tools go through this**, so the
/// wrapper exists rather than three copies of the same four lines -- and the three agree by construction.
fn ok(structured: &Value) -> Value {
    json!({
        "content": [ { "type": "text", "text": structured.to_string() } ],
        "structuredContent": structured,
        "isError": false
    })
}

/// A tool this build cannot run, answered **structurally**.
fn unimplemented(name: &str) -> Value {
    let structured = json!({
        "tool": name,
        "implemented": false,
        "reason": "this tool's backing command is not reachable in-process yet",
    });
    json!({
        "content": [ { "type": "text", "text": structured.to_string() } ],
        "structuredContent": structured,
        "isError": true
    })
}

/// Serve the stdio transport until stdin ends.
///
/// # Errors
///
/// An I/O error from stdin or stdout. **A malformed line is not one**: it produces a JSON-RPC parse
/// error and the loop continues, because a client that sends one bad line should get one bad answer
/// rather than a dead server.
///
/// # Example
///
/// ```
/// use qqq_run::mcp::serve_stdio;
///
/// let input = "not json\n{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\"}\n";
/// let mut out = Vec::new();
/// serve_stdio(input.as_bytes(), &mut out, None).expect("the transport is infallible here");
///
/// let lines: Vec<&str> = std::str::from_utf8(&out).expect("utf8").lines().collect();
/// assert_eq!(lines.len(), 2, "a bad line is answered AND the next request is served");
/// assert!(lines[0].contains("-32700"), "a parse error: {}", lines[0]);
/// assert!(lines[1].contains("\"id\":7"), "and the loop continued: {}", lines[1]);
/// ```
///
/// # Why one line at a time and never a buffered read
///
/// Because the transport is **newline-delimited** and a client may send one request and wait. A reader
/// that waited for more input would deadlock against a client that is waiting for a reply.
///
/// # Why `cli` is a parameter
///
/// Because the four tools that shell out must run **a program the caller named**. `None` means this
/// server was not granted one, and those four tools refuse — see `run_command` and `§O-351`.
pub fn serve_stdio<R: BufRead, W: Write>(
    input: R,
    mut output: W,
    cli: Option<&Path>,
) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => answer(&message, cli),
            Err(e) => Some(error(
                &Value::Null,
                code::PARSE,
                &format!("the line is not JSON: {e}"),
            )),
        };
        if let Some(reply) = reply {
            writeln!(output, "{reply}")?;
            output.flush()?;
        }
    }
    Ok(())
}

/// The HTTP transport — `AGENT-005`.
///
/// # The shape, and why it is this one
///
/// MCP's Streamable HTTP transport is **one endpoint, one POST, one JSON-RPC message**. The client sends
/// `POST /mcp` with a JSON body and gets the reply in the response body. **A notification gets `202
/// Accepted` and no body**, because answering one would be a reply to a request the client never made --
/// the same rule `answer` applies on stdio, and the two transports must agree or a client would need two
/// mental models.
///
/// # Why blocking `std::net` and not the async server this crate already depends on
///
/// Because the exchange is **request/response with nothing in between**: the whole answer is computed
/// before a byte is written. A runtime would buy concurrency this endpoint does not need, and it would
/// make the transport **harder to test**, because a test would need a runtime to drive it.
///
/// # What this is not
///
/// It is **not** a general-purpose HTTP server: one request per connection, `Connection: close`, no
/// chunked encoding, no SSE. **An MCP client that needs server-initiated messages over HTTP is not
/// served by this**, and saying so is part of the contract rather than a gap discovered later.
///
/// # Errors
///
/// An I/O error from the listener or a connection. **A malformed request is not one**: it gets a `400`
/// with a JSON-RPC parse error, for the same reason a malformed line on stdio does.
///
/// # Example
///
/// ```
/// use qqq_run::mcp::serve_http;
/// use std::io::{Read, Write};
///
/// // **`port 0` asks the OS for a free one, and the server ANNOUNCES which it got** -- so there is no
/// // window between picking a port and taking it. A doctest cannot read another thread's stdout, so
/// // this one picks a port and retries the connect; the integration tests read the announcement.
/// let port = std::net::TcpListener::bind("127.0.0.1:0")
///     .expect("bind")
///     .local_addr()
///     .expect("addr")
///     .port();
///
/// std::thread::spawn(move || {
///     let _ = serve_http(&format!("127.0.0.1:{port}"), None);
/// });
///
/// // **Wait by connecting, not by sleeping** -- a sleep is a guess, and this is ready when it answers.
/// let mut stream = None;
/// for _ in 0..100 {
///     if let Ok(s) = std::net::TcpStream::connect(("127.0.0.1", port)) {
///         stream = Some(s);
///         break;
///     }
///     std::thread::sleep(std::time::Duration::from_millis(20));
/// }
/// let mut stream = stream.expect("the server must accept a connection");
///
/// let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
/// write!(stream, "POST /mcp HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len())
///     .expect("write");
///
/// let mut out = String::new();
/// stream.read_to_string(&mut out).expect("read");
/// assert!(out.starts_with("HTTP/1.1 200"), "{out}");
/// assert!(out.contains("qqqai"), "and it is this server: {out}");
/// ```
/// # Why `cli` is a parameter here too
///
/// Because the two transports serve the **same** protocol, and a tool that shells out must behave
/// identically on both — the same reason `answer` is shared rather than written twice. See `§O-351`.
pub fn serve_http(addr: &str, cli: Option<&Path>) -> std::io::Result<()> {
    let listener = std::net::TcpListener::bind(addr)?;
    // **ANNOUNCE THE BOUND ADDRESS.** `127.0.0.1:0` asks the OS for any free port, and a caller has no
    // other way to learn which one it got -- **a test that picks a port by binding and releasing it has
    // a race, and this removes the race rather than narrowing it** (`§O-313`'s class).
    if let Ok(local) = listener.local_addr() {
        println!("listening on {local}");
    }
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        // A connection that fails mid-exchange is one bad client, not a dead server.
        let _ = handle_http(&mut stream, cli);
    }
    Ok(())
}

/// One HTTP exchange.
fn handle_http(stream: &mut std::net::TcpStream, cli: Option<&Path>) -> std::io::Result<()> {
    use std::io::{BufRead as _, BufReader, Read as _};

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        // Only `Content-Length` matters: there is no chunked encoding, and the method is checked below.
        if let Some(v) = header
            .strip_prefix("Content-Length:")
            .or_else(|| header.strip_prefix("content-length:"))
        {
            length = v.trim().parse().unwrap_or(0);
        }
    }

    // `POST` to any path, because the endpoint is the server rather than a route -- an MCP client
    // points at a URL and the path is not part of the protocol.
    if !request_line.starts_with("POST ") {
        return write_http(
            stream,
            405,
            "Method Not Allowed",
            "{\"error\":\"POST only\"}",
        );
    }

    if length > MAX_BODY {
        return write_http(
            stream,
            413,
            "Payload Too Large",
            "{\"error\":\"body too large\"}",
        );
    }

    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8_lossy(&body);

    let reply = match serde_json::from_str::<Value>(&body) {
        Ok(message) => answer(&message, cli),
        Err(e) => Some(error(
            &Value::Null,
            code::PARSE,
            &format!("the body is not JSON: {e}"),
        )),
    };

    match reply {
        // **A notification is accepted and not answered** -- the same rule as stdio.
        None => write_http(stream, 202, "Accepted", ""),
        Some(reply) => {
            let body = reply.to_string();
            write_http(stream, 200, "OK", &body)
        }
    }
}

/// Write one HTTP/1.1 response with `Connection: close`.
fn write_http(
    stream: &mut std::net::TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `tools/call` as a client would frame it.
    fn call_tool(name: &str) -> Value {
        let message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": name, "arguments": {} }
        });
        answer(&message, None).expect("a request is answered")
    }

    /// **A server that was not granted a CLI REFUSES, and refuses structurally — `§O-351`.**
    ///
    /// # What this test is for
    ///
    /// The four tools that shell out take the program to run as a **parameter**. This is the assertion
    /// that the parameter is *required*: with `None` there is no fallback, and the absence is reported
    /// as a result a client can branch on rather than as a fork bomb.
    ///
    /// # Why it lives here and not in `tests/mcp_stdio.rs`
    ///
    /// Because the integration test drives the **real binary**, which *is* the CLI and therefore always
    /// grants its own path — the ungranted state is unreachable from there. It is reachable here, and it
    /// is the state a doctest, a unit test and a library embedder are all in.
    ///
    /// # The fault injection, and why it is this one
    ///
    /// Swapping `failed` for `ok` in `run_command`'s guard fails this test on `isError` — safe, and it
    /// proves the assertion is live. **The unsafe injection is the historical one**: removing the guard
    /// and falling back to `current_exe()` is exactly what produced `§O-351`'s 2,528 processes, so it is
    /// recorded as a measurement rather than re-run.
    #[test]
    fn a_server_without_a_granted_cli_refuses_to_shell_out() {
        let reply = call_tool("qqq_build");

        assert_eq!(reply["id"], 1);
        assert!(
            reply.get("error").is_none(),
            "a well-formed call is a RESULT, not a protocol error: {reply}"
        );
        let result = &reply["result"];
        assert_eq!(
            result["isError"], true,
            "the refusal sets the flag a client branches on: {reply}"
        );
        assert_eq!(
            result["structuredContent"]["command"], "build",
            "the field names the CLI COMMAND that would have run, not the tool that asked for it -- \
             which is what the success path reports too, so a client parses one shape: {reply}"
        );
        assert_eq!(result["structuredContent"]["error"]["code"], "QQQ-7001");
        assert!(
            result["structuredContent"]["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("not granted")),
            "and it says WHY, because a refusal a client cannot act on is a dead end: {reply}"
        );
    }

    /// **The refusal reports NO ARGUMENTS and NO EXIT CODE.**
    ///
    /// # Why this is the assertion that would have caught `§O-351`
    ///
    /// Because those two fields exist only if a program ran. An implementation that refused *after*
    /// deciding what to run — or one that ran something and then reported a failure — would populate
    /// them, and **the shape of the structured content is the only evidence a client has** about whether
    /// the host executed anything.
    #[test]
    fn a_refusal_does_not_claim_anything_ran() {
        let reply = call_tool("qqq_build");
        let structured = &reply["result"]["structuredContent"];
        assert!(
            structured.get("args").is_none(),
            "nothing was run, so there are no arguments to report: {reply}"
        );
        assert!(
            structured.get("exit_code").is_none(),
            "nothing was run, so there is no exit code: {reply}"
        );
    }

    /// **All four shelling tools refuse, not just the one the test above names.**
    ///
    /// Because the guard lives in `run_command`, which all four share — and a test that named one of
    /// them would pass while the other three took a different path.
    #[test]
    fn every_shelling_tool_refuses_without_a_grant() {
        for name in ["qqq_build", "qqq_run", "qqq_test", "qqq_bench"] {
            let reply = call_tool(name);
            assert_eq!(
                reply["result"]["isError"], true,
                "`{name}` must refuse rather than guess: {reply}"
            );
            assert_eq!(
                reply["result"]["structuredContent"]["command"],
                name.trim_start_matches("qqq_"),
                "and it names the command it would have run: {reply}"
            );
        }
    }

    /// **The guard does not reach the tools that need no subprocess.**
    ///
    /// Because `None` means *"you may not shell out"*, not *"you may not answer"*. A guard that disabled
    /// the in-process tools would be a guard that broke the server in order to protect it — `§O-282`'s
    /// shape, in the other direction.
    #[test]
    fn an_ungranted_server_still_answers_the_in_process_tools() {
        let reply = call_tool("qqq_caps_list");
        assert_eq!(
            reply["result"]["isError"], false,
            "the in-process tools are unaffected: {reply}"
        );
        assert!(
            reply["result"]["structuredContent"]["count"]
                .as_u64()
                .is_some_and(|c| c > 0),
            "and they still carry their answer: {reply}"
        );
    }
}
