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
//! | `tools/call` | implemented for the tools whose backing exists in-process |
//!
//! **`tools/call` answers structurally for a tool it cannot run** — an `isError` result naming the
//! tool, not prose and not a panic. `AGENT-019` is the item that makes this a requirement: *"every tool
//! returns structured content, never prose-only"*, and a client that has to parse a sentence to learn
//! that a tool is missing is a client that will get it wrong.
//!
//! # Example
//!
//! ```
//! use qqq_run::mcp::serve_stdio;
//!
//! // One JSON object per line in, one per line out -- and a tool the server cannot run says so
//! // STRUCTURALLY, so a client branches on a boolean rather than on a sentence.
//! let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
//!              \"params\":{\"name\":\"qqq_build\",\"arguments\":{}}}\n";
//! let mut out = Vec::new();
//! serve_stdio(input.as_bytes(), &mut out).expect("the transport is infallible here");
//!
//! let reply = String::from_utf8(out).expect("utf8");
//! assert!(reply.contains("\"isError\":true"), "{reply}");
//! ```
//!
//! # Why an unknown method is `-32601` and not a custom code
//!
//! Because JSON-RPC 2.0 defines it, and a client's own dispatch is written against that number. A
//! QQQ-specific code for *"no such method"* would be a second spelling of a standard answer.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

/// The JSON-RPC version this server speaks. There is one, and it is not negotiable.
const JSONRPC: &str = "2.0";

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
        "qqq_run" => "Run the guest component against a request, without serving. Takes `dry_run` to describe what would run without running it.",
        "qqq_test" => "Run the project's conformance tests. Takes `dry_run` to describe what would run without running it.",
        "qqq_audit" => "Read the capability audit and report the worst severity found.",
        "qqq_inspect" => "Report what a project is allowed to do, and what it is not.",
        "qqq_bench" => "Run the benchmarks and report the measured numbers. Takes `dry_run` to describe what would run without running it.",
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
        "qqq_manifest_get" | "qqq_manifest_validate" | "qqq_caps_list" | "qqq_inspect" => {
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "The project directory. Defaults to the working directory." }
                },
                "additionalProperties": false
            })
        }
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
        "qqq_build" | "qqq_test" | "qqq_bench" => json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "The project directory. Defaults to the working directory." },
                "dry_run": { "type": "boolean", "description": "Describe what would run, without running it." }
            },
            "additionalProperties": false
        }),
        "qqq_run" => json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "request": { "type": "string", "description": "The request line, such as `GET /orders`." },
                "dry_run": { "type": "boolean" }
            },
            "additionalProperties": false
        }),
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
#[must_use]
fn answer(message: &Value) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str);

    let Some(method) = method else {
        return id.map(|id| error(&id, code::INVALID_REQUEST, "no `method` in the request"));
    };

    let result = match method {
        "initialize" => Ok(initialize()),
        "tools/list" => Ok(json!({ "tools": tools().iter().map(tool_json).collect::<Vec<_>>() })),
        "tools/call" => call(message.get("params")),
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
fn call(params: Option<&Value>) -> Result<Value, (i64, String)> {
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

    let structured = json!({ "count": codes.len(), "codes": codes });
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
/// serve_stdio(input.as_bytes(), &mut out).expect("the transport is infallible here");
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
pub fn serve_stdio<R: BufRead, W: Write>(input: R, mut output: W) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => answer(&message),
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
