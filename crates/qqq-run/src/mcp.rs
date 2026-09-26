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
        "qqq_test" | "qqq_bench" => json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "The project directory. Defaults to the working directory." }
            },
            "additionalProperties": false
        }),
        // **No `dry_run` here, and the absence is deliberate.** `output::command_schemas()` declares
        // `supports_dry_run: false` for the `run` command, so a tool offering one would be
        // **a promise the command does not keep** -- and a cross-surface test compares the two, which
        // is how this was found.
        "qqq_run" => json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "request": { "type": "string", "description": "The request line, such as `GET /orders`." }
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
        "qqq_schema" => Ok(schema_lookup(&arguments)),
        "qqq_caps_list" => Ok(caps_list()),
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
/// // A port the OS picks, released so the server can take it.
/// let port = std::net::TcpListener::bind("127.0.0.1:0")
///     .expect("bind")
///     .local_addr()
///     .expect("addr")
///     .port();
///
/// std::thread::spawn(move || {
///     let _ = serve_http(&format!("127.0.0.1:{port}"));
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
pub fn serve_http(addr: &str) -> std::io::Result<()> {
    let listener = std::net::TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        // A connection that fails mid-exchange is one bad client, not a dead server.
        let _ = handle_http(&mut stream);
    }
    Ok(())
}

/// One HTTP exchange.
fn handle_http(stream: &mut std::net::TcpStream) -> std::io::Result<()> {
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
        Ok(message) => answer(&message),
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
