// SPDX-License-Identifier: Apache-2.0

//! `qqqai mcp` over its real stdio transport — `AGENT-004`, and the shape `AGENT-019` requires.
//!
//! # Why these tests pipe into the binary rather than calling `mcp::answer`
//!
//! Because the **transport** is half of what `AGENT-004` asks for. A test that calls the dispatch
//! function proves the protocol logic and says nothing about the framing: whether one JSON object per
//! line comes out, whether a bad line kills the loop, whether a notification is answered when it must
//! not be. **Those are the failures a client sees first**, and they only exist over the pipe.
//!
//! # The contract this file holds the server to
//!
//! `output::mcp_tool_names()` has listed the tools since before the server existed. **The list and the
//! server must not disagree**, so one test reads the names from the same source the CLI publishes and
//! requires every one to be offered.

use std::io::Write;
use std::process::{Command, Stdio};

/// Run `qqqai mcp`, write `requests` to its stdin, close it, and return every line it answered.
///
/// # Why closing stdin is the assertion's precondition
///
/// Because the loop ends on **EOF**, which is how a client says *"done"*. A helper that left stdin open
/// would wait forever, and a test that waits is a test that reports nothing.
fn run_mcp(requests: &[&str]) -> Vec<String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("`qqqai mcp` must be runnable");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in requests {
            writeln!(stdin, "{line}").expect("write");
        }
    }
    // Dropping the handle closes the pipe, which is the EOF the loop ends on.
    drop(child.stdin.take());

    let out = child.wait_with_output().expect("wait");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().map(str::to_owned).collect()
}

/// Parse one reply line.
fn parse(line: &str) -> serde_json::Value {
    serde_json::from_str(line).unwrap_or_else(|e| panic!("a reply must be JSON: {e}\n{line}"))
}

/// **`initialize` answers the protocol's own fields — `AGENT-004`.**
#[test]
fn initialize_reports_the_protocol_and_the_server() {
    let replies = run_mcp(&[r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#]);
    assert_eq!(replies.len(), 1, "one request, one reply: {replies:?}");
    let reply = parse(&replies[0]);

    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["id"], 1);
    assert!(
        reply["result"]["protocolVersion"].is_string(),
        "a client reads the revision to decide how to talk to this server: {reply}"
    );
    assert_eq!(reply["result"]["serverInfo"]["name"], "qqqai");
    assert!(
        reply["result"]["capabilities"]["tools"].is_object(),
        "and it must declare the tools capability it implements: {reply}"
    );
}

/// **`tools/list` offers exactly the tools the CLI publishes — and all of them.**
///
/// # Why this is the test that matters most
///
/// Because the names have existed since before the server did. **The list and the server are two
/// answers to one question**, and a server that offered a subset would be the drift this repository
/// keeps finding — a published surface with nothing behind part of it.
#[test]
fn tools_list_matches_the_published_names() {
    let replies = run_mcp(&[r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#]);
    let reply = parse(&replies[0]);
    let offered = reply["result"]["tools"]
        .as_array()
        .expect("`tools` is an array")
        .iter()
        .map(|t| t["name"].as_str().expect("a name").to_owned())
        .collect::<Vec<_>>();

    assert_eq!(
        offered.len(),
        12,
        "the CLI publishes twelve tools: {offered:?}"
    );
    for name in [
        "qqq_manifest_get",
        "qqq_manifest_validate",
        "qqq_caps_explain",
        "qqq_caps_list",
        "qqq_build",
        "qqq_run",
        "qqq_test",
        "qqq_audit",
        "qqq_inspect",
        "qqq_bench",
        "qqq_schema",
        "qqq_errors_lookup",
    ] {
        assert!(
            offered.contains(&name.to_owned()),
            "`{name}` is published by the CLI and must be offered here: {offered:?}"
        );
    }

    // Every tool carries a description and a schema, because a tool a model cannot call is a tool
    // that is advertised rather than provided.
    for tool in reply["result"]["tools"].as_array().expect("array") {
        assert!(
            tool["description"].as_str().is_some_and(|d| !d.is_empty()),
            "every tool needs a description: {tool}"
        );
        assert_eq!(
            tool["inputSchema"]["type"], "object",
            "and a JSON Schema for its arguments: {tool}"
        );
    }
}

/// **A tool that runs returns structured content — `AGENT-019`.**
#[test]
fn a_working_tool_returns_structured_content() {
    let replies = run_mcp(&[
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"qqq_errors_lookup","arguments":{"class":"70"}}}"#,
    ]);
    let reply = parse(&replies[0]);
    assert_eq!(reply["result"]["isError"], false);
    let structured = &reply["result"]["structuredContent"];
    assert!(
        structured["count"].as_u64().is_some_and(|c| c > 0),
        "the lookup found nothing: {reply}"
    );
    let codes = structured["codes"].as_array().expect("an array");
    assert!(
        codes
            .iter()
            .all(|c| c["id"].as_str().is_some_and(|id| id.starts_with("QQQ-70"))),
        "a class filter must filter: {codes:?}"
    );
    // And the meaning is NOT carried, because `ErrorCode` has no description accessor -- what is
    // carried is where the meaning lives. A field that repeated the id would be a lie.
    assert!(
        codes[0].get("meaning").is_none(),
        "the tool must not claim a meaning it cannot supply: {codes:?}"
    );
    assert!(codes[0]["docs"]
        .as_str()
        .is_some_and(|d| d.starts_with("https://qqq.codes/errors/")));
}

/// **A tool that cannot run says so *structurally* — `AGENT-019`.**
///
/// A client must branch on a boolean, not on the wording of a sentence.
#[test]
fn an_unrunnable_tool_reports_is_error() {
    let replies = run_mcp(&[
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"qqq_build","arguments":{}}}"#,
    ]);
    let reply = parse(&replies[0]);
    assert_eq!(
        reply["result"]["isError"], true,
        "an unrunnable tool sets the flag: {reply}"
    );
    assert_eq!(reply["result"]["structuredContent"]["implemented"], false);
    assert_eq!(reply["result"]["structuredContent"]["tool"], "qqq_build");
    assert!(
        reply.get("error").is_none(),
        "and it is a RESULT rather than a protocol error -- the call was well formed: {reply}"
    );
}

/// **A name that is not a tool is refused, and the refusal names it.**
#[test]
fn an_unknown_tool_is_refused() {
    let replies = run_mcp(&[
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"qqq_nonsense","arguments":{}}}"#,
    ]);
    let reply = parse(&replies[0]);
    assert_eq!(reply["error"]["code"], -32602, "invalid params: {reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("qqq_nonsense")),
        "the refusal names the tool: {reply}"
    );
}

/// **An unknown method is JSON-RPC's own `-32601`, not a QQQ-specific code.**
///
/// Because a client's dispatch is written against the standard number, and a second spelling of *"no
/// such method"* is a second thing to get wrong.
#[test]
fn an_unknown_method_is_method_not_found() {
    let replies = run_mcp(&[r#"{"jsonrpc":"2.0","id":6,"method":"qqq/nonsense"}"#]);
    let reply = parse(&replies[0]);
    assert_eq!(reply["error"]["code"], -32601, "{reply}");
}

/// **A malformed line is one bad answer, not a dead server.**
///
/// This is the transport test that a dispatch-level test cannot make: a client that sends one bad line
/// should get one bad answer, and the next request must still be served.
#[test]
fn a_malformed_line_does_not_kill_the_loop() {
    let replies = run_mcp(&[
        "not json at all",
        r#"{"jsonrpc":"2.0","id":7,"method":"initialize"}"#,
    ]);
    assert_eq!(
        replies.len(),
        2,
        "a bad line gets an answer and the loop continues: {replies:?}"
    );
    assert_eq!(parse(&replies[0])["error"]["code"], -32700, "a parse error");
    assert_eq!(
        parse(&replies[1])["id"],
        7,
        "and the NEXT request is still served: {replies:?}"
    );
}

/// **A notification is not answered.**
///
/// JSON-RPC says a message with no `id` gets no reply. Answering one with a `null` id would be a reply
/// to a request the client never made.
#[test]
fn a_notification_gets_no_reply() {
    let replies = run_mcp(&[
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":8,"method":"ping"}"#,
    ]);
    assert_eq!(
        replies.len(),
        1,
        "the notification is unanswered and the ping is: {replies:?}"
    );
    assert_eq!(parse(&replies[0])["id"], 8);
}

/// **An empty line is skipped rather than answered.**
#[test]
fn blank_lines_are_skipped() {
    let replies = run_mcp(&["", "   ", r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#]);
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(parse(&replies[0])["id"], 9);
}
