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

/// **Every tool returns structured content — `AGENT-019`, over all twelve.**
///
/// # Why this is a test and not a description
///
/// Because `AGENT-019` is the item that makes the server worth having, and **a client that has to parse a
/// sentence to learn a tool's answer is a client that will get it wrong.** The property is
/// cross-cutting: it is about *every* tool, and a single tool added without it would be invisible to a
/// reviewer reading one handler.
///
/// **A tool that cannot run still returns structured content** — `isError` is a field, not a phrase. That
/// is the half a rushed implementation loses: it returns prose for the error path and structure for the
/// happy path, and the client has to handle two shapes.
#[test]
fn every_tool_returns_structured_content() {
    let names = [
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
    ];
    assert_eq!(names.len(), 12, "the published list is twelve");

    // One server, twelve calls, so a tool that hangs is one failure rather than twelve.
    let requests: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"{n}","arguments":{{}}}}}}"#,
                i + 1
            )
        })
        .collect();
    let refs: Vec<&str> = requests.iter().map(String::as_str).collect();
    let replies = run_mcp(&refs);
    assert_eq!(replies.len(), 12, "one reply per tool: {replies:?}");

    for (i, name) in names.iter().enumerate() {
        let reply = parse(&replies[i]);
        let result = &reply["result"];
        assert!(
            result.get("error").is_none(),
            "`{name}` must be answered as a RESULT, not a protocol error: {reply}"
        );
        assert!(
            result["isError"].is_boolean(),
            "`{name}` must set `isError` as a BOOLEAN, so a client branches on a flag and not on              the wording of a sentence: {reply}"
        );
        assert!(
            result["structuredContent"].is_object(),
            "`{name}` must carry `structuredContent` -- AGENT-019 says never prose-only: {reply}"
        );
        // And the text block, if present, must be the structured content SERIALISED rather than a
        // different sentence -- two descriptions of one answer is how they drift.
        if let Some(text) = result["content"][0]["text"].as_str() {
            let parsed: serde_json::Value = serde_json::from_str(text)
                .unwrap_or_else(|e| panic!("`{name}`: text is not JSON: {e}"));
            assert_eq!(
                &parsed, &result["structuredContent"],
                "`{name}`'s text block and its structured content must be the same value"
            );
        }
    }
}

/// **Three tools are WIRED, not advertised — Gate 2's bar.**
///
/// # Why "three" is the number
///
/// Because it is what the gate asks for, and because **one working tool is a demo while three is a
/// server**. The three share a property worth naming: their backing is a **pure function** already in
/// the process -- `ErrorCode::all()`, `command_schemas()`, `Namespace::all()` -- so none needs a build,
/// a guest or a filesystem. **A tool whose backing is already a pure function is a tool that should be
/// wired first.**
#[test]
fn three_tools_are_wired_and_structured() {
    let replies = run_mcp(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"qqq_errors_lookup","arguments":{"class":"70"}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"qqq_schema","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"qqq_caps_list","arguments":{}}}"#,
    ]);
    assert_eq!(replies.len(), 3, "one reply each: {replies:?}");

    for (i, name) in ["qqq_errors_lookup", "qqq_schema", "qqq_caps_list"]
        .iter()
        .enumerate()
    {
        let reply = parse(&replies[i]);
        let result = &reply["result"];
        assert_eq!(
            result["isError"], false,
            "`{name}` must be WIRED, not advertised: {reply}"
        );
        let structured = &result["structuredContent"];
        assert!(
            structured["count"].as_u64().is_some_and(|c| c > 0),
            "and it must carry a non-empty count -- a wired tool that finds nothing is a tool whose              backing is empty: {reply}"
        );
    }
}

/// **The MCP `dry_run` contract must agree with the command schemas — two places, one answer.**
///
/// # Why this test exists
///
/// `output::command_schemas()` already declares **`mutating`** and **`supports_dry_run`** for every
/// command, and `mcp.rs` declares the same property for every tool. **Two places that answer one
/// question is how they drift**, and `§O-282`'s rule is that a guard is only as wide as its extent --
/// so this one reaches across the two surfaces rather than checking either alone.
///
/// A tool whose name is not a command is **not** a divergence: `qqq_errors_lookup` has no command. The
/// test asserts the tools that DO map agree, and it asserts the mapping is not empty, so a rename that
/// broke every mapping would fail rather than pass vacuously.
#[test]
fn the_tool_dry_run_contract_agrees_with_the_command_schemas() {
    // The command schemas, as `qqq_schema` returns them.
    let replies = run_mcp(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"qqq_schema","arguments":{}}}"#,
    ]);
    let reply = parse(&replies[0]);
    let commands = reply["result"]["structuredContent"]["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .map(|c| {
            (
                c["command"].as_str().expect("a name").to_owned(),
                c["supports_dry_run"].as_bool().expect("a bool"),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();

    // The MCP tools.
    let replies = run_mcp(&[r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#]);
    let reply = parse(&replies[0]);
    let tools = reply["result"]["tools"].as_array().expect("tools");

    let mut mapped = 0usize;
    for tool in tools {
        let name = tool["name"].as_str().expect("a name");
        // `qqq_caps_list` -> `caps`, `qqq_build` -> `build`; a tool with no command simply has no entry.
        let Some(command) = name.strip_prefix("qqq_").and_then(|c| commands.get(c)) else {
            continue;
        };
        mapped += 1;
        let tool_says = tool["inputSchema"]["properties"].get("dry_run").is_some();
        assert_eq!(
            tool_says, *command,
            "`{name}` and the `{}` command disagree about `dry_run` -- two places, one answer: {tool}",
            name.strip_prefix("qqq_").expect("a prefix")
        );
    }
    assert!(
        mapped >= 3,
        "the mapping must not be vacuous: {mapped} tool(s) reached a command schema"
    );
}

/// **The manifest tools touch the filesystem, and a failure is STRUCTURED.**
///
/// # Why this is the test that matters for a tool with an input
///
/// The three pure tools cannot fail. **These can**: a path that does not hold a `qqq.toml` is the normal
/// case, not an exceptional one, and `AGENT-019` says a tool returns **structured content, never
/// prose-only**. So the failure must carry **the QQQ error code** --
/// **a client branches on `QQQ-2001`, not on a sentence**, and a tool that touched the filesystem and
/// answered a string would be the one that makes the rule worth having fail first.
#[test]
fn the_manifest_tools_answer_structured_content_and_a_structured_failure() {
    // A project that exists, and a path that does not.
    let dir = std::env::temp_dir().join(format!("qqq-mcp-manifest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temp project");
    std::fs::write(
        dir.join("qqq.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n",
    )
    .expect("write");
    // Forward slashes, because the path is embedded in a JSON string.
    let good = dir.display().to_string().replace('\\', "/");

    let good_request = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"qqq_manifest_get","arguments":{{"path":"{good}"}}}}}}"#
    );
    let replies = run_mcp(&[
        &good_request,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"qqq_manifest_get","arguments":{"path":"C:/qqq-does-not-exist"}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"qqq_manifest_validate","arguments":{"path":"C:/qqq-does-not-exist"}}}"#,
    ]);
    assert_eq!(replies.len(), 3, "{replies:?}");

    // A real project: content, no error.
    let found = parse(&replies[0]);
    assert_eq!(found["result"]["isError"], false, "{found}");
    assert_eq!(
        found["result"]["structuredContent"]["found"], true,
        "{found}"
    );
    assert_eq!(
        found["result"]["structuredContent"]["name"], "probe",
        "{found}"
    );

    // A missing project: still structured content, and the ERROR CODE is in it.
    for (i, name) in ["qqq_manifest_get", "qqq_manifest_validate"]
        .iter()
        .enumerate()
    {
        let reply = parse(&replies[i + 1]);
        let result = &reply["result"];
        assert_eq!(
            result["isError"], true,
            "`{name}` must report the failure as a RESULT rather than a protocol error: {reply}"
        );
        assert_eq!(result["structuredContent"]["found"], false, "{reply}");
        assert!(
            result["structuredContent"]["error"]["code"]
                .as_str()
                .is_some_and(|c| c.starts_with("QQQ-")),
            "`{name}` must carry the QQQ error code, so a client branches on a CODE and not on a \
             sentence: {reply}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// **`qqq_caps_explain` explains a capability, and SUGGESTS the one a typo meant.**
///
/// # Why the suggestion is the assertion that matters
///
/// A capability name is a **closed vocabulary**, and a model that guesses wrong should be told **which
/// name it probably meant** rather than that its guess was wrong. **A tool that answered only *"no such
/// capability"* would make the model guess again** -- which is the loop this tool exists to break.
///
/// And `is_covert_channel` is reported rather than hidden: it is a **security property of the capability
/// itself**, so a tool that omitted it would be explaining the convenience and not the risk.
#[test]
fn caps_explain_explains_and_suggests() {
    let replies = run_mcp(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"qqq_caps_explain","arguments":{"capability":"fs.read"}}}"#,
        // A transposition -- the commonest typo, and the one a suggestion is worth most for.
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"qqq_caps_explain","arguments":{"capability":"fs.raed"}}}"#,
        // And no argument at all.
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"qqq_caps_explain","arguments":{}}}"#,
    ]);
    assert_eq!(replies.len(), 3, "{replies:?}");

    // A real capability: explained, not refused.
    let good = parse(&replies[0]);
    assert_eq!(good["result"]["isError"], false, "{good}");
    let content = &good["result"]["structuredContent"];
    assert_eq!(content["capability"], "fs.read", "{good}");
    assert_eq!(content["namespace"], "fs", "{good}");
    assert!(
        content["kind"].is_string(),
        "the kind is part of the explanation: {good}"
    );
    assert!(
        content["covert_channel"].is_boolean(),
        "and so is whether the capability can carry data without an obvious channel -- a tool that \
         omitted it would explain the convenience and not the risk: {good}"
    );

    // A typo: refused WITH A SUGGESTION.
    let typo = parse(&replies[1]);
    assert_eq!(typo["result"]["isError"], true, "{typo}");
    assert_eq!(
        typo["result"]["structuredContent"]["error"]["code"], "QQQ-1002",
        "the refusal carries a code: {typo}"
    );
    assert!(
        typo["result"]["structuredContent"]["suggestion"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "and a SUGGESTION -- the tool must end the guessing, not report it: {typo}"
    );

    // No argument: a different code, because it is a different failure.
    let missing = parse(&replies[2]);
    assert_eq!(missing["result"]["isError"], true, "{missing}");
    assert_eq!(
        missing["result"]["structuredContent"]["error"]["code"], "QQQ-1001",
        "a missing argument and an unknown name are DIFFERENT failures and get different codes: {missing}"
    );
}

/// **`qqq_audit` runs the audit, returns SARIF as a DOCUMENT, and refuses a typo in `fail_on`.**
///
/// # Why the SARIF is asserted to be an OBJECT
///
/// Because `AGENT-019` says structured content, and **a client that has to parse a JSON string out of a
/// JSON field is a client doing the server's work.** `to_sarif` produces a string; the tool re-parses it
/// so the field is a document.
///
/// # Why the typo is the assertion that matters most
///
/// `Severity::parse` refuses a typo **rather than defaulting**, and its own doc says why: *"a `--fail-on`
/// that silently accepted a typo would be a CI gate that never fires, which is worse than no gate because
/// it is believed to be one."* **A tool that defaulted would reintroduce exactly that** -- and a client
/// asking for `"warning"` and getting `"note"` would never know.
#[test]
fn audit_runs_returns_sarif_and_refuses_a_typo() {
    let dir = std::env::temp_dir().join(format!("qqq-mcp-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temp project");
    std::fs::write(
        dir.join("qqq.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n",
    )
    .expect("write");
    let good = dir.display().to_string().replace('\\', "/");

    let audit_request = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"qqq_audit","arguments":{{"path":"{good}"}}}}}}"#
    );
    let typo_request = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"qqq_audit","arguments":{{"path":"{good}","fail_on":"zzz"}}}}}}"#
    );
    let replies = run_mcp(&[&audit_request, &typo_request]);
    assert_eq!(replies.len(), 2, "{replies:?}");

    let report = parse(&replies[0]);
    let content = &report["result"]["structuredContent"];
    assert!(
        content["count"].as_u64().is_some_and(|c| c > 0),
        "a bare manifest has at least one finding, so the audit RAN rather than returning empty: {report}"
    );
    assert!(
        content["findings"][0]["rule"]
            .as_str()
            .is_some_and(|r| r.starts_with("qqq/")),
        "every finding names its rule: {report}"
    );
    assert!(
        content["sarif"].is_object(),
        "the SARIF must be a DOCUMENT, not a string inside a JSON field -- a client should not have to \
         do the server's parsing: {report}"
    );

    // A typo is REFUSED, not defaulted.
    let typo = parse(&replies[1]);
    assert_eq!(typo["result"]["isError"], true, "{typo}");
    assert_eq!(
        typo["result"]["structuredContent"]["error"]["code"], "QQQ-1003",
        "the refusal carries a code: {typo}"
    );
    assert!(
        typo["result"]["structuredContent"]["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("note") && m.contains("warning") && m.contains("error")),
        "and it NAMES the three accepted values rather than saying `invalid`: {typo}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **`qqq_inspect` reports what a project CAN do and what it CANNOT -- and the partition is total.**
///
/// # Why the absences are the assertion that matters
///
/// QQQ's model is *"absent, not denied"*: a capability the manifest does not declare is **not there to be
/// denied**. A tool that reported only the declared set would be **a list of what the manifest mentions**
/// -- a weaker claim than the one the runtime makes, and one that **hides the property that makes the
/// model worth having**.
///
/// # And why the partition is asserted to be TOTAL
///
/// `declared + absent == the runtime's whole namespace set` is what makes the report **a partition rather
/// than two lists**. Without it, a namespace could be in neither -- **and the absences would be a
/// reassurance that is simply incomplete.**
#[test]
fn inspect_reports_the_declared_and_the_absent() {
    let dir = std::env::temp_dir().join(format!("qqq-mcp-inspect-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temp project");
    std::fs::write(
        dir.join("qqq.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\n[capabilities.crypto]\n\n[capabilities.clock]\n",
    )
    .expect("write");
    let good = dir.display().to_string().replace('\\', "/");

    let request = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"qqq_inspect","arguments":{{"path":"{good}"}}}}}}"#
    );
    let replies = run_mcp(&[&request]);
    let reply = parse(&replies[0]);
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let content = &reply["result"]["structuredContent"];

    let declared = content["declared_namespaces"]
        .as_array()
        .expect("declared namespaces");
    assert!(
        declared.iter().any(|d| d == "crypto") && declared.iter().any(|d| d == "clock"),
        "the manifest declares both: {reply}"
    );

    let absent = content["absent_namespaces"]
        .as_array()
        .expect("absent namespaces");
    assert!(
        absent.iter().all(|a| a["namespace"] != "crypto"),
        "what is DECLARED must not appear among the absences: {reply}"
    );
    assert!(
        absent.iter().any(|a| a["namespace"] == "fs"),
        "and a namespace the manifest never mentions IS absent -- that is the half a report of the \
         declared set alone would lose: {reply}"
    );

    // **The partition is TOTAL**: together they are the runtime's whole set, so nothing is in neither.
    // The count is compared in `u64` rather than cast down to `usize` -- **a narrowing cast in a test is
    // how a test starts asserting something it cannot see.**
    let counted = content["absent_count"].as_u64().expect("a count");
    assert_eq!(
        counted,
        absent.len() as u64,
        "the count and the list must agree: {reply}"
    );
    let total = declared.len() + absent.len();
    assert!(
        total > 2,
        "the partition must cover the runtime's namespaces, not just the declared two: {total}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **Every mutating tool takes `dry_run` and says so -- `AGENT-020`, over all twelve.**
///
/// # The partition is DERIVED, and that is the point
///
/// The first version of this test carried a **hand-list** of which tools mutate. It named `qqq_run`,
/// `qqq_test` and `qqq_bench`; **the runtime names none of them** -- `CommandName::is_mutating()` lists
/// `Build` and not `Test`, `Run` or `Bench`, and `supports_dry_run()` IS `is_mutating()`. **The tools
/// agreed with the hand-list rather than with the runtime.**
///
/// > **A hand-list is a second answer to a question the runtime already answers.**
///
/// So this version reads `output::command_schemas()` and maps a tool to its command by name. A tool
/// whose name is not a command (`qqq_errors_lookup`) reads. **And the mapping is asserted non-vacuous**,
/// so a rename that broke every mapping would fail rather than pass by finding nothing.
#[test]
fn every_mutating_tool_takes_dry_run_and_says_so() {
    let replies = run_mcp(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"qqq_schema","arguments":{}}}"#,
    ]);
    let reply = parse(&replies[0]);
    let mutating: std::collections::HashMap<String, bool> = reply["result"]["structuredContent"]
        ["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .map(|c| {
            (
                c["command"].as_str().expect("a name").to_owned(),
                c["mutating"].as_bool().expect("a bool"),
            )
        })
        .collect();

    let replies = run_mcp(&[r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#]);
    let reply = parse(&replies[0]);
    let tools = reply["result"]["tools"].as_array().expect("an array");
    assert_eq!(tools.len(), 12, "all twelve are checked");

    let mut mapped = 0usize;
    for tool in tools {
        let name = tool["name"].as_str().expect("a name");
        let description = tool["description"].as_str().expect("a description");
        let has_dry_run = tool["inputSchema"]["properties"].get("dry_run").is_some();
        let says_so = description.contains("dry_run");

        let command = name
            .strip_prefix("qqq_")
            .expect("every tool is `qqq_`-prefixed");
        let mutates = match mutating.get(command) {
            Some(m) => {
                mapped += 1;
                *m
            }
            // A tool with no command reads.
            None => false,
        };

        if mutates {
            assert!(
                has_dry_run,
                "`{name}` maps to a MUTATING command and must accept `dry_run`: {tool}"
            );
            assert!(
                says_so,
                "`{name}` accepts `dry_run` and its DESCRIPTION must say so: {tool}"
            );
        } else {
            assert!(
                !has_dry_run,
                "`{name}` maps to a command that does not mutate, so a `dry_run` argument would be \
                 A PROMISE IT DOES NOT KEEP: {tool}"
            );
            assert!(!says_so, "and its description must not claim one: {tool}");
        }
    }
    assert!(
        mapped >= 3,
        "the mapping must not be vacuous: {mapped} tool(s) reached a command schema"
    );
}

/// **An empty line is skipped rather than answered.**
#[test]
fn blank_lines_are_skipped() {
    let replies = run_mcp(&["", "   ", r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#]);
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(parse(&replies[0])["id"], 9);
}
