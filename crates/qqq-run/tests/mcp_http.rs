// SPDX-License-Identifier: Apache-2.0

//! `qqqai mcp --http` over a real socket — `AGENT-005`.
//!
//! # Why these tests open a socket rather than calling `serve_http`
//!
//! Because the transport **is** the socket. A test that called the handler would prove the protocol logic
//! and say nothing about whether a client can reach it: whether the request line is parsed, whether
//! `Content-Length` is honoured, whether a notification gets `202` and not a body, whether a `GET` is
//! refused. **Those are the failures a client sees first.**
//!
//! # Why the two transports must agree
//!
//! `mcp_stdio.rs` holds the same rules over a pipe. **A client that switched transports must not have to
//! learn a second protocol** — so the notification rule, the parse-error rule and the `-32601` rule are
//! asserted in both files, deliberately.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Start `qqqai mcp --http 127.0.0.1:0` and read the port it **announced**.
///
/// # Why the port is READ rather than chosen
///
/// Because choosing one has a race. `free_port` binds port 0, reads the number and **releases it** --
/// and between the release and the server's bind, another test can take it. **That is `§O-313`'s class,
/// and it failed on Linux while passing on Windows**: the Linux run refused to connect, because two
/// parallel tests had been handed the same port.
///
/// **A server that announces the port it bound has no window at all**, and `127.0.0.1:0` becomes a
/// legitimate request -- *"any free port, and tell me which"* -- rather than a trick a test plays.
fn start() -> Server {
    let mut child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args(["mcp", "--http", "127.0.0.1:0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("`qqqai mcp --http` must be runnable");

    let stdout = child.stdout.take().expect("stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    // The announcement is the FIRST line, written before the accept loop -- so this cannot block on a
    // connection the server has not made yet.
    std::io::BufRead::read_line(&mut reader, &mut line).expect("the server must announce its port");
    let port = line
        .trim()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("the announcement must end in a port: {line:?}"));

    Server {
        child,
        port,
        _stdout: reader,
    }
}

/// A server that is killed when the test ends, whatever happens.
struct Server {
    child: Child,
    port: u16,
    /// Held so the pipe stays open: dropping it would close the child's stdout.
    _stdout: std::io::BufReader<std::process::ChildStdout>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// POST `body` to the server and return the whole raw response.
fn post(port: u16, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write");
    stream.flush().expect("flush");
    let mut out = String::new();
    stream.read_to_string(&mut out).expect("read");
    out
}

/// The status line and body of a response.
fn status_and_body(response: &str) -> (&str, &str) {
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("a response has a header block: {response}"));
    let status = head.lines().next().expect("a status line");
    (status, body)
}

/// **`initialize` over HTTP returns a JSON-RPC result — `AGENT-005`.**
#[test]
fn initialize_over_http_answers() {
    let server = start();
    let response = post(
        server.port,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    );
    let (status, body) = status_and_body(&response);
    assert!(
        status.contains("200"),
        "a well-formed request is 200: {status}"
    );
    let reply: serde_json::Value = serde_json::from_str(body).expect("the body is JSON");
    assert_eq!(reply["id"], 1);
    assert_eq!(
        reply["result"]["serverInfo"]["name"], "qqqai",
        "and it is the SAME answer the stdio transport gives: {reply}"
    );
}

/// **`tools/list` over HTTP offers all twelve.**
#[test]
fn tools_list_over_http_offers_twelve() {
    let server = start();
    let response = post(
        server.port,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    );
    let (_, body) = status_and_body(&response);
    let reply: serde_json::Value = serde_json::from_str(body).expect("JSON");
    assert_eq!(
        reply["result"]["tools"].as_array().expect("an array").len(),
        12,
        "the transport must not narrow the surface: {reply}"
    );
}

/// **A tool call over HTTP returns structured content.**
#[test]
fn a_tool_call_over_http_is_structured() {
    let server = start();
    let response = post(
        server.port,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"qqq_errors_lookup","arguments":{"class":"70"}}}"#,
    );
    let (_, body) = status_and_body(&response);
    let reply: serde_json::Value = serde_json::from_str(body).expect("JSON");
    assert!(
        reply["result"]["structuredContent"].is_object(),
        "`AGENT-019` holds on both transports: {reply}"
    );
}

/// **A notification gets `202` and no body — the same rule as stdio.**
///
/// This is the rule that must not diverge: a client that sends a notification over HTTP and gets a reply
/// would be reading an answer to a request it never made.
#[test]
fn a_notification_over_http_is_accepted_and_not_answered() {
    let server = start();
    let response = post(
        server.port,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let (status, body) = status_and_body(&response);
    assert!(status.contains("202"), "a notification is 202: {status}");
    assert!(body.is_empty(), "and it has no body: {body:?}");
}

/// **A malformed body is one bad answer, not a dead server.**
#[test]
fn a_malformed_body_does_not_kill_the_server() {
    let server = start();
    let response = post(server.port, "not json at all");
    let (status, body) = status_and_body(&response);
    assert!(status.contains("200"), "the exchange completed: {status}");
    let reply: serde_json::Value = serde_json::from_str(body).expect("JSON");
    assert_eq!(
        reply["error"]["code"], -32700,
        "a parse error, as on stdio: {reply}"
    );

    // And the NEXT request is still served, which is the half a `return` on error would lose.
    let response = post(server.port, r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#);
    let (_, body) = status_and_body(&response);
    let reply: serde_json::Value = serde_json::from_str(body).expect("JSON");
    assert_eq!(reply["id"], 9, "the server survived: {reply}");
}

/// **An unknown method is JSON-RPC's own `-32601` here too.**
#[test]
fn an_unknown_method_over_http_is_method_not_found() {
    let server = start();
    let response = post(
        server.port,
        r#"{"jsonrpc":"2.0","id":4,"method":"qqq/nope"}"#,
    );
    let (_, body) = status_and_body(&response);
    let reply: serde_json::Value = serde_json::from_str(body).expect("JSON");
    assert_eq!(reply["error"]["code"], -32601, "{reply}");
}

/// **A non-`POST` is refused with `405` rather than served.**
#[test]
fn a_get_is_refused() {
    let server = start();
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream
        .write_all(b"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .expect("write");
    let mut out = String::new();
    stream.read_to_string(&mut out).expect("read");
    assert!(
        out.contains("405"),
        "the endpoint is POST-only and says so: {out}"
    );
}
