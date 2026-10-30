# Live production serve transcripts (narrowed serve path, manifest-driven).

Captured by driving the REAL `qqqai serve` binary (debug build of this
tree) against a fixture project (`qqq.toml` with `/` http, `/ws` ws,
`/events` sse routes; echo guest assembled from
`crates/qqq-run/tests/fixtures/echo-http.wat`), over real loopback TCP.
Reproduce: `cargo test -p qqq-run --test cli production_serve`
(same probes, same assertions; the test is the procedure, these logs are
one captured run with digests).

Digests (`digests.txt`, sha256 over the exact response bytes):
- h1-get-root: 200 OK, empty echo body (GET has no body to echo).
- ws-echo: 101 + masked `hello-ws` echoed back unmasked as text; the
  server access log carries a line for the /ws exchange naming tenant
  `127.0.0.1` (see run.log) — tenant attribution of the served exchange
  live. (The H2c preface is rejected at parse and never reaches routing,
  so it leaves no access line: the 400 bytes are the whole record.)
- sse-events: 502 `sse-content-type`, naming `text/event-stream` — the
  specified fail-closed for a guest that answers no event stream (the echo
  guest carries no content type). No silent framing of a non-event.
- h2c-preface: an H2c prior-knowledge preface draws `HTTP/1.1 400 Bad
  Request` — explicit, no upgrade, no hang. The in-house production loop
  is HTTP/1.1-only; H2 promotion stays owner handoff SRV-023.
- ws-fallthrough: an Upgrade on plain `/` answers 200, not 101 — the
  dispatcher resolves by manifest `kind`, proven by the no-kind control
  test (`production_serve_without_ws_kind_does_not_upgrade`).

What is NOT claimed: a live HTTP/2 upgrade, guest WS/SSE beyond this echo
shape, or host/path tenant resolution — owner handoffs SRV-023/SRV-024
(residual) and ARCH-017, with red-first boundary pins in-tree. The live
transcripts above prove exactly what production dispatch does today,
including its explicit refusals.

Each .log carries the response bytes twice: decoded UTF-8 and an
`offset  hex-bytes` dump (16 bytes per row). The sha256 in digests.txt
is over the exact response bytes, which are precisely the concatenation
of the hex dump — reparse and rehash to verify. All five were checked
byte-identical after capture, and every digest reproduced unchanged
across three separate production runs.

Review (Meta Muse proxy; Copilot subscription quota-exhausted):
cr-serve-live-review.log — scoped on-topic review of the two new tests
plus helpers: CLEAN. (Two earlier rounds returned stale-mixed outputs
framing an older TEST-018 diff; their actionable cli.rs items —
WouldBlock-only arms, overbroad 101 scan, tenant assertion satisfiable
by readiness polls, missing write timeouts, stale comment — were each
verified against the code and fixed in-tree before commit: TimedOut
arms, write timeouts on all sockets, graceful WS close before asserting
the access line, same-line /ws+tenant assertion, starts_with status
checks. The committed tests plus this log are the honest record.)
