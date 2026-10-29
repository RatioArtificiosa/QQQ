Live-serve bridge evidence (2026-10-29 work): manifest `kind` marker, guest
WebSocket/SSE bridges, per-message tenant gates, and audit-tenant fix.

WHAT THIS PROVES
- `RouteKind::{Http,Ws,Sse}` parses, defaults to Http, round-trips, refuses
  unknown spellings by name (`red-routekind.log` red, `green-kinds-routekind.log` green).
- Conflicting non-HTTP kinds/paths for one handler are refused naming the
  handler (`red-kinds-conflict.log` red, green in the same green log).
- A WS message round-trips through a real guest over a live socket with
  tenant-attributed audit (`live-ws-sse-dispatch.log` green; `red-ws-echo.log`
  red when the bridge answers wrong bytes; `red-audit-tenant.log` red when the
  audit handle carries None, `green-audit-tenant.log` green after the fix).
- An SSE route through `serve` refuses a non-event guest answer with 502
  naming `text/event-stream` (`red-sse.log` red when the bridge frames
  everything, `green-sse.log` green after restore).
- `register_stateful_routes` installs WS/SSE entries by handler name
  (`red-dispatch.log` red when registration is skipped, `green-dispatch.log`
  green after restore).
- Per-message tenant gates: over-cap body closes 1009, spent rate closes 1013
  (covered in the green `guest_ws` run; see `live-ws-sse-dispatch.log`).
- HTTP/2 is proven at the hyper transport (`live-h2-transport.log`: flat 200,
  multiplexed streams share a connection) and TLS ALPN routing
  (`live-tls.log`: h2→H2 driver, h1→H1 driver) with auth/metrics parity
  (`live-auth-metrics.log`: 403 auth, metrics path). Production `qqqai serve`
  still runs the in-house H1 loop — H2 promotion stays owner handoff SRV-023.
- Independent review: `copilot-review-proxy.log` (Meta Muse proxy, Copilot
  subscription quota-exhausted). All High findings fixed in-tree; triage in
  the commit message.

HOW TO REPRODUCE
- Red/green pairs: each `red-*.log` was produced by a one-file mutation
  described in the log header, restored byte-identical before the green run
  (verify with `git diff` empty for that file after restore).
- Live transcripts: `cargo test -p qqq-run --lib -- guest_ws guest_sse
  serve::tests::non_http serve_routes` plus the hyper suites named above.
- Tree: uncommitted working state at capture; commit message names the
  checklist disposition (SRV-024 narrowed, SRV-023/ARCH-017 still carried).
