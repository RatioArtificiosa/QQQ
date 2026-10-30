# H2 + tenant-resolve + SSE live transcripts on the production serve path.

Captured by driving the REAL `qqqai serve` binary (debug build of this
tree) over real loopback TCP against a fixture project (`qqq.toml` with
`/` flat, `/events` kind=`sse`, `[server.tenants]` hosts table, and
`[server.tls]`; static event-stream guest assembled from
`crates/qqq-run/tests/fixtures/sse-event.wat`).
Reproduce: `cargo test -p qqq-run --test cli production_serve_h2_tenant_sse_live`
(the test is the procedure; these logs are one captured run with digests).
H1 probes use a TLS client offering `http/1.1`; H2 probes use a TLS client
offering ALPN `h2` with a hand-rolled frame layer (preface, SETTINGS,
HEADERS, DATA; connection-level frames ACKed like a real client).

Digests (`digests.txt`, sha256 over the exact response bytes):
- h1-sse-200: 200 OK with `Content-Type: text/event-stream`,
  `Cache-Control: no-store`, `X-Accel-Buffering: no`, and the guest's
  `data: hello` body — a SERVED event stream through the `sse` route
  kind, not the 502 the echo guest (no event content type) correctly
  draws in `production_serve_live_transcript`.
- h1-tenant-mapped-200: 200 for `Host: shop.example.com` — a mapped host
  passes the loopback allow-list and the tenant gate to the dispatcher.
- h1-tenant-unknown-421: 421 `tenant-unknown-host` naming
  `evil.example.com` — an unmapped host with a configured table is
  refused before routing, limits, or auth, on the H1 driver.
- h2-sse-200-body: the H2 answer body is byte-identical to the guest's
  `data: hello` event (status 200, ALPN `h2`) — the hyper H2 driver on
  the production accept loop serves a real guest, not a refusal or a
  downgrade. The same guest bytes arrive over H1 (one dispatcher, two
  protocols).
- h2-tenant-unknown-status=421: `:authority: evil.example.com` is
  refused 421 on the H2 driver too — tenant-resolve runs before
  dispatch in each driver.
- run-access.log: the server stdout. Mapped exchanges log
  `tenant":"shop"`; the 421 refusals log the peer-derived fallback
  tenant (there is no mapped tenant to attribute a refused host to —
  the refusal names the host instead, which is the `X-QQQ-Error` row).

Red proofs (each fails loudly when the behavior is absent; captured from
real runs, then reverted byte-identical to green):
- red1: the same test against the echo fixture (no event content type)
  fails with 502 naming `(absent)` — the SSE assertion discriminates
  guest content, it does not pass on any 200.
- red2: H2 with `:authority: evil.example.com` fails with 421 naming the
  host — the H2 200 assertion discriminates tenant mapping.
- red3: with the `[server.tenants]` table removed, the mapped-host
  readiness probe never answers 200 (the loopback gate refuses the
  unlisted host) — the table drives serving, not the test client.

What is NOT claimed: trailing-header SSE over H2 (the bridge delivers
one guest answer per request — see `guest_sse.rs` one-shot semantics),
multi-tenant isolation beyond host->label attribution, or performance.
The WS two-message echo (per-message guest calls) is proven in
`production_serve_live_transcript`, not re-transcribed here.

Stability note: two readiness-timeout failures (60s, `TLS GET / never
answered 200`) were observed while iterating on red variants, then the
test passed 4 consecutive runs (0.14s each) with no code change. Cause
undetermined — consistent with the server running unbuilt (503) during
concurrent file activity, but not proven. Three consecutive green runs
were recorded after the final tree state; the committed gate log is the
standing evidence.

Each .log carries the response bytes twice: decoded UTF-8 and an
`offset  hex-bytes` dump (16 bytes per row). The sha256 in digests.txt
is over the exact response bytes, which are precisely the concatenation
of the hex dump — reparse and rehash to verify.
