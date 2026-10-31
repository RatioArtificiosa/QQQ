# H2 + tenant-resolve + SSE + per-tenant-component live transcripts.

Captured by driving the REAL `qqqai serve` binary (debug build of this
tree) over real loopback TCP against fixture projects. Every log below is
one captured run with digests; the committed tests are the procedure and
reproduce every byte shape asserted here:
- `cargo test -p qqq-run --test cli production_serve_h2_tenant_sse_live`
  (H2 + tenant-resolve + multi-shot SSE on the production listener)
- `cargo test -p qqq-run --test cli production_serve_sse_multishot_live`
  (one stream, three guest executions, over H1 and H2)
- `cargo test -p qqq-run --test cli production_serve_tenant_components_live`
  (mTLS-attested per-tenant component selection on H1 and H2)
H1 probes use a TLS client offering `http/1.1`; H2 probes use a TLS client
offering ALPN `h2` with a hand-rolled frame layer (preface, SETTINGS,
HEADERS, DATA; connection-level frames ACKed like a real client).

Digests (`digests.txt`, sha256 over the exact response bytes named):
- h1-sse-200: REFRESHED. The one-shot `Content-Length: 13` body belongs to
  the pre-bridge era; the multi-shot bridge never ends the stream, so this
  transcript is now a bounded prefix: 200 OK head (`Content-Type:
  text/event-stream`, `Cache-Control: no-store`, `X-Accel-Buffering: no`,
  `Transfer-Encoding: chunked`) plus the first events, one per chunk. The
  digest pins this capture (head plus 9 events here); the committed
  multishot tests pin the invariant (every stream carries >=3
  byte-identical events, one guest execution per event, H1 and H2).
- h2-sse-3events-body: the de-framed payload of one H2 stream stopped
  after three events - `data: hello` x3, proving multi-shot over H2.
- h2-sse-200-body: kept - the first event's bytes, still byte-identical
  to the guest's single event (the bridge's first poll answers what the
  one-shot path answered).
- h1-tenant-mapped-200: UNCHANGED bytes - 200 for `Host:
  shop.example.com`. Reproduces byte-identically: the tenant path did
  not drift under the dispatch refactor.
- h1-tenant-unknown-421: UNCHANGED bytes - 421 `tenant-unknown-host`
  naming `evil.example.com`. Reproduces byte-identically.
- h1-components-shop-200: 200 for the shop client certificate
  (`Host: shop.example.com`): the shop component's bytes, digest-equal
  to h1-tenant-mapped-200 - one guest, two routes to it, selected by
  identity through `TenantDispatch`.
- h1-components-default-200: 200 for an authenticated-but-unmapped
  identity (`other` certificate, same `Host`): the default component
  echoes the POST body - unmapped means default, never another tenant's
  component. This pair (shop/other, same request) proves identity
  outranks `Host` for attribution on the live path.
- h1-components-loopback-421: 421 `misdirected request` for the shop
  certificate with `Host: evil.example.com`. Identity selects the
  tenant, not the listener's names: on a loopback listener the `Host`
  allow-list (`F-14` rebinding defense) still refuses unmapped names
  even when authenticated - the terse body names nothing, unlike the
  tenant table's 421 which names the host so the operator can fix the
  mapping. Layering, not contradiction.
- h2-components-shop-200-body: the H2 POST answer is the shop
  component's bytes, digest-equal to h2-sse-200-body - per-tenant
  selection runs identically on the hyper H2 driver.
- h2-negotiated-alpn=h2 h2-sse-200-status=200
  h2-tenant-unknown-status=421: the H2 driver negotiates, serves, and
  refuses exactly like H1.
- run-access.log: earlier sample (mapped 200s, unmapped 421s).
- run-access-components.log: this slice's listener. Every exchange is
  attributed to its resolved tenant - `shop` for the shop identity
  (including its loopback 421), `other` for the unmapped identity -
  with the peer-derived fallback appearing only where no identity or
  mapping exists.

What the transcripts do NOT show (proven by tests, not bytes):
- The certificate-less handshake failure: under TLS 1.3 the client's
  `connect` can return before the server's alert arrives, so the probe
  asserts on first read (`AlertReceived(CertificateRequired)`, zero
  application bytes). Pinned live in
  `production_serve_tenant_components_live` and in-process in
  `tls_required_client_auth_refuses_uncertified_clients`.
- The `Done` end: an empty event body closes the stream orderly
  (`a_live_sse_stream_ends_when_the_guest_is_done` plus the
  `event_and_done_follow_the_body` classifier pin).

Red proofs (each fails loudly when the behavior is absent; captured from
real runs, then restored byte-identical to green):
- red1: the same test against the echo fixture (no event content type)
  fails with 502 naming `(absent)` - the SSE assertion discriminates
  guest content, it does not pass on any 200.
- red2: H2 with `:authority: evil.example.com` fails with 421 naming the
  host - the H2 200 assertion discriminates tenant mapping.
- red3: with the `[server.tenants]` table removed, the mapped-host
  readiness probe never answers 200 (the loopback gate refuses the
  unlisted host) - the table drives serving, not the test client.
- red5 (red5-multishot-one-shot-closes-early.log): the multishot test
  against the pre-bridge one-shot path serves one event with
  `Content-Length: 13` then closes - `one H1 stream must carry three
  guest events, not one-and-close` fails on exactly one `data:` line.
- red6 (red6-tenant-dispatch-missing.log): the tenant-selection test
  against the pre-`TenantDispatch` tree does not compile (`E0432: no
  TenantDispatch in server`) - two components cannot be expressed
  through one dispatcher.

What is NOT claimed: trailing-header SSE over H2, a native multi-shot
guest ABI (the bridge polls the one-shot export per event - the
`no_multishot_http_guest_export_exists_yet` tripwire still holds, and a
guest export that holds the socket open remains owner-blocked),
multi-tenant isolation beyond host/identity->label attribution plus
per-component dispatch, manifest-rev beyond `unknown`, or performance.
- h1-ws-2echo: the WS two-message echo over the production listener,
  captured live from the real `qqqai serve` binary (same fixture and
  client literals as `production_serve_live_transcript`): 101 head
  with the RFC 6455 canonical accept key, two per-message guest echoes
  (`hello-ws`, `second-message`, one guest execution each), and the
  close echo. The digest pins the 159 response bytes (head + 3 server
  frames); reparse the hex dumps and rehash to verify.

Stability note (root cause found and fixed): the earlier
readiness-timeout failures (60s, `TLS GET / never answered 200` with
`tcp_connected=true tls_handshake=false`) were NOT environmental. Both
TLS live tests shared one sandbox directory
(`test-serve-h2-tenant-sse`), so they overwrote each other's
freshly-generated `cert.pem` while running in parallel: the server
served with test B's certificate while the client trusted test A's, and
every handshake failed deterministically for the full 60s. Solo runs
passed, which is exactly why it read as load flake. The fix gives each
test its own sandbox (`test-serve-h2-tenant-sse` vs
`test-serve-sse-multishot`); all four production-serve tests now pass
in parallel in under a second. The waiter still classifies
(`wait_tls_serving` reports tcp_connected / tls_handshake /
last_response / server stdout tail), and the probe now reports a
handshake as failed when the first read aborts with zero application
bytes - under TLS 1.3 `connect` can succeed before the server's alert
arrives, so connect-Ok alone does not prove a handshake.

Each .log carries the response bytes twice: decoded UTF-8 and an
`offset  hex-bytes` dump (16 bytes per row). The sha256 in digests.txt
is over the exact response bytes named by the entry, which are precisely
the concatenation of the hex dump for full-response entries - reparse
and rehash to verify. The streaming entry pins its bounded capture;
re-running captures a different-length prefix of the same infinite
stream, which is why its digest is a capture pin and its shape is a
test pin.

Load-flake watch list (no code change; re-open as a residual only if
either recurs outside a fully parallel gate):
- `f16_rapid_reset_cannot_exceed_stream_budget` (`hyper_h2.rs`, saw 0
  RST_STREAM): one full-gate run failed while the box ran the whole
  gate in parallel; passed solo three times, in the full `hyper_h2`
  suite, and in the re-run gate. The flood test asserts reset counts
  with no synchronization to the server's processing, so an overloaded
  scheduler can tip it from per-stream RSTs to a bare connection close
  - a timing shape, not a verdict change (the concurrency bound it
  guards was never touched by this slice).
- `metrics_wiring` trio (`body_bytes_are_recorded`,
  `the_peer_ip_is_one_series_key_not_one_per_request`,
  `latency_is_recorded`): one full-gate run hit `could not bind` on two
  tests plus an off-by-one count on the third - the repo-documented
  free-port race (sibling parallel tests hold the port; cross-talk then
  skews counts). Passing solo and in-suite; no limiter, metric, or
  dispatch code changed by this slice.
If either recurs outside a loaded gate, harden the test's
synchronization (f16) or port allocation (metrics) rather than the
product path; do not "fix" either by weakening an assertion.
