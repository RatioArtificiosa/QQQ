# Changelog

## Unreleased

### Security

- **cap**: model `[capabilities.ai]` (CAP-020): either-list
  grants, empty-table refusal, generator stanza, refusal
  range narrowed to CAP-021..022, `why` pin repointed.
  Red-first.

- **cap**: model `[capabilities.queue]` (CAP-019): typed
  entries with a direction enum selecting the grant (no
  widening flag to forget), named validation, generator
  stanzas for both directions, refusal range narrowed to
  CAP-020..022. Red-first.

- **cap**: model `[capabilities.kv]` (CAP-018): typed stores
  with read-by-default and explicit `write = true` widening,
  blank-store validation, generator stanzas for both grants,
  refusal range narrowed to CAP-019..022. Red-first.

- **cap**: model `[capabilities.sql]` (CAP-017): typed entries
  with named validation, query by default, explicit
  `execute = true` widening, generator stanzas for both
  grants, refusal range narrowed to CAP-018..022. Red-first.

- **wave**: Wave-1 closures and homes: REG-009/010 ticked on
  measured re-runs; SRV-022 keeps the http/1.1-only default
  (shared with the h1-only in-house path) with the existing
  test as pin; PERF rotation failures now name the bootstrap
  path at the failure site; TEST-019 wires h2spec into CI
  against a committed example server (145/145 + 146 strict
  locally green).

- **cap**: namespaces derive, stanzas prove, roots refuse:
  `fix_stanza_for` no longer prints stanzas the parser
  rejects for `sql`/`kv`/`queue`/`ai` (or any future
  namespace) — unmodelled namespaces name their state plus
  CAP-017..023 instead of guessing a schema; `Capabilities`
  gains a validated flatten catch-all so all 13 namespaces
  declare while the host binds what it models; the `Manifest`
  root denies unknown fields so `[limmits]` fails loudly.
  Red-first proofs for all four tests plus a 14th-namespace
  probe (since removed). Review follow-up: `deny` and
  `flatten` cancel out on one struct, so the denial lives on
  the inner structs and the root while the validator checks
  the catch-all — pinned both ways by new tests. Partner
  review round: non-table values refused, `secret.use`
  resolves through `crypto.secrets`, parsed stanzas must
  grant, `FsWatch` contract pinned with CAP-024 as home.

- **serve**: ping floods die on the idle bound (`F-16`
  parity): codec-level traffic never stamps activity, so a
  peer holding a connection open with cheap PING frames is
  still reclaimed on the idle deadline — the live cutoff for
  the flood class hyper answers without collapsing. Pinned by
  a test that pings inside the bound and still observes the
  idle close (red-proven by neutering the idle arm: no
  `IdleTimeout` verdict).

- **host**: clock-guard discrimination (`I-02` audit): the
  forced-tick anti-vacuity test asserted render-level
  inequality, which passes with a dead clock because sequence
  always differs. Both clock tests now assert the timestamp
  field against the pinned instant — red on a dead clock,
  green live, 20/20 loop.

- **serve**: post-deletion doc truth (`F-16` parity): the TLS
  ALPN docs tied the HTTP/1.1-only default to the h2 loop's
  absence — the loop has landed on the hyper path, so the
  default's reason is now least-surprise with `with_alpn` the
  explicit opt-in (behavior unchanged); the header-list
  ceiling notes its provenance. No behavior change.

- **serve**: delete the dead in-house h2 codec (`F-16` parity):
  `h2/{conn,frame,flow,stream,settings}` served nothing —
  `server.rs` has no h2 path, the §O-676 flood budgets run over
  hyper, and zero references existed outside the codec's own
  tests — and is deleted on parity evidence (h2spec 145/145
  plus 146/146 strict green against the hyper driver, full
  gate green). What stays, and why: `h2::hpack` (raw-h2
  speaker for the hyper conformance tests) with `h2::error`
  (the shared wire-code vocabulary it maps onto), `tls.rs`
  (live cipher/ALPN/mTLS/peer-identity policy the hyper path
  itself uses), in-house `http1` (differential oracle).
  History preserved in git; the module doc names the commit.

- **serve**: CONNECT review hardening (`F-16` parity): task
  handles prune on push at both sites through one helper
  (sequential upgrades on a long h2 connection no longer
  collect dead slots); any method at a WebSocket route takes
  the CONNECT arm, and non-CONNECT methods answer the h1-like
  400 — without it an h2 `GET` fell through to the flat
  handler and answered `200` where h1 answers `400`, a fork
  the new test caught red. Pins: prune unit, `GET`-to-WS
  400, TE-chunked reset at the framing layer, Drained
  surviving a protocol error (the error lives in the access
  record the loop already emitted).

- **serve**: WebSocket over HTTP/2 extended-CONNECT (`F-16`
  parity): the last `501` is now a mechanism — the h2 builder
  advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` (with its own
  test on the setting bytes), and `CONNECT` with
  `:protocol: websocket` at a WebSocket route answers `200`
  with only `Sec-WebSocket-Accept` (connection headers are
  forbidden on h2) while the shared frame loop runs on a
  spawned task over the upgraded stream. Refusal order mirrors
  the h1 arm minus the h1-only checks: declared body 400,
  foreign `:protocol` 501, foreign origin 403, bad version 426
  naming 13, bad key 400 — all recorded. The handshake tail
  (version, key, subprotocols) is shared with the `101` path
  through one `assemble` function so the mechanisms cannot
  disagree. A `CONNECT` without `:protocol` dies reset at
  hyper's framing layer (pinned on the wire, never framed);
  a `CONNECT` at a route with no handler falls through to an
  explicit 405. Drained/timeout connection verdicts now
  survive a cleanly closed frame loop instead of being
  overwritten by it. Pins: 8 extended-CONNECT tests (echo
  round trip with accept check and close echo over DATA,
  all six refusals, flat-route fall-through).

- **serve**: streaming hardening from review (`F-16` parity):
  the channel writer is bounded (16 pieces, `send().await`),
  restoring the socket path's stall shape — a fast handler
  behind a slow consumer waits instead of queueing without
  limit — and streaming tasks are tracked per connection with
  prune-on-push and aborted at every driver return, mirroring
  the accept loop's `JoinSet` abandon (silence matches the
  abandon, which never reaches the emit either). A declared
  h2 DATA length question was rebutted with pins, not fixed:
  both protocols dispatch declared/window-bounded bodies to
  the handler through the same shared predicate. Pins:
  seventeenth-write stalls, parked handler drops on shutdown,
  h1 declared-length and h2 DATA-without-length both 200 with
  one invocation.

- **serve**: streaming and SSE over the hyper path (`F-16`
  parity): the `501` arm for h1/h2 streaming routes is now a
  channel writer — the handler runs on a spawned task against
  `StreamWriter::channel` while the response carries the
  receiving end as `WatchBody::Stream`, so the first event
  leaves while the handler is still parked (a buffered path
  would deadlock the gated test, not merely fail it). The
  head mirrors `write_stream_head` minus framing (hyper owns
  DATA framing; no content-length/connection/
  transfer-encoding), h1 closes after the body like in-house
  shuts the socket down, and the record fires in the task with
  the outcome and bytes written. Chunked bodies on streaming
  and upgrade routes are refused before dispatch through one
  shared drain-then-400 (`drain_hyper_body` bounded like
  `drain_for_refusal`), since committing to frames or events
  with bytes in flight bypasses the body cap. Pins:
  first-event-before-return over h1 and h2 DATA, SSE codec
  byte round trip, chunked-body refusals with zero handler
  invocations, h2 shutdown-drains verdict.

- **serve**: WebSocket upgrades over the hyper path (`F-16`
  parity): the `501` arm for h1 upgrade routes is now a real
  handshake — same refusal order as `serve_ws_route`
  (non-upgrade 400, origin 403, handshake 400/426), recorded
  and closed the same way — then a `101` with the RFC 6455
  accept headers while the frame loop runs on a spawned task
  over a `HyperUpgraded` bridge (hyper 1.x speaks its own
  `rt::Read`/`Write`, so polls delegate across a cursor
  boundary). The loop, codecs, `WsSender`, and audit record
  are shared with the in-house path: `ws_conn` is generic over
  the stream and `WsContext` is owned, so one loop serves both
  transports and the driver awaits it at connection end
  (ledger slot lasts as long as frames do, `Served` maps the
  same way). h2 upgrades keep the loud 501 — extended-CONNECT
  is a separate unit. Pins: echo round trip with accept-value
  check and close echo, non-upgrade refusal, foreign-origin
  refusal.

- **serve**: TLS termination in front of the hyper drivers
  (`F-16` parity): new `serve_hyper_tls` handshakes with the
  `rustls::ServerConfig` that `TlsConfig::build` produces (so
  the cipher policy, versions, and client-auth mode stay the
  documented ones), then routes by negotiated ALPN — `h2` to
  the HTTP/2 driver, anything else to HTTP/1.1, the same
  default `Negotiated::http_version` makes — and reports the
  outcome, negotiation, and mTLS peer identity together in
  `TlsServed`, so no caller can serve on one handshake while
  reporting another's identity. `tokio-rustls` moves from
  dev-dependencies to dependencies. Pins: ALPN-`h2` and
  ALPN-`http/1.1` round trips over real loopback TLS, and mTLS
  identity naming the certificate subject.

- **serve**: the hyper path serves any stream (`F-16` parity):
  `serve_hyper_h1`/`serve_hyper_h2` take `impl AsyncRead +
  AsyncWrite + Unpin + Send + 'static` instead of `TcpStream` —
  the drivers only ever polled through `TokioIo`, so a
  server-side `TlsStream` now flows where a socket or test
  duplex flows. Pins: flat-route round trips over duplex on both
  protocols, including an h2 shutdown-drains verdict.

- **replay**: first-divergent-checkpoint bisect (`I-03` core): a
  lower-bound search over stored `(call_index, rolling_hash)`
  checkpoints, comparing hashes under an aligned-grid contract
  (tuple comparison would break binary-search monotonicity on
  index-only shifts — a review finding, fixed with red proof),
  verified against brute force on two thousand shaped inputs
  plus fixed points (empty, singleton, last-checkpoint,
  index-shift, unequal lengths). The audit sketch's version
  carried two defects — `hi = mid + 1` spins forever when the
  probe lands on `hi - 1`, and returning `lo` after early exit
  reports a matching index — both caught by the mandated
  property test before anything trusted the search.
  Rolling-hash maintenance on the record path and golden-file CI
  stay scheduled.

- **cap**: attenuable token primitives (`I-06` core): a new
  `token` module with HMAC-SHA-256 `mint`/`attenuate` chain math,
  a closed `Caveat` codec (`exp`, `calls`, everything else fails
  closed at parse), pure evaluation against caller-supplied time
  and usage, and constant-time chain verification via `subtle`.
  New workspace pins `hmac` 0.12 and `subtle` 2 (both inside
  deny.toml). Host wiring of caveats to live policy (allowlist
  subsets, call counters) stays scheduled: a constructor anywhere
  but `mint`/`attenuate` would be a second mint, and there is
  none. Pins: drop/reorder breaks the chain, attenuation never
  widens, expiry and unknown-kind refusal, doctests on every
  public item.

- **audit**: signed checkpoint primitives (`I-02` core):
  `audit_checkpoint::{checkpoint_message, sign_checkpoint,
  verify_checkpoint}` over ed25519-dalek 2.x (existing workspace
  pin, promoted to `qqq-host`), with the domain-separated layout
  `qqq-audit-checkpoint-v1\0 || seq || head || ts`. Key
  management, sink scheduling, `qqq audit verify`, and anchoring
  are the scheduled product wiring — this commit is the pure
  crypto both halves build on. Pins: round-trip plus per-field
  tamper, wrong-key refusal, signing determinism, and doctests on
  every public item.

- **host**: redirect hop chains plus cleartext transports (`I-01`,
  Phase 3): `PlainTransport` serves cleartext-vetted destinations
  only (TLS-vetted addresses refuse before dialling, mirroring
  `SystemTransport`'s refusal from the other side),
  `EgressTransport` selects per hop from the freshly vetted
  destination, and `request` follows at most the minimum of the
  tenant grant, the operational switch, and the protocol ceiling of
  3 — re-vetting every hop through the full policy, refusing
  `https`→`http` downgrades before the next hop is even resolved,
  stripping credential headers before cross-origin hops
  (forward-only), and converting a cross-origin POST to a bodyless
  GET so one origin's body is never delivered to another
  (same-origin chains keep method and body). Manifest declares both grants (`cleartext`,
  `redirects`), and `send_via` aligns the operational switch with
  the tenant grant so a declared grant is live, not believed-live.
  Pins: cleartext refused without the opt-in (no DNS, no dial),
  granted cleartext and TLS routing through the selector,
  ungranted redirect refused after the first hop, 3-hop re-vetted
  chain, downgrade refusal, fourth-follow refusal, ceiling over a
  grant of 5, credential stripping, manifest derivation, and the
  `send_via` grant/no-grant pair proving the production path.

- **host**: `send` is wired to the egress connector (`I-01`): grant
  re-check, then `SEC-009` budget charge, then vet → open →
  exchange → audit over the store's egress policy, with one
  audit row per visited hop (plus one for a terminal chain
  refusal). `StoreData` carries the `TenantEgress`
  policy (deny-all unless built from a manifest, which derives it
  from `[capabilities.http] client`) and the row buffer with a
  take-drain; a scoped thread plus fresh runtime bridges sync to
  async with no ambient assumptions. Refusal taxonomy preserved:
  ungranted, unwired, and vet-denied stay `host-not-allowed`,
  budget stays `subrequest-limit-exceeded`, connector failures map
  by direction. Pins: granted-host round trip with wire-echo
  mapping proof, vet-refusal row without dialling, failure
  mapping, untranslatable-method refusal, manifest-derived policy.

- **deps**: wasmtime 48.0.5 → 48.0.6 plus wasmtime-wasi to match
  (`RUSTSEC-2026-0352`–`0356`): four guest-reachable panics in
  async-lifted `call`, `call_async` cancellation, component
  stream/future type confusion, and guest-realloc call-to-host,
  plus a macOS/FreeBSD WASI filesystem sandbox escape. Triaged per
  SEC-014/R-04: QQQ calls `call_async` from `instance.rs` and
  drives component streams, so the four panic entries are
  plausibly guest-triggerable (panics, not escapes — availability,
  contained by the F-01 abort guard either way); the filesystem
  escape is unreachable here by construction (WASI p2 only, no
  preopens, preview-1 filesystem ABI not compiled in — asserted by
  `registering_against_a_real_linker_succeeds_and_links_no_filesystem_or_sockets`).
  No Advisories issue open. `ENGINE_VERSION` moved with the lock
  (both anti-drift tests green), hostile suite 6/6 and fuzz corpus
  5/5 green on the new engine, full host suite 613/614 with the
  single failure re-proven 3/3 green in isolation — the known
  §O-683 millisecond-boundary flake, not a taxonomy shift, and it
  stays scheduled as Phase-5 work.

- **deps**: rustls 0.23.45 → 0.23.46 (`RUSTSEC-2026-0346`–`0349`):
  derived `Debug` on client session values leaked key material,
  ECH rejection mis-ordered buffered application data, Brotli cert
  decompression pre-allocated 1 GiB pre-authentication, and an
  unauthenticated ServerHello could pin later connections to
  classical key exchange. Triaged against this tree: no custom
  `ClientSessionStore`, no `EchMode::Enable`, no `brotli` feature —
  so the first three are not reachable in QQQ configuration, while
  the key-share-prediction downgrade plausibly touches the egress
  client (default resumption) and is closed by the upgrade either
  way. No Advisories issue open; `cargo deny check` green.

- **serve**: the Option A serving transport begins with its seam
  (`F-16`): `RequestHead`/`Response`/`Transport` types plus
  `HyperLimits` (every audit-named flood knob mapped from
  `ConnectionConfig`, QQQ budgets staying in middleware) applied to
  the real hyper 1.x builders. Hyper 1.12.0, MIT — inside deny.toml,
  no direct `h2` dep. Review-driven corrections in the same seam:
  the H2 PING cadence is a separate `h2_ping_interval` (PINGs are not
  an idle bound; `idle_timeout` rides along for the serve path to
  enforce), every builder gets a `TokioTimer` (hyper panics on a
  timeout without one), and the response-body budget is documented as
  serve-path-enforced, not already observed. In-house paths
  untouched; the serve-path commit lands the flood acceptance tests
  green next.

- **serve**: the Option A hyper path serves flat routes (`F-16`):
  `serve_hyper_h1` drives hyper's HTTP/1.1 connection with the same
  pipeline as the in-house path — same gates in the same order
  (loopback `Host`, process budget, tenant limits, auth), bodies
  through the shared `BodyReader` (chunked counted directly, since
  hyper delivers it decoded), dispatch through `dispatch_off_thread`,
  render validated by the new `validate_outbound` F-02 gate against
  `max_response_body_bytes`, plus QQQ-side idle, drain, and
  per-connection-ceiling enforcement hyper cannot express. A 22-test
  differential suite pins agreement with the in-house oracle row by
  row, including the documented deltas: hyper strips
  `Content-Length` beside `Transfer-Encoding`, answers some parse
  failures natively, and writes canonical reason phrases. WebSocket
  and streaming routes answer loud `501` until the parity commit.
  In-house paths untouched; no deletion.

- **serve**: the Option A hyper path serves HTTP/2 (`F-16`):
  `serve_hyper_h2` drives hyper's H2 connection through the same
  pipeline - `:authority` synthesised as the first `host` header
  (disagreeing `host` refused as `DuplicateHost`), undeclared bodies
  streamed to the shared cap, every QQQ control mapped
  (`max_concurrent_streams`, `max_header_list_size`, both reset
  budgets, PING cadence plus a new explicit `h2_ping_ack_timeout`,
  body ceiling) or enforced QQQ-side (idle, drain, per-connection
  ceiling). A 16-test raw-socket suite pins it: concurrent opens
  against a blocked service are cut off by the reset budget with the
  connection reclaimed (plus a knob-contrast proof the budget is the
  cause), sequential resets are absorbed, and multiplexing, the
  421/TE refusals, and keep-alive/idle/drain/ceiling parity all hold.
  Measured gap, recorded in-test rather than relaxed silently: 100k
  PINGs and 10k SETTINGS are answered/acked without collapse but NOT
  cut off - hyper 1.12 over h2 0.4.20 auto-acks both at the codec
  level with no rate knob (verified in the h2 source), so the
  `§O-676` `GOAWAY(ENHANCE_YOUR_CALM)` cutoff is inexpressible on
  this stack; the tests are named for what they pin and the flood
  stays symmetric (17 bytes each way), single-slot, idle-bounded.
  Specified difference from the in-house path, pinned with red proof: the
  ceiling counts attempted answers including reset streams (a dead
  stream must not kill its h2 siblings, so the ceiling carries the
  bound the in-house socket-close carried). In-house paths
  untouched; no deletion.

- **serve**: the hyper drivers track idle as inactivity, not wall
  time (`F-16`): the first version slept the bound once from
  connect, killing active connections exactly like idle ones — the
  in-house `Connection` accrues idle only between requests, never
  mid-request. An `IdleWatch` shared by both drivers stamps every
  answered request, guards each flight through cancellation, polls
  for no-flight plus no-recent-activity on subdivided ticks, and
  stamps response sends per 16KB body poll (single-frame bodies
  poll once no matter the size, so one stamp per response would
  cover only the send's start). Fully stalled sends still reclaim.
  Known residual, measured not hidden: hyper front-loads polls up
  to its write quantum, so a trickle slower than quantum-per-bound
  under a tiny bound can reclaim mid-send where in-house never
  would — defaults immune by roughly two orders of magnitude, and matching
  it exactly needs a send-completion signal hyper withholds.
- **serve**: flood tests deterministic under CI starvation (`F-16`):
  the PING test splits into strict 1k-answered plus 100k
  survival-via-fresh-connection (an undrained 100k blast outruns
  every absolute bound on a starved runner); the reset-budget knob
  raises both budgets (either fires under pressure); the
  sequential test raises the pending-accept budget beside the
  ceiling; the multiplex harness sorts interleaved answers by
  stream with a deterministic slow/fast proof. Past-ceiling 503s
  are recorded and metered, and records describe post-validation
  wire bytes, so refusals and caps never split the log from the
  wire.

- **serve**: the request line must be ASCII outright (`I-07`
  differential finding): the nightly fuzzer caught U+2001 (EM QUAD)
  prefixed to `GET` trimming into a valid method via `str::trim`'s
  Unicode whitespace while httparse refused — a tolerance mismatch with
  smuggling shape. The server now refuses non-ASCII request lines as its
  own policy (the request line is method SP target SP version per RFC
  9112 §3), with a red-first F-04 table row and the crash bytes promoted
  as a reject row. No allowlist entry: allowlists record intentional
  differences.

- **serve**: TLS defaults to HTTP/1.1-only ALPN (`F-16`, Option A decided
  2026-10-12): with no h2 dispatch loop in the server, offering `h2`
  first negotiated clients into an unserved protocol (RFC 9113 §3.2 gives
  `h2` that meaning). `TlsConfig::new` now offers exactly `http/1.1`;
  `ALPN_ALL` still documents the future set and `with_alpn` stays the
  explicit opt-in once the h2 loop exists under its own gate. A red-first
  test pins the default; all 21 TLS integration tests use explicit
  overrides. No TLS/h2 wiring in this change — migration is a follow-up.

- **host**: the egress connector vets URLs before any socket opens
  (`I-01`): `is_forbidden_ip` screens the canonical-mapped address
  against the v4/v6 forbidden tables (loopback, private, link-local,
  metadata, CG-NAT, 6to4, Teredo, NAT64 and the rest, one test row per
  table row); `vet` parses strictly, checks the tenant grant, resolves
  once through an injectable resolver, and refuses on ANY forbidden
  answer — never filter-and-continue. Literals never touch DNS. The
  connector dials only vetted addresses (TCP with timeouts, TLS against
  OS roots with SNI plus verification of the vetted name), speaks one
  capped HTTP/1.1 round trip (chunked decoded, trailers dropped,
  over-cap bodies refused as errors, redirects refused with no hop
  chain), and emits one audit row per call with byte counts, never the
  body. A libFuzzer target feeds arbitrary URL strings through vetting
  (2.15M executions, ASan, clean) and is wired into the nightly matrix.
  `send` stays refused; wiring comes later.

- **serve**: the HTTP/1.1 head parser is now fuzzed differentially against
  `httparse` (`I-07`): a nightly target parses the same bytes with both
  and aborts on any field disagreement when both accept, or on any input
  QQQ accepts that the reference rejects (QQQ stays the stricter parser;
  its refusals are by design). Seeded with every `F-04` table row, wired
  into the nightly fuzz schedule with crash artifacts, and backed by a
  regression corpus that pins the rows on stable Rust. The first 10-minute
  run (15.5M executions, ASan, Linux) is clean with an empty allow-list.
  (`I-07`)

- **serve, host, cap**: integer overflow in release now panics instead of
  wrapping ‐ per-package `overflow-checks` for the three security-critical
  crates, so the parsers, limiters and capability engine run the same
  arithmetic the tests exercise. The Wave-0 advisory lints (`unwrap_used`,
  `expect_used`, `indexing_slicing`, lossy casts) are deny in those crates,
  with `saturating_*`/`checked_*`/`.get()` conversions across 13 parser and
  accounting modules at zero warnings; the workspace is on edition 2024,
  migrated one crate at a time with the full suite green between each (the
  migration deleted a stale `WASMTIME_COMPONENT_MODEL_ASYNC_STACKFUL` gate
  the gate test proved gone in Wasmtime 48). Measured cost of the checks on
  the `parse_head` hot path is below the noise floor (200,000 parses:
  191.3 ms on vs 196.1 ms off, medians of 3 on the same machine).
  (`F-18`)

- **serve, host**: every HTTP/1.1 parse error now closes the connection —
  one unified rule replacing the subset method (`closes_connection`
  deleted; the old keep-alive-after-414 described a socket the server had
  already shut down). A tab anywhere in the request line is refused
  (previously only tab separators were; a tab inside the target was
  accepted — probed, then fixed with an F-04 table row). Stale comments
  corrected against shipped code: the `RawWaker` note (safe wakers exist
  via `Waker::noop`), the F-10 admission test doc, and the workspace tier
  labels (target tier, not done-ness). The Latin-1 and `MAX_ESCAPED_RUN`
  docs already matched. (`F-23`)

- **run**: the epoch ticker parks on the deadline-scaled period instead of
  sleeping 1 ms — one lineage wakes ~10/s at the default 100 ms tick
  rather than 1,000/s forever. One process-wide thread serves every
  lineage (replacing per-lineage threads): engines register weakly and
  prune out every pass, each entry accrues ticks at its own rate from
  measured elapsed with no credit for pre-registration idle time, lock
  poison recovers instead of silently unticking, and shutdown needs no
  join because dropping the last handle unregisters. Tick counts are
  ceiling-rounded with a minimum of 1, and the catch-up and
  Windows-granularity handling survive unchanged. Measured: an idle 10 ms
  engine draws 100 ticks in 1.03–1.04 s (three runs), the trap test lands
  inside deadline + 2 ticks + tolerance, and three new doctests hold the
  api-examples ratchet at its allowance. (`F-17`)

- **cap**: serialized `GrantSet` and `Resolution` blobs no longer
  deserialize back into authority — data cannot construct it. The manifest
  remains the authorized construction input and overlays only narrow the
  result. Serialization for `why` and audit output stays; a compile-time
  guard fails the build if the derive returns; monotonicity sweeps 200
  deterministic-random overlays and commutativity sweeps 200 overlay
  pairs. (`F-15`)

- **host**: WebAssembly threads are disabled in every mode, not only
  deterministic mode. An interim diagnostic proved the hang real: a guest
  parked in `memory.atomic.wait32` ignores the epoch deadline, pinning one
  worker thread per malicious request. Shared-memory modules now fail to
  compile on the production engine with an error naming threads; the
  deterministic refusal test stays as defence in depth. No thread-spawn
  host function exists, so nothing legitimate used shared memory. (`F-22`)

- **serve**: `qqqai serve` accepts `--deterministic` (fixed clock, seeded
  RNG) on loopback listeners only; a non-loopback listener needs the
  explicit `--allow-deterministic-public`, otherwise startup is refused
  before anything binds. Either active mode prints a loud startup warning
  and reports it in the JSON. Guest randomness in deterministic mode now
  comes from a SHA-256 hash DRBG (fixed seed, per-block counter, atomically
  reserved) instead of splitmix64 — reproducible across architectures with
  uniform output. Still reproducible by design (the seed is fixed and
  public): the gate above is what keeps reproducible randomness off
  production, never the mixer.
  The first-bytes pin changed intentionally (`36cfb6d2be11236b`); replay
  fixtures still reproduce because replay consumes recorded values, never
  the generator. (`F-20`)

- **serve**: WebSocket upgrades check `Origin` (same-origin by default,
  requests without an `Origin` header are accepted, mismatch refused 403
  pre-upgrade, `*` an explicit opt-in sharing the CORS origin type), loopback listeners
  refuse foreign `Host` values with 421 on every route (DNS-rebinding
  defence), and buffer caps default to 1 MiB frames / 1 MiB messages under
  a 64 MiB process-wide budget — configurable to the previous 16 MiB /
  64 MiB absolute ceilings, with over-cap closing 1009. Refusals and the
  close echo drain the peer (close, half-close, read to EOF/close/2 s
  timeout/8 MiB cap) before teardown so the close-frame bytes reach the
  peer before the TCP FIN instead of being lost to a reset on stacks
  that discard buffered bytes. (`F-14`)

- **serve**: tenants are keyed by IP prefix (`TenantKey`: exact IPv4, /64
  IPv6 with canonical mapped addresses) instead of the textual address, so
  rotating addresses inside one IPv6 /64 no longer buys fresh limits; the
  rate windows are fixed-size sharded buckets that cannot fill (collisions
  share, never evict), and a process-wide admission budget sheds rotation
  floods with 503 + `Retry-After`. (Rotating across /64s or across IPv4
  addresses still changes identity — the prefix is the unit, not the
  address.) The per-tenant connection fallback is 256, down from
  10,000. Trusted-proxy identity (forwarded headers behind configured
  proxies) is explicitly deferred, not half-built. (`F-13`)

### Changed

- **ci**: install `wasm-tools` before the gate, not after it. The
  gate runs guest-build tests and WIT validation that shell out
  to the binary, but the install step sat below the gate — so
  seven consecutive windows runs failed with `wasm-tools not
  found on PATH` the moment the runner image stopped preprinting
  it, each burning a full gate run to report an infra absence as
  test failures. The file's own convention ("the job provides
  the tools, the gate only runs them") now holds for this tool
  too; a runner that cannot obtain it still fails loudly at the
  install step instead of mid-gate. (`§O-725`)

- **audit**: the millisecond-boundary flake in
  `two_identical_events_render_identically` gets its durable fix
  (§O-683): `AuditStream` carries an injectable clock, wall time by
  default, pinned by `set_fixed_clock_for_test` in tests. The test
  pins both streams to the same instant, and a companion test
  proves a forced tick moves the render — so the seam is read, not
  stored-but-ignored. Production rows still carry wall time;
  nothing else changes. (`I-02` prep, `DET`)

- Developer gate unified (`I-08` phase 1): `cargo xtask ci` runs the union
  of the CI Rust job and the bridge checks — format, lints, build, test,
  ignored suites, every checker with its liveness proof, the release probe
  — in parallel where independent with summary aggregation, and both
  `ci.yml` and `docker/entrypoint.sh` call it. The gate-parity checker
  stays as the backstop (now `xtask`-aware); fault injection runs on `git
  worktree` copies, never the real tree. Phase 2 (porting checkers to Rust,
  semver/structure tooling) is explicitly out of scope.
  (`I-08`)

- **build**: the bridge and the gate agree about what runs them. Five Linux
  bridge findings from the unification, each fixed with its own red proof:
  `cargo` subcommand prerequisites (`cargo-deny`, `cargo-machete`) are now
  installed at runtime in `docker/entrypoint.sh` beside the gate, because the
  bridge image never carried them and the old bridge path never ran them;
  `check_error_standard.py` picks its binary by platform and reads
  `CARGO_TARGET_DIR`, instead of executing the first existing name (which on
  the bind-mounted bridge was the host's PE binary — `Exec format error`);
  the xtask worktree path comparison canonicalizes both sides, so git's
  resolved path matches the caller's unresolved one on macOS and Windows;
  and the bridge container's memory limit is 16 GiB, explicit, because the
  full test suite peaks past 8 GiB and was OOM-killed at exactly
  8.00/8.00 GiB in a targeted reproduction. The binary-consuming checker now
  runs sequentially after `build` in the gate's step table.
  (`I-08`, `bridge`)

- **audit**: the capability-use record format moved from v1 to v2
  (`timestamp_unix_ms` on every row, HMAC-SHA-256 chain when
  `--audit-hmac-key-file` is given). Old files keep verifying: the
  reader accepts v1 rows (no timestamp, unkeyed chain) and v2 rows,
  and refuses anything else rather than misreading it. New rows are
  always v2. (`F-09`)

## v0.1.1 - 2026-10-05

### Security

- **deps**: Wasmtime 48.0.3 to 48.0.5 for RUSTSEC-2026-0321 through RUSTSEC-2026-0327
  (`ENGINE_VERSION` 48.0.3 to 48.0.5; `wasmtime-wasi-http` documented negative,
  not in the resolve) — triaged in issue #4, patched in `37c3636`
- **deps**: yanked transitive `yoke-derive` 0.8.3 to 0.8.4 (`Cargo.lock` only,
  Wasmtime stays at 48) — triaged in issue #3, patched in `de908e7`

## v0.1.0 - 2026-09-24

### Added

- QQQ v1 design corpus, repo foundation, and verified architecture claims (`96fa621a`)
- **abi**: the first QQQ application world, and the checkers that had to learn about it (`937f21f5`)
- **bench**: the benchmark harness, where §9.1's methodology is a type (`02c50ea4`)
- **bench**: the measured ABI costs, replacing section 9.3's estimates (PERF-005) (`8fd4ecb8`)
- **bench**: the ten 9.1 benchmarks, and qqqai bench to drive them (`d15b01e2`)
- **cap**: model the `[server]` section, unblocking four HTTP items (`4248f778`)
- **cap**: per-tenant isolation with a proof against cross-tenant handles (CAP-014) (`7437c29f`)
- **cap**: the restricted policy expression language (CAP-011) (`9ca34836`)
- **cap,run**: declare and build per-tenant limits from the manifest (SRV-020) (`752bd619`)
- **cli**: implement qqqai audit with SARIF output and --fail-on (CLI-016) (`38a2905e`)
- **cli**: make --help meet the 40-line commitment, with progressive disclosure (DX-013) (`08527893`)
- **docs**: publish llms.txt and llms-full.txt, generated rather than written (DOC-020) (`fbdc1b7b`)
- **h2**: restore the HTTP/2 module, join it to a connection layer, and fix a flow-control defect (`476a6ec4`)
- **host**: WASI host support, and the guest chain finally reaches a real app (`a15f29a3`)
- **host**: enforce that every host function has a WIT definition (ARCH-003) (`3d3bca98`)
- **host**: make the call-time grant re-check survive the next edit (ARCH-012) (`25f10dfe`)
- **host**: qqq-host::invoke — the call between the host and a guest (`3e0a7a04`)
- **host**: qqq:http host side, and the guest chain reaches a real application (`bd0d8c66`)
- **host**: resolve a detached trap report to source lines (HOST-009) (`31165978`)
- **host**: the Wasmtime compatibility suite and the upgrade runbook (HOST-020) (`4eeab7db`)
- **host**: the capability audit stream, append-only and hash-chained (CAP-015) (`226e3f28`)
- **host**: the qqq:http canonical ABI types, and the two gaps injections found (`e379518b`)
- **pkg**: lockfile-hash covers build config, not only resolved artifacts (CON-005) (`ec2debfb`)
- **qqq-abi**: thirteen WIT interfaces, validated against the real toolchain (`1cfcdc6b`)
- **qqq-cap**: capability vocabulary with typo-resistant parsing (`84d431d8`)
- **qqq-cap**: normalization (pipeline step 2) with host-injected environment (`c8d031e3`)
- **qqq-cap**: resolution pipeline with a provable narrowing-only invariant (`b8a02f2e`)
- **qqq-cap**: strict qqq.toml parsing and validation (`13930878`)
- **qqq-core**: implement the error model, identifiers and version types (`2abeaac2`)
- **qqq-host**: qqq:crypto random and hashing, and the tests that expired (`966007b4`)
- **qqq-host**: the first host implementations -- qqq:clock and qqq:crypto (`ae2fbfc3`)
- **qqq-host**: the grant-built linker, verified against the real toolchain (`df4956d0`)
- **qqq-host**: the instance lifecycle, with limits proven by execution (`2af298b9`)
- **qqq-host**: trap taxonomy and engine configuration (`d04feb1a`)
- **qqq-io**: the reactor -- listener, accept loop, and sharding (`5eb1d46a`)
- **qqq-run**: build and run -- the loop closes, and a component calls a capability (`b8ce3456`)
- **qqq-run**: qqqai dev -- the tier-1 reload loop (`3f6a67c4`)
- **qqq-run**: qqqai init -- adopt an existing project without destroying it (`ea46c53e`)
- **qqq-run**: the file watcher -- ignore rules and debounce (`d36efc9b`)
- **qqq-run**: the qqqai CLI with a universal machine-readable contract (`29a216c7`)
- **qqq-run**: why, caps and inspect -- the capability engine becomes reachable (`7626ddd2`)
- **qqq-serve**: response writing, and the trap-to-status policy (`6abcefc6`)
- **qqq-serve**: the HTTP/1.1 request parser, with the bomb limits (`c294baa8`)
- **qqq-serve**: the connection lifecycle -- keep-alive, timeouts, drain (`0c82dec5`)
- **qqq-serve**: the route table, and OQ-007 resolved (`a06abdf6`)
- **run**: `qqqai fmt` and `qqqai lint` over the project's language toolchain (`CLI-014`) (`da46915e`)
- **run**: `schema --all` was a no-op, and §8.3's document now exists (`ba2b71bb`)
- **run**: build a router from the manifest, making `[server]` reachable (`4fea20f9`)
- **run**: guest_handler — the four links composed into a Dispatch handler (`9805ac85`)
- **run**: qqqai openapi — an OpenAPI 3.0 document from the manifest (SRV-017) (`0206038d`)
- **run**: qqqai serve — the production server, prepared rather than merely started (`e64738e1`)
- **run**: the HTTP-to-guest bridge, and the method that cannot be expressed (`7ed818a5`)
- **run**: the HTTP-to-guest bridge, and the method that cannot be expressed (`fb726d9a`)
- **run,pkg**: `qqqai verify` — a real Ed25519 check behind an exit-status gate (`CLI-017`, `SUP-002`) (`733fb3ac`)
- **serve**: CORS with deny-by-default, and the bypasses it refuses (SRV-019) (`c2dd6f37`)
- **serve**: Server-Sent Events, and the streaming response framing it needs (SRV-010) (`f6f2c98f`)
- **serve**: WebSocket message assembly across fragments (SRV-009) (`50368047`)
- **serve**: a streaming response writer, so a handler can emit a body in pieces (`ebd28990`)
- **serve**: apply CORS headers, closing the SRV-019 wiring gap (`5b9c4d0d`)
- **serve**: dispatch streaming routes, closing the SRV-004 wiring gap (`641c4484`)
- **serve**: enforce per-tenant limits in serve_connection, closing SRV-020 (`c3cfd9c4`)
- **serve**: per-tenant request limits, and a flaky epoch test fixed (SRV-020) (`5dd539e5`)
- **serve**: serve WebSockets end to end, closing SRV-009 (`b21e5777`)
- **serve**: structured access logging with tenant and trace correlation (SRV-013) (`87776583`)
- **serve**: the WebSocket frame layer, per RFC 6455 section 5 (SRV-009) (`a8bad1ab`)
- **serve**: the WebSocket opening handshake, per RFC 6455 section 4 (SRV-009) (`e36bcfea`)
- **serve**: the default metric set, per Proposal section 10.2 (OBS-005, SRV-020) (`5096b87f`)
- **serve**: wire the metric set into serve, and bound the tenant label (OBS-005) (`97ab7139`)
- **srv**: the per-tenant connection ceiling becomes configurable, and the reset that hid every refusal (`e2a2fd45`)
- **tools**: publish the derived schemas and fail CI when they drift (CON-016) (`3b6fef00`)
- **tools**: the developer bootstrap, installing and verifying the component toolchain (FND-012) (`10abf70b`)

### Fixed

- nine CodeRabbit findings, and the two that corrected the repair (`aa38f661`)
- three CodeRabbit findings, and a stale fuzz lockfile found while checking them (`8bf74882`)
- **bench**: a separate connect deadline, and a failing target diagnosed in seconds (`9beffd17`)
- **bench**: clear every lint the bench round left, and format (`d3915f3e`)
- **build**: split planning into a pure half and an environment half (`3a8c8241`)
- **ci**: --locked on the reference-app steps, so the instrument is reproducible (`ab1d8152`)
- **ci**: `@master` requires an explicit channel, and add a check that the four copies agree (`722ee340`)
- **ci**: derive the crate list instead of enumerating it, and drop an unused dep (`b80da72c`)
- **ci**: repair the two checks the HOST-020 round broke (`4ff2c97d`)
- **ci**: rustfmt across the workspace, and make the unsafe check test code not prose (`d0ad390f`)
- **ci**: the naming harness's third injection was testing nothing (`4d9c485d`)
- **cli**: audit printed its conclusion twice, and --sarif was not pipeable (`4c0adba4`)
- **cli**: audit printed its conclusion twice, and --sarif was not pipeable (`fd672837`)
- **deps**: commit Cargo.lock after adding the qqq-io edge (`37474071`)
- **docs**: prove the xref validator detects breakage; close two real defects (`9dcc3bd4`)
- **docs**: re-record the corpus digests, and the unsafe-audit file count (`363b801f`)
- **examples**: gate the reference application, which no CI job had ever built (`eeba589e`)
- **examples**: the cap test's flake was a lock that covered one module and not the other (`4deebf10`)
- **h2**: use as_chunks for SETTINGS, a lint rustc 1.98 added and my local 1.97 could not see (`3d3a100b`)
- **host**: a capability leak — granting one clock granted both (CodeRabbit) (`a509e5fd`)
- **io**: retry the ephemeral port helper, and record two findings honestly (`415e2e71`)
- **qqq-host**: make the registration-detection tests layout-independent (`6cdc0141`)
- **qqq-host**: the epoch tests hung CI, because they proved yielding by racing a clock (`7366e0c2`)
- **review,docs**: four real defects from the external review, one of them in a contract (`a0b42bdb`)
- **run,docs**: `caps --explain` did nothing, `why` exited zero on a denial, and the count CI counts (`f1b182eb`)
- **serve**: five defects external review found in the access logger (SRV-013) (`780f583c`)
- **serve**: retry the bind, because CI lost a port race (O-137) (`0e2765ac`)
- **serve**: the reclaim sweep used the arriving tenant's window for every entry (O-139) (`41c5ad7f`)
- **serve**: the request body reaches the guest, and HEAD obeys RFC 9110 (`a7c6c534`)
- **serve**: two real WebSocket defects found by CodeRabbit (O-135) (`94c1bd39`)
- **serve**: two real limit defects from CodeRabbit, plus two doc corrections (O-138) (`926d5c86`)
- **serve,cap,run**: the per-tenant key was a name nothing produces, and three gate reds (`67ff5818`)
- **srv**: two clippy errors CI caught, the inspect report that hid the limits, and the log I read only the tail of (`22bc7036`)
- **supply-chain**: remove unmaintained rustls-pemfile, and add the ISC licence that was missing (`ad3daca9`)
- **tools**: categorize exclusions by where a file lives, not by what it is for (`5532a387`)
- **tools**: close the EOL blind spot that let a CRLF shell script reach a commit (`7a0e4d79`)
- **tools**: every inject/restore cycle left a tracked file CRLF, and no job ran both halves (`01ce32d8`)
- **tools**: give check_scope_table.py the SPDX header every tool must carry (`fe261d81`)
- **tools**: make llms.txt reproducible across platforms, found by its own drift check (`abf40170`)
- **tools**: split the exclusion lists, because a gitignored secret wants the opposite check (`15b83135`)
- **tools**: stop llms.txt churning on every commit, reproduced in a clean clone (`01451bda`)
- **tools**: the check-[4] injection stripped one citation of seven, so its check went dead (`e20334af`)
- **tools**: the checklist progress line counted two of the five markers it reports (`14e9eaf1`)
- **tools**: the corpus guard repaired the damage, then died on a name it never assigned (`4a95619c`)
- **tools**: the guard fault-injector depended on a gitignored directory, so it could never run in CI (`db587d73`)
- **tools**: the mutating corpus harness now refuses to run twice at once (`bfee205e`)

### Changed

- **ci**: derive the topology injection target instead of hardcoding it (`178e135d`)

### Documentation

- DOC-005, DOC-008, DOC-011, DOC-013, DOC-014 -- the documentation system (`79152f6b`)
- SEC-014 -- the Wasmtime advisory process, and the check it proved was missing (`59de4524`)
- correct a false tick -- HOST-016 was never implemented (O-051) (`855696e6`)
- correct the line-ending root cause I got wrong, and detect it (`b71c5552`)
- correct §O-140 — my first fix was half a fix (`029fd3f2`)
- correct §O-150 — I blamed a tool for my own malformed tool calls (`432bb2ad`)
- doctor was three defects, and the envelope had two answers to one question (`28952842`)
- make O-109's evidence reproducible rather than transcribed (`6a55c237`)
- record O-041 -- three wrong diagnoses, and the check that caught itself (`ed433c8a`)
- record O-042d -- one diagnostic, two CI-only bugs (`f2d86aac`)
- record O-044 and the audit's missing-tool distinction (`072771fa`)
- record O-049 -- five failing tests and the code was right in all five (`a8ebe306`)
- record O-050 -- the narrowing invariant, verified rather than believed (`17aa079b`)
- record O-058f -- the fault-injector that could only ever run locally (`37002fb5`)
- record O-064 -- four engine modules, and where the defects actually were (`bb7cff97`)
- record O-065 -- the security test caught a defect in the test double (`3ffbe3a5`)
- record O-066 -- the memory limit was advisory and QQQ-3001 was unreachable (`244a551d`)
- record O-067 -- path traversal passed the containment check (`de32c1c8`)
- record a check that a leak would have satisfied, and a document that was not reproducible (O-114) (`c9d9cbc7`)
- record a length field four orders of magnitude too wide (O-134) (`daa0a92d`)
- record a lifetime that reads as correct (O-133) (`04866e6e`)
- record a protocol bug only a version-switched test could find (O-132) (`53c9c9c9`)
- record a repair that was half a fix (O-139) (`9f4221e6`)
- record a topology constraint that was the design (O-131) (`d3858e35`)
- record categorizing by purpose when the property was location, twice (O-115) (`4e15d96c`)
- record five attempts at the ARCH-003 check, and the one that nearly always passed (O-111) (`0ba1e012`)
- record four features that were complete and unreachable (O-130) (`69643f9d`)
- record four measurements of ARCH-012, three of them wrong (O-109) (`c5e2f9e3`)
- record how the guest call works, and the channel that hid my own errors (`e9608dee`)
- record proving both directions of a one-sided wall (O-102) (`44412b90`)
- record that SRV-018 is blocked behind CLI-011 (`b5f373a0`)
- record that the same churn defect took three attempts, each a boundary (O-117) (`c5cb9bdd`)
- record the ABI audit -- eleven items were done, two were not (O-099) (`1d25b2a2`)
- record the CodeRabbit findings, and add a coderabbit skill (`1b1154fa`)
- record the SPDX round, and why a wrong header beats a missing one (O-101) (`bcf76482`)
- record the assumed mechanism that cost two CI failures (O-123) (`13c9cd3a`)
- record the excluded HTTP/2 module (O-120) and complete SRV-002 (`2cc7b048`)
- record the four checker corrections, and why removal beat an allowlist (O-098) (`cd451192`)
- record the gate-as-one-action rule (O-129) (`7b0ea514`)
- record the generator that reported failure and exited zero (O-112); tick CON-016, CON-004 (166/586) (`54a297e3`)
- record the hash that promised everything and covered the artifacts only (O-110) (`df92c950`)
- record the injection that left the fault in place (O-108), tick CAP-015 (160/586) (`22906a7b`)
- record the limits review, and the ratio across two of them (O-138) (`25e4560d`)
- record the local/CI lockfile blind spot (`3d8d1507`)
- record the ninth instance -- two WIT files published and invisible (O-100) (`0402658c`)
- record the three self-tests that were wrong before the code was (O-096) (`4f1d4827`)
- record the two gaps fault injection found in the ABI tests (`55b1f08e`)
- record the two generated references and the parser bugs counting caught (O-097) (`0b3c72ef`)
- record the two grammar gaps and the four readings of one condition (O-106, O-107) (`a20d793c`)
- record the verified CI outcome for the --locked fix (O-159) (`fb9bcde7`)
- record the verified CI outcome for the bench round (O-162) (`18ad4c12`)
- record the verified CI outcome for the reference-app gate (`ee414149`)
- record three bugs of one shape in the tombstone checker (O-103) (`a61a00ce`)
- record three defects in the bootstrap script, and the third was in the tool meant to prevent the second (O-113); tick FND-012 (167/586) (`9163c5ec`)
- record what "safe defaults" means for a security control (O-128) (`c603c6ed`)
- the checklist was understating the work by 26 items (`14e67b85`)
- the container guard ran, CI is green on all eleven jobs, and the model's reuse is measured (`19af4498`)
- the guest chain is complete, and what it cost to build (`ef79110b`)
- the three architecture ADRs, written to the register's own template (ARCH-001/005/013) (`63163639`)
- tick HOST-009, and record three near-misses from the round (`38c8a4e4`)
- tick HOST-020, and record three findings it produced (`fb5410af`)
- tick SRV-017, and record a false red my own verifier invented (`c45a1497`)
- **checklist**: CLI-016 and CLI-019 were implemented and unticked (`2b7a8bfe`)
- **checklist**: CLI-017's tick names the half that is real and the half that is absent (`a90b83fd`)
- **checklist**: CON-016's tick described a superseded state, so it now names all four (`4783cdb4`)
- **checklist**: SRV-018's workspace test count, re-measured instead of carried (`c8e73652`)
- **checklist**: six stale numbers in the ticked entries, re-derived from their sources (`8a2f70d0`)
- **checklist**: the eight per-module claims checked -- seven held, one drifted, two misfiled (`e27dfa10`)
- **checklist**: the three counts O-202 left open, resolved by the test runner (`2a30b38f`)
- **checklist**: two stale counts, re-derived from the tools that print them (`36ec53f3`)
- **checklist,observations**: CLI-014 ticked on re-verified behavior, and O-223 records a blind harness (`d8420172`)
- **contributing**: the runtime-vs-framework rule, and DOC-015 ticked (`341687b1`)
- **host**: correct the runbook's rollback claim, which was thinner than it read (`fefd02a7`)
- **obs**: O-174, the honest state of the tool-call-repair plugin (`8195e26b`)
- **obs**: O-175, the §4.3 order has three copies — and a correction to it (`b7d0a917`)
- **obs**: O-176, three CI failures that were one bug in three costumes (`032e48d2`)
- **obs**: O-177, the repair plugin is wired correctly and cannot catch a leak (`d3e71fd9`)
- **obs**: O-178 (the 30-commit CodeRabbit review) and O-179 (a withdrawn claim) (`02e49ab9`)
- **obs**: O-180, the handover state and the five open findings (`4e4c7773`)
- **observations**: DCO runs only on pull requests, and five commits went in unsigned (`d96c3520`)
- **observations**: O-221 and O-222 — a null-filled source file, and a falsified finding (`ad58b8ec`)
- **observations**: record the CI failure, the plan split and the scaffold bugs (`fdadecf1`)
- **observations**: record the HTTP/1.1 parser decisions (`ddf3a9ca`)
- **observations**: record the connection lifecycle decisions (`88b3a1d8`)
- **observations**: record the reactor decisions (`029cdda0`)
- **observations**: record the status policy and the lint that found a modelling problem (`3df9271d`)
- **observations**: record the watcher design and the dev reload loop (`2d3e2268`)
- **observations**: y1 audited all 188 ticked items by re-derivation, not by reading (`98e1142f`)

