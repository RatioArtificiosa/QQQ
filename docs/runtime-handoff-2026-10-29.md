# Handoff: core-runtime closure blockers (2026-10-29 work)

Three dependency-ordered core-runtime items were investigated end to end
against the tree and found blocked on owner/designer decisions — not on
code. Each dossier below names the exact item, what was tried, what cannot
be done in-tree, the decision needed, the acceptance test, the owner, and
the re-measure command. No registry files were touched.

Related checklist items added this round: `ARCH-017`, `SRV-023`, `SRV-024`
(all `[!]`, each with owner, tripwire, and re-measure command).

## 1. ARCH-017 — host/path → tenant → component mapping (lifecycle step 4)

- **Current evidence.** The runtime tenant is the peer prefix by ratified
  design (`F-13`): `tenant_of` keys on the client IP (`crates/qqq-serve/src/server.rs`),
  per-tenant limits/ledger key off it, and manifest name keys are refused at
  parse time because they could never match (`§O-185`; test
  `a_per_tenant_key_that_is_a_name_is_refused`). `Route` has no host field,
  and `a_route_with_a_host_key_is_refused_at_parse_time` (red-proven:
  removing `deny_unknown_fields` parses the key silently) pins the
  path-only router at the manifest boundary. Lifecycle step 4 reads
  `Absent`; steps 7 and 15 were flipped to `Implemented` in the same
  re-survey that confirmed this gap.
- **What was tried.** Searched for any host→tenant→component map, any
  consumer of a `Host` header for tenancy, any authenticating identity:
  none exist. `ConnectionId::tenant_label` derives from the peer only.
- **What cannot be done in-tree.** Implementing a real mapping means
  choosing the tenant identity (authenticated subject vs address) and
  adding host-dimension routing — both contradict ratified design
  (`F-13` peer-prefix tenancy; all authenticating `AuthMode`s refuse per
  `§O-181`). Writing the code unilaterally would reverse those decisions
  by stealth.
- **Decision needed.** Architect: either ratify an authenticated tenant
  identity (which unblocks the mapping and the auth modes that verify)
  or explicitly scope §4.4's mapping to a future multi-tenant deployment
  and correct the claim.
- **Acceptance test.** Lifecycle step-4 row flips to `Implemented` (or the
  §4.4 claim is corrected with owner sign-off) plus a tenant test naming
  principals instead of prefixes; `check_lifecycle_counts.py` must stay
  green throughout.
- **Owner / tripwire / re-measure.** Owner: Architect. Tripwire: an
  authenticating `AuthMode` lands or `Route` gains a host dimension.
  Re-measure: `python tools/check_lifecycle_counts.py` (step-4 row flip).
  Next look: the M7 scope gate.

## 2. SRV-023 — HTTP/2 on the production listener

- **Current evidence.** `qqqai serve` runs the in-house accept loop
  (`crates/qqq-run/src/serve.rs` → `qqq_serve::serve`), which is
  HTTP/1.1-only with no h2 driver (`SRV-022`; pinned by
  `f16_default_alpn_stays_http11_h2_is_an_explicit_opt_in`). The hyper
  driver owns h2 framing/HPACK/streams/flow-control (h2spec 145/145 +
  146/146 strict) and `serve_hyper_tls` routes by ALPN — but its only
  callers are `crates/qqq-serve/tests/*` and the `h2spec_serve` example
  harness (verified: `grep -rn "serve_hyper" crates/qqq-run/src`
  returns nothing).
- **What was tried.** Traced the production serve path end to end;
  confirmed no flag, config, or code path selects the hyper listener.
- **What cannot be done in-tree.** Promoting hyper is a transport cutover
  with security/limits parity obligations (same pre-reading gates,
  tenant limits, auth, metrics, drain) — a behavior change the goal
  (§5.4.1) reserves to an explicit decision. Quietly switching the
  listener, or silently claiming h2 is served, are both rejected
  alternatives.
- **Decision needed.** Maintainer/Architect: promote hyper to the
  production listener with parity proven, or ratify in-house
  HTTP/1.1-only and scope the `lib.rs` "HTTP/2 on a listener" row to the
  hyper transport path.
- **Acceptance test.** A real-listener h2 test through `qqai serve`
  (ALPN `h2`, multiplexed streams) plus the h2spec run; or the corrected
  claim with owner sign-off.
- **Owner / tripwire / re-measure.** Owner: Maintainer/Architect.
  Tripwire: hyper parity sign-off or claim correction. Re-measure:
  `grep -rn "serve_hyper" crates/qqq-run/src` (non-empty means wired)
  plus the h2spec command. Next look: the M7 scope gate.

## 3. SRV-024 — guest WebSocket/message and server-push event ABI

- **Current evidence.** Host transports are complete and tested: RFC 6455
  handshake/frame loop, hyper h1 `101` and h2 extended-CONNECT upgrades,
  streaming dispatch maps, SSE encoder, `F-14` upgrade policy,
  `[server.websocket]` manifest policy. What does not exist: any guest
  export that receives a WS message or pushes an event
  (`wit/qqq-http.wit` carries only the `http` and `incoming-handler`
  interfaces — `incoming-streaming` is named in a comment but no such
  interface exists), and no ws/stream marker on manifest `Route`. `build_dispatch` therefore registers guest
  handlers only — flat-only by construction. `with_websocket` /
  `with_streaming` callers are tests only; `WebSocketHandler` is
  implemented only by `Echo` and test handlers.
- **What was tried.** Implementing a host-side registration without the
  guest contract: rejected — an upgrade nobody answers is either a hang
  or a silent flat answer, both worse than the current loud fallthrough.
  The fallthrough is now pinned:
  `an_upgrade_without_a_websocket_entry_falls_through_to_flat`
  (red-proven: wiring an entry yields `101`), with the `101` tests as
  the positive control.
- **Decision needed.** Architect + registry owner: WIT guest
  message/event-stream exports (frozen `wit/` surface — coordinated
  handoff required), a manifest route-kind marker, and the host↔guest
  bridge design (per-message guest calls vs a duplex export).
- **Acceptance test.** A guest probe that echoes WS messages (and emits an
  SSE stream) over a real listener, granted and ungranted by name.
- **Owner / tripwire / re-measure.** Owner: Architect + registry owner.
  Tripwire: `wit/` gains WS/message exports. Re-measure: the guest
  WS-echo probe test plus the fallthrough pin (which must then change).
  Next look: the M7 scope gate.

## Verification evidence produced this round (kept with the goal)

- `docs/gate-evidence-2026-10-29/red-hostkey.log` — host-key test fails
  with `deny_unknown_fields` removed (parses silently), passes with it.
- `docs/gate-evidence-2026-10-29/red-ws-fallthrough.log` — fallthrough
  test fails with a WS entry wired (`101`), passes without it.
- `docs/gate-evidence-2026-10-29/xtask-ci-148-green.log` — full gate on
  the evidence commit (command, count, commit reproduced below).
