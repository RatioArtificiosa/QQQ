# Agent cookbook — a reproducer for every error code

`AGENT-024`. `docs/errors.md` is the **catalogue**: what each `QQQ-NNNN` means, its cause and its
remediation. This is the **cookbook**: how to make one happen, so an agent can tell a code it read
from a code it can trust.

**The catalogue is generated and validated for completeness — every code has a cause and a
remediation. Nothing validated that a code can be *produced*.** That is the gap this page closes, and
measuring it is how the page was written: every code below was classified by **running the CLI** or by
**searching the tree**, not by reading the catalogue.

**And the first version of that measurement was wrong, in a way worth recording.** It searched the
tree for the code *string* — `QQQ-7004` — and the tree raises the code as an **enum variant**,
`ErrorCode::CliFlagUnknown`. The literal appears only in the catalogue and in a handful of places that
happen to spell it out, so **ten codes were reported as emitted by nothing when every one of them is
named in the tree**. A guard is only as narrow as its pattern (`§O-282`), and a checker that reads a
different language than the code writes measures something else (`§O-361`). The predicate now matches
the **variant** and excludes the enum declaration — which names all 44, so including it would have
matched everything and certified nothing. See `§O-374`.

```bash
python tools/check_agent_cookbook.py             # re-derives every classification below
python tools/check_agent_cookbook.py --self-test # proves the checker fires
```

---

## The four kinds, and why there are four

| Kind | Meaning | How it is verified |
|---|---|---|
| **`cli`** | A command reproduces it | the checker **runs** the reproducer and asserts the code comes back |
| **`test`** | A test reproduces it | the checker asserts the code is named in a file under `crates/*/tests/` |
| **`src`** | The code is **raised** in `src`, and **no test reproduces it** | the checker asserts it is named in a non-test `.rs` file and in **no** test |
| **`unreachable`** | Nothing in the tree names it at all | the checker asserts the **variant** is named nowhere outside the enum declaration |

The last two are the reason this page exists. A cookbook with only the first two would have silently
omitted **28 of the 43 codes**, and an agent that read `docs/errors.md` would have no way to tell which
of the 43 it could ever see.

**`unreachable` is now empty, and that is the honest result rather than a disappointment.** Every one
of the 45 codes has a construction site. What the corrected measurement does say — and it is the claim
that survives — is that **only five can be reached from a shell**, and that **30 have no test
reproducing them**.

### Measured, by kind

| Kind | Count | Codes |
|---|---|---|
| `cli` | **5** | `1001`, `2001`, `2002`, `6004`, `7001` |
| `test` | **10** | `3001`, `3002`, `3003`, `3004`, `3006`, `3007`, `3008`, `4003`, `6002`, `6003` |
| `src` | **30** | `1002`, `1003`, `1004`, `1005`, `2003`, `2004`, `2005`, `2006`, `2007`, `3005`, `3009`, `4001`, `4002`, `4004`, `4005`, `5001`, `5002`, `5003`, `5004`, `5005`, `5006`, `5007`, `6001`, `6005`, `6006`, `6007`, `6008`, `7002`, `7003`, `7004` |
| `unreachable` | **0** | *(none)* |

**Only 5 of 45 codes can be reproduced from the command line.** The other 40 need a Rust test, a
running server, or a hostile guest — which is itself the most useful thing this page can tell an
agent: *if you are debugging from a shell, you will see at most these five.*

---

## The `cli` reproducers, in full

Each block below is executed by `tools/check_agent_cookbook.py` against a project it prepares, and the
assertion is that the code appears in the output.

### `QQQ-1001` — `CompilationFailed`

Make the crate's source file not be Rust. The scaffold names it after the project (`src/p.rs` for
`qqqai new p`), so find it with `ls src/*.rs`:

```bash
printf 'this is not rust\n' > src/*.rs
qqqai build          # -> QQQ-1001
```

### `QQQ-2001` — `ManifestSyntaxInvalid`

Make `qqq.toml` not be TOML:

```bash
printf 'this is not toml [[[\n' > qqq.toml
qqqai build          # -> QQQ-2001
```

### `QQQ-2002` — `ManifestSchemaViolation`

Valid TOML, invalid manifest — an unknown top-level key:

```bash
printf 'unknown_top_level_key = 1\n' >> qqq.toml
qqqai build          # -> QQQ-2002
```

### `QQQ-6004` — `InternalInvariantViolated`

Run a command that is advertised and not implemented:

```bash
qqqai migrate        # -> QQQ-6004
```

> **The code is the wrong class, and the cookbook is where that shows.** `QQQ-6004` is
> `InternalInvariantViolated`; `migrate` emits it to mean *"not implemented yet"*. A reader who looked
> up the code would be told the host found a broken invariant, which is not what happened. See
> `§O-373`.

### `QQQ-7001` — `McpArgumentInvalid`

Pass a flag the command does not take:

```bash
qqqai build --nonsense-flag    # -> QQQ-7001
```

> **`QQQ-7004` (`CliFlagUnknown`) is the code that *should* fire here, and it fires for nothing.**
> An unknown flag **and** an unknown subcommand both report `QQQ-7001` — an MCP argument error for a
> CLI typo. `QQQ-7004` is `unreachable`. See `§O-373`.

---

## The `test` reproducers

Ten codes are reproduced by the permanent suite rather than by a command. The checker asserts the
**file** exists and names the code; run it with the code as a filter to watch it happen.

| Code | Test file |
|---|---|
| `QQQ-3001` `MemoryLimitExceeded` | `crates/qqq-host/tests/compatibility.rs`, `crates/qqq-host/tests/hostile_guests.rs` |
| `QQQ-3002` `FuelExhausted` | `crates/qqq-host/tests/compatibility.rs`, `crates/qqq-host/tests/hostile_guests.rs`, `crates/qqq-host/tests/subrequest_limits.rs` |
| `QQQ-3003` `EpochDeadlineExceeded` | `crates/qqq-host/tests/compatibility.rs`, `crates/qqq-host/tests/hostile_guests.rs` |
| `QQQ-3004` `GuestTrap` | `crates/qqq-host/tests/compatibility.rs`, `crates/qqq-host/tests/hostile_guests.rs` |
| `QQQ-3006` `GuestPanic` | `crates/qqq-host/tests/compatibility.rs`, `crates/qqq-host/tests/hostile_guests.rs` |
| `QQQ-3007` `GuestOutOfBounds` | `crates/qqq-host/tests/compatibility.rs`, `crates/qqq-host/tests/hostile_guests.rs` |
| `QQQ-3008` `SubrequestLimitExceeded` | `crates/qqq-host/tests/refusal_amplification.rs`, `crates/qqq-host/tests/subrequest_limits.rs` |
| `QQQ-4003` `CapabilityDenied` | `crates/qqq-host/tests/hostile_guests.rs` |
| `QQQ-6002` `ListenerBindFailed` | `crates/qqq-io/tests/listener.rs` |
| `QQQ-6003` `ComponentLoadFailed` | `crates/qqq-host/tests/hostile_guests.rs` |

---

## The `src`-only codes

**Thirty codes are raised by the code and reproduced by no integration test.** They are not unreachable — a
guest that trips them gets one — but nothing under `crates/*/tests/` proves the path works, so a regression in
any of them is invisible to the integration suite. (`QQQ-3009` is the partial exception: its refusal paths are
covered by the `f02_*` unit tests inside `crates/qqq-run/src/guest_handler.rs`, which is why it still counts as
`src` — the kind tracks where the reproducer lives, not whether any test exists. The checker promotes a code to
`test` the moment a file under `crates/*/tests/` names it.)

| Code | Name |
|---|---|
| `QQQ-1002` | `InvalidComponentArtifact` |
| `QQQ-1003` | `MissingTarget` |
| `QQQ-1004` | `WitInterfaceMismatch` |
| `QQQ-1005` | `NonReproducibleBuild` |
| `QQQ-2003` | `SecretUnresolvable` |
| `QQQ-2004` | `CapabilityPathInvalid` |
| `QQQ-2005` | `LimitOutOfRange` |
| `QQQ-2006` | `RequiresFabric` |
| `QQQ-2007` | `CapabilitySyntaxInvalid` |
| `QQQ-3005` | `InvalidResourceHandle` |
| `QQQ-3009` | `GuestResponseRefused` |
| `QQQ-4001` | `CapabilityOutOfScope` |
| `QQQ-4002` | `CapabilityWideningRefused` |
| `QQQ-4004` | `SecretUseFailed` |
| `QQQ-4005` | `CapabilityQuotaExhausted` |
| `QQQ-5001` | `RegistryUnreachable` |
| `QQQ-5002` | `SignatureVerificationFailed` |
| `QQQ-5003` | `LockfileOutOfDate` |
| `QQQ-5004` | `VersionUnsatisfiable` |
| `QQQ-5005` | `DependencyCapabilityEscalation` |
| `QQQ-5006` | `StoreCorrupted` |
| `QQQ-5007` | `DependencyNotFound` |
| `QQQ-6001` | `InstancePoolExhausted` |
| `QQQ-6005` | `HostResourceExhausted` |
| `QQQ-6006` | `RequestBodyTooLarge` |
| `QQQ-6007` | `HostPanicContained` |
| `QQQ-6008` | `DeterminismUnsupported` |
| `QQQ-7002` | `UnknownSchemaSurface` |
| `QQQ-7003` | `ProtocolVersionUnsupported` |
| `QQQ-7004` | `CliFlagUnknown` |

**What to do instead.** Treat a `src`-only code as untested surface. The next test written in its area
should reproduce it, and `tools/check_agent_cookbook.py` will move it from this table to the `test`
one the moment a test names it — the classification is re-derived, so the table cannot rot.

---

## The `unreachable` codes — none

**This table is empty, and it was not empty in the first version of this page.** Ten codes were
listed here as *"published and emitted by nothing"*; all ten are named in the tree, and the
paragraph above records why the measurement said otherwise. The row is kept, empty, because a
category that can only ever be populated by a mistake is worth having a name for.

| Code | Name | What it would take |
|---|---|---|

**What to do instead.** Do not write a handler for a code in this table, and do not cite one in a bug
report: nothing emits it. If a code here *should* be reachable, the work is to raise it at the right
place — and if it should not, the work is to remove it from the catalogue, which is generated.

**This is the finding the cookbook was written to produce.** The catalogue is complete by its own
checker — *"45 code(s), every one with a cause and a remediation"* — and completeness of
**documentation** is not completeness of **behaviour**. What survives the correction is the size of
the gap that is real: **40 of 45 codes cannot be reached from a shell, and 30 have no test
reproducing them**, so a regression in any of those is invisible.
