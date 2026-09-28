# Agent cookbook — a reproducer for every error code

`AGENT-024`. `docs/errors.md` is the **catalogue**: what each `QQQ-NNNN` means, its cause and its
remediation. This is the **cookbook**: how to make one happen, so an agent can tell a code it read
from a code it can trust.

**The catalogue is generated and validated for completeness — every code has a cause and a
remediation. Nothing validated that a code can be *produced*.** That is the gap this page closes, and
measuring it is how the page was written: every code below was classified by **running the CLI** or by
**searching the tree**, not by reading the catalogue.

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
| **`unreachable`** | **Nothing in the tree emits it.** The code is published and cannot happen | the checker asserts it is named **nowhere** in the Rust tree |

The last two are the reason this page exists. A cookbook with only the first two would have silently
omitted **28 of the 43 codes**, and an agent that read `docs/errors.md` would have no way to tell which
of the 43 it could ever see.

### Measured, by kind

| Kind | Count | Codes |
|---|---|---|
| `cli` | **5** | `1001`, `2001`, `2002`, `6004`, `7001` |
| `test` | **10** | `1002`, `1003`, `3001`, `3002`, `3003`, `3006`, `3007`, `3008`, `6001`, `6002` |
| `src` | **18** | `1004`, `1005`, `2004`, `2005`, `2007`, `3004`, `3005`, `4003`, `4004`, `5001`, `5002`, `5003`, `5004`, `5006`, `6003`, `6005`, `6006`, `6007` |
| `unreachable` | **10** | `2003`, `2006`, `4001`, `4002`, `4005`, `5005`, `5007`, `7002`, `7003`, `7004` |

**Only 5 of 43 codes can be reproduced from the command line.** The other 38 need a Rust test, a
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
| `QQQ-1002` `InvalidComponentArtifact` | `crates/qqq-run/tests/mcp_stdio.rs` |
| `QQQ-1003` `MissingTarget` | `crates/qqq-run/tests/lang001_rust_guest.rs`, `crates/qqq-run/tests/cli.rs` |
| `QQQ-3001` `MemoryLimitExceeded` | `crates/qqq-host/tests/compatibility.rs` |
| `QQQ-3002` `FuelExhausted` | `crates/qqq-host/tests/compatibility.rs`, `crates/qqq-host/tests/engine.rs` |
| `QQQ-3003` `EpochDeadlineExceeded` | `crates/qqq-host/tests/compatibility.rs`, `crates/qqq-host/tests/engine.rs` |
| `QQQ-3006` `GuestPanic` | `crates/qqq-host/tests/compatibility.rs` |
| `QQQ-3007` `GuestOutOfBounds` | `crates/qqq-serve/tests/access.rs` |
| `QQQ-3008` `SubrequestLimitExceeded` | `crates/qqq-host/tests/subrequest_limits.rs` |
| `QQQ-6001` `InstancePoolExhausted` | `crates/qqq-run/tests/worker_pool.rs` |
| `QQQ-6002` `ListenerBindFailed` | `crates/qqq-run/tests/reap_bounded.rs`, `crates/qqq-run/tests/common/mod.rs` |

---

## The `src`-only codes

**Eighteen codes are raised by the code and reproduced by no test.** They are not unreachable — a
guest that trips them gets one — but nothing in the suite proves the path works, so a regression in
any of them is invisible.

| Code | Name |
|---|---|
| `QQQ-1004` | `WitInterfaceMismatch` |
| `QQQ-1005` | `NonReproducibleBuild` |
| `QQQ-2004` | `CapabilityPathInvalid` |
| `QQQ-2005` | `LimitOutOfRange` |
| `QQQ-2007` | `CapabilitySyntaxInvalid` |
| `QQQ-3004` | `GuestTrap` |
| `QQQ-3005` | `InvalidResourceHandle` |
| `QQQ-4003` | `CapabilityDenied` |
| `QQQ-4004` | `SecretUseFailed` |
| `QQQ-5001` | `RegistryUnreachable` |
| `QQQ-5002` | `SignatureVerificationFailed` |
| `QQQ-5003` | `LockfileOutOfDate` |
| `QQQ-5004` | `VersionUnsatisfiable` |
| `QQQ-5006` | `StoreCorrupted` |
| `QQQ-6003` | `ComponentLoadFailed` |
| `QQQ-6005` | `HostResourceExhausted` |
| `QQQ-6006` | `RequestBodyTooLarge` |
| `QQQ-6007` | `HostPanicContained` |

**What to do instead.** Treat a `src`-only code as untested surface. The next test written in its area
should reproduce it, and `tools/check_agent_cookbook.py` will move it from this table to the `test`
one the moment a test names it — the classification is re-derived, so the table cannot rot.

---

## The `unreachable` codes

**Ten codes are published and emitted by nothing.** They are named nowhere in the Rust tree, so no
command, no test and no guest can produce them.

| Code | Name | What it would take |
|---|---|---|
| `QQQ-2003` | `SecretUnresolvable` | `qqq:secrets` is declared and **not bound**; the manifest parses secret references but nothing resolves them at runtime |
| `QQQ-2006` | `RequiresFabric` | the fabric tier does not exist |
| `QQQ-4001` | `CapabilityOutOfScope` | an import reachable outside the grant set — which the design makes **impossible** (`absent, not denied`), so the code may be unneeded rather than unimplemented |
| `QQQ-4002` | `CapabilityWideningRefused` | no widening path exists to refuse |
| `QQQ-4005` | `CapabilityQuotaExhausted` | per-capability quotas are not accounted |
| `QQQ-5005` | `DependencyCapabilityEscalation` | a dependency that grants more than its parent — no registry resolution to detect it |
| `QQQ-5007` | `DependencyNotFound` | dependency resolution reports `QQQ-5001`/`QQQ-5003` instead |
| `QQQ-7002` | `UnknownSchemaSurface` | `qqqai schema` has no surface parameter |
| `QQQ-7003` | `ProtocolVersionUnsupported` | the MCP server negotiates but does not reject a version with this code |
| `QQQ-7004` | `CliFlagUnknown` | **the CLI reports `QQQ-7001` instead** — see the `cli` section |

**What to do instead.** Do not write a handler for a code in this table, and do not cite one in a bug
report: nothing emits it. If a code here *should* be reachable, the work is to raise it at the right
place — and if it should not, the work is to remove it from the catalogue, which is generated.

**This is the finding the cookbook was written to produce.** The catalogue is complete by its own
checker — *"43 code(s), every one with a cause and a remediation"* — and completeness of
**documentation** is not completeness of **behaviour**. Ten published codes are documentation of
errors that cannot occur.
