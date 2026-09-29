# Rust recipes

Task-oriented recipes for Rust guests. Each one is **Measured** — with the command that produced it
— or **Absent**, with what to do instead, in the sense
[`docs/contributing/claims-policy.md`](../contributing/claims-policy.md) defines.

**The recipes below are the ones that can be written today**, and that is a smaller set than `§11.3`
implies. Three of the four tasks that section names are recipes for capabilities the host does not
bind, and they are listed at the end as absences rather than omitted — a reader who looks for
"connect to Postgres" should find out here why there is nothing to find.

---

## What the host actually binds

`wit/` declares <!-- qqq:claim wit-packages -->15<!-- /qqq:claim --> packages. `qqq-host`'s linker
registers <!-- qqq:claim host-bound-modules -->5<!-- /qqq:claim --> modules: the **WASI baseline**,
**three** capability modules, and `qqq:test/assertions` -- which a test runner links and nothing
grants, because an assertion interface is not a capability. The count is five and the *kinds* are
three, which is why the sentence no longer says "plus three capability modules": that was true at
four and stopped being true at five.

```bash
rg 'host_[a-z0-9_]+::register\(' crates/qqq-host/src/linker.rs
#   host_wasi::register      <- the baseline, not a QQQ capability
#   host_clock::register
#   host_crypto::register
#   host_http::register
```

Everything else — `qqq:sql`, `qqq:kv`, `qqq:fs`, `qqq:queue`, `qqq:env`, `qqq:ai`, `qqq:dns`,
`qqq:trace`, `qqq:secrets` — is **declared and not bound**. A guest that imports one of them fails
at **instantiation**, because the linker is built from the grant set alone and an unbounded import is
*absent* rather than denied.

**`qqqai inspect` is how you check before writing code:**

```bash
qqqai inspect target/qqq/my-app.component.wasm --json | jq '.data.required'
```

---

## 1. Serve an HTTP request

The whole contract is one export. `qqqai new --template http` writes it for you, and
`examples/orders-api` is a working instance of it.

**The world** (`wit/app.wit`, byte-identical to `wit/app/app.wit`):

```wit
package qqq:app@1.0.0;

world app {
  export qqq:http/incoming-handler@1.0.0;
}
```

**The handler:**

```rust
wit_bindgen::generate!({ world: "app", path: "wit", generate_all });

use exports::qqq::http::incoming_handler::{Guest, HttpError, Request, Response};

struct Component;

impl Guest for Component {
    fn handle(_req: Request) -> Result<Response, HttpError> {
        Ok(Response { status: 200, headers: Vec::new(), body: b"ok".to_vec() })
    }
}

export!(Component);
```

**The manifest** — a guest that implements the handler but whose manifest denies `http.server` cannot
be served, and a guest whose routes are undeclared is unreachable by design (NN-5):

```toml
[capabilities.http]
server = true

[server]
routes = [{ path = "/", methods = ["GET"], handler = "index" }]
default_auth = "none"
```

**Verified by** `crates/qqq-run/tests/lang003_template.rs`, which scaffolds a project, runs its own
CI steps, and asserts through `qqqai build` + `wasm-tools` that the artifact **exports**
`qqq:http/incoming-handler@1.0.0`.

---

## 2. Hash bytes on the host

**Declare the import** in your own world, and vendor the interface:

```wit
world app {
  export qqq:http/incoming-handler@1.0.0;
  import qqq:crypto/hashing@1.0.0;
}
```

```bash
mkdir -p wit/deps/qqq-crypto && cp wit/qqq-crypto.wit wit/deps/qqq-crypto/
```

**Call it.** The generated path is measured, not guessed — this compiled:

```rust
let digest = qqq::crypto::hashing::digest(
    qqq::crypto::hashing::Algorithm::Sha256,
    b"abc",
)?;                       // result<list<u8>, hash-error>
```

**The manifest:**

```toml
[capabilities.crypto]
hash = ["sha256"]
```

**Verified by** `crates/qqq-run/tests/lang002_bindings.rs`, which builds a probe that imports this
interface and asserts, through `qqqai inspect --json`, that the artifact requires `qqq:crypto/hashing@1.0.0`
and that QQQ maps it to the `crypto.hash` capability.

---

## 3. Read a monotonic clock

**Declare the import:**

```wit
import qqq:clock/monotonic-clock@1.0.0;
```

**Call it** — again measured by compiling, not by reading:

```rust
let started = qqq::clock::monotonic_clock::now();        // duration-ns, not a result
let tick    = qqq::clock::monotonic_clock::resolution(); // duration-ns
```

### The caveat this recipe has, which the others do not

**Importing `monotonic-clock` also imports `wall-clock`.** `generate_all` binds every interface in the
package, so the artifact requires both:

```text
$ qqqai inspect target/qqq/probe-clock.component.wasm
2 required capabilities from qqq:clock
  clock.monotonic      from qqq:clock/monotonic-clock@1.0.0
  clock.wall           from qqq:clock/wall-clock@1.0.0
```

**So the manifest must grant both, or instantiation fails:**

```toml
[capabilities.clock]
monotonic = true
wall      = true    # forced by `generate_all`, not by your code
```

That is worth knowing before you write it, because **`wall` is the clock a deterministic workload
must not have** — the reference application turns it off for exactly that reason. If you need the
monotonic clock without the wall clock, do not use `generate_all` for this package: give
`wit_bindgen::generate!` a `with:` mapping for `qqq:clock/wall-clock` so the interface is generated
without being imported.

---

## 4. Run untrusted code with no capabilities

This is the recipe the runtime exists for, and it needs no guest code at all — only a manifest that
grants nothing:

```toml
[capabilities]
# absent means DENIED
```

```bash
qqqai build
qqqai inspect target/qqq/my-app.component.wasm
#   This artifact imports nothing: it can reach no host capability.
#   Posture: minimal
qqqai run --manifest qqq.toml
```

**Verified by** the reference application's own posture check: `qqqai caps --manifest
examples/orders-api/qqq.toml --json` and `qqqai inspect --json` are asserted to name **the same set**,
so a grant nothing exercises cannot hide. See `crates/qqq-run/tests/lang005_reference_app.rs`.

---

## Examples

| Example | What it is |
|---|---|
| `examples/orders-api` | The reference application: the ten §9.1 workloads as routes, 57 tests, and the guest the conformance suite's execution half runs against |
| `qqqai new --template http` | A servable application in eleven files, with its own CI |
| `qqqai new --template worker`, `cli`, `lib`, `ai-tool` | **Libraries, not applications** — see the first absence below |

---

## What cannot be written yet

### Connect to Postgres

**Absent.** `§11.3` names this recipe. `wit/qqq-sql.wit` declares `qqq:sql@1.0.0`, and **the host
does not bind it**: `qqq-host` has no `host_sql` module, so `build_linker` never registers the
interface. A guest that imports `qqq:sql` fails at **instantiation**, not at first call.

**What to do instead.** There is no QQQ path to Postgres today. A guest can reach a database over
`qqq:http` as a **client** only if `[capabilities.http] client` names the host — but `qqq:http`'s
client side is registered only when that grant exists, and the reference application deliberately
leaves it out. Watch `LANG-0xx`-adjacent work on the `qqq:sql` host module; until it lands, this
recipe has nothing to teach.

### Rate limit

**Absent.** `§11.3` names this recipe. There is **no request rate limiter** in `qqq-serve`; the
`[limits]` stanza bounds memory, fuel, epochs, instances, open handles and subrequests, and
`qqq-host::admission` refuses **degenerate** limits at load time — none of which is rate limiting.

**What to do instead.** Bound the *cost* per request rather than the *rate*: `[limits] fuel` and
`epoch_deadline_ms` cap what one request can consume, and `max_instances` caps concurrency. A rate
limiter belongs in front of the server today.

### Stream a large file

**Absent.** `§11.3` names this recipe. `wit/qqq-http.wit` declares **two** interfaces — `http` and
`incoming-handler` — and neither streams. The `incoming-handler.handle` contract returns a single
`response` whose body is a `list<u8>`, so a body that exceeds memory is not expressible.

**What to do instead.** Bound the body size in the manifest and return a refusal for anything
larger. A streaming interface is a WIT change plus a host binding, and neither exists.

### And the templates that are libraries

**Absent.** `qqqai new` offers five templates and **only `http` is an application**. The other four
write no `wit/` tree and no bindings, so `qqqai build` **succeeds** and produces a component whose
world is empty:

```text
$ qqqai new p-worker --language rust --template worker && cd p-worker && qqqai build
p-worker: target/qqq/p-worker.component.wasm (287061 bytes) for wasm32-wasip2   # exit 0

$ wasm-tools component wit target/qqq/p-worker.component.wasm
package root:component;
world root {
}
```

**What to do instead.** Use `--template http`, or add the four things yourself: a `wit/` tree, a
`wit-bindgen` dependency, a `Guest` implementation, and `export!`. Check with `qqqai inspect` — an
artifact with no required capabilities is a library, not a server.
