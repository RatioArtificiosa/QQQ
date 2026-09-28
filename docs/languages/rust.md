# Rust

The state of QQQ's Rust toolchain. Every sentence here is one of the four kinds
[`docs/contributing/claims-policy.md`](../contributing/claims-policy.md) defines — **Measured** (with
the command that produced it), **Derived** (with the mechanism), **Intended** (with a milestone), or
**Absent** (with what to do instead). Where a number appears, it is behind a resolver rather than
typed in.

`LANG-008` asks for this page *"with honest limitations (there are few)"*. **The parenthetical is
wrong**, and saying so is the first useful thing this page can do: the limitations below are neither
few nor hypothetical, and each one was measured rather than recalled. A guide that repeated "there
are few" would be the most expensive kind of documentation error — one that reads as verified and is
discovered by someone who acted on it.

---

## What works

### Build, end to end

**Measured.** `cargo build --target wasm32-wasip2` is a native target, and `qqqai build` drives it:

```bash
cd examples/orders-api
qqqai build
# orders-api: target/qqq/orders-api.component.wasm (167387 bytes) for wasm32-wasip2
```

The artifact is a **component**, not a core module — its first eight bytes are `0d 00 01 00` rather
than `01 00 00 00`. The two share the `\0asm` magic, so a check that only looked for `\0asm` would
pass on a build that produced the wrong thing. `crates/qqq-run/tests/lang001_rust_guest.rs` asserts
the whole preamble.

### The scaffold

**Measured.** `qqqai new <name> --language rust --template http` writes eleven files, of which these
are the ones that make it a QQQ application rather than a crate:

| File | Why |
|---|---|
| `wit/app.wit` | The world — byte-identical to `wit/app/app.wit`, because it is `include_str!` of it |
| `wit/deps/qqq-http/qqq-http.wit` | The vendored interface, from `qqq-abi`'s registry |
| `rust-toolchain.toml` | The same channel the runtime pins |
| `.github/workflows/ci.yml` | `fmt`, `clippy -D warnings`, `test`, and a `wasm32-wasip2` build |

and the project passes those four steps as generated. `crates/qqq-run/tests/lang003_template.rs`
runs them and then asserts, through `qqqai build` and `wasm-tools`, that the artifact **exports**
`qqq:http/incoming-handler@1.0.0`.

### Bindings

**Derived.** `wit_bindgen::generate!` reads `wit/` while it expands, so the bindings are generated
from the same WIT the runtime publishes — there is no checked-in copy to drift. The pinned
requirement is `wit-bindgen = "0.62"`, and the scaffold emits it from one place
(`tools/mark_complete.py`'s neighbour `crates/qqq-run/src/new.rs`), held equal to the reference
application's by a test.

### The conformance row

**Measured.** Rust passes the whole suite. `conformance/suite.json` declares
<!-- qqq:claim conformance-cases -->8<!-- /qqq:claim --> cases, of which
<!-- qqq:claim conformance-definition-cases -->6<!-- /qqq:claim --> are **definitions** enforced by a
checker that runs in both gates, and
<!-- qqq:claim conformance-execution-cases -->2<!-- /qqq:claim --> **execute** against a built guest:

```bash
python tools/check_conformance.py --matrix     # rust: yes, for all 15 capabilities
cargo test -p qqq-run --all-features --test conformance_exec -- --ignored
```

---

## What does not work, or works with a caveat

### 1. The `wit-bindgen` version is load-bearing, and an older one fails outright

**Absent.** `wit-bindgen 0.44` pulls `wit-parser 0.236.1`, which requires every hyphen-separated
segment of an identifier to start with a letter. `wit/qqq-crypto.wit` names an AEAD construction
`aes-256-gcm`, so **bindings cannot be generated from the canonical `wit/` at all**:

```text
error: failed to resolve directory while parsing WIT for path [...\wit]
  Caused by: invalid character in identifier '2'
     --> ...\wit\qqq-crypto.wit:118:5
      |     aes-256-gcm,
```

**What to do instead.** Pin `wit-bindgen = "0.62"` — which is what the scaffold emits — or `%`-escape
nothing and rename nothing: the grammar was relaxed upstream, so the WIT is right and the old parser
is old. Re-derive with
`cargo test -p qqq-run --all-features --test lang002_bindings -- --ignored`.

### 2. Only the `http` template is an application

**Measured.** `qqqai new` offers five templates. Every one except `http` produces a component that
**exports nothing**, because it has no `wit/` tree and no bindings dependency — it is a pure-logic
library:

```text
$ qqqai new p-worker --language rust --template worker && cd p-worker && qqqai build
p-worker: target/qqq/p-worker.component.wasm (287061 bytes) for wasm32-wasip2   # exit 0

$ wasm-tools component wit target/qqq/p-worker.component.wasm
package root:component;
world root {
}
```

**The build succeeds and the application cannot run.** `qqq-host::invoke` resolves the export by
name, finds nothing, and `qqqai serve` has no function to call — while `qqqai build` prints a byte
count and `qqqai inspect` prints a posture word. Both commands say yes.

**What to do instead.** Use `--template http`, or add the world and the bindings yourself: a `wit/`
tree, a `wit-bindgen` dependency, a `Guest` implementation, and `export!`.

### 3. `wit/` is a `wasm-tools` layout, not a `wit-bindgen` one

**Derived.** `wit/` holds fifteen **different** packages as siblings plus one world package under
`app/`. That is legal for `wasm-tools`, which validates each file on its own, and it is not something
`wit-bindgen` can resolve: WIT resolves dependencies only from a `deps/` directory beside the
package.

**What to do instead.** Vendor the interfaces you bind into `wit/deps/<name>/<name>.wit`. The
reference application does exactly this for `qqq-http`, and `tools/check_wit_vendoring.py` keeps
every vendored copy byte-identical to its source.

### 4. Editing `wit/` does not re-run the macro

**Measured.** `wit_bindgen::generate!` reads `wit/` while it expands, but `wit/` is **not a declared
dependency** of the crate, so cargo's fingerprint does not include it:

```text
$ # edit wit/deps/... and rebuild
Finished `release` profile [optimized] target(s) in 0.13s     # nothing recompiled
```

**What to do instead.** Touch a source file after editing WIT, or you will test the previous
artifact and believe it is the new one.

### 5. The build-time budget is not met

**Measured.** `§9.2` budgets `qqqai build`, 10k LOC Rust, at **≤ 20 s**. A cold release build of the
reference application — 2,513 lines, four times smaller than the subject the budget names — takes
**25.34 s**. `PERF-013` records the full measurement and `LANG-007` is `[~]` rather than `[x]`.

**What to do instead.** Nothing yet: this is an open budget with a recorded shortfall, and hiding it
would be worse than showing it. The size half *is* met — installed footprint 19.3 MiB against ≤ 60 MB,
and it is gated in CI.

### 6. The conformance suite's execution half is thin

**Measured.** Of the suite's cases, the definitions outnumber the executions by three to one (the
claim markers above carry the current numbers). A language can therefore pass every definition
without ever running a guest.

**What to do instead.** Treat the definitions as a floor rather than a pass. `TEST-016` is the runner
and `TEST-010` grows the suite; a language row that only clears definitions has cleared a specification
rather than a result.

### 7. There is no published site

**Absent.** `§11.3` names `docs.qqq.codes` as the human documentation surface. It does not exist: no
site generator, no workflow, and no `DIST-*` item that creates one. This page is therefore *published*
in the sense that matters for this repository — indexed in `docs/README.md`, scanned by
`tools/check_doc_claims.py`, and generated into `llms.txt` for agents — and not in the sense of a live
URL.

**What to do instead.** Read it in the repository. Building the site is real work that no checklist
item currently owns.

---

## Where the numbers in this page come from

| Fact | Resolver |
|---|---|
| Cases the conformance suite declares | `conformance-cases` |
| How many of those are definitions | `conformance-definition-cases` |
| How many of those execute against a guest | `conformance-execution-cases` |

`python tools/check_doc_claims.py` fails when any of them disagrees with the tree, and
`--self-test` proves the scanner and the resolvers are live. The other numbers on this page are
**measured claims**: each names the command that produced it, in the same paragraph, as
`docs/contributing/claims-policy.md` requires.
