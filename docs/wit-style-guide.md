# The WIT style guide

Implements Checklist `CON-011`. Proposal §6.3 states six rules for every interface and says they
are *"enforced in review"*. Review is prose, and in this repository prose does not fail a build —
so four of the six now have a machine check and the remaining two are stated with their scope.

**This page is the prose half.** The checks are in `tools/`, and each one's module doc is the
authoritative statement of what it does and does not attempt.

---

## The rules, and who enforces each

| # | Rule (Proposal §6.3) | Enforced by | Kind |
|---|---|---|---|
| 1 | Batch-first: list-shaped operations take lists | `check_batch_first.py` | decided |
| 2 | Streaming for anything that can exceed 64 KiB | `check_wit_style.py` (the decidable half) | **judgement** |
| 3 | Explicit `result<T, E>`; no sentinels, no `-1` | `check_wit_errors.py` | decided |
| 4 | No `option<option<T>>`; model the domain | `check_wit_style.py` | decided |
| 5 | A `///` doc comment on every function | `check_wit_style.py` | decided |
| 6 | `@since(version = …)` on every published function | `check_wit_since.py` | decided |

A rule marked **judgement** is one a checker cannot decide, because it depends on a payload's
realistic size rather than on syntax. Saying so is not a gap in the enforcement; it is the
difference between a check that can be satisfied and one that generates paperwork.

---

## Rule 1 — batch-first

> *"Chatty interfaces are a defect."* — Proposal §4.5

A host interface that would naturally be called in a loop must accept a batch instead. This is the
single rule with the largest measured performance effect, because per-call ABI cost is the dominant
term in a chatty design (see [`abi-cost-measured.md`](abi-cost-measured.md)).

**Write** `get-many(keys: list<string>) -> list<option<string>>`, not `get(key)` called in a loop.

## Rule 2 — streaming

Anything whose size a guest, a network peer, or a file can decide must be a `stream<T>` rather than
`list<T>`, because a `list` is materialised in the guest's linear memory before the host sees it.

**The decidable half.** `.wit` files are checked for a declared `stream<T>` that appears in no
function signature. A stream type no function consumes is a type no caller can obtain — the
feature-with-no-caller shape (§O-130) at the type level — and it makes any review of this rule
vacuous, because the reviewer is looking for streaming that cannot exist.

**The judgement half.** Whether a given `list<u8>` is "anything that can exceed 64 KiB" depends on
what the payload means. A hash digest never will; a file body always might. This stays in review,
and the reviewer's question is *"who chooses this size?"* — if the answer is anyone but the
interface author, it is a stream.

## Rule 3 — typed errors

Every fallible call returns `result<T, E>` where **`E` is a named variant declared in the
interface**, never `string` and never an integer status. A caller in any of the five languages then
gets an exhaustive `match` rather than a comparison against constants it has to look up.

A function that genuinely cannot fail is listed by name in `check_wit_errors.py`'s allowlist, which
turns *"this cannot fail"* from an omission into a claim someone wrote down.

## Rule 4 — no `option<option<T>>`

```wit
// Wrong: three states, two meanings. The caller cannot tell "no value" from "value absent".
type depth = option<option<u32>>;

// Right: name the states.
variant depth {
    unlimited,
    absent,
    at(u32),
}
```

WIT flattens the nesting rather than rejecting it, so the compiler is silent and the ambiguity
survives to runtime. The check is complete: every occurrence is a violation, because the
deliberate version of this shape is a named variant.

## Rule 5 — documentation

> *"Document every function with a `///` doc comment — it becomes the generated docs."* —
> Proposal §6.3

A function without one appears in the interface and is absent from the published reference: the
checker cannot see it, and neither can a reader of [`wit-reference.md`](wit-reference.md).

**Scope.** The requirement applies to **`@since`-published** functions — the set the Proposal
calls published. A function carrying `@since(version = …)` has declared itself part of the
contract, and the generated docs are part of that contract. A blanket requirement over every
function would produce a check nobody could turn green, which is the outcome
`check_batch_first.py` names as *"paperwork"*.

The doc comment should carry, in this order:

1. **What the call does**, in one sentence.
2. **`# Errors`** — which error variants, and what each means to a caller.
3. **`# Panics`** — never applicable: a host function that panics violates the trap contract.
4. Anything a caller must know to use it correctly. `qqq:env`'s `get` is a good example: it says a
   guest should treat `not-allowed` as a configuration error and `unset` as a deliberate state.

## Rule 6 — `@since`

Every published function carries `@since(version = …)`. The check reads both the quoted and the
bare form, because this corpus uses the bare one (`@since(version = 1.0.0)`).

**When to add a new version.** Never. `@since` records when a function entered the contract, and a
function's version does not change when its behaviour is clarified. If a change is not
backward-compatible, that is a new function and a deprecation of the old one — see
[`contributing/claims-policy.md`](contributing/claims-policy.md) for how a claim about compatibility
is made.

---

## Writing a new interface

The order that avoids rework:

1. **Decide the capability name first.** The interface follows from it, and `qqq-cap`'s registry is
   where the mapping lives. An interface with no capability cannot be granted, so nobody can call it.
2. **Write the types before the functions.** Rules 3 and 4 are about types, and fixing a type after
   three functions use it is three edits.
3. **Make every error a variant, and give it a doc comment.** An error variant is read by a caller
   deciding what to do; `other` is not a decision.
4. **Then the functions**, shortest first: infallible queries, then fallible operations.
5. **Run all four checkers before opening a review.** They are the review's mechanical half, and a
   reviewer spending attention on a missing `@since` is attention not spent on the design.

```sh
python tools/check_wit.py             # does it parse, and does it validate
python tools/check_wit_errors.py      # rule 3
python tools/check_wit_style.py       # rules 2, 4, 5
python tools/check_wit_since.py       # rule 6
```

## What this guide does not cover

- **The WIT language itself.** See the upstream Component Model specification; `check_wit.py`
  validates with `wasm-tools`, which is the authority on what parses.
- **The interface catalogue.** [`wit-reference.md`](wit-reference.md) is generated from `wit/` and
  is the list; this page is the rules for adding to it.
- **Capability semantics.** Which capability an interface requires is `qqq-cap`'s registry, and
  `check_wit_bindings.py` verifies the two agree.
- **ABI cost.** [`abi-cost-measured.md`](abi-cost-measured.md) has the measured per-call numbers
  that make rule 1 worth enforcing.
