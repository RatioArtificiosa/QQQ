# qqq-cap

The capability engine. **This crate is the authority gate** — every other
component asks it what a guest may do, and nothing else decides.

Implements `QQQ-Proposal-V1.md` §6.2 and Checklist `CAP-001` … `CAP-024`.

## The pipeline

```
qqq.toml ──parse──> Manifest ──normalize──> ──resolve──> GrantSet ──> linker
                      (§5.3)      (real paths,     (narrowing-only
                                  real hosts)      overlays)
```

Each stage is a module:

| Module | Question it answers |
|---|---|
| `manifest` | What did the file declare? Includes `[dependencies]`, which is validated rather than ignored (`§O-033`). |
| `normalize` | Is the declaration **real**? A path is resolved, a host is checked for shape. |
| `resolve` | What is the effective grant set after every layer, with a full trace? |
| `capability` | The 24 capabilities and their namespaces. |

## The one invariant everything else depends on

**Overlays may only narrow.**

An overlay is a deployment-time policy layer. It can remove authority and can
never add it — so a compromised or mistaken deployment configuration cannot
widen what a developer wrote, and the worst case is a component that does less
than it asked for. The rule is enforced rather than documented: `narrow` refuses
an overlay that claims granting authority when it is not the manifest layer, so
a programming error cannot become a security change.

Because narrowing is an **intersection**, `GrantSet::empty().narrow(…)` grants
nothing — intersecting with the empty set is empty. This is correct and
surprising enough that the test helper builds a real grant set from a manifest
and asserts its own precondition, rather than producing a test that passes for
the wrong reason.

## Why deny-by-default is the only default

An ungranted import is **absent, not denied**. The linker is built from the
grants alone, so a guest that imports `qqq:fs/filesystem` without `fs.read`
does not get a host function that returns "permission denied" — it gets a
**link error**, because the import is not there.

The difference matters: a function that exists and refuses can be probed for
timing, error-shape and side-channel information. A function that was never
linked cannot be called at all.

| Approach | Attack surface |
|---|---|
| Grant everything, check at call time | Every host function is reachable; the check is one `if` away from a bug |
| **Build the linker from grants only** | Ungranted functions do not exist in the instance |
| Both (`linker` + call-time re-check) | Defence in depth: a linker bug is still caught |

QQQ does the third. `qqq-cap` produces the grant set; `qqq-host` builds the
linker from it *and* re-checks at call time, deliberately redundantly.

## `qqqai why`

`resolve` records a **trace** of every layer's decision, which is what makes
`qqqai why <capability>` possible: it can name the layer that decided, not just
the outcome. The trace is the mechanism; the command is the surface.

## Checklist coverage

`CAP-001` … `CAP-024`, `CON-014`, `CON-016`. See `QQQ-Proposal-V1.md` §6.2.
