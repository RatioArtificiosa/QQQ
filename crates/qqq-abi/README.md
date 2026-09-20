# qqq-abi

The host interface definitions in WIT, and the **registry** that keeps
`qqqai inspect` and the runtime in agreement about what a capability unlocks.

Implements `QQQ-Proposal-V1.md` §6.3 and Checklist `CON-001` … `CON-016`.

## Why the WIT is a crate and not a directory of files

The WIT packages are the contract between a guest and the host. If the
`.wit` files and the host's Rust bindings could drift, a guest would compile
against an interface the host does not implement — and the failure would appear
at instantiation, in a user's deployment, rather than at build time in CI.

So `wit/` is validated in CI (`tools/check_wit.py`) and the registry in this
crate is the single place that answers "which capability unlocks which
interface". Both are checked, and neither is a hand-maintained parallel list.

## The registry, and the granularity that matters

`interface_for(capability)` maps a capability to the interface it requires.
Several packages contain **several interfaces**:

| Package | Interfaces |
|---|---|
| `qqq:clock` | `wall-clock`, `monotonic-clock` |
| `qqq:crypto` | `random`, `hashing`, `hmac`, `aead`, `signing` |
| `qqq:http` | `http`, `incoming-handler` |

That is why there are **two** mappings, and the difference is not cosmetic:

| Function | Answers | Used by |
|---|---|---|
| `interface_for(c)` | the **package** | the linker, and error messages naming a stanza |
| `interface_path_for(c)` | the exact **interface** | `qqqai inspect`, mapping an import back to a capability |

Returning the package-level answer for an import is wrong rather than imprecise:
`qqq:clock/wall-clock` would be reported as requiring whichever of the two clock
capabilities the registry happened to list first, and an artifact importing the
wall clock was reported as needing the *monotonic* clock (`§O-038b`).

`interface_path_for` returns `None` for anything it cannot name exactly, and the
caller reports that as an **unmapped interface**. An interface the host cannot
describe is a finding an auditor needs, not a detail to discard.

## WIT conventions

* Package versions are full `major.minor.patch` (`@1.0.0`) — the component
  model requires it, and a two-component version is a syntax error.
* Doc comments are part of the contract: they are what a guest author reads, and
  what the documentation generator will emit (`DOC-017`, not yet built).
* `list`, `use` and `string` are WIT keywords, and `borrow<T>` cannot be
  returned. Both bit during authoring and are recorded in the Observations.

The sets are discoverable at runtime rather than only by reading the files:
`qqqai schema --json` emits the capability catalogue, and `qqqai inspect
<artifact>` maps an artifact's imports back through this registry to the
capabilities it requires.

## Checklist coverage

`CON-001` … `CON-016`, `ARCH-007`. See `QQQ-Proposal-V1.md` §6.3.
