# qqq-pkg

The dependency manager: a content-addressed store, the lockfile, version
requirements, and the **capability diff**.

Implements `QQQ-Proposal-V1.md` §6.5 and Checklist `PKG-001` … `PKG-024`.

## The feature that is genuinely new

Proposal §5.4:

> *"`caps` is recorded per dependency. `qqqai install` prints a **capability
> diff** — 'this update adds `http.client` to `qqqai/telemetry`'. Supply-chain
> attacks today hide in code; here the **authority** delta is visible in the
> diff."*

That is why this crate exists **before** the registry does. A dependency update
that changes no code but gains `http.client` is a supply-chain event, and no
mainstream package manager can currently show it. Building the lockfile and its
diff first means the property is designed in rather than retrofitted onto a
registry built without it.

Two consequences shape the code:

* `caps` is a **first-class field**, not metadata. It participates in equality
  and in the covering hash, so a version bump that adds authority changes the
  lockfile even if the artifact digest somehow does not.
* `LockDiff` distinguishes an authority change from a version change, and
  `escalation` is a value CI can branch on rather than prose it must parse.

## Honest scope

| Area | State |
|---|---|
| `qqq.lock` read/write with a covering hash | **implemented** (`PKG-004`) |
| Capability diff between two lockfiles | **implemented** (`PKG-009` partial) |
| Version requirement parsing and matching | **implemented** (`PKG-003` partial) |
| Content-addressed store layout and verified reads | **implemented** (`PKG-001` partial) |
| **Hard-link/reflink materialization** | **not implemented** — the half that makes the store worth having |
| Full solver with backtracking | not implemented (`PKG-003`) |
| Registry client, fetching, resume | not implemented (`PKG-002`, `PKG-011`) |
| Signature verification and trust policy | not implemented (`PKG-015`) |
| The registry itself | not implemented (`PKG-006` … `PKG-008`) |

## The lockfile covers itself

`qqq.lock` is a file a human can edit, and an edited lockfile is
indistinguishable from an unedited one unless something checks. Every entry is
hashed together with a covering hash, computed over fields joined by **NUL**
separators — chosen because no field may contain a NUL, so no two distinct field
sets can produce the same digest input.

Joining with `-` or `:` would let `["a-b", "c"]` and `["a", "b-c"]` collide, and
the collision would be silent: the file would verify and the wrong packages
would install.

## Version requirements, and the rule that matters

| Form | Meaning |
|---|---|
| `1.2` | compatible — `>=1.2.0, <2.0.0` |
| `^0.2.3` | `>=0.2.3, <0.3.0` — **not** `<1.0.0` |
| `>=1.0, <2.0` | a **conjunction**; every clause must hold |
| `*` | any |

Comma lists are supported and `||` unions are not, and the distinction is the
point. A comma is a *conjunction* — the bounded range the caret already expands
into internally. A `||` is a *disjunction*, which admits versions from unrelated
ranges and hides a dependency's true span.

An earlier version rejected both together, which contradicted this crate's own
error messages: the remediation text tells the user to write `>=1.0, <2.0`.

`^0.2.3` is singled out because the naive rule passes every `^1.x` test and then
silently accepts an incompatible `0.x` upgrade. Cargo's rule is that the caret
pins everything left of the first non-zero component.

## Known gap: pre-releases are not representable

`qqq_core::Version` is strictly `major.minor.patch` and has no pre-release
field. So `^1.0.0` **cannot express** "must not adopt `1.1.0-beta.1`". The parser
is honest — it refuses `1.2.3-beta` rather than silently truncating it — but the
gap propagates into `PKG-007`'s immutability promise. Recorded in Observations
`§O-032a` with what has to change when it is lifted.

## Modules

| Module | Responsibility |
|---|---|
| `semver` | `Requirement`, `Op`, and the partial-version fill rule |
| `lock` | `Lockfile`, `LockPackage`, `LockDiff`, `CapabilityDelta` |
| `store` | `Digest`, `StoreLayout` — the content-addressed store |

## Checklist coverage

`PKG-001`, `PKG-003`, `PKG-004`, `PKG-009`. See `QQQ-Proposal-V1.md` §5.4, §6.5.
