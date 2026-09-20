# qqq-run

The `qqqai` CLI. Every command emits stable, machine-readable JSON, because the
primary consumer is an agent and the secondary consumer is a human — in that
order, deliberately (`QQQ-Proposal-V1.md` §8.2).

The binary is named **`qqqai`**. The brand is QQQ; the crate, npm package,
binary and command are all `qqqai`, because `qqq` is taken on crates.io and npm.
A build producing a `qqq` binary is a defect, and a test asserts the invariant.

## What works, and what does not

Stated as a table rather than implied, because a CLI whose surface is unclear
wastes the most valuable thing a user has — their first ten minutes.

| Command | State |
|---|---|
| `new`, `init` | working |
| `add`, `remove` | working — edits text, preserves comments, writes atomically |
| `install` | working — resolves, writes the lockfile, prints the capability diff |
| `update` | working — within the requirement by default, `--latest` to cross it |
| `build` | working — produces a real `.component.wasm` |
| `run` | working — explicit capabilities, fuel and epoch limits |
| `dev` | working — the tier-1 reload loop |
| `inspect` | working — the manifest, an artifact's imports, and `--diff` |
| `caps`, `why`, `doctor`, `schema` | working |
| `test`, `serve`, `audit`, `verify`, `trace`, `mcp`, `migrate`, `fmt`, `lint`, `bench` | **not implemented** — they report the checklist item that tracks them and exit `UNAVAILABLE` (69) |

An unimplemented command **says so** rather than pretending. A stub that looks
like it worked is worse than one that reports it is missing — especially for an
agent, which would otherwise proceed on a false success.

## The exit-code contract

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | the operation failed, and the tool worked |
| `2` | usage error — bad flags or arguments |
| `69` (`UNAVAILABLE`) | a command or environment prerequisite is not ready |
| `70` | `qqqai` itself is broken; **please report it** |

The distinction that matters most: a guest that traps exits `1`, not `70`. A trap
means "your program or your limits are wrong", and `70` means "QQQ is broken".
Conflating them sends every trapped guest to a bug tracker that cannot help.

`qqqai doctor` exits **69** when a check fails, so it is usable as a CI gate. It
returned `0` unconditionally at one point, which made it useless in the one place
it is most valuable (`§O-036b`).

## In human format, `summary()` is the entire output

`Output::emit` writes `summary()` and nothing else when the format is human. So
any data a command does not put there **does not exist for a human reader**.

This was learned by using the tool: `qqqai caps` printed "2 capabilities across
2 namespaces" and not one capability name; `why` printed a verdict and dropped
the stanza; `doctor` printed a count and withheld which checks ran. All had
correct `--json` output the whole time (`§O-036a`).

Any command whose payload matters must carry it in `summary()`, and the tests
assert on **what a user sees**, not on the struct fields behind it.

## Every command is a contract

* `--json` on every command, with a stable envelope:
  `producer`, `version`, `schema_version`, `command`, `ok`, `summary`, `data`.
* Errors carry a stable `QQQ-XXXX` code, a docs URL, a cause chain and a
  **remediation**. An error without a fix is half a job.
* `qqqai schema --json` publishes the command, error and capability catalogues
  so an agent can discover the surface without parsing `--help`.

## Modules

| Module | Responsibility |
|---|---|
| `main` | argument parsing and dispatch — the map of the whole CLI |
| `output` | the envelope, the `CommandOutput` trait, formatting |
| `build` | `qqqai build` — toolchain probing, artifact location and verification |
| `run` | `qqqai run` — grant resolution, import checking, execution |
| `dev` | the reload loop and the capability warning |
| `watch` | file watching, debouncing, ignore rules |
| `deps` | `add` / `remove` — textual manifest edits |
| `install` | resolution, `LockMode`, the capability diff |
| `update` | `VersionSource`, the two update strategies |
| `commands` | `why`, `caps`, `inspect`, `inspect <artifact>`, `--diff` |
| `new` | the scaffold generator (module named `scaffold`; `new` is a keyword) |
| `manifest_loader` | locating and parsing `qqq.toml` |

## Checklist coverage

`CLI-001` … `CLI-017`. See `QQQ-Proposal-V1.md` §5.2, §8.2, §9.3.
