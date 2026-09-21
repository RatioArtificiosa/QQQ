---
name: coderabbit
description: Run an external AI code review on this repository with the CodeRabbit CLI before committing or pushing. Use whenever a non-trivial change is complete and needs an independent professional review — especially for security posture, capability/permission logic, output-format contracts, error handling, and anything where a silent pass would be worse than a failure. Also use when the user says "have CodeRabbit check this", "get an external review", or asks whether the CLI is set up.
---

# CodeRabbit — external review for the QQQ repository

CodeRabbit reviews local Git changes with frontier models and returns structured
findings. It is the project's **independent second opinion**: it does not share the
blind spots of a test suite written by the same mind that wrote the code.

## Install state on this machine

| Item | Value |
|---|---|
| Version | `0.7.8` |
| Location | `%LOCALAPPDATA%\Programs\coderabbit` (`coderabbit.exe`, `cr.exe`) |
| Account | `RatioArtificiosa` (`disenos.superiores@gmail.com`), GitHub provider, US region |
| Doctor | 9 passed, 0 failed |

**Fresh shells only.** The installer appends the directory to the *user* PATH; an
already-running shell will not see it. In a non-login process prepend it:

```powershell
$env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
            [Environment]::GetEnvironmentVariable("Path","User")
```

**A known quirk of this machine.** `cli.coderabbit.ai` fails the TLS handshake
(`SEC_E_ILLEGAL_MESSAGE`, from both PowerShell and native curl, while npm and
GitHub succeed). This affects the **installer and `coderabbit update` only** — the
review service itself is reached over `app.coderabbit.ai` / `ide.coderabbit.ai`,
which the CLI talks to fine. If an install or update is ever needed, fetch through
an OpenSSL stack (Python's `ssl`) and replicate the installer's steps:
single-entry `coderabbit.exe` archive, valid Authenticode signature from *CodeRabbit
Inc.* via *Microsoft ID Verified CS*, Code Signing EKU `1.3.6.1.5.5.7.3.3`, then
hash- and version-verify before installing.

## Reviewing

```sh
# THE INVOCATION TO USE. Reviews everything since <sha> and completes.
coderabbit review --agent --light --committed --base-commit <sha>

coderabbit review --agent --light --committed     # see the caveat below
coderabbit review --light --committed             # plain text for a human
coderabbit review                                 # all tracked changes
coderabbit review --uncommitted                   # staged + unstaged tracked edits
coderabbit review --include-untracked             # also files never `git add`ed
coderabbit review --dir crates/qqq-serve          # narrow to one directory
coderabbit review --base main                     # compare against another branch
```

`cr` is an exact alias for `coderabbit`.

### Why `--base-commit` is required on this repo

`coderabbit review --committed` on `main` returns:

```json
{"type":"review_context","reviewType":"committed","currentBranch":"main","baseBranch":"main"}
{"type":"status","status":"review_skipped","message":"No committed changes detected"}
```

It diffs the current branch **against itself**, so it finds nothing even with a fresh
commit at HEAD. This is not a bug in the CLI — it is a single-branch repository using
a default base that only makes sense for a feature branch. **`--base-commit <sha>` is
the fix**, and it is the only way I have seen a run reach
`{"status":"complete","outcome":"completed"}`.

### Scope is always a git diff

There is **no "review the whole repository" flag.** Every mode is a diff
(`--committed`, `--uncommitted`, `--include-untracked`, `--base`, `--base-commit`,
`--dir`) — so the whole-repo view is obtained by choosing a diff base that reaches
everything, e.g. the empty tree or the first commit:

```sh
git log --oneline | tail -1         # find the root commit, then
coderabbit review --agent --light --committed --base-commit <root-commit>^
```

For a large repository this will exceed one check's context; use `--dir` to walk the
tree crate by crate, spending one check each. `--dir src` is a **separate scope** from
a whole-repo review, with its own stored findings and its own `--clear`.

**Use `--agent` when the findings are going to be acted on.** It emits one JSON
object per line and nothing else:

| `type` | Meaning |
|---|---|
| `review_context` | branch, base branch, base commit, working directory |
| `status` | phase transitions (`connecting`, `setting_up`, `summarizing`, `reviewing`) |
| `heartbeat` | still working; not a finding |
| `finding` | `severity`, `fileName`, `codegenInstructions`, `suggestions` |
| `complete` | `findings` count, `reviewedFiles`, `outcome` |

**Always read the `complete` line's `reviewedFiles`.** It is the only evidence of what
was actually looked at; without it a "completed, 0 findings" result is
indistinguishable from a review that skipped every file.

**`--light` is not optional in practice here.** A run without it failed with
`{"type":"error","errorType":"connection","message":"Connection failed: WebSocket
closed","recoverable":true}` after reaching `summarizing`. A `recoverable: true`
transport error is worth **one** retry in a different mode before drawing any
conclusion about connectivity — and check `coderabbit doctor` first, which reports
backend and WebSocket reachability separately.

**A long run can still lose the socket after emitting findings.** One review delivered
three findings and *then* died with `TRPCWebSocketClosedError`. The findings already
on stdout are valid; parse them rather than discarding the run.

## Acting on findings that arrived without a `complete` line

Parse the JSONL for `"type":"finding"` and check `severity` — `major` and `critical`
first. A run that died mid-review may have covered only the first few files, so treat
an interrupted run as **partial coverage**, not as a clean result.

## The first-pass findings on this repository (2026-09-21)

Recorded because the *shape* of what it finds is the useful part — see `§O-125`.
Two runs, eight findings, seven real, in code whose own 527 tests were green:

| Finding | Verdict |
|---|---|
| `render_human` wrote control characters verbatim → a guest could forge a second log line and inject ANSI escapes | real, **security** |
| `println!` panics on a closed stdout, inside a spawned task → dropped connection | real |
| trace id from a per-connection counter → every connection's first request identical | real |
| `TraceCounter` started at `0` → the first id is the reserved all-zero W3C value | real |
| `Redactor` deduped *after* a length sort → one secret, two marker numbers | real |
| checklist test count stale | real (its replacement figure was also wrong) |
| rewrite `render_human` to sanitize `extra` too | already covered by the first fix |
| `--fail-on` did not gate `--sarif` (earlier run) | real |

**The common cause, and the reason to keep running this.** Four of them are a check
aimed at a *nearby property that is easy to assert* instead of the property that
matters: `!contains('\n')` on newline-free input; ids *distinct* where *validity* was
the requirement; uniqueness within a scope where cross-scope uniqueness was the point;
a `dedup` whose precondition (sortedness by value) was never established. None is
visible from the code's own tests, because the tests were written by the reasoning that
produced the defect.

## Configuration

`.coderabbit.yaml` at the repo root is live and authoritative — verify with
`coderabbit config --agent`, which reports `"activeConfig"` and `"authority": "yaml"`.
Validate edits against the schema before committing:

```sh
coderabbit config validate .coderabbit.yaml
```

The file encodes the project's **reviewed-only** invariants — unnamed rules, tests
whose fixtures cannot fail, doc comments that state an unchecked invariant, silent
stubs — and switches off linters that CI already blocks, since a comment about them
is noise. Read `AGENTS.md` and `QQQ-Observations-and-Memories.md` before changing it;
they are listed under `knowledge_base.code_guidelines` so reviews consult them.

## Other capabilities of the CLI

| Command | What it is for |
|---|---|
| `coderabbit pullrequest <n-or-url> --agent` | Read CodeRabbit's **PR-level** review output (the SaaS product, not the CLI review). Needs a stored agentic API key and the repo installed in the org. This is a *different and more thorough* review than `review` — the one to use once the repo is on GitHub with PRs. |
| `coderabbit pullrequest <url> --show-prompts` | Print the consolidated agent prompt behind a PR review. |
| `coderabbit auth status` / `auth org` | Confirm login and switch the default organization. |
| `coderabbit doctor` | Installation, storage, auth, git state, update policy, service connectivity. Run this first when anything fails. |
| `coderabbit stats` | Cumulative reviews and issues found. |
| `coderabbit usage` | Billing-period review count and spend. |
| `coderabbit review findings [--dir]` | Replay findings from the most recent stored session (10 retained per scope, no expiry). Survives a lost socket. |
| `coderabbit review findings --clear [--dir]` | Dismiss findings after they are fixed or rejected. Dismissed, not deleted; incremental state is preserved. **Do this after fixing**, or the next run keeps surfacing stale findings. |
| `coderabbit skills` | Install verified CodeRabbit skills for coding agents. Hit a GitHub `504` here once — transient; retry later. |
| `coderabbit update` | Update the CLI. |

**`review findings --clear` is the step most easily forgotten.** It is what makes the
next review's output trustworthy: without it, a fix is followed by a run that re-reports
the thing that was just fixed.

## How to act on findings

**Reproduce before fixing.** A finding is an input, not an authority. The project's
standing rule applies unchanged: verify every claim with a real command. Several of the
highest-value findings this project received were confirmed by writing a failing test
that exercised the exact defect — and one was confirmed *not* real that way.

**Then, if it is real, fix it and prove the test catches it.** This project's rule
for every checker — *generator/validator plus `--self-test` with fault injection* —
applies to the regression test too. Re-introduce the defect, watch the new test
fail, restore. A regression test that has never failed is not evidence.

**Beware the stale build when doing this.** Overwriting a source file with a backup
sets its mtime backwards and cargo may reuse the old artifact, so the injected defect
appears not to fail. Touch the file (`(Get-Item $p).LastWriteTime = Get-Date`) after
restoring, or the fault injection proves nothing.

**Say why a finding is skipped.** A dismissed finding with a recorded reason is
auditable; a silently ignored one is not.

**Record every finding in `QQQ-Observations-and-Memories.md`.** The user asked for
this explicitly, and it is the right call: the *shape* of what an external reviewer
catches is itself a durable finding about this codebase.

## The rule this workflow exists to enforce

**After fixing an output-shape or control-flow defect, enumerate every mode that
flows through the same code path.** `qqqai audit --sarif` was fixed and `--json`
was not checked, and `--json` had the identical defect — found one commit later by
CodeRabbit, not by the 1566 passing tests.

**Internal tests and the code share a mental model.** Use this for what internal
review structurally cannot see:

* the **mode matrix** — every flag combination of one command;
* **silent passes** — a gate that exits 0 when it should exit 1;
* **output that has more in it than it should** — prose sharing a stream with
  machine-readable output;
* **seam defects** — two components that are each individually correct.

## Budget

The advanced plan allows **10 checks per hour**. Spend them on changes that carry
risk — security posture, capability logic, parsers, output contracts, error paths —
not on documentation or formatting, which `tools/*.py` already validates.

## Output of a review run

Do not commit review transcripts. `.scratch/` is gitignored; write JSONL there if it
needs to be kept for the current session.
