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
coderabbit review --agent --light --committed     # JSONL for an agent to parse
coderabbit review --light --committed             # plain text for a human
coderabbit review                                 # all tracked changes
coderabbit review --uncommitted                   # staged + unstaged tracked edits
coderabbit review --include-untracked             # also files never `git add`ed
```

`cr` is an exact alias for `coderabbit`.

**Use `--agent` when the findings are going to be acted on.** It emits one JSON
object per line and nothing else:

| `type` | Meaning |
|---|---|
| `review_context` | branch, base branch, working directory |
| `status` | phase transitions (`connecting`, `setting_up`, `summarizing`, `reviewing`) |
| `heartbeat` | still working; not a finding |
| `finding` | `severity`, `fileName`, `codegenInstructions`, `suggestions` |
| `complete` | `findings` count, `reviewedFiles`, `outcome` |

**`--light` is not optional in practice here.** A run without it failed with
`{"type":"error","errorType":"connection","message":"Connection failed: WebSocket
closed","recoverable":true}` after reaching `summarizing`. The `--light` run
completed. A `recoverable: true` transport error is worth **one** retry in a
different mode before drawing any conclusion about connectivity — and check
`coderabbit doctor` first, which reports backend and WebSocket reachability
separately.

## How to act on findings

**Reproduce before fixing.** A finding is an input, not an authority. The project's
standing rule applies unchanged: verify every claim with a real command. Two of the
highest-value findings this project received were confirmed by running the exact
command they described and observing the wrong exit code.

**Then, if it is real, fix it and prove the test catches it.** This project's rule
for every checker — *generator/validator plus `--self-test` with fault injection* —
applies to the regression test too. Re-introduce the defect, watch the new test
fail, restore. A regression test that has never failed is not evidence.

**Say why a finding is skipped.** A dismissed finding with a recorded reason is
auditable; a silently ignored one is not.

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
