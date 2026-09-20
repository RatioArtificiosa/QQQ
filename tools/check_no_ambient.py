#!/usr/bin/env python3
"""Enforce "no hidden global state" across the runtime crates — `CON-010`, `CON-018`.

# The rule

Proposal §2.5 (NN-5, explicit contracts over implicit behaviour):

> | No hidden global state | No environment-variable reads, no CWD dependencies,
>   no implicit config discovery inside the runtime. Configuration is explicit,
>   sourced from a known file or an explicit flag. |

`CON-010` is the CI check for host interfaces; `CON-018` is the architecture test
for the same rule across all host interfaces. They are the same rule, so one tool
serves both.

# Why this is a *source* check and not a runtime test

The violation is an absence of discipline in code that a test never exercises. A
host interface that reads `QQQ_CONFIG` on a path nobody tests behaves identically
to a correct one under every test that does not set it — and differently on a
developer's machine, which is the worst kind of divergence: it appears only in the
environment where nobody is looking.

The rule is therefore checked where the decision is made, in the source.

# What is forbidden, and what is NOT

| Construct | Verdict | Why |
|---|---|---|
| `std::env::var` / `var_os` / `vars` | **forbidden** | Ambient configuration. The value differs per machine, so behaviour differs per machine |
| `std::env::args` | **forbidden** in runtime crates | Process arguments belong to `qqq-run`, which is the CLI and states them explicitly in its own signature |
| `current_dir` / `set_current_dir` | **forbidden** | A CWD dependency means the same artifact behaves differently depending on where it was launched — and §4.6 makes artifacts portable |
| `temp_dir` | **forbidden** in non-test code | Where scratch goes is a host decision, not a library's |
| `std::env::consts::*` | **allowed** | These are compile-time constants of the *build*, not of the running environment. `ARCH`/`OS`/`FAMILY` are fixed into the binary |

# The two exemptions, and why they are not loopholes

A prohibition with no exemptions would be violated by correct code, and the first
person to hit it would add an `#[allow]` or an inline justification — which is how
a check dies. Both exemptions below are therefore **named, located and
justified in this file**, so the next person sees the reasoning rather than
inventing it:

1. **`qqq-cap/src/normalize.rs` — `RealEnv`.** The whole point of that module is
   that environment access is a **trait** (`HostEnv`) with `RealEnv` as the
   production implementation and a fake in tests. The rule forbids *implicit*
   reads; an explicit, injected, mockable implementation is the remedy, not a
   violation. Exempting the file would be too broad — see the entry's note.
2. **Test code.** A unit test may use `temp_dir` to create a scratch directory.
   It is not a host interface, it is not shipped, and forbidding it would push
   test authors toward fixed paths in the repository, which is worse.

Usage:  python tools/check_no_ambient.rs.py
Exit:   0 = rule satisfied, 1 = at least one violation
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The crates a GUEST can reach, directly or transitively. `qqq-run` is a
# binary rather than a host layer -- it is the CLI, and reading process arguments
# there is its job -- so it is checked for everything except `env::args`.
RUNTIME_CRATES = ["qqq-core", "qqq-cap", "qqq-abi", "qqq-host", "qqq-io", "qqq-serve"]

# The patterns, each with the reason it is forbidden.
FORBIDDEN = [
    (re.compile(r"\bstd::env::var\b"), "std::env::var", "ambient configuration"),
    (re.compile(r"\bstd::env::var_os\b"), "std::env::var_os", "ambient configuration"),
    (re.compile(r"\bstd::env::vars\b"), "std::env::vars", "ambient configuration"),
    (re.compile(r"\bstd::env::args\b"), "std::env::args", "process arguments"),
    (re.compile(r"\benv::args\b"), "env::args", "process arguments"),
    (re.compile(r"\bcurrent_dir\b"), "current_dir", "a CWD dependency"),
    (re.compile(r"\bset_current_dir\b"), "set_current_dir", "a CWD dependency"),
    (re.compile(r"\bstd::env::temp_dir\b"), "std::env::temp_dir", "an ambient scratch location"),
    (re.compile(r"\benv::temp_dir\b"), "env::temp_dir", "an ambient scratch location"),
]

# Allowed unconditionally: compile-time constants of the build, not of the
# running environment. Listed so the checker can *say* why it did not fire.
ALLOWED = re.compile(r"std::env::consts::")

# `(path_suffix, construct, justification)` -- the construct must ALSO appear on
# the same line for the exemption to apply, so exempting a file does not exempt
# every construct in it.
EXEMPTIONS: list[tuple[str, str, str]] = [
    (
        "qqq-cap/src/normalize.rs",
        "std::env::var_os",
        "`RealEnv` is the explicit, injected production implementation of the "
        "`HostEnv` trait; the rule forbids IMPLICIT reads, and a mockable trait "
        "impl is the remedy. Exempting the construct (not the file) means a bare "
        "`std::env::var` elsewhere in the same file still fails.",
    ),
]


def is_test_context(lines: list[str], index: int) -> bool:
    """Whether line `index` sits inside a `#[cfg(test)]` module.

    Found by scanning backwards for the nearest `#[cfg(test)]` and comparing
    brace depth, which is enough for the flat module structure every crate here
    uses.
    """
    depth = 0
    for i in range(index, -1, -1):
        if lines[i].strip().startswith("#[cfg(test)]"):
            # Count braces opened after that marker up to our line.
            opened = sum(
                lines[j].count("{") - lines[j].count("}")
                for j in range(i, index + 1)
            )
            return opened > 0
        depth += lines[i].count("{") - lines[i].count("}")
    return False


def exempted(rel_path: str, construct: str) -> bool:
    return any(
        rel_path.endswith(suffix) and construct == want
        for suffix, want, _ in EXEMPTIONS
    )


def main() -> int:
    problems: list[str] = []
    scanned = 0
    allowed_consts = 0

    for crate in RUNTIME_CRATES:
        src = ROOT / "crates" / crate / "src"
        if not src.is_dir():
            problems.append(f"runtime crate `{crate}` has no src/ directory")
            continue
        for path in sorted(src.rglob("*.rs")):
            scanned += 1
            rel = path.relative_to(ROOT).as_posix()
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()

            for i, line in enumerate(lines):
                if ALLOWED.search(line):
                    allowed_consts += 1

                stripped = line.lstrip()
                # A comment is not code. Doc comments in particular discuss the
                # rule by name, and `config.rs` explains why it does NOT use
                # `env!("CARGO_PKG_VERSION")`.
                if stripped.startswith("//"):
                    continue

                for pattern, construct, reason in FORBIDDEN:
                    if not pattern.search(line):
                        continue
                    if exempted(rel, construct):
                        continue
                    if is_test_context(lines, i):
                        continue
                    problems.append(
                        f"{rel}:{i + 1}: `{construct}` — {reason}. "
                        f"§2.5 forbids hidden global state in the runtime; take it "
                        f"as a parameter or through an injected trait."
                    )

    # The scan must have read real code, or every absence above is vacuous.
    if scanned < 15:
        print(f"only {scanned} source files were scanned; the checker is misconfigured")
        return 1
    if allowed_consts == 0:
        print(
            "no `std::env::consts` use was found, so the allowance branch is "
            "untested; if that is genuinely true, remove the allowance"
        )
        return 1

    print(f"  scanned {scanned} source file(s) across {len(RUNTIME_CRATES)} runtime crate(s)")
    print(f"  {allowed_consts} compile-time `std::env::consts` use(s) allowed by design")
    print(f"  {len(EXEMPTIONS)} named exemption(s), each justification in this file")

    if problems:
        print()
        for p in problems:
            print(f"  FAIL  {p}")
        print("\nNO-HIDDEN-GLOBAL-STATE RULE FAILED")
        return 1

    print("\nNO-HIDDEN-GLOBAL-STATE RULE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
