#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Keep the threat model's claims pointing at real code (`SEC-001`).

# The decay this prevents

A threat model's most perishable content is its mitigation-to-code mapping. Every
`Where:` line in `docs/threat-model.md` names a module that implements a defence, and
each of those names is a path that a refactor can move. When one moves, the document
keeps asserting that a defence lives somewhere that no longer exists — and it reads
exactly as confidently as it did before.

That is the failure shape this repository has recorded repeatedly: a control believed
live that is not. A threat model is the highest-stakes place for it, because it is the
document a reviewer trusts when deciding whether the system is safe to adopt.

# What is enforced

  1. Every backticked `crate::module` reference in the document names a crate that
     exists, and — when a module path is given — a module file that exists.
  2. Every `docs/*.md` link resolves.
  3. Every adversary from the Proposal's §7.2 table has a section.
  4. The document states that no external validation has occurred, as long as
     `SEC-024` and `SEC-025` are unticked in the checklist. A threat model that
     stopped saying so while the audits remain uncommissioned would be claiming
     validation it does not have.

Usage:  python tools/check_threat_model.py [--self-test]
Exit:   0 = the document's claims resolve, 1 = at least one does not
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "threat-model.md"
CHECKLIST = ROOT / "QQQ-Checklist-V1.md"
PROPOSAL = ROOT / "QQQ-Proposal-V1.md"

# The §7.2 adversaries, keyed by a fragment of their name. Anchored on a distinctive
# word so a reworded table row does not break the check.
ADVERSARIES = {
    "malicious guest": "malicious guest",
    "malicious dependency": "malicious dependency",
    "compromised tenant": "compromised tenant",
    "hostile network client": "hostile network client",
    "insider with deploy access": "insider with deploy access",
    "supply-chain nation-state": "supply-chain nation-state",
    "nation-state against the sandbox": "nation-state against the sandbox",
}

# The audits that would turn this from a design model into a validated one.
AUDIT_ITEMS = ["SEC-024", "SEC-025"]


def crate_exists(name: str) -> bool:
    """Whether `crates/<name>` is a real crate directory."""
    return (ROOT / "crates" / name).is_dir()


def module_exists(crate: str, module: str) -> bool:
    """Whether `crates/<crate>/src/<module>.rs` exists.

    A module written as `qqq-host::limits` maps to `crates/qqq-host/src/limits.rs`.
    A nested path (`qqq-serve::tls::config`) is tried as a file first and then as a
    directory module, because both are valid Rust layouts.
    """
    base = ROOT / "crates" / crate / "src"
    parts = module.split("::")
    if not parts:
        return True
    candidate = base.joinpath(*parts).with_suffix(".rs")
    if candidate.is_file():
        return True
    directory = base.joinpath(*parts) / "mod.rs"
    return directory.is_file()


def code_references(text: str) -> list[str]:
    """Every `crate::module` reference in backticks."""
    # Matches `qqq-host::limits`, `qqq-core::error`, `qqq-cap::egress`.
    return re.findall(r"`(qqq-[a-z]+(?:::[a-z_]+)*)`", text)


def audit_is_commissioned(checklist: str, item: str) -> bool:
    """Whether a checklist item is ticked `[x]`."""
    pattern = re.compile(rf"(?m)^- \[([ x])\] \*\*{re.escape(item)}\*\*")
    match = pattern.search(checklist)
    return bool(match and match.group(1) == "x")


def check(doc: str, checklist: str, proposal: str, root: Path | None = None) -> list[str]:
    """Return the problems with the threat model. Empty means it resolves."""
    problems: list[str] = []

    if not doc.strip():
        return ["docs/threat-model.md is empty"]

    # 1. Every code reference must resolve.
    for reference in sorted(set(code_references(doc))):
        parts = reference.split("::")
        crate = parts[0]
        if not crate_exists(crate):
            problems.append(
                f"`{reference}` names the crate `{crate}`, which does not exist under "
                f"crates/. A threat model that points at a crate that is gone asserts "
                f"a defence nobody can check."
            )
            continue
        if len(parts) > 1:
            module = "::".join(parts[1:])
            if not module_exists(crate, module):
                problems.append(
                    f"`{reference}` names `{crate}::src/{module}.rs`, which does not "
                    f"exist. The defence may have moved; the document still claims it "
                    f"lives here."
                )

    # 2. Internal links must resolve.
    for target in re.findall(r"\]\(([^)]+)\)", doc):
        if target.startswith(("http://", "https://", "#")):
            continue
        candidate = (DOC.parent / target).resolve()
        if not candidate.exists():
            problems.append(f"the link `{target}` does not resolve")

    # 3. Every §7.2 adversary needs a section here.
    lowered = doc.lower()
    for label, fragment in ADVERSARIES.items():
        if fragment not in lowered:
            problems.append(
                f"the adversary {label!r} from the Proposal §7.2 has no section in the "
                f"threat model, so the document covers fewer adversaries than the "
                f"Proposal states"
            )

    # The Proposal must still carry the same set, or one of the two drifted.
    proposal_lower = proposal.lower()
    for label, fragment in ADVERSARIES.items():
        if fragment not in proposal_lower:
            problems.append(
                f"the Proposal §7.2 no longer names {label!r}; if the adversary list "
                f"changed, the threat model must change with it"
            )

    # 4. While the audits are uncommissioned, the document must say so.
    commissioned = [i for i in AUDIT_ITEMS if audit_is_commissioned(checklist, i)]
    if not commissioned:
        # Every audit still open: the document must not claim validation.
        claims_validation = re.search(
            r"(?i)(has been (externally )?(audited|validated)|audit(ed)? by an external)",
            doc,
        )
        if claims_validation:
            problems.append(
                "the threat model claims external validation while SEC-024 and SEC-025 "
                "are both unticked. A design model presented as a validated one is the "
                "most dangerous document in this repository."
            )
        if "not a validation" not in doc.lower() and "no external audit" not in doc.lower():
            problems.append(
                "the threat model does not state that no external validation has "
                "occurred, while SEC-024 and SEC-025 remain uncommissioned"
            )

    return problems


def validate() -> int:
    for path in (DOC, CHECKLIST, PROPOSAL):
        if not path.exists():
            print(f"FATAL: {path} does not exist")
            return 1

    problems = check(
        DOC.read_text(encoding="utf-8"),
        CHECKLIST.read_text(encoding="utf-8"),
        PROPOSAL.read_text(encoding="utf-8"),
    )
    if problems:
        print("THREAT MODEL FAILED")
        print("")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    references = len(set(code_references(DOC.read_text(encoding="utf-8"))))
    print(
        f"THREAT MODEL OK -- {len(ADVERSARIES)} adversaries covered, {references} code "
        f"reference(s) resolve, no validation is claimed while the audits are open"
    )
    return 0


# A valid fixture: every reference resolves, every adversary is present, and the
# absence of validation is stated.
VALID_FIXTURE = (
    "# Threat model\n\n"
    "This is a design model. It is **not a validation** -- no external audit has "
    "occurred.\n\n"
    "## T1 malicious guest\n\nWhere: `qqq-host` and `qqq-core::error`.\n\n"
    "## T2 malicious dependency\n\nWhere: `qqq-pkg`.\n\n"
    "## T3 compromised tenant\n\nWhere: `qqq-cap::egress`.\n\n"
    "## T4 hostile network client\n\nWhere: `qqq-serve`.\n\n"
    "## T5 insider with deploy access\n\nWhere: `qqq-pkg`.\n\n"
    "## T6 supply-chain nation-state\n\nWhere: `deny.toml`.\n\n"
    "## T7 nation-state against the sandbox\n\nWhere: `qqq-host`.\n\n"
    "## T8 malicious host administrator\n\nNot defended; see the out-of-scope list.\n"
)

VALID_PROPOSAL = (
    "| Adversary | Capability |\n|---|---|\n"
    "| **Malicious guest** | x |\n"
    "| **Malicious dependency** | x |\n"
    "| **Compromised tenant** | x |\n"
    "| **Hostile network client** | x |\n"
    "| **Insider with deploy access** | x |\n"
    "| **Supply-chain nation-state** | x |\n"
    "| **Nation-state against the sandbox** | x |\n"
)

VALID_CHECKLIST = "- [ ] **SEC-024** audit\n- [ ] **SEC-025** audit\n"


def self_test() -> int:
    """Prove every check can fail."""
    cases = [
        ("clean threat model", VALID_FIXTURE, VALID_CHECKLIST, VALID_PROPOSAL, ""),
        (
            "a code reference to a missing module",
            VALID_FIXTURE.replace("`qqq-host`", "`qqq-host::nonexistent_module`", 1),
            VALID_CHECKLIST,
            VALID_PROPOSAL,
            "does not exist",
        ),
        (
            "a code reference to a missing crate",
            VALID_FIXTURE.replace("`qqq-pkg`", "`qqq-telepathy`", 1),
            VALID_CHECKLIST,
            VALID_PROPOSAL,
            "which does not exist under",
        ),
        (
            "an adversary with no section",
            VALID_FIXTURE.replace("## T4 hostile network client", "## T4 something else"),
            VALID_CHECKLIST,
            VALID_PROPOSAL,
            "has no section in the threat model",
        ),
        (
            "the proposal drops an adversary",
            VALID_FIXTURE,
            VALID_CHECKLIST,
            VALID_PROPOSAL.replace("| **Compromised tenant** | x |\n", ""),
            "no longer names 'compromised tenant'",
        ),
        (
            "a claim of validation while audits are open",
            VALID_FIXTURE.replace(
                "It is **not a validation**", "It has been externally audited and"
            ).replace(" -- no external audit has occurred.", ""),
            VALID_CHECKLIST,
            VALID_PROPOSAL,
            "claims external validation",
        ),
        (
            "the absence of validation goes unstated",
            VALID_FIXTURE.replace("It is **not a validation** -- no external audit has "
                                  "occurred.", "This document is thorough."),
            VALID_CHECKLIST,
            VALID_PROPOSAL,
            "does not state that no external validation",
        ),
    ]

    failures = 0

    def run(name: str, doc: str, checklist: str, proposal: str, expect: str) -> bool:
        problems = check(doc, checklist, proposal)
        joined = "\n".join(problems)
        ok = (not problems) if expect == "" else (expect in joined)
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            print(f"        expected {expect!r}, got: {joined[:200]}")
        return ok

    for name, doc, checklist, proposal, expect in cases:
        if not run(name, doc, checklist, proposal, expect):
            failures += 1

    # A broken internal link must be rejected, checked against a real temp file so
    # the path resolution is the same code the real run uses.
    tmp = Path(tempfile.mkdtemp(prefix="qqq-threat-selftest-"))
    try:
        import contextlib
        import io

        # Redirect the module-level DOC so relative links resolve inside the temp dir.
        global DOC
        original = DOC
        DOC = tmp / "threat-model.md"
        (tmp / "out-of-scope.md").write_text("x", encoding="utf-8")
        doc = VALID_FIXTURE.replace(
            "Not defended; see the out-of-scope list.",
            "Not defended; see [out-of-scope](out-of-scope.md) and [gone](missing.md).",
        )
        DOC.write_text(doc, encoding="utf-8")

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            problems = check(doc, VALID_CHECKLIST, VALID_PROPOSAL)
        ok = any("missing.md" in p for p in problems)
        print(f"  {'OK  ' if ok else 'DEAD'}  a link that does not resolve")
        if not ok:
            failures += 1
            print(f"        got: {problems}")
        DOC = original
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total = len(cases) + 1
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every check is live")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    return validate()


if __name__ == "__main__":
    raise SystemExit(main())
