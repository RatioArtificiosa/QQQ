#!/usr/bin/env python3
"""Validate generated CycloneDX SBOM files (`SEC-028`).

An SBOM generation step that succeeds is not evidence that the SBOM is *useful*.
`cargo cyclonedx` will happily emit a structurally valid document that names no
components, and a consumer asking "am I affected by CVE-X?" learns nothing from it.
The failure is invisible: the step is green, the artifact exists, and the artifact
does not answer the only question it exists to answer.

This checker asserts the properties that make an SBOM answerable:

  1. The directory contains at least one SBOM file.
  2. Every file parses as JSON.
  3. Every file declares `bomFormat: CycloneDX` and a `specVersion`.
  4. Every file lists at least one component.
  5. Every component has a `name` and a `version`.
  6. At least one component is the crate the SBOM is for, so the file is not a
     copy of an unrelated tree.
  7. No component is a path or `file:` dependency, because those do not reproduce
     on another machine and an SBOM full of them describes the generating host
     rather than the software.

Usage:  python tools/check_sbom.py <directory> [--self-test]
Exit:   0 = every SBOM is usable, 1 = at least one is not
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

# A minimal but valid CycloneDX document, shaped like real `cargo cyclonedx`
# output: the SUBJECT lives in `metadata.component`, and `components` lists the
# subject's *dependencies*. Anchored on a real generated file rather than on a
# reading of the spec, because the first fixture here asserted the opposite.
VALID_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {"component": {"name": "bom-qqq-core", "version": "0.0.0", "type": "library"}},
    "components": [
        {"name": "serde", "version": "1.0.219", "type": "library"},
        {"name": "wasmtime", "version": "48.0.2", "type": "library"},
    ],
}

# The filename the fixture is written under. `check_file` compares the subject's
# name against it, so these must agree.
VALID_FILENAME = "bom-qqq-core.cdx.json"


def load(path: Path) -> tuple[dict | None, str | None]:
    """Parse an SBOM file, returning `(document, error)`."""
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as e:
        return None, f"is not valid JSON: {e}"
    except OSError as e:
        return None, f"could not be read: {e}"


def check_file(path: Path) -> list[str]:
    """Return the problems with one SBOM file. Empty means usable."""
    problems: list[str] = []

    doc, err = load(path)
    if doc is None:
        return [f"{path.name}: {err}"]

    if doc.get("bomFormat") != "CycloneDX":
        problems.append(
            f"{path.name}: bomFormat is {doc.get('bomFormat')!r}, not 'CycloneDX'. "
            f"A consumer keys on this field to decide how to parse the document."
        )

    if not doc.get("specVersion"):
        problems.append(
            f"{path.name}: no specVersion, so a consumer cannot know which schema "
            f"to validate against"
        )

    components = doc.get("components")
    if not isinstance(components, list) or not components:
        # This is the failure this checker exists for: a valid document that answers
        # nothing. It is reported as a hard error rather than a warning.
        problems.append(
            f"{path.name}: lists no components. A syntactically valid SBOM with an "
            f"empty component list passes `cargo cyclonedx` and answers none of the "
            f"questions an SBOM exists to answer."
        )
        return problems

    for i, component in enumerate(components):
        if not isinstance(component, dict):
            problems.append(f"{path.name}: component #{i} is not an object")
            continue
        name = component.get("name")
        version = component.get("version")
        if not name:
            problems.append(f"{path.name}: component #{i} has no name")
        if not version:
            # Matched by name so the message points at the actual entry.
            problems.append(
                f"{path.name}: component {name!r} has no version. An SBOM that names "
                f"a package without a version cannot be matched against an advisory."
            )
        # A path or git dependency does not reproduce elsewhere, so it describes the
        # generating machine rather than the released software.
        purl = component.get("purl", "")
        if isinstance(purl, str) and (purl.startswith("pkg:cargo/file") or "path+" in purl):
            problems.append(
                f"{path.name}: component {name!r} is a path dependency ({purl}), which "
                f"does not reproduce on another machine"
            )

    # The document must identify *its subject*: the crate the SBOM is about.
    #
    # # Why this reads `metadata.component` and NOT the component list
    #
    # The first version of this check required the subject's name to appear in
    # `components`, and running it against a real `cargo cyclonedx` output rejected
    # every file. The assumption was wrong, not the tool: in CycloneDX the document's
    # subject lives in `metadata.component`, and `components` lists its
    # *dependencies*. Found by generating a real SBOM and reading it, which is why
    # the check now asserts the spec's actual shape instead of a guess about it.
    #
    # The check still earns its place. Without it, a generation bug that wrote the
    # same file under every crate's name would pass — `components` would be full and
    # well formed, and every file would describe the wrong subject.
    metadata = doc.get("metadata")
    subject = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(subject, dict) or not subject.get("name"):
        problems.append(
            f"{path.name}: metadata.component is missing or unnamed, so the document "
            f"does not say what software it describes"
        )
    else:
        if not subject.get("version"):
            problems.append(
                f"{path.name}: the subject component {subject.get('name')!r} has no "
                f"version, so the SBOM does not identify a release"
            )
        # The filename convention is `<crate>.cdx.json`, so the subject must match
        # it. This is the check that catches a file written under the wrong name.
        expected = path.name.removesuffix(".cdx.json")
        if expected and subject["name"] != expected:
            problems.append(
                f"{path.name}: the file is named for {expected!r} but describes "
                f"{subject['name']!r}, so a consumer resolving by filename would "
                f"read the wrong software's dependency list"
            )

    return problems


def validate(directory: Path) -> int:
    """Validate every SBOM in `directory`. Returns a process exit code."""
    if not directory.is_dir():
        print(f"FATAL: {directory} is not a directory")
        return 1

    files = sorted(p for p in directory.glob("*.json"))
    if not files:
        print(
            f"FATAL: no SBOM files in {directory}. An SBOM step that produced nothing "
            f"is indistinguishable from one that was never wired up."
        )
        return 1

    problems: list[str] = []
    total_components = 0

    for path in files:
        problems.extend(check_file(path))
        doc, _ = load(path)
        if isinstance(doc, dict) and isinstance(doc.get("components"), list):
            total_components += len(doc["components"])

    if problems:
        print("SBOM VALIDATION FAILED")
        print("")
        for p in problems:
            print(f"  FAIL  {p}")
        return 1

    print(
        f"SBOM OK -- {len(files)} file(s), {total_components} component(s) total, "
        f"every component named and versioned"
    )
    return 0


def self_test() -> int:
    """Prove every check can fail.

    # Why a validator for a *generated artifact* still needs this

    The SBOM is produced by a third-party tool, so it is tempting to trust it. But
    the failure this checker guards against — a valid document with an empty
    component list — is produced by `cargo cyclonedx` itself when it is invoked
    wrongly, and it looks exactly like success. A checker that has never rejected
    anything has never been shown to work, which is the theme of this repository's
    last dozen findings.
    """
    cases = [
        ("clean sbom", VALID_SBOM, ""),
        (
            "no components",
            {**VALID_SBOM, "components": []},
            "lists no components",
        ),
        (
            "wrong bomFormat",
            {**VALID_SBOM, "bomFormat": "SPDX"},
            "not 'CycloneDX'",
        ),
        (
            "no specVersion",
            {k: v for k, v in VALID_SBOM.items() if k != "specVersion"},
            "no specVersion",
        ),
        (
            "component without a version",
            {
                **VALID_SBOM,
                "components": [
                    {"name": "serde", "version": "1.0.219"},
                    {"name": "versionless-crate"},
                ],
            },
            "has no version",
        ),
        (
            "component without a name",
            {
                **VALID_SBOM,
                "components": [{"version": "1.0.0"}],
            },
            "has no name",
        ),
        (
            "subject mismatched with the filename",
            {**VALID_SBOM, "metadata": {"component": {"name": "qqq-host", "version": "0.0.0"}}},
            "read the wrong software's dependency list",
        ),
        (
            "subject without a version",
            {**VALID_SBOM, "metadata": {"component": {"name": "bom-qqq-core"}}},
            "does not identify a release",
        ),
        (
            "no metadata subject at all",
            {k: v for k, v in VALID_SBOM.items() if k != "metadata"},
            "does not say what software it describes",
        ),
        (
            "path dependency",
            {
                **VALID_SBOM,
                "components": [
                    {"name": "serde", "version": "1.0.219"},
                    {"name": "local-thing", "version": "0.1.0", "purl": "pkg:cargo/file+local-thing"},
                ],
            },
            "does not reproduce",
        ),
    ]

    failures = 0

    def run(name: str, document, expect: str) -> bool:
        tmp = Path(tempfile.mkdtemp(prefix="qqq-sbom-selftest-"))
        try:
            if document is not None:
                (tmp / VALID_FILENAME).write_text(
                    json.dumps(document), encoding="utf-8"
                )
            import contextlib
            import io

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = validate(tmp)
            output = buf.getvalue()

            ok = (code == 0) if expect == "" else (code != 0 and expect in output)
            print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
            if not ok:
                print(f"        expected {expect!r}, got exit {code}")
                for line in output.strip().splitlines()[:3]:
                    print(f"        | {line}")
            return ok
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    for name, document, expect in cases:
        if not run(name, document, expect):
            failures += 1

    # The empty-directory case: an SBOM step that produced nothing.
    if not run("empty directory", None, "produced nothing"):
        failures += 1

    # A malformed file must be rejected rather than skipped.
    tmp = Path(tempfile.mkdtemp(prefix="qqq-sbom-selftest-"))
    try:
        (tmp / "bom-broken.cdx.json").write_text("{ not json", encoding="utf-8")
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = validate(tmp)
        ok = code != 0 and "not valid JSON" in buf.getvalue()
        print(f"  {'OK  ' if ok else 'DEAD'}  malformed json")
        if not ok:
            failures += 1
            print(f"        got exit {code}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total = len(cases) + 2
    print("")
    if failures:
        print(f"SELF-TEST FAILED -- {failures}/{total} case(s) not detected")
        return 1
    print(f"SELF-TEST PASSED -- {total}/{total} case(s), every check is live")
    return 0


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--self-test"]
    if "--self-test" in sys.argv:
        return self_test()

    # # Why a missing directory with no argument is not a failure
    #
    # `sbom/` is produced by the CI supply-chain job. Running this checker locally
    # without that step having run is the normal case, not a defect, and failing on it
    # would make `python tools/check_sbom.py` -- the obvious thing to type -- report an
    # error about the environment rather than about the SBOM.
    #
    # An explicitly named directory that does not exist *is* a failure, because the
    # caller asserted it should be there.
    if not args and not Path("sbom").is_dir():
        print(
            "no sbom/ directory here, so there is nothing to check. Generate one with "
            "`cargo cyclonedx --format json --spec-version 1.5 --describe crate --all`, "
            "or run `python tools/check_sbom.py --self-test` to prove the checks work."
        )
        return 0

    directory = Path(args[0]) if args else Path("sbom")
    return validate(directory)


if __name__ == "__main__":
    raise SystemExit(main())
