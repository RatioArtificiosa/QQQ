#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify TEST-018 CI integration examples (`examples/ci/`).

The repository's own CI (`.github/workflows/ci.yml`) proves the workspace builds;
it does not show a downstream user how to run QQQ in *their* pipeline. These
examples are that documentation, and this checker keeps them honest: every file
must exist, parse as YAML, invoke the real test commands, and pin the same Rust
toolchain the workspace builds with — read from `rust-toolchain.toml`, never
hard-coded, so a toolchain bump fails the gate until the examples follow it.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import tempfile

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass

try:
    import yaml
except (
    ImportError
):  # pragma: no cover - the CI job installs PyYAML (6.0.3, pinned in ci.yml)
    yaml = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI_DIR = ROOT / "examples" / "ci"
TOOLCHAIN_FILE = ROOT / "rust-toolchain.toml"

# The three examples TEST-018 names: GitHub Actions, GitLab CI, and one more
# (CircleCI) so "and others" is a list, not a wish.
EXPECTED = ("github-actions.yml", "gitlab-ci.yml", "circleci.yml")


def read_toolchain_channel() -> str:
    """The `[toolchain] channel` from `rust-toolchain.toml` (e.g. `1.98`)."""
    text = TOOLCHAIN_FILE.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("channel"):
            _, _, value = stripped.partition("=")
            return value.strip().strip('"').strip("'")
    raise AssertionError(f"no [toolchain] channel in {TOOLCHAIN_FILE}")


def check_file(path: pathlib.Path, channel: str) -> list[str]:
    """Return a list of problems (empty means OK) for one example file."""
    problems: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{path.name}: unreadable: {exc}"]
    if yaml is None:
        return [f"{path.name}: PyYAML unavailable, cannot validate"]
    try:
        doc = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 - the message is the finding
        return [f"{path.name}: invalid YAML: {exc}"]
    if not isinstance(doc, dict):
        return [f"{path.name}: top level must be a mapping, got {type(doc).__name__}"]
    # The file must actually run the tests, not just mention QQQ in prose.
    if "cargo test" not in text:
        problems.append(f"{path.name}: must invoke `cargo test`")
    if "qqqai test" not in text:
        problems.append(f"{path.name}: must show `qqqai test`")
    # The toolchain pin must match the workspace, read live above.
    if channel not in text:
        problems.append(
            f"{path.name}: must pin Rust {channel} (from rust-toolchain.toml)"
        )
    return problems


def check_dir(ci_dir: pathlib.Path = CI_DIR) -> list[str]:
    """All problems across the examples directory (empty means OK)."""
    problems: list[str] = []
    try:
        channel = read_toolchain_channel()
    except (OSError, AssertionError) as exc:
        return [f"toolchain: {exc}"]
    for name in EXPECTED:
        path = ci_dir / name
        if not path.is_file():
            problems.append(
                f"{name}: missing (TEST-018 requires {', '.join(EXPECTED)})"
            )
            continue
        problems.extend(check_file(path, channel))
    # No stray files: an example nobody checks is an example nobody maintains.
    if ci_dir.is_dir():
        for entry in sorted(ci_dir.iterdir()):
            if (
                entry.is_file()
                and entry.name not in EXPECTED
                and entry.suffix in {".yml", ".yaml"}
            ):
                problems.append(
                    f"{entry.name}: unexpected CI example (add to EXPECTED or remove)"
                )
    return problems


def run_self_test() -> int:
    """Exercise the checker against good and broken fixtures (no network)."""
    failures: list[str] = []

    def expect_ok(ci_dir: pathlib.Path, label: str) -> None:
        problems = check_dir(ci_dir)
        if problems:
            failures.append(f"{label}: expected OK, got {problems}")

    def expect_fail(ci_dir: pathlib.Path, fragment: str, label: str) -> None:
        problems = check_dir(ci_dir)
        if not any(fragment in p for p in problems):
            failures.append(
                f"{label}: expected a problem containing {fragment!r}, got {problems}"
            )

    channel = read_toolchain_channel()
    good = {
        "github-actions.yml": (
            f"name: qqq\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - uses: actions/checkout@v4\n"
            f"      - name: Install Rust {channel}\n        run: rustup toolchain install {channel}\n"
            f"      - run: cargo test --workspace --all-features\n"
            f"      - run: cargo install --path crates/qqq-run && qqqai test\n"
        ),
        "gitlab-ci.yml": (
            f"image: rust:{channel}\ntest:\n  script:\n"
            f"    - cargo test --workspace --all-features\n"
            f"    - qqqai test\n"
        ),
        "circleci.yml": (
            f"version: 2.1\njobs:\n  test:\n    docker:\n      - image: cimg/rust:{channel}\n"
            f"    steps:\n      - checkout\n"
            f"      - run: cargo test --workspace --all-features\n"
            f"      - run: qqqai test\n"
        ),
    }
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp) / "good"
        base.mkdir()
        for name, text in good.items():
            (base / name).write_text(text, encoding="utf-8")
        expect_ok(base, "good fixtures")

        # Missing file.
        missing = pathlib.Path(tmp) / "missing"
        missing.mkdir()
        for name, text in good.items():
            if name != "circleci.yml":
                (missing / name).write_text(text, encoding="utf-8")
        expect_fail(missing, "circleci.yml: missing", "missing file")

        # Broken YAML.
        broken = pathlib.Path(tmp) / "broken"
        broken.mkdir()
        for name, text in good.items():
            (broken / name).write_text(text, encoding="utf-8")
        (broken / "gitlab-ci.yml").write_text(":\n  - [\n", encoding="utf-8")
        expect_fail(broken, "invalid YAML", "broken YAML")

        # No cargo test.
        nocargo = pathlib.Path(tmp) / "nocargo"
        nocargo.mkdir()
        for name, text in good.items():
            (nocargo / name).write_text(text, encoding="utf-8")
        (nocargo / "github-actions.yml").write_text(
            (nocargo / "github-actions.yml")
            .read_text(encoding="utf-8")
            .replace("cargo test", "cargo build"),
            encoding="utf-8",
        )
        expect_fail(nocargo, "must invoke `cargo test`", "no cargo test")

        # No qqqai test (bare qqqai mention must not pass).
        noqqqai = pathlib.Path(tmp) / "noqqqai"
        noqqqai.mkdir()
        for name, text in good.items():
            (noqqqai / name).write_text(text, encoding="utf-8")
        (noqqqai / "gitlab-ci.yml").write_text(
            (noqqqai / "gitlab-ci.yml")
            .read_text(encoding="utf-8")
            .replace("qqqai test", "qqqai --version"),
            encoding="utf-8",
        )
        expect_fail(noqqqai, "must show `qqqai test`", "no qqqai test")

        # Wrong toolchain pin.
        oldpin = pathlib.Path(tmp) / "oldpin"
        oldpin.mkdir()
        for name, text in good.items():
            (oldpin / name).write_text(text.replace(channel, "1.0"), encoding="utf-8")
        expect_fail(oldpin, f"must pin Rust {channel}", "stale toolchain pin")

    if failures:
        print("CI EXAMPLES SELF-TEST FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        "CI EXAMPLES SELF-TEST OK -- good, missing, broken-YAML, no-cargo-test, no-qqqai-test, stale-pin"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify TEST-018 CI examples.")
    parser.add_argument(
        "--self-test", action="store_true", help="run the checker's own tests"
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    problems = check_dir()
    if problems:
        print("CI EXAMPLES FAILED -- problems in examples/ci/:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"CI EXAMPLES OK -- {len(EXPECTED)} examples pin Rust {read_toolchain_channel()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
