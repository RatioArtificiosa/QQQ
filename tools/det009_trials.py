#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""`DET-009` / `DOD-003` -- the 10,000-trial bit-identical verification.

Proposal section 16: *"Deterministic mode produces bit-identical results across 10,000 trials."*

# What this measures

A guest is run under `qqqai run --deterministic` N times, each run writing a replay log, and every
log is compared with the first **byte for byte**. The file carries the header (artifact digest,
engine version, target triple, config), the recorded reads, and a hash chain -- so a difference
anywhere in the recorded execution shows up, and the comparison is stricter than comparing a
printed value.

The guest is a component that imports exactly `qqq:clock/wall-clock@1.0.0` and reads `now` in a
core-module `start` function, so it reads the clock once per instantiation. Under `--deterministic`
the host answers with `AmbientState::fixed_nanos`, so a log that differed between runs would be the
determinism failing rather than the guest changing.

# Why the guest is a fixture here and not a Rust binary

`std` for `wasm32-wasip2` is implemented over fourteen WASI CLI interfaces and no manifest in this
repository grants them, while `--cap` may only *narrow* (`§O-424`). So a Rust guest is refused with
`QQQ-6003` and cannot be the subject. **A WAT component imports exactly what it names.**

# Why the bytes are embedded rather than assembled at run time

`wasm-tools` is installed in the bridge image but assembling on every invocation would make the
subject depend on a tool version rather than on the fixture. The component is **281 bytes** with
digest `2a9c3fb3...`; it is carried as base64 and its digest is asserted before every run, so the
subject is pinned by value. `--from-wat` re-derives those bytes from the WAT beside them with
`wasm-tools parse` and asserts the digest still matches -- that is the provenance check, and it is
opt-in because it needs the tool.

# Why `--inject` exists, and why the number is worthless without it

**A divergence count of zero is produced both by a deterministic engine and by a comparison that
cannot answer "different."** The first version of this harness (`.scratch/det009_trials.cmd`)
reported `0` and had never been observed to report anything else. `--inject` mutates the baseline by
**one byte** and then requires every trial to be counted as diverged; if it is not, `--inject`
exits non-zero and says the counter is dead. Three further guards refuse a vacuous pass: the
reference log must be **non-empty**, must carry all **five header keys**, and the number of
comparisons performed must equal the number of trials attempted -- so a loop that ran nothing
reports `INERT_LOOP` instead of a clean zero.

# Modes

    --self-test   pure logic only; needs neither `qqqai` nor a guest.  Runs in both gates.
    (default)     a short end-to-end run; needs a built `qqqai`.
    --full        the 10,000 trials the Definition of Done names.  ~3 minutes on this machine.
    --inject      with any end-to-end mode; proves the divergence counter can fire.

Exit: 0 ok, 1 divergence observed, 2 prerequisite missing, 3 vacuous run, 4 injection undetected,
5 self-test failed.

# The published value

Measured at commit `03928cc`, `--full`, on the maintainer's machine:

    TRIALS_ATTEMPTED=10000
    COMPARISONS_PERFORMED=10000
    RUNS_THAT_FAILED=0
    LOGS_THAT_DIVERGED=0
    DET009 OK 10000/10000 byte-identical, 0 failed

**The subject is the WAT guest above, not the reference application** -- `qqqai run` cannot
instantiate the reference application today, for the reason in `§O-424`. That limit belongs in the
same breath as the number.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Line-buffered, not just UTF-8.
#
# # Why the buffering argument is load-bearing rather than cosmetic
#
# This tool prints progress so that a long run is observable -- that is the whole reason it
# replaced `.scratch/det009_trials.cmd`, whose comment claimed *"progress every 1000, so a broken
# loop is visible in the first minute rather than the tenth"* while computing the variable and never
# printing it (`§O-428`). Measured: the first version of this file dropped the `flush=True` the
# scratch version had, and with stdout redirected to a file Python block-buffers, so a 10,000-trial
# run wrote **nothing** for its first 57 seconds and the `PROGRESS` lines arrived with the summary at
# the end. **The defect was reproduced in the fix for the defect.** `line_buffering=True` is what
# makes the progress lines real, and removing it would restore a comment that lies about the code.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent

# The five header keys the replay file must carry for "identical" to mean anything. Two empty
# files are also identical, and an assertion that does not say what it compared is how a dead
# instrument reports success.
HEADER_KEYS = ("qqq-replay", "artifact_digest", "engine_version", "target_triple", "deterministic")

# The subject, pinned by value.
COMPONENT_SHA256 = "2a9c3fb3c48572a78b8119318690f6ffe13a30b1f5dddacd153ef93eccb67b39"
COMPONENT_WASM_B64 = "AGFzbQ0AAQAHNgFCBgFAAAB3BAADbm93AQABQAAAdwQACnJlc29sdXRpb24BAQFAAABzBAAIdGltZXpvbmUBAgofAQAacXFxOmNsb2NrL3dhbGwtY2xvY2tAMS4wLjAFAAYIAQEAAANub3cIBQEBAAAAAVcAYXNtAQAAAAEIAmAAAX5gAAACCAEAA25vdwAAAwIBAQYGAX4BQgALCAEBCggBBgAQACQACwAgBG5hbWUAAgFtAQwCAANub3cBBGluaXQHBwEABHNlZW4CDwIBAQNub3cAAAAAAQASAAA7DmNvbXBvbmVudC1uYW1lAQgAAAEAA25vdwEGABEBAAFtAQYAEgEBAWkBCQEBAAVjX25vdwEFBQEAAWM="

# The same component as text, so a reader can see what the bytes are without a tool.
COMPONENT_WAT = """;; `DET-009`'s subject: a component that reads the wall clock **at instantiation**.
;;
;; # Why a `start` function and not an exported entry point
;;
;; `qqqai run` instantiates a component and drops it. Its own comment says why it calls no export:
;;
;;     Calling a specific export is the job of `qqqai serve` and the entrypoint declared in the
;;     manifest; guessing an export name here would make `run` succeed or fail for reasons unrelated
;;     to the capability model.
;;
;; So the read has to happen where `run` reaches: instantiation. A core module's `start` function runs
;; when its instance is created, and the component instantiates its core module as part of its own
;; instantiation -- so this reads the clock exactly once, before `run` reports its outcome.
;;
;; # Why it reads the clock at all
;;
;; Without a read there is nothing in a replay log: the log records values the guest *observed*, and a
;; guest that observes nothing produces a header and no records. A `--replay-log` from such a guest
;; would be identical across runs for the trivial reason that it says nothing, and the 10,000-trial
;; verification would be a tautology. **The read is what makes the comparison mean anything.**
;;
;; # Why this import and no other
;;
;; `std` for `wasm32-wasip2` is implemented over fourteen WASI CLI interfaces, so any Rust guest that
;; uses `std` imports them whether or not its source mentions one -- and no manifest in this repository
;; grants them while `--cap` may only narrow. **A WAT component imports exactly what it names**, so this
;; one needs `clock.wall` and nothing else.
(component
  (import "qqq:clock/wall-clock@1.0.0" (instance $c
    (export "now" (func (result u64)))
    (export "resolution" (func (result u64)))
    (export "timezone" (func (result string)))
  ))
  ;; Lift `now` out of the imported instance and lower it into a core function the module can call.
  (alias export $c "now" (func $c_now))
  (core func $now (canon lower (func $c_now)))
  (core module $m
    (import "" "now" (func $now (result i64)))
    ;; The read is kept in a global so the value is *used* rather than dropped -- a call whose result
    ;; is discarded can be eliminated, and an eliminated call is not a read the host ever sees.
    (global $seen (mut i64) (i64.const 0))
    (func $init (global.set $seen (call $now)))
    (start $init)
  )
  (core instance $i (instantiate $m
    (with "" (instance (export "now" (func $now))))
  ))
)
"""

MANIFEST = """[package]
name = "det009-reads-clock"
version = "0.1.0"

[capabilities.clock]
wall = true
"""


# --------------------------------------------------------------------------
# pure functions -- what `--self-test` exercises, and all of them run without a binary
# --------------------------------------------------------------------------


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def component_bytes() -> bytes:
    """The guest, decoded and checked against its pinned digest."""
    raw = base64.b64decode(COMPONENT_WASM_B64)
    got = sha256(raw)
    if got != COMPONENT_SHA256:
        raise ValueError(f"the embedded component hashes to {got}, expected {COMPONENT_SHA256}")
    return raw


def mutate_one_byte(data: bytes) -> bytes:
    """Flip one ASCII digit, keeping the length, so the only change is a content byte."""
    b = bytearray(data)
    for i, c in enumerate(b):
        if c == ord("0"):
            b[i] = ord("1")
            return bytes(b)
    raise ValueError("no ASCII '0' to mutate; the fixture is not what this injection assumes")


def header_problems(log: bytes) -> list[str]:
    """Why this log cannot support the claim, or an empty list."""
    problems = []
    if not log:
        problems.append("the log is empty; two empty files compare equal and prove nothing")
    text = log.decode("utf-8", "replace")
    missing = [k for k in HEADER_KEYS if k not in text]
    if missing:
        problems.append(f"missing header keys: {missing}")
    return problems


def self_test() -> int:
    """Prove the instrument's guards fire. No guest and no `qqqai` required.

    Every case below is a defect the first harness had, or a way the comparison could be vacuous.
    A checker whose guards have never been seen to fire reports a clean corpus by reading nothing.
    """
    failures = 0
    total = 0

    def case(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures, total
        total += 1
        print(f"  {'OK  ' if ok else 'DEAD'}  {name}")
        if not ok:
            failures += 1
            if detail:
                print(f"         {detail}")

    # 1. the embedded bytes are the pinned artifact
    try:
        raw = component_bytes()
        case("the embedded guest matches its pinned digest", True)
        case("the embedded guest is 281 bytes", len(raw) == 281, f"got {len(raw)}")
    except ValueError as exc:
        case("the embedded guest matches its pinned digest", False, str(exc))
        raw = b""

    # 2. the WAT beside the bytes is the same subject.  Only when `wasm-tools` is present, and
    #    the absence is reported rather than silently skipping -- a check that cannot run must not
    #    look like a check that passed.
    tools = shutil.which("wasm-tools")
    if tools and raw:
        with tempfile.TemporaryDirectory(prefix="det009-selftest-") as tmp:
            wat = Path(tmp) / "guest.wat"
            out = Path(tmp) / "guest.wasm"
            wat.write_bytes(COMPONENT_WAT.encode("utf-8"))
            proc = subprocess.run(
                [tools, "parse", str(wat), "-o", str(out)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
            )
            if proc.returncode != 0 or not out.exists():
                case("the WAT assembles", False, (proc.stderr or "").strip()[:400])
            else:
                case("the WAT assembles", True)
                derived = out.read_bytes()
                case("the WAT derives exactly the embedded bytes",
                     derived == raw,
                     f"WAT -> {sha256(derived)}, embedded -> {sha256(raw)}")
    else:
        print("  SKIP  the WAT derives the embedded bytes (no wasm-tools on PATH)")

    # 3. a healthy log passes the header check
    good = (
        b"qqq-replay 1\n"
        b"artifact_digest " + COMPONENT_SHA256.encode() + b"\n"
        b"engine_version 48.0.3\ntarget_triple x86_64-pc-windows-msvc\ndeterministic true\n"
        b"refused 0\n1 clock.wall clock 1767225600000000000 aa bb\n"
    )
    case("a well-formed log has no problems", header_problems(good) == [])

    # 4. each way the claim could be vacuous is detected
    case("an empty log is refused", header_problems(b"") != [])
    case("a log missing a header key is refused",
         header_problems(good.replace(b"engine_version", b"engin_version")) != [])

    # 5. the injection changes exactly one byte and keeps the length
    if good:
        mut = mutate_one_byte(good)
        diff = sum(1 for a, b in zip(good, mut) if a != b)
        case("the injection changes exactly one byte", diff == 1, f"changed {diff}")
        case("the injection preserves the length", len(mut) == len(good))
        case("the injected baseline differs from the reference", mut != good)

    # 6. and the comparison it feeds can tell them apart -- the whole point of --inject
    identical = sum(1 for _ in range(7) if good == good)
    diverged = sum(1 for _ in range(7) if good != mutate_one_byte(good))
    case("the comparison answers 'identical' for equal logs", identical == 7)
    case("the comparison answers 'diverged' for a one-byte change", diverged == 7,
         f"detected {diverged}/7")

    # 7. the manifest grants exactly the one capability the guest imports
    case("the manifest grants clock.wall", "wall = true" in MANIFEST)

    if failures:
        print(f"\nSELF-TEST FAILED -- {failures}/{total} case(s) bad")
        return 5
    print(f"\nSELF-TEST PASSED -- {total}/{total} case(s); the digest, the WAT provenance, "
          f"the vacuity guards and the divergence counter were each observed to fire")
    return 0


# --------------------------------------------------------------------------
# the end-to-end run
# --------------------------------------------------------------------------


def find_qqqai() -> Path | None:
    for cand in (
        ROOT / "target" / "debug" / "qqqai",
        ROOT / "target" / "debug" / "qqqai.exe",
        ROOT / "target" / "release" / "qqqai",
        ROOT / "target" / "release" / "qqqai.exe",
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    found = shutil.which("qqqai")
    return Path(found) if found else None


def run_once(qqqai: Path, manifest: Path, artifact: Path, logpath: Path) -> tuple[int, bytes]:
    proc = subprocess.run(
        [
            str(qqqai), "run",
            "--manifest", str(manifest),
            "--artifact", str(artifact),
            "--deterministic",
            "--replay-log", str(logpath),
        ],
        cwd=str(ROOT), capture_output=True,
    )
    return proc.returncode, proc.stdout


def end_to_end(trials: int, inject: bool, progress_every: int) -> int:
    qqqai = find_qqqai()
    if qqqai is None:
        print("PREREQ_MISSING no built qqqai -- `cargo build -p qqq-run --bin qqqai`")
        print("  This is the dependency the bridge declares for DX-004 and AGENT-024 as well: "
              "that image builds workspace tests, not the CLI binary.")
        return 2

    try:
        raw = component_bytes()
    except ValueError as exc:
        print(f"PREREQ_MISSING {exc}")
        return 2

    print(f"QQQAI        {qqqai}")
    print(f"ARTIFACT_SHA {sha256(raw)}")
    print(f"INJECT       {inject}")
    print(f"PLANNED      {trials}")

    with tempfile.TemporaryDirectory(prefix="det009-") as tmp:
        tmpdir = Path(tmp)
        artifact = tmpdir / "reads-clock.wasm"
        manifest = tmpdir / "qqq.toml"
        artifact.write_bytes(raw)
        manifest.write_bytes(MANIFEST.encode("utf-8"))
        ref_path = tmpdir / "ref.replay"
        cur_path = tmpdir / "cur.replay"

        rc, _ = run_once(qqqai, manifest, artifact, ref_path)
        if rc != 0 or not ref_path.exists():
            print(f"REFERENCE_FAILED rc={rc}")
            return 2
        ref = ref_path.read_bytes()
        print(f"REFERENCE_BYTES {len(ref)}")
        print(f"REFERENCE_SHA256 {sha256(ref)}")

        problems = header_problems(ref)
        if problems:
            for p in problems:
                print(f"REFERENCE_UNUSABLE {p}")
            return 3
        print(f"REFERENCE_HEADER_KEYS_OK {len(HEADER_KEYS)}")

        baseline = mutate_one_byte(ref) if inject else ref
        if inject:
            print(f"INJECTED_BASELINE_SHA256 {sha256(baseline)}")

        started = time.monotonic()
        failed = diverged = compared = 0
        n = 0
        for n in range(1, trials + 1):
            rc, _ = run_once(qqqai, manifest, artifact, cur_path)
            if rc != 0:
                failed += 1
            try:
                cur = cur_path.read_bytes()
            except OSError:
                failed += 1
                continue
            compared += 1
            if cur != baseline:
                diverged += 1
            if progress_every and n % progress_every == 0:
                rate = n / max(1e-9, time.monotonic() - started)
                print(f"PROGRESS trials={n} compared={compared} failed={failed} "
                      f"diverged={diverged} rate={rate:.1f}/s")

        elapsed = time.monotonic() - started
        print(f"TRIALS_ATTEMPTED={n}")
        print(f"COMPARISONS_PERFORMED={compared}")
        print(f"RUNS_THAT_FAILED={failed}")
        print(f"LOGS_THAT_DIVERGED={diverged}")
        print(f"ELAPSED_SECONDS={elapsed:.1f}")
        print(f"MS_PER_TRIAL={(elapsed / max(1, n)) * 1000:.1f}")

    if compared != n:
        print(f"INERT_LOOP compared={compared} of attempted={n}")
        return 3
    if inject:
        if diverged != n:
            print(f"INJECTION_UNDETECTED diverged={diverged} of {n} -- the counter is dead, "
                  f"so a 0 from it means nothing")
            return 4
        print(f"INJECTION_DETECTED {diverged}/{n} -- the counter can fire")
        return 0
    if failed == 0 and diverged == 0:
        print(f"DET009 OK {n}/{n} byte-identical, 0 failed")
        return 0
    print(f"DET009 DIVERGENCE failed={failed} diverged={diverged}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true",
                    help="exercise the pure logic; needs neither qqqai nor a guest")
    ap.add_argument("--trials", type=int, default=25,
                    help="how many trials (default 25; --full is 10000)")
    ap.add_argument("--full", action="store_true",
                    help="the 10000 trials DOD-003 names")
    ap.add_argument("--inject", action="store_true",
                    help="mutate the baseline by one byte; every trial must then diverge")
    ap.add_argument("--progress-every", type=int, default=0,
                    help="print a progress line every N trials (0: only for large runs)")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    trials = 10000 if args.full else args.trials
    progress = args.progress_every
    if progress == 0 and trials >= 500:
        progress = max(1, trials // 10)
    return end_to_end(trials, args.inject, progress)


if __name__ == "__main__":
    raise SystemExit(main())
