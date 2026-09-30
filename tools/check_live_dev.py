#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise CLI rebuild/activation, failed-build retention, manifest barrier and AOT.

Requires a built target/debug/qqqai, cargo, wasm32-wasip2 and wasm-tools.
All mutations occur in an isolated copy of the reference guest.
Exit: 0 = checks passed, 1 = a failed check or missing prerequisite.
--self-test exercises the activation assertion and missing-binary refusal without
a compiler or server. This integration checker reports failures as FAIL on stderr.
"""

from pathlib import Path
import argparse
import contextlib
import io
from types import SimpleNamespace
import http.client
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target" / "debug" / ("qqqai.exe" if sys.platform == "win32" else "qqqai")


def wait_for(predicate, child, log, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if child.poll() is not None:
            if predicate():
                return
            raise AssertionError(f"dev exited unexpectedly: {log.read_text(encoding='utf-8')}")
        time.sleep(0.05)
    raise AssertionError(f"dev verification deadline expired: {log.read_text(encoding='utf-8')}")


def status(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        response.read()
        return response.status
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def wait_for_activation(child, log, timeout=120):
    wait_for(lambda: "reload 1: activated" in log.read_text(encoding="utf-8"), child, log, timeout)


def wait_for_exit(child, log, timeout=120):
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise AssertionError(f"dev did not exit after reload: {log.read_text(encoding='utf-8')}") from error


def verify_retention(observed_status):
    assert observed_status == 404, "failed build must retain v2"


def verify_manifest_barrier(text):
    assert "reload 4: restart required" in text, "manifest barrier must survive later source edits"


def verify_aot(report, native):
    assert report["ok"] and report["data"]["aot_performed"], "AOT was not performed"
    assert len(native) >= 4 and native[:4] != b"\0asm", "AOT output must be native code, not portable Wasm"


def run(binary):
    if not binary.is_file():
        print("FAIL: qqqai is missing; run cargo build -p qqq-run before this integration check", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="qqq-live-dev-") as temporary:
        root = Path(temporary)
        project = root / "guest"
        shutil.copytree(ROOT / "examples" / "orders-api", project, ignore=shutil.ignore_patterns("target"))
        # Reuse local compilation intermediates when available; guest source is still rebuilt.
        built = ROOT / "examples" / "orders-api" / "target"
        if built.is_dir():
            shutil.copytree(built, project / "target")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        log = root / "dev.log"
        with log.open("w", encoding="utf-8") as output:
            child = subprocess.Popen([str(binary), "dev", "--port", str(port), "--reload-limit", "4"],
                                     cwd=project, stdout=output, stderr=output)
            try:
                wait_for(lambda: status(port) == 200, child, log)
                pid = child.pid
                source = project / "src" / "router.rs"
                original = source.read_text(encoding="utf-8")
                assert 'path: "/healthz"' in original
                replacement = original.replace('path: "/healthz"', 'path: "/updated"', 1)
                source.write_text(replacement, encoding="utf-8", newline="")
                wait_for_activation(child, log)
                assert child.pid == pid and status(port) == 404, "same process must serve changed guest code"
                source.write_text("not valid Rust", encoding="utf-8", newline="")
                wait_for(lambda: "reload 2:" in log.read_text(encoding="utf-8"), child, log)
                verify_retention(status(port))
                manifest = project / "qqq.toml"
                manifest.write_text(manifest.read_text(encoding="utf-8") + "\n# policy edit\n", encoding="utf-8", newline="")
                wait_for(lambda: "reload 3: restart required" in log.read_text(encoding="utf-8"), child, log)
                assert status(port) == 404
                source.write_text(original, encoding="utf-8", newline="")
                wait_for(lambda: "reload 4: restart required" in log.read_text(encoding="utf-8"), child, log)
                wait_for_exit(child, log)
                assert child.returncode == 0
                verify_manifest_barrier(log.read_text(encoding="utf-8"))
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=10)
        cache = root / "native-cache"
        built = subprocess.run([str(binary), "build", "--release", "--aot", "--aot-cache", str(cache), "--json"],
                               cwd=project, capture_output=True, text=True, encoding="utf-8", timeout=180)
        assert built.returncode == 0, built.stdout + built.stderr
        report = json.loads(built.stdout.strip().splitlines()[-1])
        native = list((project / "target" / "qqq" / "aot").glob("*.cwasm"))
        assert len(native) == 1
        verify_aot(report, native[0].read_bytes())
        metadata = json.loads(native[0].with_suffix(".json").read_text(encoding="utf-8"))
        assert metadata["engine"] == "wasmtime"
    print("PASS: same PID/listener, live rebuild, failed-build retention, manifest barrier, CLI AOT output")
    return 0


def self_test():
    with tempfile.TemporaryDirectory(prefix="qqq-live-dev-self-") as temporary:
        root = Path(temporary)
        log = root / "dev.log"
        child = SimpleNamespace(poll=lambda: None)
        log.write_text("reload 1: activated\n", encoding="utf-8")
        wait_for_activation(child, log, timeout=0.1)
        log.write_text("reload 1: build succeeded\n", encoding="utf-8")
        try:
            wait_for_activation(child, log, timeout=0.01)
        except AssertionError as error:
            assert "dev verification deadline expired" in str(error), error
        else:
            raise AssertionError("missing activation was not detected")
        def stuck_child(timeout):
            raise subprocess.TimeoutExpired("fixture-child", timeout)
        try:
            wait_for_exit(SimpleNamespace(wait=stuck_child), log, timeout=0.01)
        except AssertionError as error:
            assert "dev did not exit" in str(error) and "build succeeded" in str(error)
        else:
            raise AssertionError("stuck child was not detected")
        diagnostic = io.StringIO()
        with contextlib.redirect_stderr(diagnostic):
            assert run(root / "missing-qqqai") == 1
        assert "FAIL:" in diagnostic.getvalue() and "cargo build -p qqq-run" in diagnostic.getvalue()
    verify_retention(404)
    verify_manifest_barrier("reload 4: restart required")
    good_report = {"ok": True, "data": {"aot_performed": True}}
    verify_aot(good_report, b"\x7fELF")
    faults = [
        (lambda: verify_retention(200), "failed build"),
        (lambda: verify_manifest_barrier("reload 4: activated"), "manifest barrier"),
        (lambda: verify_aot(good_report, b"\0asm"), "native code"),
        (lambda: verify_aot(good_report, b""), "native code"),
        (lambda: verify_aot({"ok": False}, b"\x7fELF"), "not performed"),
    ]
    for action, message in faults:
        try:
            action()
        except AssertionError as error:
            assert message in str(error), error
        else:
            raise AssertionError(f"fault not detected: {message}")
    print("SELF-TEST PASSED: activation, retention, manifest barrier, AOT faults and missing binary")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        return self_test() if args.self_test else run(BINARY)
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
