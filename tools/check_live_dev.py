#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise CLI rebuild/activation, failed-build retention, manifest barrier and AOT.

Requires a built target/debug/qqqai, cargo, wasm32-wasip2 and wasm-tools.
All mutations occur in an isolated copy of the reference guest.
"""

from pathlib import Path
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


def main():
    if not BINARY.is_file():
        raise RuntimeError("build qqq-run before running this integration check")
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
            child = subprocess.Popen([str(BINARY), "dev", "--port", str(port), "--reload-limit", "4"],
                                     cwd=project, stdout=output, stderr=output)
            try:
                wait_for(lambda: status(port) == 200, child, log)
                pid = child.pid
                source = project / "src" / "router.rs"
                original = source.read_text(encoding="utf-8")
                assert 'path: "/healthz"' in original
                replacement = original.replace('path: "/healthz"', 'path: "/updated"', 1)
                source.write_text(replacement, encoding="utf-8", newline="")
                wait_for(lambda: "reload 1: activated" in log.read_text(encoding="utf-8"), child, log)
                assert child.pid == pid and status(port) == 404, "same process must serve changed guest code"
                source.write_text("not valid Rust", encoding="utf-8", newline="")
                wait_for(lambda: "reload 2:" in log.read_text(encoding="utf-8"), child, log)
                assert status(port) == 404, "failed build must retain v2"
                manifest = project / "qqq.toml"
                manifest.write_text(manifest.read_text(encoding="utf-8") + "\n# policy edit\n", encoding="utf-8", newline="")
                wait_for(lambda: "reload 3: restart required" in log.read_text(encoding="utf-8"), child, log)
                assert status(port) == 404
                source.write_text(original, encoding="utf-8", newline="")
                child.wait(timeout=120)
                assert child.returncode == 0
                assert "reload 4: restart required" in log.read_text(encoding="utf-8"), "manifest barrier must survive later source edits"
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=10)
        cache = root / "native-cache"
        built = subprocess.run([str(BINARY), "build", "--release", "--aot", "--aot-cache", str(cache), "--json"],
                               cwd=project, capture_output=True, text=True, encoding="utf-8", timeout=180)
        assert built.returncode == 0, built.stdout + built.stderr
        report = json.loads(built.stdout.strip().splitlines()[-1])
        assert report["ok"] and report["data"]["aot_performed"], report
        native = list((project / "target" / "qqq" / "aot").glob("*.cwasm"))
        assert len(native) == 1
        assert native[0].read_bytes()[:4] != b"\0asm"
        metadata = json.loads(native[0].with_suffix(".json").read_text(encoding="utf-8"))
        assert metadata["engine"] == "wasmtime"
    print("PASS: same PID/listener, live rebuild, failed-build retention, manifest barrier, CLI AOT output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
