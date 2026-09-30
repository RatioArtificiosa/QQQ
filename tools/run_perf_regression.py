#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Run the reference application and compare measured performance with a baseline.

This is deliberately a regression gate, not an absolute §9.2 budget gate. The
published budget targets are stated for a reference hardware profile that the
ordinary hosted CI runner does not promise. Comparing repeated measurements on
the same runner profile catches material regressions without claiming that the
runner meets the product target.

The first run may use ``--allow-missing-baseline`` to produce a candidate. That
candidate must be reviewed and committed as the baseline before the flag is
removed from the workflow. A missing or incompatible baseline is then a hard
failure, never an automatic pass.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
EXPECTED_WORKLOADS = {
    "hello",
    "json",
    "route",
    "db",
    "crypto",
    "template",
    "cpu",
    "multi",
    "tailp99",
    "cold",
}
LATENCY_METRICS = {"hello": "p99_nanos", "tailp99": "p99_nanos"}
THROUGHPUT_METRICS = {"json": "requests_per_second", "multi": "requests_per_second"}
SCHEMA_VERSION = 1


class PerfError(RuntimeError):
    """A measured-input or comparison failure that should fail the CI step."""


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PerfError(f"could not read JSON `{path}`: {error}") from error


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def envelope_data(document: Any, source: str) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("ok") is not True:
        raise PerfError(f"{source}: qqqai bench did not report an ok envelope")
    data = document.get("data")
    if not isinstance(data, dict):
        raise PerfError(f"{source}: qqqai bench envelope has no object data field")
    return data


def budget_source_items(text: str) -> tuple[set[str], set[str]]:
    """Return implemented and explicitly unimplemented budget item ids.

    The runner must not carry a second hand-written list of the seven gaps. It
    reads the same machine-readable table that the static contract checker reads,
    and refuses an unfamiliar method shape rather than silently dropping a row.
    """

    blocks = re.findall(r"Self\s*\{(?P<body>.*?)\s*\},", text, flags=re.DOTALL)
    implemented: set[str] = set()
    unimplemented: set[str] = set()
    for block in blocks:
        item = re.search(r"item:\s*Item::(Perf\d+)", block)
        method = re.search(r'method:\s*"([^"]+)"', block)
        if item is None or method is None:
            continue
        item_id = f"PERF-{item.group(1)[4:]}"
        if method.group(1).startswith("NOT_IMPLEMENTED::"):
            unimplemented.add(item_id)
        else:
            implemented.add(item_id)
    if len(implemented) + len(unimplemented) != 10:
        raise PerfError(
            "Budget::ALL parser found "
            f"{len(implemented) + len(unimplemented)} rows; expected 10"
        )
    if implemented & unimplemented:
        raise PerfError("Budget::ALL classified an item as both implemented and unimplemented")
    return implemented, unimplemented


def environment_signature(environment: dict[str, Any]) -> str:
    required = ("cpu_model", "physical_cores", "memory_bytes", "os", "kernel", "toolchains")
    for key in required:
        value = environment.get(key)
        if value in (None, "", {}, []):
            raise PerfError(f"benchmark environment is missing `{key}`")
    return json.dumps({key: environment[key] for key in required}, sort_keys=True)


def normalize_run(document: Any, source: str, implemented_items: set[str]) -> dict[str, Any]:
    data = envelope_data(document, source)
    environment = data.get("environment")
    results = data.get("results")
    if not isinstance(environment, dict):
        raise PerfError(f"{source}: environment is not an object")
    environment_signature(environment)
    if not isinstance(results, list):
        raise PerfError(f"{source}: results is not an array")

    by_name: dict[str, dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("benchmark"), str):
            raise PerfError(f"{source}: result has no benchmark name")
        name = result["benchmark"]
        if name in by_name:
            raise PerfError(f"{source}: duplicate benchmark `{name}`")
        if name not in EXPECTED_WORKLOADS:
            raise PerfError(f"{source}: unexpected benchmark `{name}`")
        if not isinstance(result.get("attempted"), int) or result["attempted"] <= 0:
            raise PerfError(f"{source}: `{name}` attempted no requests")
        if result.get("failed") != 0:
            raise PerfError(f"{source}: `{name}` recorded failed requests")
        by_name[name] = result

    if set(by_name) != EXPECTED_WORKLOADS:
        missing = sorted(EXPECTED_WORKLOADS - set(by_name))
        raise PerfError(f"{source}: missing benchmark rows: {', '.join(missing)}")

    observed_items: set[str] = set()
    for result in by_name.values():
        budget = result.get("budget")
        if budget is None:
            continue
        if not isinstance(budget, dict) or not isinstance(budget.get("item"), str):
            raise PerfError(
                f"{source}: `{result['benchmark']}` has a budget without a string item"
            )
        if not budget["item"].strip():
            raise PerfError(f"{source}: `{result['benchmark']}` has a blank budget item")
        observed_items.add(budget["item"])
    if observed_items != implemented_items:
        raise PerfError(
            f"{source}: measured budget items {sorted(observed_items)} do not match "
            f"Budget::ALL's implemented items {sorted(implemented_items)}"
        )

    for name, metric in {**LATENCY_METRICS, **THROUGHPUT_METRICS}.items():
        value = by_name[name].get(metric)
        if not isinstance(value, (int, float)) or value <= 0:
            raise PerfError(f"{source}: `{name}` has no positive `{metric}`")

    does_not_measure = data.get("does_not_measure")
    if not isinstance(does_not_measure, list) or not does_not_measure:
        raise PerfError(f"{source}: does_not_measure must be a non-empty array")
    if not all(isinstance(item, str) and item.strip() for item in does_not_measure):
        raise PerfError(f"{source}: does_not_measure contains a blank or non-string claim")
    harness_source = data.get("harness_source")
    if not isinstance(harness_source, str) or not harness_source.strip():
        raise PerfError(f"{source}: harness_source must be non-empty")

    return {
        "environment": environment,
        "environment_signature": environment_signature(environment),
        "results": by_name,
        "does_not_measure": does_not_measure,
        "harness_source": harness_source,
    }


def metric_value(run: dict[str, Any], name: str, metric: str) -> float:
    value = run["results"][name][metric]
    if not isinstance(value, (int, float)) or value <= 0:
        raise PerfError(f"`{name}` has no positive `{metric}`")
    return float(value)


def aggregate(runs: list[dict[str, Any]], profile: str, commit: str) -> dict[str, Any]:
    if not runs:
        raise PerfError("no benchmark runs were supplied")
    signatures = {run["environment_signature"] for run in runs}
    if len(signatures) != 1:
        raise PerfError("benchmark runs disagree about their measured environment")

    metrics: dict[str, dict[str, Any]] = {}
    for name, metric in {**LATENCY_METRICS, **THROUGHPUT_METRICS}.items():
        values = [metric_value(run, name, metric) for run in runs]
        metrics[name] = {
            "metric": metric,
            "samples": values,
            "median": statistics.median(values),
        }

    budget_misses = sorted(
        name
        for run in runs
        for name, result in run["results"].items()
        if isinstance(result.get("budget"), dict) and result["budget"].get("met") is False
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": profile,
        "commit": commit,
        "samples": len(runs),
        "environment": runs[0]["environment"],
        "metrics": metrics,
        "budget_misses": sorted(set(budget_misses)),
        "measured_budget_items": sorted(
            {
                result["budget"]["item"]
                for result in runs[0]["results"].values()
                if isinstance(result.get("budget"), dict)
            }
        ),
        "does_not_measure": runs[0]["does_not_measure"],
        "harness_source": runs[0]["harness_source"],
    }


def compare(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    latency_tolerance: float,
    throughput_tolerance: float,
) -> list[str]:
    if baseline.get("schema_version") != SCHEMA_VERSION:
        raise PerfError("baseline schema version is not supported")
    if baseline.get("profile") != candidate["profile"]:
        raise PerfError(
            f"baseline profile `{baseline.get('profile')}` does not match `{candidate['profile']}`"
        )
    if baseline.get("environment") != candidate["environment"]:
        raise PerfError(
            "baseline environment does not match the current runner; refresh it only after "
            "reviewing the runner/profile change"
        )

    failures: list[str] = []
    for name, candidate_metric in candidate["metrics"].items():
        baseline_metric = baseline.get("metrics", {}).get(name)
        if not isinstance(baseline_metric, dict):
            raise PerfError(f"baseline has no `{name}` metric")
        baseline_value = baseline_metric.get("median")
        current_value = candidate_metric.get("median")
        if not isinstance(baseline_value, (int, float)) or baseline_value <= 0:
            raise PerfError(f"baseline `{name}` has no positive median")
        if not isinstance(current_value, (int, float)) or current_value <= 0:
            raise PerfError(f"candidate `{name}` has no positive median")

        if name in LATENCY_METRICS:
            limit = float(baseline_value) * (1.0 + latency_tolerance)
            if current_value > limit:
                failures.append(
                    f"{name} {current_value:.2f} > {limit:.2f} ns "
                    f"(baseline {baseline_value:.2f}, tolerance {latency_tolerance:.0%})"
                )
        else:
            limit = float(baseline_value) * (1.0 - throughput_tolerance)
            if current_value < limit:
                failures.append(
                    f"{name} {current_value:.2f} < {limit:.2f} RPS "
                    f"(baseline {baseline_value:.2f}, tolerance {throughput_tolerance:.0%})"
                )
    return failures


def baseline_mode(path: Path, allow_missing: bool) -> str:
    """Decide whether a path is ready for comparison or explicit bootstrap."""

    if path.is_file():
        return "compare"
    if allow_missing:
        return "bootstrap"
    raise PerfError(
        f"baseline `{path}` is missing; review the candidate and commit it, "
        "or use --allow-missing-baseline only for bootstrap"
    )


def choose_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def health_status(port: int) -> int | None:
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


def wait_for_health(child: subprocess.Popen[str], port: int, log: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if health_status(port) == 200:
            return
        if child.poll() is not None:
            detail = log.read_text(encoding="utf-8", errors="replace")
            raise PerfError(f"qqqai serve exited with {child.returncode}:\n{detail}")
        time.sleep(0.1)
    detail = log.read_text(encoding="utf-8", errors="replace")
    raise PerfError(f"qqqai serve did not become healthy within {timeout:.0f}s:\n{detail}")


def run_bench(
    binary: Path,
    project: Path,
    port: int,
    output: Path,
    timeout: float,
) -> dict[str, Any]:
    command = [str(binary), "bench", "--listen", f"127.0.0.1:{port}", "--json"]
    completed = subprocess.run(
        command,
        cwd=project,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(completed.stdout, encoding="utf-8")
    output.with_suffix(".stderr").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise PerfError(
            f"qqqai bench failed with exit {completed.returncode}; "
            f"see `{output}` and `{output.with_suffix('.stderr')}`"
        )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise PerfError(f"{output}: qqqai bench produced no JSON")
    try:
        document = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise PerfError(f"{output}: last output line is not JSON: {error}") from error
    return document


def stop_server(child: subprocess.Popen[str]) -> None:
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=10)


def execute(args: argparse.Namespace) -> int:
    binary = Path(args.binary)
    if not binary.is_absolute():
        binary = ROOT / binary
    binary = binary.resolve()
    project = Path(args.project)
    if not project.is_absolute():
        project = ROOT / project
    project = project.resolve()
    if not binary.is_file():
        raise PerfError(f"qqqai binary does not exist: `{binary}`")
    if not project.is_dir():
        raise PerfError(f"reference project does not exist: `{project}`")

    runs_dir = Path(args.runs_dir)
    if not runs_dir.is_absolute():
        runs_dir = ROOT / runs_dir
    runs_dir = runs_dir.resolve()
    runs_dir.mkdir(parents=True, exist_ok=True)
    candidate_path = Path(args.candidate)
    if not candidate_path.is_absolute():
        candidate_path = ROOT / candidate_path
    baseline_path = Path(args.baseline)
    if not baseline_path.is_absolute():
        baseline_path = ROOT / baseline_path

    budget_text = (ROOT / "crates" / "qqq-bench" / "src" / "budget.rs").read_text(
        encoding="utf-8"
    )
    implemented_items, unimplemented_items = budget_source_items(budget_text)
    commit = os.environ.get("GITHUB_SHA", "local")
    port = choose_port()
    log = runs_dir / "server.log"
    with log.open("w", encoding="utf-8") as stream:
        child = subprocess.Popen(
            [str(binary), "serve", "--listen", f"127.0.0.1:{port}", "--config", "qqq.toml"],
            cwd=project,
            stdout=stream,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            wait_for_health(child, port, log, args.health_timeout)
            runs: list[dict[str, Any]] = []
            for index in range(1, args.samples + 1):
                output = runs_dir / f"run-{index}.json"
                document = run_bench(binary, project, port, output, args.bench_timeout)
                runs.append(normalize_run(document, str(output), implemented_items))
        finally:
            stop_server(child)

    candidate = aggregate(runs, args.profile, commit)
    candidate["not_measured_budget_items"] = sorted(unimplemented_items)
    write_json(candidate_path, candidate)

    print(f"PERF-020 profile: {args.profile}")
    print(f"PERF-020 samples: {args.samples} medians written to {candidate_path}")
    print(f"measured budget items: {', '.join(candidate['measured_budget_items'])}")
    print(f"not measured in the socket harness: {', '.join(candidate['not_measured_budget_items'])}")
    if candidate["budget_misses"]:
        print(
            "absolute §9.2 misses are informational on this runner: "
            + ", ".join(candidate["budget_misses"])
        )

    if baseline_mode(baseline_path, args.allow_missing_baseline) == "bootstrap":
        print("PERF-020 BOOTSTRAP: no baseline exists; comparison intentionally skipped")
        return 0

    baseline = read_json(baseline_path)
    failures = compare(baseline, candidate, args.latency_tolerance, args.throughput_tolerance)
    for name, metric in candidate["metrics"].items():
        print(f"{name}: median {metric['median']:.2f} {metric['metric']}")
    if failures:
        print("PERF REGRESSION DETECTED")
        for failure in failures:
            print(f"  FAIL  {failure}")
        return 1
    print("PERF REGRESSION GATE OK")
    return 0


def fixture_run(scale: float = 1.0) -> dict[str, Any]:
    environment = {
        "cpu_model": "fixture-cpu",
        "physical_cores": 4,
        "memory_bytes": 1024,
        "os": "fixture x86_64",
        "kernel": "fixture-kernel",
        "toolchains": {"rustc": "fixture"},
    }
    results = []
    for name in sorted(EXPECTED_WORKLOADS):
        result: dict[str, Any] = {
            "benchmark": name,
            "attempted": 10,
            "failed": 0,
            "p99_nanos": 100.0,
            "requests_per_second": 100.0,
            "budget": None,
        }
        if name == "hello":
            result["budget"] = {"item": "PERF-002", "met": True}
            result["p99_nanos"] = 100.0 * scale
        elif name == "json":
            result["budget"] = {"item": "PERF-010", "met": True}
            result["requests_per_second"] = 100.0 * scale
        elif name == "multi":
            result["budget"] = {"item": "PERF-010", "met": True}
            result["requests_per_second"] = 100.0 * scale
        elif name == "tailp99":
            result["budget"] = {"item": "PERF-011", "met": True}
            result["p99_nanos"] = 100.0 * scale
        results.append(result)
    return {
        "ok": True,
        "data": {
            "environment": environment,
            "results": results,
            "does_not_measure": ["fixture"],
            "harness_source": "fixture",
        },
    }


def self_test() -> int:
    # The fixture is intentionally synthetic: it tests the parser independently
    # from the production table while preserving the ten-row anti-vacuity rule.
    synthetic = "\n".join(
        f'Self {{ item: Item::Perf{i:03d}, method: "{("NOT_IMPLEMENTED::x" if i % 2 else "crate::x")}" }},'
        for i in range(2, 12)
    )
    implemented, unimplemented = budget_source_items(synthetic)
    expected_implemented = {f"PERF-{i:03d}" for i in range(2, 12) if i % 2 == 0}
    expected_unimplemented = {f"PERF-{i:03d}" for i in range(2, 12) if i % 2 == 1}
    if implemented != expected_implemented or unimplemented != expected_unimplemented:
        raise AssertionError("synthetic Budget::ALL classification drifted")

    def expect_error(label: str, function) -> None:
        try:
            function()
        except PerfError:
            return
        raise AssertionError(f"{label} was accepted")

    expect_error("a short Budget::ALL source", lambda: budget_source_items("Self {}"))

    real_items = {"PERF-002", "PERF-010", "PERF-011"}
    runs = [
        normalize_run(fixture_run(), "fixture", real_items),
        normalize_run(fixture_run(), "fixture", real_items),
        normalize_run(fixture_run(), "fixture", real_items),
    ]
    baseline = aggregate(runs, "fixture", "base")
    if compare(baseline, aggregate(runs, "fixture", "current"), 0.25, 0.20):
        raise AssertionError("an unchanged baseline was rejected")
    if not compare(
        baseline,
        aggregate(
            [normalize_run(fixture_run(2.0), "fixture", real_items)] * 3,
            "fixture",
            "current",
        ),
        0.25,
        0.20,
    ):
        raise AssertionError("latency regression was accepted")
    if not compare(
        baseline,
        aggregate(
            [normalize_run(fixture_run(0.5), "fixture", real_items)] * 3,
            "fixture",
            "current",
        ),
        0.25,
        0.20,
    ):
        raise AssertionError("throughput regression was accepted")
    mismatched = aggregate(runs, "other-profile", "current")
    expect_error("a profile mismatch", lambda: compare(baseline, mismatched, 0.25, 0.20))
    malformed = fixture_run()
    malformed["data"]["results"] = malformed["data"]["results"][:-1]
    expect_error("a missing benchmark row", lambda: normalize_run(malformed, "fixture", real_items))
    malformed_budget = fixture_run()
    malformed_budget["data"]["results"][0]["budget"] = {"met": True}
    expect_error(
        "a budget without an item",
        lambda: normalize_run(malformed_budget, "fixture", real_items),
    )
    missing_metric = json.loads(json.dumps(baseline))
    del missing_metric["metrics"]["hello"]
    expect_error(
        "a baseline missing a metric",
        lambda: compare(missing_metric, baseline, 0.25, 0.20),
    )
    with tempfile.TemporaryDirectory(prefix="qqq-perf-self-test-") as temporary:
        missing_baseline = Path(temporary) / "baseline.json"
        expect_error("a missing baseline without bootstrap", lambda: baseline_mode(missing_baseline, False))
        if baseline_mode(missing_baseline, True) != "bootstrap":
            raise AssertionError("explicit bootstrap was not accepted")
    print("PERF REGRESSION SELF-TEST OK — parser, schema, bootstrap inputs and both regression directions")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--binary", default="target/release/qqqai")
    parser.add_argument("--project", default="examples/orders-api")
    parser.add_argument("--baseline", default=".github/perf/baseline.json")
    parser.add_argument("--candidate", default="target/perf-regression/candidate.json")
    parser.add_argument("--runs-dir", default="target/perf-regression")
    parser.add_argument("--profile", default="local")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--health-timeout", type=float, default=120)
    parser.add_argument("--bench-timeout", type=float, default=300)
    parser.add_argument("--latency-tolerance", type=float, default=0.25)
    parser.add_argument("--throughput-tolerance", type=float, default=0.20)
    parser.add_argument("--allow-missing-baseline", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.samples < 1:
        parser.error("--samples must be positive")
    try:
        return execute(args)
    except (OSError, PerfError, subprocess.SubprocessError) as error:
        print(f"PERF REGRESSION ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
