# SPDX-License-Identifier: Apache-2.0

"""Prove the architecture tests detect real violations.

Three injections, each of which must make exactly the intended test go red:

  1. A topology violation: `qqq-cap` (position 1) gains a dependency on
     `qqq-serve` (position 5) — an edge pointing UP the §4.3 order.
  2. An unsafe-code violation: `qqq-io` loses its `forbid` and takes a bare
     `allow`.
  3. A widening constructor: `qqq-cap` gains a `fn union(` on `GrantSet`.

Every injection must produce **valid Rust or valid TOML** — an injection that
fails to parse proves nothing about the check, because the check never runs
(Observations §O-048c, §O-058e). Where an injection would break the build, this
harness reports that separately rather than counting it as a detection.

The working tree is restored from a `tempfile` copy, not from `.scratch/`, which
is gitignored and absent on a fresh checkout (§O-058f).
"""
import io
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def derive_topology_injection():
    """Pick an upward, acyclic edge to inject into `crates/qqq-cap/Cargo.toml`.

    The old version hardcoded `qqq-cap -> qqq-debug`. That was correct while
    `qqq-debug` sat at position 9; `HOST-009` moved it to position 2, the edge
    became downward and legal, and CI reported `MISSED topology (upward
    dependency)` -- the harness correctly detecting that its *target* had gone
    stale.

    Two conditions, both from §O-059c:

    1. **Upward** -- the target sits above the source in §4.3, so the edge is a
       real violation.
    2. **Acyclic** -- the target must not already reach the source. A cycle makes
       Cargo refuse the manifest, and the test never runs, which reports BROKEN
       rather than DETECTED. A cycle is a different protection from the one under
       test.

    The order is read from `check_topology.py` and the graph from the manifests,
    deliberately duplicated rather than imported: an injector sharing the
    checker's code could not detect a bug in that code. `qqq-sys` is skipped
    because the checker treats it as exempt.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import check_topology
        order = [n for n in check_topology.ORDER if n != 'qqq-sys']
    except Exception as exc:  # pragma: no cover - reported, not swallowed
        print(f'  SKIP      topology: could not read the order ({exc})')
        raise SystemExit(f'cannot derive the topology injection: {exc}')

    source = 'qqq-cap'
    index = {name: i for i, name in enumerate(order)}

    # Declared dependencies, from the manifests (the *declared* graph, matching
    # what the architecture test reads).
    def declared(name):
        manifest = ROOT / 'crates' / name / 'Cargo.toml'
        if not manifest.is_file():
            return set()
        found = set()
        for line in manifest.read_text(encoding='utf-8').splitlines():
            head = line.split('=', 1)[0].strip().strip('"')
            if head.startswith('qqq-') and head in index:
                found.add(head)
        return found

    def reaches(start):
        seen, stack = set(), [start]
        while stack:
            for dep in declared(stack.pop()):
                if dep not in seen:
                    seen.add(dep)
                    stack.append(dep)
        return seen

    if source not in index:
        raise SystemExit(f'{source} is not in the order; cannot derive')

    for target in order:
        if target == source or target in declared(source):
            continue
        upward = index[target] > index[source]
        acyclic = source not in reaches(target)
        if upward and acyclic:
            return (
                'topology (upward dependency)',
                Path(f'crates/{source}/Cargo.toml'),
                '[dependencies]',
                f'[dependencies]\n{target} = {{ path = "../{target}", version = "0.0.0" }}',
                'no_crate_depends_on_a_crate_above_it',
                f'depends on `{target}`',
            )

    raise SystemExit(
        f'no upward, acyclic target for {source} -- the injection cannot be derived'
    )


INJECTIONS = [
    # DERIVED, not hardcoded -- see `derive_topology_injection` below.
    derive_topology_injection(),
    (
        'unsafe policy (bare allow)',
        Path('crates/qqq-io/src/lib.rs'),
        '#![forbid(unsafe_code)]',
        '#![allow(unsafe_code)]',
        'every_non_exception_crate_forbids_unsafe_code',
        'does not forbid `unsafe_code`',
    ),
    (
        'grant widening (union on GrantSet)',
        Path('crates/qqq-cap/src/resolve.rs'),
        'impl GrantSet {',
        'impl GrantSet {\n    /// INJECTED widening primitive, for the architecture test.\n    pub fn union(&self, _other: &Self) -> Self {\n        self.clone()\n    }\n',
        'no_widening_constructor_on_grants_exists_anywhere',
        'widening primitive',
    ),
]


def run_test(name: str) -> str:
    out = subprocess.run(
        ['cargo', 'test', '-p', 'qqq-core', '--test', 'architecture', name],
        capture_output=True, text=True, errors='replace', cwd=ROOT,
    )
    return out.stdout + out.stderr


def main() -> int:
    failures = []

    for label, path, needle, replacement, test_name, expect in INJECTIONS:
        full = ROOT / path
        original = io.open(full, encoding='utf-8').read()
        if needle not in original:
            print(f'  SKIP  {label}: injection point moved in {path}')
            failures.append(label)
            continue

        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / full.name
            shutil.copy(full, backup)
            try:
                io.open(full, 'w', encoding='utf-8', newline='').write(
                    original.replace(needle, replacement, 1)
                )
                combined = run_test(test_name)

                if expect in combined and 'test result: FAILED' in combined:
                    print(f'  DETECTED  {label}')
                elif 'error[' in combined or 'error: ' in combined:
                    print(f'  BROKEN    {label}: injected source did not compile')
                    for line in combined.splitlines():
                        if line.startswith('error'):
                            print('              ' + line[:120])
                    failures.append(label)
                else:
                    print(f'  MISSED    {label}: the test passed on violating code')
                    failures.append(label)
            finally:
                shutil.copy(backup, full)

            if io.open(full, encoding='utf-8').read() != original:
                print(f'  RESTORE FAILED for {label} -- fix the tree')
                return 3

    print()
    if failures:
        print(f'ARCHITECTURE FAULT INJECTION FAILED -- {len(failures)} of '
              f'{len(INJECTIONS)} injections were not detected: {failures}')
        return 1
    print(f'ALL {len(INJECTIONS)} ARCHITECTURE FAULT INJECTIONS DETECTED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
