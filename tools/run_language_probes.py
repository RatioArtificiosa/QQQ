#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build narrow language probes and execute the same five HTTP vectors in QQQ.

This is an opt-in laboratory, not the qqqai build driver or the full conformance
suite. Results include failed builds/calls. No missing compiler is a passing test.
Install the pinned tools described in docs/languages/phase3.md first.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'examples/language-probes'
LANGUAGES = ('assemblyscript', 'go', 'python', 'c', 'cpp', 'typescript')
MARKER = 'QQQ_LANGUAGE_RESULT='


def run(args, cwd, timeout=600, env=None):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env,
                            capture_output=True, text=True, encoding='utf-8',
                            errors='replace', timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f'{args!r}: exit {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def npm_bin(name):
    """Return a node_modules/.bin entry that is executable on this host.

    npm installs POSIX shell shims alongside Windows `.cmd` shims.  The
    former are the useful files on Linux, but launching one directly on
    Windows raises ``WinError 193`` before the probe reaches its compiler.
    Choosing the platform-specific wrapper here keeps the measured probe
    identical while making the local and CI drivers agree about what was
    actually executed.
    """
    path = SOURCE / 'node_modules/.bin' / name
    if os.name == 'nt':
        return path.with_suffix('.cmd')
    return path


def runtime_result(text):
    rows = [line.split(MARKER, 1)[1] for line in text.splitlines() if line.startswith(MARKER)]
    if len(rows) != 1:
        raise ValueError('exactly one executed runtime result required')
    result = json.loads(rows[0])
    if result.get('cases_passed') != 5 or len(result.get('call_ms', [])) != 5:
        raise ValueError('all five vectors must execute')
    return result


def input_hashes():
    paths = [ROOT / 'wit/qqq-http.wit', ROOT / 'examples/orders-api/wit/app.wit',
             ROOT / 'crates/qqq-run/tests/language_probe.rs', Path(__file__)]
    paths += [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'rust-toolchain.toml']
    paths += list((ROOT / 'crates').rglob('*.rs'))
    paths += list((ROOT / 'crates').rglob('Cargo.toml'))
    paths += [p for p in SOURCE.rglob('*') if p.is_file() and 'node_modules' not in p.parts]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}


def build(language, work):
    wit = work / 'wit'
    shutil.copytree(ROOT / 'examples/orders-api/wit', wit)
    # Read the current canonical type declarations, not a stale vendored copy.
    shutil.copyfile(ROOT / 'wit/qqq-http.wit', wit / 'deps/qqq-http/qqq-http.wit')
    out = work / 'app.wasm'
    if language == 'assemblyscript':
        shutil.copyfile(SOURCE / language / 'index.ts', work / 'index.ts')
        run([npm_bin('asc'), 'index.ts', '--runtime', 'stub', '--use', 'abort=index/abort',
             '--outFile', 'core.wasm', '--optimize'], work)
        wat = run(['wasm-tools', 'print', 'core.wasm'], work)
        anchor = '(export "handle" '
        if wat.count(anchor) != 1:
            raise ValueError('expected exactly one AssemblyScript handle export')
        # Canonical flat ABI is intentionally narrow and guarded by the WIT digest.
        expected = json.loads((ROOT / 'conformance/languages/policy.json').read_text(encoding='utf-8'))
        actual = hashlib.sha256((ROOT / 'wit/qqq-http.wit').read_bytes()).hexdigest()
        if actual != expected['assemblyscript_http_wit_sha256']:
            raise ValueError('HTTP WIT changed: regenerate/review the AssemblyScript ABI adapter')
        (work / 'core.wat').write_text(wat.replace(anchor, '(export "qqq:http/incoming-handler@1.0.0#handle" '), encoding='utf-8')
        run(['wasm-tools', 'component', 'embed', wit, 'core.wat', '--world', 'app', '-o', 'typed.wasm'], work)
        run(['wasm-tools', 'component', 'new', 'typed.wasm', '-o', out], work)
    elif language == 'go':
        for name in ('main.go', 'go.mod', 'go.sum'):
            shutil.copyfile(SOURCE / 'go' / name, work / name)
        run(['wit-bindgen-go', 'generate', wit, '--world', 'app', '--out', 'gen',
             '--package-root', 'example.com/probe/gen'], work)
        tinyroot = Path(run(['tinygo', 'env', 'TINYGOROOT'], work).strip())
        wasi = tinyroot / 'lib/wasi-cli/wit'
        shutil.copytree(wasi / 'deps', wit / 'deps', dirs_exist_ok=True)
        (wit / 'deps/cli').mkdir()
        for path in wasi.glob('*.wit'):
            shutil.copyfile(path, wit / 'deps/cli' / path.name)
        app = wit / 'app.wit'
        app.write_text(app.read_text(encoding='utf-8').replace('world app {', 'world app {\n include wasi:cli/imports@0.2.0;'), encoding='utf-8')
        run(['tinygo', 'build', '-target=wasip2', '-wit-package', 'wit', '-wit-world', 'app', '-o', out, '.'], work)
    elif language in ('c', 'cpp'):
        run(['wit-bindgen', 'c', wit, '--world', 'app', '--out-dir', '.'], work)
        shutil.copytree(SOURCE / 'c', work / 'c')
        shutil.copytree(SOURCE / 'cpp', work / 'cpp')
        run(['clang', '--target=wasm32-wasip2', '-O2', '-I.', '-c', 'app.c', '-o', 'bindings.o'], work)
        compiler = 'clang++' if language == 'cpp' else 'clang'
        source = 'cpp/main.cpp' if language == 'cpp' else 'c/main.c'
        args = [compiler, '--target=wasm32-wasip2', '-mexec-model=reactor', '-O2', '-I.']
        if language == 'cpp':
            args += ['-std=c++17']
        run(args + [source, 'bindings.o', 'app_component_type.o', '-o', out], work)
    elif language == 'python':
        shutil.copyfile(SOURCE / 'python/app.py', work / 'app.py')
        run(['componentize-py', '-d', wit, '-w', 'app', 'bindings', '.'], work)
        # This pure HTTP probe uses no WASI. Stubbed randomness is NOT suitable
        # for production: componentize-py's seed is snapshotted into the guest.
        run(['componentize-py', '-d', wit, '-w', 'app', 'componentize', '--stub-wasi', 'app', '-o', out], work)
    else:
        run([npm_bin('tsc'), SOURCE / 'typescript/app.ts', '--target', 'es2022',
             '--module', 'es2022', '--outDir', work], work)
        run(['node', SOURCE / 'typescript/build.mjs', work / 'app.js', wit, out], work)
    run(['wasm-tools', 'validate', out], work)
    return out


def measure(language, destination):
    row = {'language': language, 'status': 'failed', 'inputs': {},
           'environment': {'platform': sys.platform, 'machine': __import__('platform').machine()},
           'tool_versions': {}}
    versions = [['rustc', '--version'], ['wasm-tools', '--version']]
    versions += {'go': [['go', 'version'], ['tinygo', 'version'], ['wit-bindgen-go', '--version']],
                 'python': [['componentize-py', '--version']],
                 'c': [['clang', '--version'], ['wit-bindgen', '--version']],
                 'cpp': [['clang++', '--version'], ['wit-bindgen', '--version']],
                 'assemblyscript': [[npm_bin('asc'), '--version']],
                 'typescript': [['node', '--version'], [npm_bin('tsc'), '--version']]}[language]
    with tempfile.TemporaryDirectory(prefix=f'qqq-{language}-') as scratch:
        work = Path(scratch)
        try:
            row['inputs'] = input_hashes()
            for command in versions:
                row['tool_versions'][Path(command[0]).name] = run(command, ROOT).strip()
            started = time.perf_counter()
            component = build(language, work)
            row.update(build_seconds=time.perf_counter() - started,
                       bytes=component.stat().st_size,
                       component_sha256=hashlib.sha256(component.read_bytes()).hexdigest())
            env = os.environ.copy()
            env['QQQ_LANGUAGE_COMPONENT'] = str(component)
            output = run(['cargo', 'test', '-p', 'qqq-run', '--locked', '--test', 'language_probe',
                          '--', '--ignored', '--nocapture'], ROOT, env=env)
            row.update(runtime_result(output))
            row['status'] = 'passed'
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            row['error'] = str(exc)
            rejection = [line.split('=', 1)[1] for line in str(exc).splitlines()
                         if line.startswith('QQQ_LANGUAGE_REJECTION=')]
            if len(rejection) == 1:
                row.update(json.loads(rejection[0]))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(row, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f"{language}: {row['status']} ({destination})")
    return 0 if row['status'] == 'passed' else 1


def self_test():
    expected_suffix = '.cmd' if os.name == 'nt' else ''
    assert str(npm_bin('tsc')).endswith(f'tsc{expected_suffix}')
    assert str(npm_bin('asc')).endswith(f'asc{expected_suffix}')
    good = MARKER + json.dumps({'cases_passed': 5, 'call_ms': [1] * 5})
    assert runtime_result(good)['cases_passed'] == 5
    for bad in ('', good + '\n' + good, MARKER + '{"cases_passed":0}'):
        try:
            runtime_result(bad)
        except ValueError:
            continue
        raise AssertionError('missing, duplicate or vacuous runtime result accepted')
    with tempfile.TemporaryDirectory() as scratch:
        try:
            run([sys.executable, '-c', 'raise SystemExit(7)'], scratch)
        except RuntimeError as exc:
            assert 'exit 7' in str(exc)
        else:
            raise AssertionError('compiler failure accepted')
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as scratch:
        output = Path(scratch) / 'failure.json'
        with patch(__name__ + '.input_hashes', side_effect=FileNotFoundError('missing probe source')):
            assert measure('assemblyscript', output) == 1
        failed = json.loads(output.read_text(encoding='utf-8'))
        assert failed['status'] == 'failed' and failed['inputs'] == {}
        assert 'missing probe source' in failed['error']
    print('PASS: missing/duplicate/vacuous results, compiler failure and unreadable inputs rejected')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--language', choices=LANGUAGES)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.language:
        parser.error('--language is required')
    return measure(args.language, args.output or ROOT / f'target/language-probes/{args.language}.json')


if __name__ == '__main__':
    raise SystemExit(main())
