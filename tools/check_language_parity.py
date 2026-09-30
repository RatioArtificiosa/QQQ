#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail on an unexplained language gap, stale evidence, or a changed failure mode.

Static mode validates all 40 LANG obligations and their dated ownership. --results
validates fresh execution reports and generates the CI matrix. Expected failures
stay FAILED in that matrix; a passing governance gate is not a conformance pass.
"""
from __future__ import annotations

import argparse
import copy
from datetime import date
import json
from pathlib import Path
import re

from run_language_probes import LANGUAGES, ROOT, input_hashes

POLICY = ROOT / 'conformance/languages/policy.json'


def validate(policy, checklist):
    errors = []
    expected = set(re.findall(r'^- \[[ x~!-]\] \*\*(LANG-\d{3})\*\*', checklist, re.M))
    if len(expected) != 40 or set(policy.get('obligations', {})) != expected:
        errors.append('exactly all 40 checklist LANG IDs must have an obligation row')
    if set(policy.get('languages', {})) != set(LANGUAGES):
        errors.append('every probe language must have exactly one policy row')
    for key, row in {**policy.get('obligations', {}), **policy.get('languages', {})}.items():
        if not all(isinstance(row.get(field), str) and row[field].strip()
                   for field in ('owner', 'reason', 'review_by')):
            errors.append(f'{key}: owner, reason and dated review required')
            continue
        try:
            date.fromisoformat(row['review_by'])
        except ValueError:
            errors.append(f'{key}: invalid ISO review date')
        if key.startswith('LANG-'):
            if row.get('status') not in ('existing', 'partial', 'open', 'done', 'blocked-by-upstream-and-time'):
                errors.append(f'{key}: unknown obligation status')
        elif row.get('expected_probe') not in ('passed', 'failed'):
            errors.append(f'{key}: probe expectation required')
        elif row['expected_probe'] == 'failed' and not row.get('failure_contains'):
            errors.append(f'{key}: expected failure must name its specific diagnostic')
        if not key.startswith('LANG-'):
            for field in ('cli_driver', 'capability_parity', 'reference_application'):
                if row.get(field) != 'gap':
                    errors.append(f'{key}: scaffold cannot assert production {field}')
    for key in ('LANG-023', 'LANG-024'):
        if policy.get('obligations', {}).get(key, {}).get('status') != 'blocked-by-upstream-and-time':
            errors.append(f'{key}: upstream/time obligation must remain blocked')
    return errors


def review_warnings(policy, today):
    """Calendar reminders must not make the same source pass or fail overnight."""
    return [f"{key}: review date expired; reassess evidence and ownership"
            for key, row in {**policy['obligations'], **policy['languages']}.items()
            if date.fromisoformat(row['review_by']) < today]


def evidence_errors(language, result, policy, hashes):
    errors = []
    if result.get('language') != language or result.get('inputs') != hashes:
        errors.append(f'{language}: missing/wrong language or stale input hashes')
    want = policy['languages'][language]
    if result.get('status') != want['expected_probe']:
        errors.append(f'{language}: changed result; review policy rather than silently advancing it')
    if result.get('status') == 'passed':
        if result.get('cases_passed') != 5 or len(result.get('call_ms', [])) != 5:
            errors.append(f'{language}: not all five HTTP vectors executed')
    elif want.get('failure_contains', '') not in result.get('error', ''):
        errors.append(f'{language}: failure differs from the owned known gap')
    if not isinstance(result.get('bytes'), int) or result['bytes'] <= 0:
        errors.append(f'{language}: no compiled component measured')
    if not result.get('tool_versions'):
        errors.append(f'{language}: tool version evidence missing')
    return errors


def render(results, policy):
    lines = ['# Language probe matrix', '',
             'Generated from this job’s execution reports. HTTP probes are narrower than the full conformance suite.', '',
             '| Language | HTTP vectors | Component bytes | CLI / capability parity / reference app | Owner | Review by |',
             '|---|---|---:|---|---|---|']
    for lang in LANGUAGES:
        row, rule = results[lang], policy['languages'][lang]
        state = '5/5 passed' if row['status'] == 'passed' else 'FAILED — known gap'
        lines.append(f"| {lang} | {state} | {row['bytes']} | gap / gap / gap | {rule['owner']} | {rule['review_by']} |")
    return '\n'.join(lines) + '\n'


def self_test(policy, checklist):
    assert not validate(policy, checklist)
    for mutate in (
        lambda p: p['obligations'].pop('LANG-007'),
        lambda p: p['languages']['go'].pop('owner'),
        lambda p: p['languages']['go'].update(review_by='yesterday'),
        lambda p: p['obligations']['LANG-023'].update(status='done'),
        lambda p: p['languages']['c'].update(cli_driver='supported'),
    ):
        broken = copy.deepcopy(policy)
        mutate(broken)
        assert validate(broken, checklist), 'unexplained gap was accepted'
    assert review_warnings(policy, date(2100, 1, 1))
    assert not validate(policy, checklist), 'date reminders must not change validity'
    good = {'language': 'assemblyscript', 'inputs': {}, 'status': 'passed',
            'cases_passed': 5, 'call_ms': [1] * 5, 'bytes': 4, 'tool_versions': {'asc': 'test'}}
    assert not evidence_errors('assemblyscript', good, policy, {})
    for change in ({'inputs': {'stale': 'hash'}}, {'cases_passed': 0}, {'status': 'failed'}, {'bytes': 0}):
        assert evidence_errors('assemblyscript', {**good, **change}, policy, {})
    assert evidence_errors('go', {**good, 'language': 'go', 'status': 'failed', 'error': 'compiler missing'}, policy, {})
    print('PASS: unowned/missing gaps, false support, stale/vacuous evidence and wrong failures rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--results', type=Path)
    parser.add_argument('--matrix', type=Path)
    args = parser.parse_args()
    policy = json.loads(POLICY.read_text(encoding='utf-8'))
    checklist = (ROOT / 'QQQ-Checklist-V1.md').read_text(encoding='utf-8')
    if args.self_test:
        self_test(policy, checklist)
        return 0
    errors = validate(policy, checklist)
    results = {}
    if args.results:
        for language in LANGUAGES:
            try:
                results[language] = json.loads((args.results / f'{language}.json').read_text(encoding='utf-8'))
                errors += evidence_errors(language, results[language], policy, input_hashes())
            except (OSError, ValueError) as exc:
                errors.append(f'{language}: {exc}')
    if errors:
        print('\n'.join('FAIL: ' + error for error in errors))
        return 1
    for warning in review_warnings(policy, date.today()):
        print('WARNING: ' + warning)
    if args.matrix:
        if not args.results:
            parser.error('--matrix requires --results; no fabricated execution matrix')
        args.matrix.parent.mkdir(parents=True, exist_ok=True)
        args.matrix.write_bytes(render(results, policy).encode('utf-8'))
    print('PASS: 40 obligations and six probe paths accounted for; known failures remain gaps')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
