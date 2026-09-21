#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Insert `@since(version = 1.0.0)` before every exported function in `wit/`.

One-time migration for `CON-007`/`CON-008`. The version is `1.0.0` for every
function because every interface here ships in the V1 line and none has been
released before — so "since 1.0.0" is a statement of fact rather than a
placeholder.

It inserts **immediately before the function line**, after any doc comment, so
the annotation is adjacent to what it annotates. WIT gate syntax attaches to the
next item and tolerates comments and blank lines between, but keeping them
adjacent makes the source read the way the rule is stated.
"""
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WIT_DIR = ROOT / 'wit'

FUNC_RE = re.compile(r'^(\s*)([a-z][a-z0-9-]*)\s*:\s*(?:async\s+)?func\b')
SINCE_RE = re.compile(r'^\s*@since\s*\(')

total = 0
for path in sorted(WIT_DIR.glob('*.wit')):
    lines = io.open(path, encoding='utf-8').read().splitlines()
    out = []
    inserted = 0
    for line in lines:
        m = FUNC_RE.match(line)
        if m and not (out and SINCE_RE.match(out[-1])):
            indent = m.group(1)
            out.append(f'{indent}@since(version = 1.0.0)')
            inserted += 1
        out.append(line)
    if inserted:
        io.open(path, 'w', encoding='utf-8', newline='\n').write('\n'.join(out) + '\n')
        print(f'  {path.name}: {inserted} annotation(s) added')
        total += inserted

print(f'\n{total} @since annotation(s) added')
sys.exit(0)
