#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Enforce the batch-first rule where it is **decidable** — Checklist `CON-012`.

# The rule, and the honest scope of a check for it

Proposal §4.5:

> **The design rule that saves us:** *chatty interfaces are a defect.* A host
> interface that would naturally be called in a loop must instead accept a batch.

The operative phrase — *"would naturally be called in a loop"* — is a judgement
about how an operation is used. **A checker cannot make that judgement**, and an
earlier version of this tool tried to: it demanded that every singular function be
classified, which produced 23 demanded classifications including
`sql.txn.commit`, `trace.span.event` and `http.incoming-handler.handle`. Those
are *inherently* singular — committing a transaction in a loop is not a chatty
interface, it is what transactions are. A tool that demands a written excuse for
each of them is not enforcing a rule; it is generating paperwork, and paperwork
gets `# allow`-ed away.

So this checks the part that **is** decidable:

> **Every declared batch pair must be real, consistent, and complete.**

A batch pair is a singular operation plus its batched sibling. Once a pair exists
— because the interface author judged the operation chatty — four things can be
checked mechanically, and each is a defect that would otherwise ship:

| Check | Defect it catches |
|---|---|
| The sibling exists | A rename or deletion that leaves the singular form unreachable in bulk |
| The sibling is truly batched | `digest-many(data: list<u8>)` that takes ONE buffer is a batch form in name only |
| The singular form is still present | A batch form added while the singular was removed, breaking callers who need one item |
| The result shape matches | A `-many` whose error type disagrees with its singular form forces callers to handle two failure vocabularies for one operation |

That last one is the most valuable, because it is invisible in review: the two
signatures are in different places in the file and both look correct in isolation.

# Why pairs are declared rather than inferred from the name

Inferring `X` ↔ `X-many` from the naming convention alone would work today and
break the first time a batch form is named differently (`resolve-all`,
`get-batch`). The pair is therefore declared here, and the declaration is itself
checked: an entry naming a function that no longer exists is a failure, so the
list cannot rot.

# What this deliberately does NOT do

It does not fail because a singular function has no batch sibling. That is a
design question for the interface author, argued in review, and the Proposal
assigns it there ("*enforced in review*"). What this guarantees is that the pairs
which DO exist are correct — which is the part review reliably misses.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WIT_DIR = ROOT / "wit"

FUNC_START_RE = re.compile(r"^\s*([a-z][a-z0-9-]*)\s*:\s*(?:async\s+)?func\b")
INTERFACE_RE = re.compile(r"^\s*interface\s+([a-z0-9-]+)")
RESOURCE_RE = re.compile(r"^\s*resource\s+([a-z0-9-]+)")

# Declared batch pairs: `"file.wit:interface.function"` -> `"batched-sibling"`.
#
# Each pair is a claim that the singular operation is chatty enough to need a
# bulk form. Verified against the corpus: 5 pairs today.
BATCH_PAIRS: dict[str, str] = {
    "qqq-crypto.wit:hashing.digest": "digest-many",
    "qqq-dns.wit:resolver.resolve": "resolve-many",
    "qqq-kv.wit:store.get": "get-many",
    "qqq-log.wit:logging.emit": "emit-many",
    "qqq-queue.wit:messaging.publish": "publish-many",
}


def collapse_functions(text: str) -> list[tuple[int, str, str]]:
    """Yield `(line_number, qualified_key, full_declaration)` for each function.

    The declaration is accumulated until the terminating `;`, so a multi-line
    signature is examined whole — a line-at-a-time scanner reports correct
    multi-line functions as malformed, and `§O-062b` records that exact defect.
    """
    lines = text.splitlines()
    out: list[tuple[int, str, str]] = []
    interface: str | None = None
    resource: str | None = None
    interface_depth: int | None = None
    resource_depth: int | None = None
    depth = 0

    i = 0
    while i < len(lines):
        line = lines[i]

        m = INTERFACE_RE.match(line)
        if m:
            interface, resource = m.group(1), None
            interface_depth, resource_depth = depth, None
            depth += line.count("{") - line.count("}")
            i += 1
            continue

        m = RESOURCE_RE.match(line)
        if m:
            resource, resource_depth = m.group(1), depth
            depth += line.count("{") - line.count("}")
            i += 1
            continue

        depth += line.count("{") - line.count("}")
        if resource_depth is not None and depth <= resource_depth:
            resource, resource_depth = None, None
        if interface_depth is not None and depth <= interface_depth:
            interface = resource = interface_depth = resource_depth = None

        m = FUNC_START_RE.match(line)
        if not m or interface is None:
            i += 1
            continue

        start = i + 1
        name = m.group(1)
        key = f"{interface}.{resource}.{name}" if resource else f"{interface}.{name}"
        parts = [line.strip()]
        while not parts[-1].rstrip().endswith(";") and i + 1 < len(lines):
            i += 1
            nxt = lines[i].strip()
            if nxt and not nxt.startswith("//"):
                parts.append(nxt)
        out.append((start, key, " ".join(parts)))
        i += 1

    return out


def error_type(decl: str) -> str | None:
    """The error type of `-> result<ok, err>`, or None if not a result."""
    at = decl.find("-> result<")
    if at < 0:
        return None
    inner = decl[at + len("-> result<"):]
    depth = 1
    for i, ch in enumerate(inner):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                inside = inner[:i]
                d = 0
                for j, c in enumerate(inside):
                    if c == "<":
                        d += 1
                    elif c == ">":
                        d -= 1
                    elif c == "," and d == 0:
                        return inside[j + 1:].strip()
                return None
    return None


def takes_a_collection(decl: str) -> tuple[bool, str]:
    """Whether the signature accepts a collection of *items* to batch over.

    Returns `(ok, reason)`.

    # Why "does it take a `list`" is the wrong question

    The obvious test — does the signature contain `list<` — passes
    `digest-many(input: list<u8>)`, which is **one buffer**, not a batch. That is
    a batch form in name only, and it is exactly the defect this check exists to
    find: the name promises batching and the signature does not deliver it.

    A batch parameter is a list **of things that were previously separate
    calls**:

    * `list<list<u8>>` — many buffers (what `digest-many` should take)
    * `list<string>` — many names or keys
    * `list<tuple<...>>` — many structured records
    * `list<record-name>` — many typed records

    A `list<u8>` is a **single byte buffer**, which is what the *singular* form
    already takes. So a `u8`/`u16` scalar element type inside the outermost list
    means the parameter is a buffer rather than a batch.

    `stream<T>` is accepted for any `T`, because a stream of anything is by
    definition a sequence of items.
    """
    if "(" not in decl:
        return False, "no parameter list"
    params = decl[decl.find("(") + 1: decl.rfind(")")]

    if "stream<" in params:
        return True, "takes a `stream<...>`, which is a sequence by definition"

    # Find every `list<...>` at the top level of a parameter and inspect its
    # element type.
    found_any = False
    for m in re.finditer(r"list<", params):
        found_any = True
        inner = params[m.end():]
        # The element type is up to the matching `>`.
        depth = 1
        for i, ch in enumerate(inner):
            if ch == "<":
                depth += 1
            elif ch == ">":
                depth -= 1
                if depth == 0:
                    element = inner[:i].strip()
                    # A scalar element is a buffer, not a batch.
                    if element not in {"u8", "u16", "u32", "u64", "s32", "s64",
                                       "f32", "f64", "bool", "char"}:
                        return True, f"takes `list<{element}>`, a collection of items"
                    break
    if found_any:
        return False, (
            "takes only a scalar-element `list<...>` (a byte buffer), which is "
            "what its SINGULAR form already takes -- a batch parameter must be a "
            "list OF the things that were separate calls"
        )
    return False, "declares no `list<...>` or `stream<...>` parameter"


def main() -> int:
    files = sorted(WIT_DIR.glob("*.wit"))
    if not files:
        print(f"no .wit files found under {WIT_DIR}")
        return 1

    corpus: dict[str, dict[str, tuple[int, str]]] = {}
    for f in files:
        corpus[f.name] = {
            key: (line_no, decl)
            for line_no, key, decl in collapse_functions(f.read_text(encoding="utf-8"))
        }

    problems: list[str] = []
    checked = 0

    for full_key, sibling in sorted(BATCH_PAIRS.items()):
        file_name, key = full_key.split(":", 1)
        if file_name not in corpus:
            problems.append(f"BATCH_PAIRS names a missing file: {file_name}")
            continue

        funcs = corpus[file_name]

        # 1. Both halves exist.
        if key not in funcs:
            problems.append(f"BATCH_PAIRS names `{full_key}`, which no longer exists")
            continue

        # The sibling is resolved in the SAME interface/resource scope as its
        # singular form, which is what makes the pair meaningful: a `-many` in a
        # different interface is not a bulk path for this operation.
        #
        # `key` is `interface[.resource].function`, so the scope prefix is
        # everything before the last dot.
        scope = key.rsplit(".", 1)[0]
        sibling_key = f"{scope}.{sibling}"
        if sibling_key not in funcs:
            problems.append(
                f"{file_name}: `{key}` declares `{sibling}` as its batch form, but "
                f"`{sibling_key}` does not exist. A caller with N items crosses the "
                f"boundary N times (CON-012)."
            )
            continue

        singular_line, singular_decl = funcs[key]
        batch_line, batch_decl = funcs[sibling_key]
        checked += 1

        # 2. The batch form actually takes a collection.
        ok, reason = takes_a_collection(batch_decl)
        if not ok:
            problems.append(
                f"{file_name}:{batch_line}: `{sibling}` is a batch form in name "
                f"only -- {reason}. Its singular form is `{key}` at line "
                f"{singular_line}."
            )

        # 3. Both return a `result` with the SAME error type, or neither does.
        #
        # This is the check review misses: the two signatures sit in different
        # parts of the file, both look right alone, and a mismatch forces callers
        # to handle two failure vocabularies for one operation.
        se = error_type(singular_decl)
        be = error_type(batch_decl)
        if se != be:
            problems.append(
                f"{file_name}: `{key}` returns error `{se}` while its batch form "
                f"`{sibling}` (line {batch_line}) returns `{be}`. One operation "
                f"must not have two failure vocabularies."
            )

    if checked == 0:
        print("no batch pair was verified, so this check proves nothing")
        return 1

    print(
        f"  {len(corpus)} interface file(s), {sum(len(v) for v in corpus.values())} "
        f"function(s)"
    )
    print(f"  {checked} declared batch pair(s) verified complete and consistent")
    print(
        "  NOT checked: whether a singular function SHOULD have a batch form -- "
        "that is a design judgement, enforced in review"
    )

    if problems:
        print()
        for p in problems:
            print(f"  FAIL  {p}")
        print("\nBATCH-FIRST PAIR RULE FAILED")
        return 1

    print("\nBATCH-FIRST PAIR RULE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
