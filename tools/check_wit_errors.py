#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Enforce the typed-error rule on every WIT interface — Checklist `CON-009`.

# The rule

Proposal §2.5 (NN-5):

> | Errors are typed | Every fallible host call returns a typed error, not a
>   status code buried in a payload. |

The rule is about **fallible** calls. It does not say every function returns a
`result`, and that distinction is the whole difficulty: `clock.timezone` returns
`string` and genuinely cannot fail, while `crypto.decrypt` returns
`result<list<u8>, aead-error>` because a tag may not verify.

So a check cannot be "every function returns `result`". It has to be:

> **Every function that can fail returns `result<T, E>`, and every function that
> cannot fail is listed by name as infallible.**

An explicit list is the point rather than a workaround: it turns "this cannot
fail" from an omission into a **claim someone wrote down**, which is the property
NN-5 asks for. A function added without a `result` and without an allowlist entry
fails the check, so the author must decide which it is.

# Types of infallibility, so the allowlist is not a dumping ground

| Category | Example | Why infallible |
|---|---|---|
| **Constant** | `clock.timezone() -> string` | Always `"UTC"`; there is no failure to represent |
| **Host-fixed measurement** | `clock.resolution() -> duration-ns` | The host's own tick interval, decided at configuration and always present |
| **Pure computation on a valid input** | `crypto.key-length(construction) -> u32` | Every `construction` variant has a defined length; the enum is closed |
| **Capability-gated enumeration** | `kv.stores() -> list<string>` | Returns what was granted; an empty list is the honest answer, not an error |
| **State query on an existing handle** | `log.enabled(level) -> bool` | A boolean prediction of whether a call would be logged |

A candidate that fits none of these is **fallible**, and belongs in a `result`.

# Why `result<T, E>` and not `result<T, string>`

The rule's second half — *"not a status code buried in a payload"* — requires the
error be a **named type**: a WIT `variant` declared in the interface, so a caller
in any language gets an exhaustive `match` rather than an integer to compare
against constants. This check therefore also rejects `result<a, string>` and
`result<a, u32>`, which parse fine and defeat the purpose.

Usage:  python tools/check_wit_errors.py
Exit:   0 = rule satisfied, 1 = at least one violation
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# This tool's own stdout must be able to encode what it prints. On a Windows console the stream
# inherits `cp1252`, so a character read from a subprocess -- which this file now reads as UTF-8 --
# raises `UnicodeEncodeError` inside `print` and the tool dies while reporting its result. `§O-291`.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - a replaced stream
        pass


ROOT = Path(__file__).resolve().parent.parent
WIT_DIR = ROOT / "wit"

# A function declaration opening, capturing the name.
FUNC_START_RE = re.compile(r"^\s*([a-z][a-z0-9-]*)\s*:\s*(?:async\s+)?func\b")

# `interface foo {`
INTERFACE_RE = re.compile(r"^\s*interface\s+([a-z0-9-]+)")

# `resource foo {`
RESOURCE_RE = re.compile(r"^\s*resource\s+([a-z0-9-]+)")

# A named WIT type in the error position. `string`/`u32`/`u64`/`bool` and the
# primitive list/option wrappers are NOT named variants, so a `result` whose
# error side is one of them violates the rule's second half.
PRIMITIVE_ERRORS = {
    "string", "u32", "u64", "s32", "s64", "f32", "f64", "bool", "u8", "u16",
    "char",
}

# Functions allowed to return without `result`, each with the category that
# justifies it. Adding a name here is a claim that the function cannot fail.
#
# # The key includes the INTERFACE, not just the file
#
# A file may declare several interfaces, and the same function name may appear in
# more than one with **different failure modes**. `now` is the live example:
#
#   interface wall-clock      { now: func() -> result<instant-ns, clock-error>; }
#   interface monotonic-clock { now: func() -> duration-ns; }
#
# The wall clock can fail (a guest asking for an instant outside the virtual
# range in deterministic mode); the monotonic clock cannot. A key of
# `qqq-clock.wit:now` cannot express that, and the first version of this checker
# reported a contradiction against a file that was correct. The key is therefore
# `file.wit:interface.function`, which is unambiguous by construction.
INFALLIBLE: dict[str, str] = {
    # -- constant / host-fixed -------------------------------------------------
    "qqq-clock.wit:wall-clock.timezone": "constant: always UTC",
    "qqq-clock.wit:wall-clock.resolution": "host-fixed: the configured tick interval",
    "qqq-clock.wit:monotonic-clock.now": (
        "host-fixed: a monotonic reading cannot fail; the WALL clock's `now` "
        "carries `clock-error` because a deterministic guest may ask for an "
        "instant outside the virtual range"
    ),
    "qqq-clock.wit:monotonic-clock.resolution": "host-fixed: the configured tick interval",
    "qqq-ai.wit:inference.allowed-models": "capability-gated enumeration",
    "qqq-ai.wit:inference.remaining-tokens": "state query: a counter, never an error",

    # -- pure computation over a closed enum -----------------------------------
    "qqq-crypto.wit:aead.nonce-length": "pure: every construction has a defined length",
    "qqq-crypto.wit:aead.key-length": "pure: every construction has a defined length",

    # -- capability-gated enumeration ------------------------------------------
    #
    # Returns what was granted. An empty list is the honest answer to "what may I
    # use?", not a failure -- and making it a `result` would force every caller to
    # handle an error that carries no information.
    "qqq-dns.wit:resolver.allowed-names": "capability-gated enumeration",
    "qqq-env.wit:environment.allowed-names": "capability-gated enumeration",
    "qqq-kv.wit:store.stores": "capability-gated enumeration",
    "qqq-queue.wit:messaging.queues": "capability-gated enumeration",
    "qqq-sql.wit:database.databases": "capability-gated enumeration",
    "qqq-secrets.wit:secret-use.permitted-operations": "capability-gated enumeration",

    # -- pure predicates / queries with no failure mode ------------------------
    "qqq-log.wit:logging.enabled": "pure predicate",
    # `exists` returns `bool` by design, so a guest cannot probe a secret's value,
    # length or type -- only whether a code path is available. An error type here
    # would itself be a disclosure channel, so its absence is a security property
    # rather than an omission.
    "qqq-secrets.wit:secret-use.exists": "pure predicate; an error would be a disclosure channel",
    # The authority the host already accepted this request on. There is no
    # failure to represent: if the request arrived, it had an authority.
    "qqq-http.wit:http.incoming-authority": "host-fixed: the accepted request's own authority",
    # `None` when no span is active, which is a value rather than an error -- the
    # same reason `Option` exists.
    "qqq-trace.wit:tracing.current-traceparent": "value-or-absent: `option` IS the error channel",
    # Resource release. Every implementation is a drop, and a closer that can fail
    # forces every caller into a cleanup path it cannot act on. The host owns the
    # connection and releases it on instance teardown regardless.
    "qqq-sql.wit:database.statement.close": "infallible release: teardown is the host's responsibility",
}


def collapse_functions(text: str) -> list[tuple[int, str, str]]:
    """Yield `(line_number, qualified_key, full_declaration)` for each function.

    The key is `interface.function`, or `interface.resource.function` inside a
    `resource` block, because **the same function name may appear in two
    interfaces with different failure modes**. `qqq-clock.wit` is the live
    example:

        interface wall-clock      { now: func() -> result<instant-ns, clock-error>; }
        interface monotonic-clock { now: func() -> duration-ns; }

    A key of just `now` cannot express that, and the first version of this
    checker reported a contradiction against a file that was correct.

    # Why signatures are collapsed rather than read line by line

    That first version also matched one line at a time and reported
    `crypto.encrypt` and `crypto.decrypt` as missing a `result` — they have one,
    spanning five lines. A checker that reports a *correct* interface is worse
    than no checker, because its output is noise and the pressure is to weaken
    it. The declaration is therefore accumulated until the terminating `;`, with
    comments and blank lines dropped, and the whole text examined.
    """
    lines = text.splitlines()
    out: list[tuple[int, str, str]] = []

    interface: str | None = None
    resource: str | None = None
    # Brace depth of the CURRENT interface, and the depth at which the current
    # resource block opened. Tracking these separately is what clears `resource`
    # when its block closes while leaving the interface in scope -- an earlier
    # version cleared both together and mislabelled `database.databases` as
    # `database.statement.databases`, reporting a correct file as broken.
    interface_depth: int | None = None
    resource_depth: int | None = None
    depth = 0

    i = 0
    while i < len(lines):
        line = lines[i]

        m = INTERFACE_RE.match(line)
        if m:
            interface = m.group(1)
            resource = None
            interface_depth = depth
            resource_depth = None
            depth += line.count("{") - line.count("}")
            i += 1
            continue

        m = RESOURCE_RE.match(line)
        if m:
            resource = m.group(1)
            resource_depth = depth
            depth += line.count("{") - line.count("}")
            i += 1
            continue

        depth += line.count("{") - line.count("}")

        # A closed resource leaves the resource, not the interface.
        if resource_depth is not None and depth <= resource_depth:
            resource = None
            resource_depth = None
        # A closed interface leaves everything.
        if interface_depth is not None and depth <= interface_depth:
            interface = None
            resource = None
            interface_depth = None
            resource_depth = None

        m = FUNC_START_RE.match(line)
        if not m or interface is None:
            i += 1
            continue

        start = i + 1  # 1-based
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


def error_type_of(decl: str) -> str | None:
    """The error type of a `-> result<ok, err>`, or None if not a result."""
    at = decl.find("-> result<")
    if at < 0:
        return None
    inner = decl[at + len("-> result<"):]
    # Find the matching `>` for this `<`, tracking nesting for `list<...>`.
    depth = 1
    for i, ch in enumerate(inner):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                inside = inner[:i]
                # Split on the top-level comma.
                d = 0
                for j, c in enumerate(inside):
                    if c == "<":
                        d += 1
                    elif c == ">":
                        d -= 1
                    elif c == "," and d == 0:
                        return inside[j + 1:].strip()
                return None  # `result<T>` with no error type
    return None


def check_file(path: Path) -> tuple[list[str], int]:
    text = path.read_text(encoding="utf-8")
    problems: list[str] = []
    count = 0

    for line_no, key, decl in collapse_functions(text):
        count += 1
        err = error_type_of(decl)
        full_key = f"{path.name}:{key}"

        if err is None:
            if full_key not in INFALLIBLE:
                problems.append(
                    f"line {line_no}: `{key}` returns no `result<T, E>` and is not "
                    "in the INFALLIBLE allowlist; CON-009 requires a typed error on "
                    "every FALLIBLE call, so either add the `result`, or add this "
                    "function to the allowlist with the category that makes it "
                    "infallible"
                )
        else:
            if full_key in INFALLIBLE:
                problems.append(
                    f"line {line_no}: `{key}` is listed as infallible but returns "
                    f"`result<_, {err}>`; remove it from the allowlist"
                )
            if err in PRIMITIVE_ERRORS:
                problems.append(
                    f"line {line_no}: `{key}` returns `result<_, {err}>`; the error "
                    "type must be a NAMED variant, not a primitive — §2.5 requires a "
                    "typed error rather than a status code in a payload"
                )

    # Every allowlist entry must correspond to a real function, or the list has
    # gone stale and is silently exempting nothing.
    present = {key for _, key, _ in collapse_functions(text)}
    for full_key in INFALLIBLE:
        if full_key.startswith(f"{path.name}:"):
            key = full_key.split(":", 1)[1]
            if key not in present:
                problems.append(
                    f"the INFALLIBLE allowlist names `{key}`, which does not exist "
                    "in this file; remove the stale entry"
                )

    return problems, count


def main() -> int:
    files = sorted(WIT_DIR.glob("*.wit"))
    if not files:
        print(f"no .wit files found under {WIT_DIR}")
        return 1

    total = 0
    failed: list[str] = []
    for f in files:
        problems, count = check_file(f)
        total += count
        if problems:
            print(f"  FAIL  {f.name}")
            for p in problems:
                print(f"        {p}")
            failed.append(f.name)
        else:
            print(f"  OK    {f.name}")

    listed = len(INFALLIBLE)
    print(
        f"\n{len(files) - len(failed)}/{len(files)} interface(s) satisfy the "
        f"typed-error rule ({total} function(s); {listed} declared infallible by name)"
    )
    if total == 0:
        print("\nno functions were found at all, so this check proves nothing")
        return 1

    if failed:
        print("\nTYPED-ERROR RULE FAILED")
        return 1
    print("TYPED-ERROR RULE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
