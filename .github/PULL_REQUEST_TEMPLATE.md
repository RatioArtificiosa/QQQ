# Pull request template

<!--
This template exists because of Principle NN-8 and the anchor discipline in
§0.5. It is short on purpose: a template nobody fills in is worse than none,
because it trains people to skip the form.

Delete any section that genuinely does not apply, and say why in one line.
-->

## What this changes

<!-- One paragraph. What is different after this merges? -->

## Which Principle does this touch?

Proposal §2 lists eight non-negotiables. **Name every one this change affects,
or write "none" and mean it.**

| # | Principle | Touched? | How |
|---|---|---|---|
| NN-1 | AI Agents Are First-Class Users | | |
| NN-2 | Security and Isolation Are Non-Optional | | |
| NN-3 | Performance and Predictability Over Micro-Benchmarks | | |
| NN-4 | Multi-Language by Design | | |
| NN-5 | Explicit Contracts Over Implicit Behavior | | |
| NN-6 | Human + Machine Documentation Parity | | |
| NN-7 | Progressive Power, Safe Defaults | | |
| NN-8 | Ecosystem Integrity and Long-Term Stewardship | | |

If **NN-2**, **NN-5** or **NN-7** is touched, say in the description how the
change was verified to preserve it — a test, or a reason no test can exist.
Those three are the ones a well-meaning change most easily erodes: a new
capability that defaults to granted (NN-2), a behaviour that is inferred rather
than declared (NN-5), an advanced feature that is on by default (NN-7).

## Checklist items

<!-- The item identifier(s) this advances, e.g. CLI-015. An untracked change
     is a change nobody planned; say which item covers it or why none does. -->

- Advances:

## Verification

<!-- Commands you actually ran, and their result. "It builds" is not
     verification of a behaviour change. -->

- [ ] `cargo test --workspace --all-features` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` is clean
- [ ] `cargo fmt --all -- --check` is clean
- [ ] `python tools/check_xrefs.py` passes
- [ ] `python tools/self_test_xrefs.py` reports 8/8
- [ ] `cargo deny check` passes

## Documentation

- [ ] The Proposal section this belongs to is updated, if behaviour changed
- [ ] The Checklist item is ticked **only** if it is genuinely finished, with a
      `→ Done:` line naming the artefact
- [ ] `QQQ-Observations-and-Memories.md` records any decision, mistake or
      correction worth preserving

## What I could not verify

<!--
The most valuable field in this template. Every non-trivial change has a gap:
a platform you did not test, a case you could not construct, a claim you could
not measure. Naming it is how the next person knows where to look.

Writing "none" is only acceptable for a genuinely trivial change.
-->
