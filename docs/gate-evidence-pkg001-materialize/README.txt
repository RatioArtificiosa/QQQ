# Gate evidence: PKG-001 — materialize the content-addressed store

Commit: PKG-001 tick (QQQ-Checklist-V1.md) + `StoreLayout::materialize`
(`crates/qqq-pkg`), re-exported as `qqq_pkg::{Materialized, LinkMethod}`,
README + lib scope tables updated to `implemented`.

## What was built and why it matters

`PKG-001` asserted a content-addressed global store; the second half —
placing a stored artifact at a project path — did not exist. Now
`StoreLayout::materialize` verifies by streaming hash *before* linking,
links by hard link (plain-copy fallback across filesystems only), renames
atomically from a same-dir temp name, re-verifies after linking, refuses
symlinked/non-regular destinations and in-store destinations by name, sweeps
stale temp names, and marks placed files read-only (which also hardens the
shared store inode). No new dependencies; `forbid(unsafe_code)` intact;
`core-only` build unaffected (all new code is `fs`-gated).

## How to read this directory

- `pkg001-red.log` — red proof: 14 new tests against a tree without the
  methods (14×E0599 method-not-found, 0 syntax errors).
- `pkg001-faultinject-verify.log` — fault injection: verification disabled,
  both corruption guards fail; byte-identical restore, green again.
- `pkg001-green.log` — `cargo test -p qqq-pkg` green after implementation.
- `pkg001-green-final.log` — full `cargo test -p qqq-pkg` on the final tree
  (137 passed / 0 failed / 1 ignored — explicit-run bare-name end-to-end;
  2 unix-only symlink tests compile out on Windows), doctests, core-only.
- `pkg001-checkers.log` — doc-claims 30/30, done-lines, checklist counts,
  backlog/dashboard checks, api-examples ratchet (1931 ≤ 1932),
  public-reachability, source-claims (+self-test).
- `cr-pkg001-proxy.log` — independent review 1 (Meta Muse proxy; Copilot
  subscription quota exhausted): 10 findings (2 HIGH), all fixed in-tree.
- `cr-pkg001-proxy2.log` — independent re-review: 9/10 fixed, 1 still-open
  + 8 new findings (2 MEDIUM); all addressed.
- `cr-pkg001-proxy3.log` — final independent review of the review-2 changes:
  all verified fixed, plus 8 more (1 HIGH, 2 MEDIUM, test gaps, 3 LOW);
  all fixed in-tree (see commit message for disposition).
- `xtask-ci-green.log` — full `cargo xtask ci` on the committed tree
  (GATE GREEN expected; appended at gate time).

## Reproduce

- Red: `git stash` the `materialize` implementation (keep tests),
  `cargo test -p qqq-pkg --lib -- store::` → 14×E0599; restore.
- Fault injection: comment out the `if actual != *digest` block in
  `verified_source`, run the two corruption tests → both FAIL; restore
  byte-identical (`git diff` empty for that hunk) → green.
- Full suite: `cargo test -p qqq-pkg` (137/0/1 ignored),
  `cargo test --doc -p qqq-pkg` (4 passed, 3 new),
  `cargo build -p qqq-pkg --no-default-features --features core-only
  --target wasm32-unknown-unknown` + `cargo test -p qqq-pkg
  --no-default-features --features core-only`.
