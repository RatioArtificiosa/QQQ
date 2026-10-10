# Curated seed corpora

Each fuzzer subdirectory here holds the **curated** seed corpus for one
`cargo-fuzz` target: inputs chosen because they are interesting, not
generated. libFuzzer loads them on every run, so a run starts from the
shapes the unit tests pin rather than from empty bytes.

Machine-generated corpus (what libFuzzer writes back while exploring)
never lands here: it grows without bound and belongs in the container's
`fuzz-corpus` volume (see `docker/compose.yaml`) or the local
`fuzz/corpus/<target>/` working copy, both ignored below. A crash
artifact belongs in `fuzz/artifacts/` (also ignored) just long enough to
be promoted to a `crates/*/tests/fuzz_corpus.rs` row — see `fuzz.yml`'s
follow-up text.

To add a target's seeds: create `fuzz/corpus/<target>/`, write one file
per shape, and negate the directory in `.gitignore` next to the
`fuzz/corpus/*/` rule. The negation is per-target on purpose: a blanket
un-ignore would also admit whatever libFuzzer left behind.
