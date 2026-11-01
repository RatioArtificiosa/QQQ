// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! The naming invariant — `§D-001`, and the one rule the objective calls a defect.
//!
//! # The rule
//!
//! > **Brand is QQQ; crate, npm package, binary and command are ALL `qqqai`**,
//! > because `qqq` is taken on crates.io and npm. **A build producing a `qqq`
//! > binary is a defect.**
//!
//! `§D-001` records why, with the availability evidence, and states it as
//! *"deliberate, permanent — not a workaround awaiting a better option"*. The
//! failure mode it guards against is real and cheap to introduce: a `[[bin]]`
//! stanza added by hand, a package renamed to match the brand, or a doc example
//! that teaches `qqq new` instead of `qqqai new`.
//!
//! # Why this is checked here rather than trusted
//!
//! The naming is the project's **public install surface**. `cargo install qqqai`
//! and `npm install -g qqqai` either work or they do not, and a rename is
//! discovered by users rather than by CI unless something checks. `§D-001` calls
//! it settled; this test is what makes "settled" mean something a build enforces.
//!
//! # Why it is in `qqq-core`
//!
//! Same reason as the architecture tests beside it: it is a statement about the
//! *workspace*, and `qqq-core` is the crate that cannot create a dependency cycle
//! while reading every other crate.

use std::path::{Path, PathBuf};

/// Every subcommand the CLI teaches, shared by the document scan and the
/// drift pin below. Adding a subcommand means updating this list deliberately —
/// a new command the scan does not know is a command the scan cannot check.
const SUBCOMMANDS: &[&str] = &[
    "new", "init", "add", "remove", "install", "update", "build", "run", "dev", "serve", "test",
    "bench", "fmt", "lint", "inspect", "audit", "verify", "caps", "why", "trace", "doctor", "mcp",
    "schema", "openapi", "migrate", "bindings", "add-cap",
];

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // root
    p
}

/// Every crate's manifest, as `(crate_dir_name, contents)`.
fn manifests() -> Vec<(String, String)> {
    let dir = workspace_root().join("crates");
    let mut out = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("crates/ must be readable")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .expect("a directory has a name")
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(path.join("Cargo.toml")).expect("manifest is readable");
        out.push((name, text));
    }
    out
}

/// **The core rule.** The CLI binary is `qqqai`, and no crate produces `qqq`.
///
/// # How the binary name is determined
///
/// Cargo names the default binary after the *package*, unless a `[[bin]]` stanza
/// overrides it. `qqq-run` declares `[[bin]] name = "qqqai"` explicitly, which is
/// the only reason the default (`qqq-run`) is not produced. So both halves matter:
///
/// * a declared `[[bin]]` must be named `qqqai`;
/// * a crate with `src/main.rs` and no `[[bin]]` stanza produces `<package name>`,
///   which for a `qqq-*` package would be `qqq-…` — not `qqq`, but also not
///   `qqqai`, and therefore also wrong.
#[test]
fn the_cli_binary_is_named_qqqai_and_never_qqq() {
    let mut problems = Vec::new();
    let mut declared_bins = 0_usize;

    for (dir_name, text) in manifests() {
        for name in declared_bin_names(&text) {
            declared_bins += 1;
            if name != "qqqai" {
                problems.push(format!(
                    "`{dir_name}` declares a binary named `{name}`; §D-001 requires \
                     `qqqai` and forbids `qqq`"
                ));
            }
        }

        // A crate with a main.rs and no `[[bin]]` produces its package name.
        // `xtask` is the one exemption, for the reason stated on the package
        // rule above: its binary is never installed (the `cargo xtask` alias
        // runs it in place), so no install surface exists to collide.
        let is_xtask = dir_name == "xtask";
        let has_main = workspace_root()
            .join("crates")
            .join(&dir_name)
            .join("src/main.rs")
            .is_file();
        if has_main && declared_bin_names(&text).is_empty() && !is_xtask {
            problems.push(format!(
                "`{dir_name}` has src/main.rs and no `[[bin]]` stanza, so Cargo \
                 names the binary after the package; §D-001 requires `qqqai`"
            ));
        }
    }

    // The check must find the one binary that exists, or it proves nothing.
    assert_eq!(
        declared_bins, 1,
        "expected exactly one declared binary (the `qqqai` CLI); found {declared_bins}. \
         If a binary was added or removed, update this expectation deliberately."
    );

    assert!(
        problems.is_empty(),
        "naming violations (§D-001 — a `qqq` binary is a defect):\n  {}",
        problems.join("\n  ")
    );
}

/// The `name = "…"` values inside every `[[bin]]` stanza.
///
/// Parsed with `split_once('=')` plus a key comparison: `strip_prefix("name")`
/// also matches `names =`. Trailing comments and single-quoted values are
/// handled — see `strip_toml_comment`.
fn declared_bin_names(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let line = strip_toml_comment(line).trim();
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
            continue;
        }
        if in_bin
            && let Some((key, value)) = line.split_once('=')
            && key.trim() == "name"
        {
            out.push(
                value
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_owned(),
            );
        }
    }
    out
}

/// Strip a trailing `#` comment, ignoring `#` inside quotes.
///
/// TOML names in the scanned positions never legitimately contain `#`, but
/// neighbouring values (URLs) do — so the stripper is quote-aware rather than
/// a bare `split('#')`. (Twin of the helper in `tests/architecture.rs`; both
/// test targets need it and neither may grow a dependency for it.)
fn strip_toml_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (i, c) in line.char_indices() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return line[..i].trim_end(),
            _ => {}
        }
    }
    line
}

/// No crate is *named* `qqq`.
///
/// The `[[bin]]` name is the visible half; the package name is the half that
/// `cargo install` and crates.io see. `§D-001`'s table records `qqq` as taken on
/// crates.io, so a package called `qqq` could not be published even if it built.
#[test]
fn no_package_is_named_qqq() {
    for (dir_name, text) in manifests() {
        // The [package] name, which is the first `name =` after `[package]`.
        // Parsed strictly: `names =` is a different key, and comments/quotes
        // must not leak into the value.
        let mut in_package = false;
        let mut package_name = None;
        for line in text.lines() {
            let line = strip_toml_comment(line).trim();
            if line.starts_with('[') {
                in_package = line == "[package]";
                continue;
            }
            if in_package
                && let Some((key, value)) = line.split_once('=')
                && key.trim() == "name"
            {
                package_name = Some(
                    value
                        .trim()
                        .trim_matches(|c| c == '"' || c == '\'')
                        .to_owned(),
                );
                break;
            }
        }

        let name = package_name.unwrap_or_else(|| panic!("{dir_name} has no [package] name"));
        assert_ne!(
            name, "qqq",
            "`{dir_name}` is named `qqq`, which is taken on crates.io and npm (§D-001)"
        );
        // `xtask` is exempt from the prefix rule, not from the `qqq` ban
        // above. §D-001 guards the public install surface (crates.io, npm,
        // installed binaries); `xtask` is `publish = false` developer
        // tooling reachable only through the `cargo xtask` alias, so it can
        // collide with nothing — and renaming it would satisfy neither rule
        // (the binary still would not be `qqqai`) while breaking the
        // cargo-xtask convention the `I-08` design names. The exemption pins
        // its precondition: flip `publish` and this fails.
        if name == "xtask" {
            assert!(
                text.contains("publish = false"),
                "`xtask` is exempt as unpublished tooling only; `publish = false` is gone"
            );
            continue;
        }
        assert!(
            name.starts_with("qqq-") || name == "qqqai",
            "`{dir_name}` is named `{name}`; every package is `qqq-…` or `qqqai` (§D-001)"
        );
    }
}

/// **Every document in the list is scanned — none may silently disappear.**
///
/// A document deleted or renamed without updating this list would shrink the
/// scan without failing it. The count pins the coverage.
#[test]
fn the_document_list_is_scanned_whole() {
    let root = workspace_root();
    let docs = ["README.md", "QQQ-Proposal-V1.md", "CONTRIBUTING.md"];
    for doc in docs {
        assert!(
            root.join(doc).is_file(),
            "document {doc} is missing; update the scan list deliberately"
        );
    }
}

/// **Every command shown in the documents is `qqqai`, never bare `qqq`.**
///
/// # Why the documents are checked and not just the manifests
///
/// The naming is instructions to users. A README that says `qqq new` teaches a
/// command that does not exist, and the reader's next action fails — which is a
/// worse outcome than a wrong binary name, because it is discovered by someone
/// following the documentation exactly as written.
///
/// The scan looks for `qqq` used as a *command*, not the string `qqq`: the brand
/// appears legitimately everywhere ("QQQ is a runtime"), and `qqq-` prefixes
/// crate names. What is forbidden is `qqq` followed by a known subcommand name —
/// with spaces, tabs, or a hyphen between them. A hyphen mention that names a
/// known crate (`qqq-run`) is the crate, not the command, and is exempt.
#[test]
fn the_documents_never_teach_a_bare_qqq_command() {
    let root = workspace_root();
    let docs = ["README.md", "QQQ-Proposal-V1.md", "CONTRIBUTING.md"];
    let manifests = manifests();
    // Exempt by package name, not directory name: the two agree today, but the
    // rule is about what `cargo install` sees, so the check reads what the
    // manifest declares.
    let crate_names: Vec<String> = manifests
        .iter()
        .filter_map(|(_, text)| package_name_of(text))
        .collect();
    let mut problems = Vec::new();
    let mut scanned = 0_usize;

    for doc in docs {
        let path = root.join(doc);
        if !path.is_file() {
            continue;
        }
        scanned += 1;
        let text = std::fs::read_to_string(&path).expect("document is readable");
        for (i, line) in text.lines().enumerate() {
            for sub in SUBCOMMANDS {
                for at in command_mentions(line, sub, &crate_names) {
                    // Char-boundary-safe snippet for the message: byte slicing
                    // a multibyte line would panic, turning the report into a
                    // crash instead of a violation list.
                    let mut end = (at + 3 + 1 + sub.len()).min(line.len());
                    while !line.is_char_boundary(end) {
                        end -= 1;
                    }
                    problems.push(format!("{doc}:{}: `{}`", i + 1, &line[at..end]));
                }
            }
        }
    }

    assert_eq!(
        scanned,
        docs.len(),
        "expected to scan all {} documents; a missing one would shrink the scan silently",
        docs.len()
    );
    assert!(
        problems.is_empty(),
        "documents teach a bare `qqq` command; §D-001 requires `qqqai`:\n  {}",
        problems.join("\n  ")
    );
}

/// Byte offsets where `line` mentions `qqq <sub>` or `qqq-<sub>` as a command.
///
/// Boundaries do the work that a substring search cannot: the char before
/// `qqq` must not be alnum/`-`/`_` (so `aqqq run`, `foo-qqq run` and `qqqai run`
/// never match), and the char after the subcommand must not be alnum/`-`/`_`
/// (so `qqq runner`, `qqq-runner` and `qqq:interface` never match). Between
/// `qqq` and the subcommand, one or more spaces/tabs — or a single hyphen, for
/// the `qqq-<sub>` spelling, which is additionally exempt when the whole token
/// is a known crate name (`qqq-run` means the crate, not the command).
fn command_mentions(line: &str, sub: &str, crate_names: &[String]) -> Vec<usize> {
    fn is_word(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
    }
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 <= line.len() {
        // Byte-compared, not str-sliced: `i` advances byte-wise and may rest
        // inside a multibyte char, where `&line[i..i + 3]` would panic. ASCII
        // `qqq` at a mid-char position cannot match, so this is exact.
        if bytes.get(i..i + 3) != Some(b"qqq".as_slice()) || (i > 0 && is_word(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let mut j = i + 3;
        let hyphen = if bytes.get(j) == Some(&b'-') {
            j += 1;
            true
        } else {
            let start = j;
            while bytes.get(j).is_some_and(u8::is_ascii_whitespace) {
                j += 1;
            }
            if j == start {
                i += 1;
                continue;
            }
            false
        };
        if line[j..].starts_with(sub) {
            let end = j + sub.len();
            let after_ok = end == line.len() || !is_word(bytes[end]);
            if after_ok {
                if hyphen {
                    // A hyphen mention that names a known crate is the crate.
                    let token = &line[i..end];
                    if !crate_names.iter().any(|c| c == token) {
                        out.push(i);
                    }
                } else {
                    out.push(i);
                }
            }
            i = end;
        } else {
            i = j;
        }
    }
    out
}

/// Every `qqqai <word>` taught in the documents must be a known subcommand.
///
/// The bare-`qqq` test only checks words already in `SUBCOMMANDS`; without this
/// pin, a new `qqqai publish` subcommand would ship with documentation the
/// scan never examines — and a `qqq publish` typo for it would pass silently.
/// Failing here means: add the subcommand to `SUBCOMMANDS` deliberately, so
/// both spellings get checked from then on.
///
/// `DOCUMENTED_FUTURE` names the commands the Proposal teaches deliberately
/// ahead of implementation (`deploy` in the §4.6 artifact pipeline, `source`
/// in §4.8.4 tracked by `REG-014` and explicitly "not part of §5.2's V1
/// command set"). They are allowed in prose but must never gain a bare-`qqq`
/// spelling; promoting one to `SUBCOMMANDS` is the day it ships.
#[test]
fn every_documented_qqqai_command_is_a_known_subcommand() {
    const DOCUMENTED_FUTURE: &[&str] = &["deploy", "source"];
    let root = workspace_root();
    let docs = ["README.md", "QQQ-Proposal-V1.md", "CONTRIBUTING.md"];
    let mut unknown = Vec::new();
    for doc in docs {
        let text = std::fs::read_to_string(root.join(doc)).expect("document is readable");
        let bytes = text.as_bytes();
        let mut i = 0;
        while i + 5 <= text.len() {
            // Byte-compared, like `command_mentions`: `i` advances byte-wise
            // and may rest inside a multibyte char, where str slicing panics.
            if bytes.get(i..i + 5) != Some(b"qqqai".as_slice())
                || (i > 0 && is_qqqai_boundary(bytes[i - 1]))
            {
                i += 1;
                continue;
            }
            let mut j = i + 5;
            while bytes.get(j).is_some_and(|b| *b == b' ' || *b == b'\t') {
                j += 1;
            }
            // A subcommand starts with a lowercase letter: flags (`--help`),
            // versions (`1.2.3`) and punctuation after `qqqai` are not words
            // to pin, and matching them would cry wolf on ordinary prose.
            let word_ok = bytes.get(j).is_some_and(u8::is_ascii_lowercase);
            let start = j;
            while bytes
                .get(j)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            {
                j += 1;
            }
            if word_ok && j > start {
                let word = &text[start..j];
                if !SUBCOMMANDS.contains(&word) && !DOCUMENTED_FUTURE.contains(&word) {
                    unknown.push(format!(
                        "{doc}:{}: `qqqai {word}`",
                        line_of(&text, start) + 1
                    ));
                }
            }
            i = j.max(i + 1);
        }
    }
    assert!(
        unknown.is_empty(),
        "documents teach `qqqai` commands outside SUBCOMMANDS; add them deliberately:\n  {}",
        unknown.join("\n  ")
    );
}

/// The `[package] name` of a manifest, or `None`.
///
/// The same strict parse the package-name test uses (key comparison, comment
/// stripping, both quote styles): the bare-`qqq` crate-name exemption must key
/// on what `cargo install` sees, not on directory names.
fn package_name_of(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines() {
        let line = strip_toml_comment(line).trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package
            && let Some((key, value)) = line.split_once('=')
            && key.trim() == "name"
        {
            return Some(
                value
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_owned(),
            );
        }
    }
    None
}

/// Whether a byte continues a `qqqai` token to the left (so `aqqqai` and
/// `foo-qqqai` are not command mentions).
fn is_qqqai_boundary(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// The 0-based line number containing byte offset `at`.
fn line_of(text: &str, at: usize) -> usize {
    text[..at.min(text.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
}

/// The control for the whole module: the scanner reads real data.
#[test]
fn the_naming_scanner_finds_real_manifests() {
    let m = manifests();
    assert!(m.len() >= 10, "expected >= 10 manifests, found {}", m.len());

    let run = m
        .iter()
        .find(|(name, _)| name == "qqq-run")
        .expect("qqq-run must exist");
    assert_eq!(
        declared_bin_names(&run.1),
        vec!["qqqai".to_owned()],
        "qqq-run must declare exactly the `qqqai` binary"
    );

    let root = workspace_root();
    let _ = Path::new(&root); // the helper resolves
    assert!(root.join("Cargo.toml").is_file(), "workspace root resolved");
}
/// Unit tests for the command matcher: every boundary the scanner promises.
#[test]
fn command_mentions_matches_only_real_commands() {
    let crates = vec!["qqq-run".to_owned(), "qqq-serve".to_owned()];
    // Space and tab separators, multiple spaces.
    assert_eq!(
        command_mentions("run qqq new project", "new", &crates),
        vec![4]
    );
    assert_eq!(
        command_mentions("qqq\tserve now", "serve", &crates),
        vec![0]
    );
    assert_eq!(command_mentions("use  qqq  run x", "run", &crates), vec![5]);
    // Hyphen spelling that is NOT a crate: a command.
    assert_eq!(
        command_mentions("try qqq-new today", "new", &crates),
        vec![4]
    );
    // Hyphen spelling that IS a crate: not a command.
    assert!(command_mentions("see qqq-run for details", "run", &crates).is_empty());
    assert!(command_mentions("see qqq-serve for details", "serve", &crates).is_empty());
    // `qqqai`, WIT identifiers, longer words, and affixed tokens never match.
    assert!(command_mentions("qqqai run now", "run", &crates).is_empty());
    assert!(command_mentions("qqq:http/incoming-handler", "http", &crates).is_empty());
    assert!(command_mentions("run qqq runner", "run", &crates).is_empty());
    assert!(command_mentions("run qqq-runner", "run", &crates).is_empty());
    assert!(command_mentions("aqqq run", "run", &crates).is_empty());
    assert!(command_mentions("x-qqq run", "run", &crates).is_empty());
    // End of line and punctuation after the subcommand are fine.
    assert_eq!(command_mentions("type qqq new", "new", &crates), vec![5]);
    assert_eq!(command_mentions("type qqq new.", "new", &crates), vec![5]);
}
