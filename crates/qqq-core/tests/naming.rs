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
        let has_main = workspace_root()
            .join("crates")
            .join(&dir_name)
            .join("src/main.rs")
            .is_file();
        if has_main && declared_bin_names(&text).is_empty() {
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
fn declared_bin_names(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_bin = trimmed == "[[bin]]";
            continue;
        }
        if in_bin {
            if let Some(rest) = trimmed.strip_prefix("name") {
                let rest = rest.trim_start().trim_start_matches('=').trim();
                out.push(rest.trim_matches('"').to_owned());
            }
        }
    }
    out
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
        let mut in_package = false;
        let mut package_name = None;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_package = trimmed == "[package]";
                continue;
            }
            if in_package {
                if let Some(rest) = trimmed.strip_prefix("name") {
                    let rest = rest.trim_start().trim_start_matches('=').trim();
                    package_name = Some(rest.trim_matches('"').to_owned());
                    break;
                }
            }
        }

        let name = package_name.unwrap_or_else(|| panic!("{dir_name} has no [package] name"));
        assert_ne!(
            name, "qqq",
            "`{dir_name}` is named `qqq`, which is taken on crates.io and npm (§D-001)"
        );
        assert!(
            name.starts_with("qqq-") || name == "qqqai",
            "`{dir_name}` is named `{name}`; every package is `qqq-…` or `qqqai` (§D-001)"
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
/// crate names. What is forbidden is `qqq` followed by a known subcommand name.
#[test]
fn the_documents_never_teach_a_bare_qqq_command() {
    const SUBCOMMANDS: &[&str] = &[
        "new", "init", "add", "remove", "install", "update", "build", "run", "dev", "serve",
        "test", "bench", "fmt", "lint", "inspect", "audit", "verify", "caps", "why", "trace",
        "doctor", "mcp", "schema", "openapi", "migrate", "bindings", "add-cap",
    ];

    let root = workspace_root();
    let docs = ["README.md", "QQQ-Proposal-V1.md", "CONTRIBUTING.md"];
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
                // `qqq <subcommand>` and `qqq-<subcommand>`-style mistakes, but
                // NOT `qqqai <subcommand>` (correct) or `qqq:<interface>` (a WIT
                // identifier) or `qqq-<crate>` (a crate name).
                let bare = format!("qqq {sub}");
                let mut from = 0;
                while let Some(at) = line[from..].find(&bare) {
                    let abs = from + at;
                    // Preceded by `qqqai`? Then it is `qqqai new`... unless the
                    // match starts inside `qqqai`, i.e. at the `qqq` of `qqqai`.
                    let before = &line[..abs];
                    let is_qqqai = before.ends_with("qqqai");
                    // Preceded by `-`? Then it is a crate name like `qqq-run`.
                    let is_crate = before.ends_with('-');
                    if !is_qqqai && !is_crate {
                        problems.push(format!("{doc}:{}: `{bare}`", i + 1));
                    }
                    from = abs + bare.len();
                }
            }
        }
    }

    assert!(scanned >= 2, "expected to scan at least two documents");
    assert!(
        problems.is_empty(),
        "documents teach a bare `qqq` command; §D-001 requires `qqqai`:\n  {}",
        problems.join("\n  ")
    );
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
