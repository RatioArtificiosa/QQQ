// SPDX-License-Identifier: Apache-2.0

//! `qqqai add-cap`: append one capability stanza to `qqq.toml`.
//!
//! # Why text surgery and not struct round-tripping
//!
//! Same rule as `deps.rs`: the manifest is the file that defines a project's
//! authority, and a round-tripping serializer cannot promise to leave the
//! other 99% of it byte-for-byte alone. The edit appends one stanza and the
//! result is re-parsed by the real parser before anything is written, so an
//! edit that does not parse never replaces a file that does.
//!
//! # Why duplicates are refused rather than merged
//!
//! An `add-cap` over an existing table would silently change the meaning of
//! grants the operator wrote by hand — widening authority without saying so.
//! Refusing with the table named sends the operator to their editor, which is
//! the only place a grant change should be composed.
//!
//! # Why the stanzas grant almost nothing
//!
//! Every table lands with safe defaults (flags off, lists empty); only `fs`
//! carries a grant, because `[[capabilities.fs]]` has no meaningful empty
//! state and its path and mode are required flags. Scaffolding empty tables
//! gives the operator correct spellings — the part `deny_unknown_fields`
//! rejects loudly — while granting nothing until values are filled in. That
//! is deny by default applied to a command whose whole job is adding
//! authority: the command adds the *spelling*, the operator adds the
//! *grant*.
//!
//! ```rust
//! use qqq_run::addcap::stanza_for;
//!
//! // Every table the command accepts has a stanza, and each one parses as
//! // part of a manifest (the per-table tests assert the details).
//! for (table, header) in [
//!     ("clock", "[capabilities.clock]"),
//!     ("env", "[capabilities.env]"),
//!     ("dns", "[capabilities.dns]"),
//!     ("http", "[capabilities.http]"),
//!     ("crypto", "[capabilities.crypto]"),
//! ] {
//!     let stanza = stanza_for(table, None, None).unwrap();
//!     assert!(stanza.starts_with(header), "{table}");
//! }
//! ```

use std::path::Path;

use qqq_cap::manifest::Manifest;
use qqq_core::{Error, ErrorCode};

/// The capability tables `add-cap` knows, exactly the tables
/// `qqq_cap::manifest::Capabilities` declares. Anything else is refused with
/// this list, so a typo cannot become a table the runtime ignores.
const KNOWN_TABLES: &[&str] = &["clock", "env", "dns", "http", "crypto", "fs"];

/// Options for [`add_cap`].
///
/// ```rust
/// use qqq_run::addcap::AddCapOptions;
///
/// let opts = AddCapOptions {
///     table: "dns".to_owned(),
///     path: None,
///     mode: None,
///     dry_run: true,
/// };
/// assert_eq!(opts.table, "dns");
/// assert!(opts.dry_run);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddCapOptions {
    /// One of [`KNOWN_TABLES`].
    pub table: String,
    /// Required for `fs`: the host path to preopen.
    pub path: Option<String>,
    /// Required for `fs`: `read-only`, `append-only` or `read-write`.
    pub mode: Option<String>,
    /// Report the stanza without writing.
    pub dry_run: bool,
}

/// The result of an `add-cap` edit, for machine consumption.
///
/// ```rust
/// use qqq_run::addcap::AddCapOutput;
///
/// let out = AddCapOutput {
///     action: "add-cap".to_owned(),
///     table: "clock".to_owned(),
///     manifest: "qqq.toml".to_owned(),
///     stanza: "[capabilities.clock]\n".to_owned(),
///     dry_run: true,
/// };
/// assert_eq!(out.table, "clock");
/// assert!(out.dry_run);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AddCapOutput {
    /// Always `add-cap`.
    pub action: String,
    /// The capability table added.
    pub table: String,
    /// The manifest path, relative to the working directory when possible.
    pub manifest: String,
    /// The exact stanza text appended.
    pub stanza: String,
    /// True when nothing was written.
    pub dry_run: bool,
}

impl crate::output::CommandOutput for AddCapOutput {
    fn command(&self) -> crate::output::CommandName {
        crate::output::CommandName::AddCap
    }

    fn summary(&self) -> String {
        if self.dry_run {
            format!(
                "would append [capabilities.{}] to {}",
                self.table, self.manifest
            )
        } else {
            format!(
                "appended [capabilities.{}] to {}",
                self.table, self.manifest
            )
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// The minimal stanza for a table, without the leading blank line.
///
/// # Errors
///
/// * `QQQ-7001` — unknown table, a missing `fs` flag, or a bad mode. The
///   file is untouched: validation happens before any read that matters.
///
/// ```rust
/// use qqq_run::addcap::stanza_for;
///
/// let s = stanza_for("clock", None, None).unwrap();
/// assert!(s.starts_with("[capabilities.clock]"));
/// assert!(stanza_for("nope", None, None).is_err());
/// ```
pub fn stanza_for(table: &str, path: Option<&str>, mode: Option<&str>) -> Result<String, Error> {
    /// Refuse a flag the table does not take: silently ignoring `--path`
    /// would let a caller believe a grant was scoped.
    fn reject_flags(table: &str, path: Option<&str>, mode: Option<&str>) -> Result<(), Error> {
        if path.is_some() || mode.is_some() {
            return Err(Error::new(
                ErrorCode::McpArgumentInvalid,
                format!("`{table}` takes no --path or --mode"),
            )
            .with_remediation("only the `fs` table takes --path and --mode"));
        }
        Ok(())
    }
    match table {
        "clock" => {
            reject_flags(table, path, mode)?;
            Ok("[capabilities.clock]\n".to_owned())
        }
        "env" => {
            reject_flags(table, path, mode)?;
            Ok("[capabilities.env]\nallow = []\n".to_owned())
        }
        "dns" => {
            reject_flags(table, path, mode)?;
            Ok("[capabilities.dns]\nresolve = []\n".to_owned())
        }
        "http" => {
            reject_flags(table, path, mode)?;
            Ok("[capabilities.http]\nserver = false\n".to_owned())
        }
        "crypto" => {
            reject_flags(table, path, mode)?;
            Ok("[capabilities.crypto]\n".to_owned())
        }
        "fs" => {
            let path = path.ok_or_else(|| {
                Error::new(
                    ErrorCode::McpArgumentInvalid,
                    "`fs` needs --path: a stanza without a path preopens nothing",
                )
                .with_remediation(
                    "for example: qqqai add-cap --cap fs --path ./data --mode read-only",
                )
            })?;
            let mode = mode.ok_or_else(|| {
                Error::new(
                    ErrorCode::McpArgumentInvalid,
                    "`fs` needs --mode: read-only, append-only or read-write",
                )
                .with_remediation(
                    "for example: qqqai add-cap --cap fs --path ./data --mode read-only",
                )
            })?;
            if !matches!(mode, "read-only" | "append-only" | "read-write") {
                return Err(Error::new(
                    ErrorCode::McpArgumentInvalid,
                    format!("`{mode}` is not a filesystem mode"),
                )
                .with_remediation("use read-only, append-only or read-write"));
            }
            // Forward slashes: a Windows path in a TOML basic string would
            // turn `\U` into a unicode escape, so the stanza normalizes the
            // separators the same way matching already does.
            let slash_path = path.replace('\\', "/");
            Ok(format!(
                "[[capabilities.fs]]\npath = \"{slash_path}\"\nmode = \"{mode}\"\n"
            ))
        }
        other => Err(Error::new(
            ErrorCode::McpArgumentInvalid,
            format!("unknown capability table `{other}`"),
        )
        .with_remediation(format!("use one of: {}", KNOWN_TABLES.join(", ")))),
    }
}

/// Whether `[capabilities.<table>]` (or any `[[capabilities.fs]]` entry)
/// already exists in the source text.
fn table_present(source: &str, table: &str) -> bool {
    let header = format!("[capabilities.{table}]");
    source.lines().any(|line| {
        let t = line.trim();
        t == header || (table == "fs" && t == "[[capabilities.fs]]")
    })
}

/// Append one capability stanza to `qqq.toml`.
///
/// # Errors
///
/// * `QQQ-2001` — the manifest could not be read or written.
/// * `QQQ-2002` — the result would not parse. The edit is not applied.
/// * `QQQ-7001` — unknown table, missing or bad `fs` flags, or the table
///   already present. The file is untouched.
///
/// ```rust
/// use qqq_run::addcap::{AddCapOptions, add_cap};
///
/// let dir = std::env::temp_dir().join(format!("qqq-addcap-doc-{}", std::process::id()));
/// std::fs::create_dir_all(&dir).unwrap();
/// let path = dir.join("qqq.toml");
/// std::fs::write(&path, "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n").unwrap();
/// let out = add_cap(
///     &path,
///     &AddCapOptions {
///         table: "clock".to_owned(),
///         path: None,
///         mode: None,
///         dry_run: false,
///     },
/// )
/// .unwrap();
/// assert_eq!(out.table, "clock");
/// let m = qqq_cap::manifest::Manifest::parse(
///     &std::fs::read_to_string(&path).unwrap(),
/// )
/// .unwrap();
/// assert!(m.capabilities.clock.is_some());
/// std::fs::remove_dir_all(&dir).unwrap();
/// ```
pub fn add_cap(manifest_path: &Path, opts: &AddCapOptions) -> Result<AddCapOutput, Error> {
    let source = std::fs::read_to_string(manifest_path).map_err(|e| {
        Error::new(
            ErrorCode::ManifestSyntaxInvalid,
            format!("could not read `{}`", manifest_path.display()),
        )
        .with_cause(e.to_string())
    })?;

    // Parse first: the duplicate check below reads the operator's file, and
    // editing a file that does not parse risks compounding the breakage.
    let manifest = Manifest::parse(&source).map_err(|e| {
        Error::new(
            ErrorCode::ManifestSyntaxInvalid,
            format!("could not parse `{}`", manifest_path.display()),
        )
        .with_cause(e.to_string())
    })?;
    let _ = manifest;

    if table_present(&source, &opts.table) {
        return Err(Error::new(
            ErrorCode::McpArgumentInvalid,
            format!("[capabilities.{}] is already present", opts.table),
        )
        .with_remediation("edit the stanza by hand; add-cap never overwrites"));
    }

    let stanza = stanza_for(&opts.table, opts.path.as_deref(), opts.mode.as_deref())?;

    // For `fs`, the path must exist as a directory now, not fail later at
    // load: a grant for a path that is not there is a typo until proven
    // otherwise, and the load-time error names normalization, not this
    // command.
    if opts.table == "fs" {
        let dir = Path::new(opts.path.as_deref().unwrap_or(""));
        if !dir.is_dir() {
            return Err(Error::new(
                ErrorCode::CapabilityPathInvalid,
                format!("`{}` is not an existing directory", dir.display()),
            )
            .with_remediation("create it first, or correct --path"));
        }
    }

    let mut updated = String::with_capacity(source.len() + stanza.len() + 64);
    updated.push_str(&source);
    if !source.is_empty() && !source.ends_with('\n') {
        updated.push('\n');
    }
    if !source.is_empty() && !source.ends_with("\n\n") {
        updated.push('\n');
    }
    updated.push_str("# added by `qqqai add-cap`\n");
    updated.push_str(&stanza);

    let out = AddCapOutput {
        action: "add-cap".to_owned(),
        table: opts.table.clone(),
        manifest: crate::deps::display_manifest(manifest_path),
        stanza,
        dry_run: opts.dry_run,
    };
    if !opts.dry_run {
        // Validate before writing, mirroring `deps::write_atomically`'s
        // guarantee through the public `write_manifest`: a result that does
        // not parse never replaces a file that does.
        Manifest::parse(&updated).map_err(|e| {
            Error::new(
                ErrorCode::ManifestSchemaViolation,
                format!("the edit would produce an invalid manifest: {e}"),
            )
        })?;
        crate::deps::write_manifest(manifest_path, &updated)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch manifest directory isolated by process id, so parallel test
    /// runners never share it.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-addcap-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    const MINIMAL: &str = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n";

    fn write_manifest(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("qqq.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    fn opts(table: &str) -> AddCapOptions {
        AddCapOptions {
            table: table.to_owned(),
            path: None,
            mode: None,
            dry_run: false,
        }
    }

    /// Every table has a stanza, and each stanza parses as part of a manifest.
    #[test]
    fn every_known_table_has_a_parsing_stanza() {
        for table in ["clock", "env", "dns", "http", "crypto"] {
            let stanza = stanza_for(table, None, None)
                .unwrap_or_else(|_| panic!("{table} must have a stanza"));
            let src = format!("{MINIMAL}\n{stanza}");
            Manifest::parse(&src).unwrap_or_else(|_| panic!("{table} stanza must parse"));
        }
    }

    /// The `fs` stanza carries the requested path and mode verbatim.
    #[test]
    fn fs_stanza_names_the_granted_path_and_mode() {
        let stanza = stanza_for("fs", Some("./data"), Some("read-only")).unwrap();
        assert!(stanza.contains("[[capabilities.fs]]"), "{stanza}");
        assert!(stanza.contains("path = \"./data\""), "{stanza}");
        assert!(stanza.contains("mode = \"read-only\""), "{stanza}");
        let src = format!("{MINIMAL}\n{stanza}");
        let m = Manifest::parse(&src).expect("fs stanza must parse");
        assert_eq!(m.capabilities.fs.len(), 1);
        assert_eq!(m.capabilities.fs[0].path, "./data");
    }

    /// An unknown table is refused with the valid list — a typo must not
    /// become a table the runtime ignores.
    #[test]
    fn unknown_table_is_refused_with_the_valid_list() {
        let err = stanza_for("clokc", None, None).expect_err("typo must fail");
        assert!(err.to_string().contains("clokc"));
        assert!(
            err.remediation.as_deref().unwrap_or("").contains("clock"),
            "must list the valid tables"
        );
    }

    /// Flags a table does not take are refused, not silently ignored.
    #[test]
    fn foreign_flags_are_refused() {
        assert!(stanza_for("clock", Some("./x"), None).is_err());
        assert!(stanza_for("dns", None, Some("read-only")).is_err());
    }

    /// `fs` without its flags, or with a bad mode, is refused before any read.
    #[test]
    fn fs_requires_path_and_a_known_mode() {
        assert!(stanza_for("fs", None, Some("read-only")).is_err());
        assert!(stanza_for("fs", Some("./data"), None).is_err());
        assert!(stanza_for("fs", Some("./data"), Some("write-mostly")).is_err());
    }

    /// Adding a table present in the file is refused and leaves the bytes alone.
    #[test]
    fn duplicate_table_is_refused_without_touching_the_file() {
        let dir = temp_dir("duplicate");
        let before = format!("{MINIMAL}\n[capabilities.clock]\nwall = true\n");
        let path = write_manifest(&dir, &before);
        let err = add_cap(&path, &opts("clock")).expect_err("duplicate must fail");
        assert!(err.to_string().contains("already present"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "a refused edit must not touch the file"
        );
    }

    /// A missing manifest is an explicit error, not an auto-created one:
    /// creating `qqq.toml` unasked would invent a project.
    #[test]
    fn missing_manifest_is_refused() {
        let dir = temp_dir("missing");
        let err =
            add_cap(&dir.join("qqq.toml"), &opts("clock")).expect_err("missing file must fail");
        assert!(err.to_string().contains("could not read"));
    }

    /// An unparsable manifest is refused before any edit is composed.
    #[test]
    fn unparsable_manifest_is_refused_untouched() {
        let dir = temp_dir("unparsable");
        let before = "[package\nname = broken\n";
        let path = write_manifest(&dir, before);
        assert!(add_cap(&path, &opts("clock")).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    /// The happy path: the table lands, everything else is byte-identical,
    /// and the result re-parses with the grant visible.
    #[test]
    fn add_clock_appends_and_reparses() {
        let dir = temp_dir("happy");
        let path = write_manifest(&dir, MINIMAL);
        let out = add_cap(&path, &opts("clock")).expect("add must succeed");
        assert_eq!(out.table, "clock");
        assert!(!out.dry_run);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.starts_with(MINIMAL), "prefix untouched");
        assert!(after.contains("[capabilities.clock]"));
        let m = Manifest::parse(&after).expect("must re-parse");
        assert!(m.capabilities.clock.is_some());
    }

    /// `fs` end to end, against a real directory: the grant is visible to the
    /// manifest's own types, not just to string matching.
    #[test]
    fn add_fs_grants_the_named_directory() {
        let dir = temp_dir("fs");
        let data = dir.join("data");
        std::fs::create_dir_all(&data).unwrap();
        let path = write_manifest(&dir, MINIMAL);
        let out = add_cap(
            &path,
            &AddCapOptions {
                table: "fs".to_owned(),
                path: Some(data.to_string_lossy().into_owned()),
                mode: Some("read-only".to_owned()),
                dry_run: false,
            },
        )
        .expect("fs add must succeed");
        assert_eq!(out.table, "fs");
        let m = Manifest::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(m.capabilities.fs.len(), 1);
        assert_eq!(
            m.capabilities.fs[0].mode,
            qqq_cap::manifest::FsMode::ReadOnly
        );
    }

    /// A nonexistent `fs` path is refused: the grant would fail at load with
    /// an error naming normalization, not this command.
    #[test]
    fn add_fs_refuses_a_missing_directory() {
        let dir = temp_dir("fsmissing");
        let path = write_manifest(&dir, MINIMAL);
        let missing = dir.join("nope");
        let err = add_cap(
            &path,
            &AddCapOptions {
                table: "fs".to_owned(),
                path: Some(missing.to_string_lossy().into_owned()),
                mode: Some("read-only".to_owned()),
                dry_run: false,
            },
        )
        .expect_err("missing dir must fail");
        assert!(err.to_string().contains("not an existing directory"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            MINIMAL,
            "refused edit leaves the file alone"
        );
    }

    /// `--dry-run` reports without writing.
    #[test]
    fn dry_run_reports_and_writes_nothing() {
        let dir = temp_dir("dryrun");
        let path = write_manifest(&dir, MINIMAL);
        let out = add_cap(
            &path,
            &AddCapOptions {
                table: "dns".to_owned(),
                path: None,
                mode: None,
                dry_run: true,
            },
        )
        .expect("dry run must succeed");
        assert!(out.dry_run);
        assert!(out.stanza.contains("[capabilities.dns]"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            MINIMAL,
            "dry run must not write"
        );
    }
}
