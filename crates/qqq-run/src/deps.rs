//! `qqqai add` and `qqqai remove` — editing `[dependencies]` in `qqq.toml`.
//!
//! Implements `CLI-005`; Proposal §5.2 (command table) and §5.3 (`[dependencies]`).
//!
//! # Why this edits text instead of re-serializing the manifest
//!
//! The obvious implementation is: parse `qqq.toml` into `Manifest`, add the
//! dependency to the map, serialize it back. That is rejected, deliberately.
//!
//! `qqq.toml` is a **human-owned file**. It carries comments, deliberate
//! grouping, blank lines that separate concerns, and — most importantly —
//! entries the parser does not model. Round-tripping through a struct:
//!
//! * destroys every comment, and comments are where the *reason* for a
//!   capability lives. §5.3's own example has `# see §4.7` on
//!   `shared_memory = false`. A tool that deletes the argument for a security
//!   decision has done something worse than nothing.
//! * reorders keys into whatever the struct's field order is, so a one-line
//!   addition produces a whole-file diff — and a whole-file diff is where a
//!   reviewer stops reading.
//! * cannot represent a dependency on a package whose entry is valid TOML but
//!   outside the current schema, so an older manifest gains silent data loss on
//!   upgrade. That is exactly the failure `§O-033` recorded for
//!   `[dependencies]` itself.
//!
//! So the edit is a **surgical text operation**: find the `[dependencies]`
//! table, insert one line in the right place, and leave every other byte
//! untouched. The manifest is then re-parsed to confirm the result is valid —
//! the edit is textual, but it is never *unverified*.
//!
//! # Why the write is atomic
//!
//! A crash or a full disk midway through writing `qqq.toml` would leave the
//! project's manifest truncated — the one file whose loss makes the project
//! unbuildable and whose content cannot be regenerated. The edit is written to
//! a temporary file in the same directory and renamed over the target, so the
//! manifest is either the old bytes or the new bytes and never a prefix of
//! either.

use std::path::Path;

use qqq_core::{Error, ErrorCode, Result};

/// One dependency as it will be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEdit {
    /// The package name, e.g. `qqqai/json`. Quoted when written if it is not a
    /// bare TOML key.
    pub name: String,
    /// The version requirement, already validated by the real parser.
    pub requirement: String,
    /// Features to enable, sorted and deduplicated.
    pub features: Vec<String>,
    /// An alternative source (`registry+…`, `path+…`, `git+…`).
    pub source: Option<String>,
    /// Pin exactly, rather than the usual caret widening.
    pub exact: bool,
}

impl DependencyEdit {
    /// A plain requirement with nothing else set.
    #[must_use]
    pub fn new(name: impl Into<String>, requirement: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            requirement: requirement.into(),
            features: Vec::new(),
            source: None,
            exact: false,
        }
    }

    /// Render the value side of the entry.
    ///
    /// A bare string when nothing else is set — `"qqqai/json" = "1.2"` — because
    /// it is what a human would type and produces the smallest diff. The table
    /// form appears only when there is something to put in it.
    #[must_use]
    pub fn render_value(&self) -> String {
        if self.features.is_empty() && self.source.is_none() && !self.exact {
            return format!("\"{}\"", self.requirement);
        }

        let mut parts = vec![format!("version = \"{}\"", self.requirement)];
        if let Some(src) = &self.source {
            parts.push(format!("source = \"{src}\""));
        }
        if !self.features.is_empty() {
            let mut feats = self.features.clone();
            feats.sort_unstable();
            feats.dedup();
            let rendered: Vec<String> = feats.iter().map(|f| format!("\"{f}\"")).collect();
            parts.push(format!("features = [{}]", rendered.join(", ")));
        }
        if self.exact {
            parts.push("exact = true".to_owned());
        }
        format!("{{ {} }}", parts.join(", "))
    }

    /// The key as it must appear in the table.
    ///
    /// Quoted unless the name is a bare TOML key. `qqqai/json` contains a slash
    /// and **must** be quoted — an unquoted `qqqai/json = "1.2"` is a TOML
    /// syntax error, and it is the single most likely mistake for this command
    /// to make, since every documented QQQ package name contains a slash.
    #[must_use]
    pub fn render_key(&self) -> String {
        if is_bare_key(&self.name) {
            self.name.clone()
        } else {
            format!("\"{}\"", self.name)
        }
    }

    /// The full line, ready to insert.
    #[must_use]
    pub fn render_line(&self) -> String {
        format!("{} = {}", self.render_key(), self.render_value())
    }
}

/// Whether a name may appear unquoted in TOML.
///
/// Bare keys are `A-Za-z0-9_-` only. Anything else needs quoting.
fn is_bare_key(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The result of an edit, for machine consumption.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DependencyChangeOutput {
    /// `add` or `remove`.
    pub action: String,
    /// The package name.
    pub name: String,
    /// The requirement, for an add.
    pub requirement: Option<String>,
    /// The table edited: `dependencies` or `dev-dependencies`.
    pub table: String,
    /// The manifest path, relative to the working directory when possible.
    pub manifest: String,
    /// What the entry replaced, when it replaced one. An add over an existing
    /// entry is a change of requirement, and reporting it as a plain add would
    /// hide that the previous constraint is gone.
    pub replaced: Option<String>,
    /// True when the file was not modified because it already said this.
    pub unchanged: bool,
}

// ---------------------------------------------------------------------------
// Reading the table
// ---------------------------------------------------------------------------

/// Where a table's body starts and ends in the source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TableSpan {
    /// Byte offset just past the header line.
    body_start: usize,
    /// Byte offset of the start of the next table header, or EOF.
    body_end: usize,
}

/// Locate the body of `[table]` in a manifest.
///
/// Returns `None` when the table is absent. The scan is line-oriented, which is
/// sufficient because TOML table headers cannot span lines.
///
/// # Why this is hand-written rather than using a TOML edit crate
///
/// It must preserve the file byte-for-byte outside the edited line. A
/// round-tripping serializer cannot make that promise, and every format
/// preserving TOML editor available is a large dependency in the critical path
/// of the one file that defines a project's authority. The scan needed here is
/// a few dozen lines and is fully testable, which is a better trade than a
/// dependency whose formatting rules we would have to verify anyway.
fn table_span(source: &str, table: &str) -> Option<TableSpan> {
    let header = format!("[{table}]");
    let mut body_start = None;
    let mut offset = 0usize;

    for line in source.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(start) = body_start {
            // A new table header ends this one. `[[` array-of-tables headers
            // also end it, which is correct: they are different tables.
            if trimmed.starts_with('[') {
                return Some(TableSpan {
                    body_start: start,
                    body_end: offset,
                });
            }
        } else if trimmed == header {
            body_start = Some(offset + line.len());
        }
        offset += line.len();
    }

    body_start.map(|start| TableSpan {
        body_start: start,
        body_end: source.len(),
    })
}

/// Find the line defining `key` within a span, as a byte range covering the
/// whole line including its trailing newline.
fn find_entry(source: &str, span: TableSpan, key: &str) -> Option<(usize, usize, String)> {
    let body = &source[span.body_start..span.body_end];
    let mut offset = span.body_start;

    for line in body.split_inclusive('\n') {
        let trimmed = line.trim();
        // Compare on the key side of `=`, unquoting both, so `"qqqai/json"` and
        // `qqqai/json` are recognised as the same key. A manifest written by a
        // different tool may quote differently, and failing to find an existing
        // entry would produce a duplicate — which the lockfile reader rejects.
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            if unquote(lhs.trim()) == key {
                let value_start = span.body_start + (line.len() - rhs.len());
                let _ = value_start;
                return Some((offset, offset + line.len(), rhs.trim().to_owned()));
            }
        }
        offset += line.len();
    }
    None
}

/// Strip surrounding double quotes, if present.
fn unquote(s: &str) -> String {
    let t = s.trim();
    t.strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(t)
        .to_owned()
}

// ---------------------------------------------------------------------------
// The edits
// ---------------------------------------------------------------------------

/// Add or replace a dependency in `qqq.toml`.
///
/// # Errors
///
/// * `QQQ-2001` — the manifest could not be read or written.
/// * `QQQ-2002` — the resulting file would not parse. The edit is not applied.
pub fn add(
    manifest_path: &Path,
    table: &str,
    edit: &DependencyEdit,
) -> Result<DependencyChangeOutput> {
    let source = std::fs::read_to_string(manifest_path).map_err(|e| {
        Error::new(
            ErrorCode::ManifestSyntaxInvalid,
            format!("could not read `{}`", manifest_path.display()),
        )
        .with_cause(e.to_string())
    })?;

    let (updated, replaced, unchanged) = apply_add(&source, table, edit);
    if !unchanged {
        write_atomically(manifest_path, &updated)?;
    }

    Ok(DependencyChangeOutput {
        action: "add".to_owned(),
        name: edit.name.clone(),
        requirement: Some(edit.requirement.clone()),
        table: table.to_owned(),
        manifest: display_path(manifest_path),
        replaced,
        unchanged,
    })
}

/// Compute the updated manifest text for an add.
///
/// Returns `(new_source, replaced_value, unchanged)`. Deliberately not a
/// `Result`: every branch here succeeds. The failure that matters — the result
/// not parsing — is detected in [`write_atomically`], where the bytes are
/// actually going out. Wrapping this in `Result` would promise a check it does
/// not perform and duplicate the one that already happens.
fn apply_add(source: &str, table: &str, edit: &DependencyEdit) -> (String, Option<String>, bool) {
    let line = edit.render_line();

    if let Some(span) = table_span(source, table) {
        if let Some((start, end, old_value)) = find_entry(source, span, &edit.name) {
            // Already present. Compare what is there so a no-op is reported as
            // one — re-running `add` with the same arguments must not rewrite
            // the file, or CI diffs churn for no reason.
            let new_value = edit.render_value();
            if normalise(&old_value) == normalise(&new_value) {
                return (source.to_owned(), None, true);
            }
            let mut out = String::with_capacity(source.len() + line.len());
            out.push_str(&source[..start]);
            out.push_str(&line);
            out.push('\n');
            out.push_str(&source[end..]);
            return (out, Some(old_value), false);
        }

        // Insert at the end of the table body. Positioned at `body_end`, before
        // whatever header follows, so the entry lands inside the table rather
        // than after the next one.
        let mut insert_at = span.body_end;
        // Back up over trailing blank lines so the new entry sits with its
        // neighbours instead of after a gap.
        while insert_at > span.body_start && source[..insert_at].ends_with("\n\n") {
            insert_at -= 1;
        }
        let mut out = String::with_capacity(source.len() + line.len() + 24);
        out.push_str(&source[..insert_at]);
        if !source[..insert_at].ends_with('\n') && insert_at > 0 {
            out.push('\n');
        }
        out.push_str(&line);
        out.push('\n');
        out.push_str(&source[insert_at..]);
        return (out, None, false);
    }

    // No table at all: append one, with a blank line before it unless the file
    // already ends in a blank line or is empty.
    let mut out = String::with_capacity(source.len() + line.len() + 32);
    out.push_str(source);
    if !source.is_empty() && !source.ends_with("\n\n") {
        if !source.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }
    out.push('[');
    out.push_str(table);
    out.push_str("]\n");
    out.push_str(&line);
    out.push('\n');
    (out, None, false)
}

/// Remove a dependency from `qqq.toml`.
///
/// # Errors
///
/// * `QQQ-2001` — the manifest could not be read or written.
/// * `QQQ-2004` — the named dependency is not present. Reported rather than
///   silently succeeding: a removal that removed nothing is a typo, and a
///   script that believes it cleaned something up will not check again.
pub fn remove(manifest_path: &Path, table: &str, name: &str) -> Result<DependencyChangeOutput> {
    let source = std::fs::read_to_string(manifest_path).map_err(|e| {
        Error::new(
            ErrorCode::ManifestSyntaxInvalid,
            format!("could not read `{}`", manifest_path.display()),
        )
        .with_cause(e.to_string())
    })?;

    let span = table_span(&source, table).ok_or_else(|| not_present(name, table))?;
    let (start, end, _) =
        find_entry(&source, span, name).ok_or_else(|| not_present(name, table))?;

    let mut out = String::with_capacity(source.len());
    out.push_str(&source[..start]);
    out.push_str(&source[end..]);
    write_atomically(manifest_path, &out)?;

    Ok(DependencyChangeOutput {
        action: "remove".to_owned(),
        name: name.to_owned(),
        requirement: None,
        table: table.to_owned(),
        manifest: display_path(manifest_path),
        replaced: None,
        unchanged: false,
    })
}

fn not_present(name: &str, table: &str) -> Error {
    Error::new(
        ErrorCode::DependencyNotFound,
        format!("`{name}` is not in `[{table}]`"),
    )
    .with_remediation(
        "check the spelling, or run `qqqai inspect` to list this project's dependencies",
    )
}

/// Collapse whitespace so a cosmetic difference is not reported as a change.
fn normalise(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl crate::output::CommandOutput for DependencyChangeOutput {
    fn command(&self) -> crate::output::CommandName {
        // `add` and `remove` are different commands with the same result shape;
        // the envelope names whichever one ran, so an agent branching on
        // `command` is not told the wrong tool.
        if self.action == "remove" {
            crate::output::CommandName::Remove
        } else {
            crate::output::CommandName::Add
        }
    }

    fn summary(&self) -> String {
        if self.unchanged {
            return format!(
                "{} already depends on {} at the requested constraint; {} unchanged",
                self.manifest, self.name, self.manifest
            );
        }
        match &self.replaced {
            Some(old) => format!(
                "{}: {} changed {old} to {} in [{}]",
                self.manifest,
                self.name,
                self.requirement.as_deref().unwrap_or("-"),
                self.table
            ),
            None => match &self.requirement {
                Some(req) => format!(
                    "{}: added {} {} to [{}]",
                    self.manifest, self.name, req, self.table
                ),
                None => format!(
                    "{}: removed {} from [{}]",
                    self.manifest, self.name, self.table
                ),
            },
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Render a path relative to the working directory when it is underneath it.
fn display_path(path: &Path) -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let shown = path.strip_prefix(&cwd).unwrap_or(path);
    // Manifest paths appear in `--json` output an agent diffs, so they use
    // forward slashes on every platform.
    shown.to_string_lossy().replace('\\', "/")
}

/// Write `content` to `path` via a temporary file and a rename.
///
/// The rename is the point: it is atomic on the same filesystem, so a reader
/// sees either the old manifest or the new one. A partial write would leave a
/// truncated `qqq.toml`, which is unbuildable and unrecoverable.
fn write_atomically(path: &Path, content: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.qqqtmp{}",
        path.file_name().map_or_else(
            || "manifest".to_owned(),
            |n| n.to_string_lossy().into_owned()
        ),
        std::process::id()
    ));

    std::fs::write(&tmp, content).map_err(|e| {
        Error::new(
            ErrorCode::ManifestSyntaxInvalid,
            format!("could not write `{}`", tmp.display()),
        )
        .with_cause(e.to_string())
    })?;

    // Verify before publishing. A manifest that does not parse must never
    // replace one that does, whatever the cause.
    if let Err(e) = qqq_cap::manifest::Manifest::parse(content) {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::new(
            ErrorCode::ManifestSchemaViolation,
            format!("the edit would produce an invalid manifest: {e}"),
        )
        .with_context("file", path.display().to_string())
        .with_remediation(
            "this is a bug in `qqqai`; the manifest has been left unchanged — \
             please report it with the command you ran",
        ));
    }

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::new(
            ErrorCode::ManifestSyntaxInvalid,
            format!("could not replace `{}`", path.display()),
        )
        .with_cause(e.to_string())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-dep-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    const BASE: &str = "\
[package]
name = \"app\"
version = \"0.1.0\"
";

    // -- rendering ----------------------------------------------------------

    /// A slash-containing name must be quoted.
    ///
    /// This is the single most likely mistake this module can make: every
    /// documented QQQ package name is `qqqai/<something>`, and an unquoted
    /// `qqqai/json = "1.2"` is not valid TOML.
    #[test]
    fn a_scoped_name_is_quoted_and_a_bare_name_is_not() {
        assert_eq!(
            DependencyEdit::new("qqqai/json", "1.2").render_key(),
            "\"qqqai/json\""
        );
        assert_eq!(DependencyEdit::new("serde", "1.2").render_key(), "serde");
    }

    #[test]
    fn a_plain_requirement_renders_as_a_bare_string() {
        let e = DependencyEdit::new("qqqai/json", "1.2");
        assert_eq!(e.render_line(), "\"qqqai/json\" = \"1.2\"");
    }

    #[test]
    fn features_and_source_switch_to_the_table_form() {
        let mut e = DependencyEdit::new("qqqai/json", "1.2");
        e.features = vec!["simd".to_owned()];
        e.source = Some("registry+https://pkg.qqq.dev".to_owned());
        let line = e.render_line();
        assert!(line.contains("version = \"1.2\""), "{line}");
        assert!(line.contains("features = [\"simd\"]"), "{line}");
        assert!(line.contains("source = "), "{line}");
    }

    /// Features are sorted so the same request always produces the same bytes.
    #[test]
    fn features_are_sorted_and_deduplicated() {
        let mut e = DependencyEdit::new("p", "1");
        e.features = vec!["z".to_owned(), "a".to_owned(), "z".to_owned()];
        let line = e.render_line();
        assert!(line.contains("features = [\"a\", \"z\"]"), "{line}");
    }

    #[test]
    fn exact_renders_only_when_set() {
        let mut e = DependencyEdit::new("p", "1");
        assert!(!e.render_value().contains("exact"));
        e.exact = true;
        assert!(e.render_value().contains("exact = true"));
    }

    // -- table location -----------------------------------------------------

    #[test]
    fn an_absent_table_is_reported_as_absent() {
        assert!(table_span(BASE, "dependencies").is_none());
    }

    #[test]
    fn a_table_body_ends_at_the_next_header() {
        let src = "[package]\nname = \"a\"\n\n[dependencies]\nx = \"1\"\n\n[limits]\n";
        let span = table_span(src, "dependencies").expect("present");
        let body = &src[span.body_start..span.body_end];
        assert!(body.contains("x = \"1\""), "{body}");
        assert!(
            !body.contains("[limits]"),
            "the body must stop at the next header: {body}"
        );
    }

    // -- adding -------------------------------------------------------------

    #[test]
    fn add_creates_the_table_when_missing() {
        let dir = temp_dir("addcreate");
        let path = dir.join("qqq.toml");
        std::fs::write(&path, BASE).unwrap();

        let out = add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "1.2"),
        )
        .expect("must add");

        assert!(!out.unchanged);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[dependencies]"), "{text}");
        assert!(text.contains("\"qqqai/json\" = \"1.2\""), "{text}");
        // And the file still parses, with the dependency visible.
        let m = qqq_cap::manifest::Manifest::parse(&text).expect("must parse");
        assert_eq!(m.dependencies.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_inserts_into_an_existing_table() {
        let dir = temp_dir("addinsert");
        let path = dir.join("qqq.toml");
        std::fs::write(
            &path,
            format!(
                "{BASE}\n[dependencies]\n\"qqqai/validate\" = \"2.0\"\n\n[limits]\nfuel = 1000\n"
            ),
        )
        .unwrap();

        add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "1.2"),
        )
        .expect("must add");

        let text = std::fs::read_to_string(&path).unwrap();
        let m = qqq_cap::manifest::Manifest::parse(&text).expect("must parse");
        assert_eq!(m.dependencies.len(), 2, "{text}");
        assert!(m.dependencies.contains_key("qqqai/json"));
        assert!(m.dependencies.contains_key("qqqai/validate"));
        // The neighbouring table must survive with its content.
        assert_eq!(m.limits.fuel, 1000, "the [limits] table was disturbed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Comments are the reason this module edits text.
    ///
    /// A round-tripping implementation would delete `# expiry is 15 minutes`
    /// here, and with it the only record of why the value is what it is.
    #[test]
    fn add_preserves_comments_and_formatting() {
        let dir = temp_dir("addcomments");
        let path = dir.join("qqq.toml");
        let original = "\
[package]
name = \"app\"      # the project name
version = \"0.1.0\"

[limits]
# expiry is 15 minutes, per the audit in TICKET-4021
fuel = 1000
";
        std::fs::write(&path, original).unwrap();

        add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "1.2"),
        )
        .expect("must add");

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("# the project name"),
            "an inline comment was destroyed: {text}"
        );
        assert!(
            text.contains("# expiry is 15 minutes, per the audit in TICKET-4021"),
            "a standalone comment was destroyed: {text}"
        );
        // Every original line must still be present.
        for line in original.lines() {
            assert!(text.contains(line), "line lost: {line:?}\n{text}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Re-adding the same dependency must not rewrite the file.
    #[test]
    fn adding_an_identical_entry_is_reported_as_unchanged() {
        let dir = temp_dir("addnoop");
        let path = dir.join("qqq.toml");
        std::fs::write(&path, BASE).unwrap();

        let e = DependencyEdit::new("qqqai/json", "1.2");
        add(&path, "dependencies", &e).expect("first add");
        let after_first = std::fs::read_to_string(&path).unwrap();

        let out = add(&path, "dependencies", &e).expect("second add");
        assert!(out.unchanged, "a no-op must say so");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            after_first,
            "the file must be byte-identical after a no-op"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Changing the requirement replaces the entry, and says what it replaced.
    ///
    /// Reporting this as a plain add would hide that the previous constraint is
    /// gone, which is the whole content of the change.
    #[test]
    fn adding_a_different_requirement_replaces_and_reports_the_old_one() {
        let dir = temp_dir("addreplace");
        let path = dir.join("qqq.toml");
        std::fs::write(&path, BASE).unwrap();

        add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "1.2"),
        )
        .unwrap();
        let out = add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "2.0"),
        )
        .expect("second add");

        assert_eq!(out.replaced.as_deref(), Some("\"1.2\""));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"2.0\""), "{text}");
        assert!(
            !text.contains("\"1.2\""),
            "the old entry must be gone: {text}"
        );
        let m = qqq_cap::manifest::Manifest::parse(&text).unwrap();
        assert_eq!(m.dependencies.len(), 1, "no duplicate entry: {text}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A key quoted in the file must be recognised as the same key.
    #[test]
    fn an_existing_quoted_key_is_found() {
        let dir = temp_dir("addquoted");
        let path = dir.join("qqq.toml");
        std::fs::write(
            &path,
            format!("{BASE}\n[dependencies]\n\"qqqai/json\" = \"1.2\"\n"),
        )
        .unwrap();

        let out = add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "1.2"),
        )
        .expect("must add");

        assert!(out.unchanged, "the quoted key must be recognised");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dev_dependencies_go_in_their_own_table() {
        let dir = temp_dir("adddev");
        let path = dir.join("qqq.toml");
        std::fs::write(&path, BASE).unwrap();

        add(
            &path,
            "dev-dependencies",
            &DependencyEdit::new("qqqai/assert", "1.0"),
        )
        .expect("must add");

        let text = std::fs::read_to_string(&path).unwrap();
        let m = qqq_cap::manifest::Manifest::parse(&text).unwrap();
        assert_eq!(m.dev_dependencies.len(), 1, "{text}");
        assert!(
            m.dependencies.is_empty(),
            "a dev dependency must not appear in [dependencies]: {text}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- removing -----------------------------------------------------------

    #[test]
    fn remove_deletes_only_the_named_entry() {
        let dir = temp_dir("remove");
        let path = dir.join("qqq.toml");
        std::fs::write(&path, BASE).unwrap();
        add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "1.2"),
        )
        .unwrap();
        add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/validate", "2.0"),
        )
        .unwrap();

        remove(&path, "dependencies", "qqqai/json").expect("must remove");

        let text = std::fs::read_to_string(&path).unwrap();
        let m = qqq_cap::manifest::Manifest::parse(&text).unwrap();
        assert_eq!(m.dependencies.len(), 1, "{text}");
        assert!(m.dependencies.contains_key("qqqai/validate"));
        assert!(!m.dependencies.contains_key("qqqai/json"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Removing something absent is an error, not a silent success.
    #[test]
    fn removing_an_absent_dependency_is_an_error() {
        let dir = temp_dir("removeabsent");
        let path = dir.join("qqq.toml");
        std::fs::write(&path, BASE).unwrap();

        let e = remove(&path, "dependencies", "qqqai/nope").unwrap_err();
        assert_eq!(e.code, ErrorCode::DependencyNotFound);
        assert!(e.remediation.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Removing the last entry leaves a valid, empty table.
    #[test]
    fn removing_the_last_entry_leaves_the_manifest_valid() {
        let dir = temp_dir("removelast");
        let path = dir.join("qqq.toml");
        std::fs::write(&path, BASE).unwrap();
        add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "1.2"),
        )
        .unwrap();

        remove(&path, "dependencies", "qqqai/json").expect("must remove");

        let text = std::fs::read_to_string(&path).unwrap();
        let m = qqq_cap::manifest::Manifest::parse(&text).expect("must still parse");
        assert!(m.dependencies.is_empty(), "{text}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- atomicity and validation ------------------------------------------

    /// Every edit leaves a manifest the real parser accepts.
    ///
    /// Checked for a spread of starting points, including a file with no
    /// trailing newline, because that is where a naive append corrupts the file.
    #[test]
    fn every_edit_leaves_a_parsable_manifest() {
        let starts = [
            BASE.to_owned(),
            format!("{BASE}\n[dependencies]\n"),
            format!("{BASE}\n[dependencies]\n\"a/b\" = \"1\"\n"),
            // No trailing newline.
            format!("{BASE}\n[dependencies]\n\"a/b\" = \"1\""),
            // A table after [dependencies], so insertion must not overshoot.
            // `fuel = 1000` because that is the documented minimum — `7` would
            // make the *fixture* invalid rather than the edit, and the test
            // would be measuring the validator instead of the insertion point.
            format!("{BASE}\n[dependencies]\n\"a/b\" = \"1\"\n\n[limits]\nfuel = 1000\n"),
        ];

        for (i, start) in starts.iter().enumerate() {
            let dir = temp_dir(&format!("parsable{i}"));
            let path = dir.join("qqq.toml");
            std::fs::write(&path, start).unwrap();

            add(
                &path,
                "dependencies",
                &DependencyEdit::new("qqqai/json", "1.2"),
            )
            .unwrap_or_else(|e| panic!("case {i} failed to add: {e}"));

            let text = std::fs::read_to_string(&path).unwrap();
            let m = qqq_cap::manifest::Manifest::parse(&text)
                .unwrap_or_else(|e| panic!("case {i} produced an invalid manifest: {e}\n{text}"));
            assert!(
                m.dependencies.contains_key("qqqai/json"),
                "case {i} lost the new entry:\n{text}"
            );

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A malformed edit is refused and the original file is untouched.
    ///
    /// The requirement `1.2.3` is valid, so the edit succeeds — this instead
    /// pins the *mechanism*: the temporary file is removed and the target keeps
    /// its old bytes when validation fails. Driven through a direct call to
    /// `write_atomically` so the failure is deterministic rather than dependent
    /// on producing genuinely invalid TOML from a valid edit.
    #[test]
    fn a_write_that_would_not_parse_is_refused_and_leaves_no_temp_file() {
        let dir = temp_dir("invalid");
        let path = dir.join("qqq.toml");
        std::fs::write(&path, BASE).unwrap();

        let e = write_atomically(&path, "[package\nname = \"broken\"\n").unwrap_err();
        assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
        assert!(e.remediation.is_some());

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            BASE,
            "the original manifest must be untouched"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("qqqtmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a temporary file was left behind: {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Add then remove returns the file to its original bytes.
    ///
    /// Not merely "same meaning" — the same bytes, which is what makes the
    /// textual approach worth its complexity.
    #[test]
    fn add_then_remove_restores_the_original_bytes() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("qqq.toml");
        let original = format!("{BASE}\n[dependencies]\n\"qqqai/validate\" = \"2.0\"\n");
        std::fs::write(&path, &original).unwrap();

        add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "1.2"),
        )
        .unwrap();
        remove(&path, "dependencies", "qqqai/json").unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original,
            "the round trip must be byte-exact"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scoped_name_survives_a_write_and_read() {
        let dir = temp_dir("scoped");
        let path = dir.join("qqq.toml");
        std::fs::write(&path, BASE).unwrap();

        add(
            &path,
            "dependencies",
            &DependencyEdit::new("qqqai/json", "1.2"),
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        // The quoted key is what makes this valid TOML; assert it explicitly.
        assert!(text.contains("\"qqqai/json\" ="), "{text}");
        let m = qqq_cap::manifest::Manifest::parse(&text).expect("must parse");
        assert!(m.dependencies.contains_key("qqqai/json"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
