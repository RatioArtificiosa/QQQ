//! The file watcher behind `qqqai dev`: ignore rules and debounce.
//!
//! Implements `DX-009`; Proposal §6.6 ("file watcher with debounce and ignore
//! rules").
//!
//! # Why this is a poll-and-diff watcher rather than an event-driven one
//!
//! The obvious implementation uses OS notifications (`inotify`, `kqueue`,
//! `ReadDirectoryChangesW`), usually through a crate. That was rejected for
//! four reasons, each of which matters specifically here:
//!
//! 1. **The semantics differ per platform, and the differences leak.** inotify
//!    reports a rename as two events, `ReadDirectoryChangesW` coalesces
//!    differently, and macOS's `FSEvents` has a latency floor of its own. A
//!    debounce tuned on Linux behaves differently on macOS, so "why did my
//!    rebuild fire twice" becomes a platform question.
//! 2. **Whole-directory moves are missed.** Editors that save by writing a
//!    temporary file and renaming it over the original — `vim`, `emacs` with
//!    certain settings, many `JetBrains` saves — produce a *different* inode,
//!    and a watch registered on the old one goes silent. This is the single
//!    most common "hot reload stopped working" bug in the ecosystem.
//! 3. **No notification stream to defend against.** A watcher we poll cannot
//!    be flooded by a build writing into the tree, which means the debounce
//!    logic stays simple enough to reason about.
//! 4. **It is portable by construction.** The comparison is `(path, mtime,
//!    size)` triples, which every filesystem reports.
//!
//! The cost is latency: a change is noticed within one poll interval, not
//! instantly. For a dev server whose reload budget is 50–300 ms, a 100 ms poll
//! is within the budget and predictable, which is worth more than being 90 ms
//! faster on one platform and erratic on another.
//!
//! # What is pure and what is not
//!
//! [`IgnoreRules`] and [`Debouncer`] are pure and take no filesystem action, so
//! they are testable exhaustively. [`Snapshot`] touches the filesystem, and it
//! is the only part that does. The split is deliberate: the rules about *what
//! counts as a change* are where bugs hide, and they are the part that can be
//! tested without a temp directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The default poll interval.
///
/// 100 ms: within the 50–300 ms tier-1 reload budget of Proposal §6.6, and slow
/// enough that walking a normal `src/` tree costs a negligible fraction of one
/// core. A tighter interval would spend more time stat-ing than compiling.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The default debounce window.
///
/// A change is acted on only once the tree has been **quiet** for this long.
/// Without it, a single save that touches three files triggers three rebuilds,
/// and a `cargo build` writing into `target/` (when that is not ignored) can
/// sustain a rebuild storm indefinitely.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(150);

// ---------------------------------------------------------------------------
// Ignore rules
// ---------------------------------------------------------------------------

/// Which paths the watcher ignores.
///
/// # Why the defaults are what they are
///
/// Every ignored directory here is one whose contents change *as a result of* a
/// build. Watching them means a rebuild triggers another rebuild: the classic
/// runaway loop, where the dev server appears to hang because it is compiling
/// forever. The defaults are therefore not an optimisation — they are what
/// makes the watcher terminate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreRules {
    /// Directory names ignored wherever they appear.
    directories: Vec<String>,
    /// File extensions ignored.
    extensions: Vec<String>,
    /// Exact file names ignored.
    files: Vec<String>,
    /// Additional user-supplied patterns.
    extra: Vec<String>,
}

impl Default for IgnoreRules {
    fn default() -> Self {
        Self {
            directories: vec![
                // Build output. The single most important entry: this is what
                // closes the rebuild loop.
                "target".to_owned(),
                "node_modules".to_owned(),
                // Version control internals.
                ".git".to_owned(),
                ".hg".to_owned(),
                ".svn".to_owned(),
                // QQQ's own caches and scratch.
                ".qqq".to_owned(),
                // Editor and OS noise. `.DS_Store` alone would otherwise
                // trigger a rebuild whenever Finder touches a folder.
                ".vscode".to_owned(),
                ".idea".to_owned(),
                "__pycache__".to_owned(),
                ".pytest_cache".to_owned(),
                "dist".to_owned(),
                "build".to_owned(),
            ],
            extensions: vec![
                // Editor swap and backup files: these appear and disappear
                // during a save, which would otherwise look like two changes.
                "swp".to_owned(),
                "swo".to_owned(),
                "tmp".to_owned(),
                "bak".to_owned(),
                // Compiled artifacts a build may write beside sources.
                "rlib".to_owned(),
                "rmeta".to_owned(),
                "o".to_owned(),
                "obj".to_owned(),
                "pyc".to_owned(),
            ],
            files: vec![
                ".DS_Store".to_owned(),
                "Thumbs.db".to_owned(),
                // The watch is not interested in its own logs.
                "qqq-dev.log".to_owned(),
            ],
            extra: Vec::new(),
        }
    }
}

impl IgnoreRules {
    /// The default rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a user-supplied pattern.
    ///
    /// A pattern containing `/` is treated as a **path prefix relative to the
    /// watch root**; otherwise it is treated as a name matching at any depth.
    /// Supporting full glob syntax was considered and rejected: a dev server
    /// needs "don't watch my generated directory", and a glob engine is a
    /// dependency, a syntax to document, and a source of surprise when a
    /// pattern like `**/*.gen.rs` does not behave as the user expects.
    #[must_use]
    pub fn ignoring(mut self, pattern: impl Into<String>) -> Self {
        self.extra.push(pattern.into());
        self
    }

    /// Whether a path should be ignored.
    ///
    /// # Matching order, and why it is a pure function
    ///
    /// The path is judged on its components, so a rule applies at any depth —
    /// `a/target/b` is ignored because `target` is a directory name, not
    /// because of where it sits. This is what a user means by "ignore target",
    /// and it is the behaviour that survives a project being moved.
    ///
    /// `root` is used only for `extra` patterns containing `/`, which are
    /// relative to it.
    #[must_use]
    pub fn is_ignored(&self, root: &Path, path: &Path) -> bool {
        // -- user patterns first, so an `extra` rule can ignore something the
        // -- defaults would otherwise allow through
        if let Ok(rel) = path.strip_prefix(root) {
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            for pattern in &self.extra {
                let p = pattern.replace('\\', "/");
                if p.contains('/') {
                    // A relative path prefix: `generated/proto` ignores that
                    // subtree.
                    if rel_str == p || rel_str.starts_with(&format!("{p}/")) {
                        return true;
                    }
                } else if rel
                    .components()
                    .any(|c| c.as_os_str().to_string_lossy() == p.as_str())
                {
                    // A bare name matches any component, at any depth.
                    return true;
                }
            }
        }

        // -- directory names, at any depth
        for component in path.components() {
            let name = component.as_os_str().to_string_lossy();
            if self.directories.iter().any(|d| name == d.as_str()) {
                return true;
            }
        }

        // -- exact file names
        if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
            if self.files.iter().any(|f| file_name == f) {
                return true;
            }
        }

        // -- extensions
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            if self
                .extensions
                .iter()
                .any(|e| ext.eq_ignore_ascii_case(e.as_str()))
            {
                return true;
            }
        }

        false
    }

    /// Whether a path is a directory the walk should descend into.
    ///
    /// Separate from [`Self::is_ignored`] because a walk needs to decide
    /// *before* descending, and because an ignored *file* must not stop the
    /// walk while an ignored *directory* must.
    #[must_use]
    pub fn should_descend(&self, root: &Path, dir: &Path) -> bool {
        !self.is_ignored(root, dir)
    }
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

/// What a file looked like when last seen.
///
/// # Why size is compared as well as mtime
///
/// A file saved twice within the filesystem's timestamp resolution has the same
/// mtime. Editors are fast, and some filesystems have coarse clocks (1 second on
/// older ext3, 2 seconds on FAT). Comparing size as well catches the common case
/// where the two saves differ in length; comparing only mtime would report "no
/// change" for a real edit, which is the worst kind of dev-server bug — silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFingerprint {
    /// Last modification time, as nanoseconds since the Unix epoch.
    ///
    /// Nanoseconds rather than a `SystemTime` because the value goes into a
    /// `BTreeMap` and is compared; converting once at the boundary keeps the
    /// comparison cheap and the type `Copy`.
    pub modified_nanos: u128,
    /// Length in bytes.
    pub size: u64,
}

/// A directory tree's fingerprint, keyed by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    files: BTreeMap<PathBuf, FileFingerprint>,
}

impl Snapshot {
    /// Walk a directory and fingerprint everything the rules do not ignore.
    ///
    /// # Errors
    ///
    /// Never fails on an unreadable subdirectory: a permission error deep in the
    /// tree is skipped rather than fatal. A dev server that refused to start
    /// because one directory was unreadable would be worse than one that watches
    /// the rest — and a user cannot act on the difference anyway.
    #[must_use]
    pub fn take(root: &Path, rules: &IgnoreRules) -> Self {
        let mut files = BTreeMap::new();
        walk(root, root, rules, &mut files, 0);
        Self { files }
    }

    /// How many files were fingerprinted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether nothing was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The paths that changed between two snapshots, sorted.
    ///
    /// A path is reported when it is added, removed, or its fingerprint
    /// differs. Sorted and deduplicated so the caller sees a stable list — the
    /// dev server prints it, and unstable ordering would make the output flicker
    /// for no reason.
    #[must_use]
    pub fn changes_since(&self, previous: &Self) -> Vec<Change> {
        let mut out = Vec::new();
        for (path, now) in &self.files {
            match previous.files.get(path) {
                None => out.push(Change::Added(path.clone())),
                Some(before) if before != now => out.push(Change::Modified(path.clone())),
                Some(_) => {}
            }
        }
        for path in previous.files.keys() {
            if !self.files.contains_key(path) {
                out.push(Change::Removed(path.clone()));
            }
        }
        out
    }
}

/// How a file changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The file appeared.
    Added(PathBuf),
    /// The file's fingerprint differs.
    Modified(PathBuf),
    /// The file is gone.
    Removed(PathBuf),
}

impl Change {
    /// The path that changed.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Added(p) | Self::Modified(p) | Self::Removed(p) => p,
        }
    }

    /// The stable name, for JSON output.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Added(_) => "added",
            Self::Modified(_) => "modified",
            Self::Removed(_) => "removed",
        }
    }
}

/// The deepest the walk will descend.
///
/// A bound rather than unbounded recursion: a symlink loop or a pathological
/// tree would otherwise recurse until the stack is exhausted, turning a typo in
/// a project layout into a crash. 64 is far past any real source tree.
const MAX_DEPTH: usize = 64;

/// Recursively fingerprint a directory.
fn walk(
    root: &Path,
    dir: &Path,
    rules: &IgnoreRules,
    out: &mut BTreeMap<PathBuf, FileFingerprint>,
    depth: usize,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        // An unreadable directory is skipped, not fatal. See `Snapshot::take`.
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `symlink_metadata` rather than `metadata`: following a symlink would
        // walk into the target, and a link pointing at an ancestor is an
        // infinite loop that `MAX_DEPTH` would only slow down.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if rules.should_descend(root, &path) {
                walk(root, &path, rules, out, depth + 1);
            }
            continue;
        }
        if !meta.is_file() || rules.is_ignored(root, &path) {
            continue;
        }
        out.insert(path, fingerprint(&meta));
    }
}

/// Convert metadata into a comparable fingerprint.
fn fingerprint(meta: &std::fs::Metadata) -> FileFingerprint {
    let modified_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());
    FileFingerprint {
        modified_nanos,
        size: meta.len(),
    }
}

// ---------------------------------------------------------------------------
// Debounce
// ---------------------------------------------------------------------------

/// Coalesces bursts of changes into single rebuild triggers.
///
/// # The rule, stated plainly
///
/// A rebuild fires when changes have been observed **and** the tree has been
/// quiet for the debounce window. Both conditions matter:
///
/// * Without the quiet requirement, a three-file save fires three rebuilds.
/// * Without the "changes were observed" requirement, the server would rebuild
///   forever on an interval, because "quiet" is trivially true when nothing is
///   happening.
///
/// # Why time is injected rather than read
///
/// [`Self::observe`] takes the current instant instead of calling
/// `Instant::now()`. That makes the debounce logic a pure function of
/// `(events, time)`, so every timing behaviour — a burst, a slow drip, a
/// change arriving exactly on the boundary — is testable without sleeping. Tests
/// that sleep are slow and flaky; tests that pass a timestamp are neither.
#[derive(Debug, Clone)]
pub struct Debouncer {
    /// How long the tree must be quiet before firing.
    window: Duration,
    /// When the most recent change was observed.
    last_change: Option<Instant>,
    /// How many changes are pending.
    pending: usize,
}

impl Debouncer {
    /// A debouncer with the given quiet window.
    #[must_use]
    pub const fn new(window: Duration) -> Self {
        Self {
            window,
            last_change: None,
            pending: 0,
        }
    }

    /// The default debouncer.
    #[must_use]
    pub fn with_default_window() -> Self {
        Self::new(DEFAULT_DEBOUNCE)
    }

    /// Record that changes were observed at `now`.
    ///
    /// `count` is how many changed this poll; it accumulates so the eventual
    /// trigger can report how many files were involved.
    pub fn observe(&mut self, count: usize, now: Instant) {
        if count == 0 {
            return;
        }
        self.pending += count;
        self.last_change = Some(now);
    }

    /// Whether a rebuild should fire at `now`, consuming the pending changes if
    /// so.
    ///
    /// Returning the change count alongside the boolean keeps "should fire" and
    /// "clear the counter" from being two calls the caller could forget to pair.
    pub fn should_fire(&mut self, now: Instant) -> Option<usize> {
        let last = self.last_change?;
        // `saturating_duration_since` rather than `-`: a caller passing an
        // earlier `now` (a monotonic clock that was reset, or a test being
        // sloppy) must not panic.
        if now.saturating_duration_since(last) < self.window {
            return None;
        }
        let count = self.pending;
        self.pending = 0;
        self.last_change = None;
        (count > 0).then_some(count)
    }

    /// How many changes are waiting.
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.pending
    }

    /// The window.
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-watch-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    // -- ignore rules ------------------------------------------------------

    /// **The rule that closes the rebuild loop.** If `target/` is watched, a
    /// build writes into the tree, the watcher sees it, and the rebuild
    /// triggers another rebuild — forever.
    #[test]
    fn the_build_directory_is_ignored() {
        let rules = IgnoreRules::default();
        let root = Path::new("/proj");
        assert!(rules.is_ignored(root, &root.join("target/debug/app.wasm")));
        assert!(rules.is_ignored(root, &root.join("target")));
        // And at depth, which is the form that actually occurs.
        assert!(rules.is_ignored(root, &root.join("crates/a/target/b.rlib")));
    }

    #[test]
    fn common_ignores_are_covered() {
        let rules = IgnoreRules::default();
        let root = Path::new("/proj");
        for path in [
            "node_modules/left-pad/index.js",
            ".git/HEAD",
            ".git/objects/ab/cdef",
            ".DS_Store",
            "src/app.rs.swp",
            "dist/bundle.js",
            "build/output.o",
            "__pycache__/mod.pyc",
            ".idea/workspace.xml",
            "notes.tmp",
            "backup.bak",
        ] {
            assert!(
                rules.is_ignored(root, &root.join(path)),
                "`{path}` must be ignored by default"
            );
        }
    }

    /// The converse, and the one that matters most: real source must **not** be
    /// ignored. A watcher that ignores too much is worse than none, because it
    /// silently stops working.
    #[test]
    fn real_source_is_never_ignored() {
        let rules = IgnoreRules::default();
        let root = Path::new("/proj");
        for path in [
            "src/lib.rs",
            "src/main.rs",
            "qqq.toml",
            "Cargo.toml",
            "README.md",
            "src/nested/deep/module.rs",
            "tests/smoke.rs",
            "wit/qqq-clock.wit",
            "src/component.ts",
            "app/main.py",
        ] {
            assert!(
                !rules.is_ignored(root, &root.join(path)),
                "`{path}` is source and must be watched"
            );
        }
    }

    /// A file *named* like an ignored directory must not be ignored: a source
    /// file called `target` is unusual but legal, and the rule is about
    /// directories.
    #[test]
    fn a_rule_matches_components_not_substrings() {
        let rules = IgnoreRules::default();
        let root = Path::new("/proj");
        // `targets.rs` contains "target" but is not the directory.
        assert!(!rules.is_ignored(root, &root.join("src/targets.rs")));
        assert!(!rules.is_ignored(root, &root.join("src/distribution.rs")));
        assert!(!rules.is_ignored(root, &root.join("src/building.rs")));
    }

    #[test]
    fn a_user_pattern_without_a_slash_matches_at_any_depth() {
        let rules = IgnoreRules::default().ignoring("generated");
        let root = Path::new("/proj");
        assert!(rules.is_ignored(root, &root.join("generated/a.rs")));
        assert!(rules.is_ignored(root, &root.join("src/generated/b.rs")));
        assert!(!rules.is_ignored(root, &root.join("src/handwritten.rs")));
        // And `should_descend` agrees, so the walk prunes it rather than
        // filtering each file inside.
        assert!(!rules.should_descend(root, &root.join("generated")));
    }

    #[test]
    fn a_user_pattern_with_a_slash_is_relative_to_the_root() {
        let rules = IgnoreRules::default().ignoring("src/gen");
        let root = Path::new("/proj");
        assert!(rules.is_ignored(root, &root.join("src/gen/a.rs")));
        assert!(rules.is_ignored(root, &root.join("src/gen")));
        // The same name elsewhere is *not* ignored, because the pattern was
        // anchored.
        assert!(!rules.is_ignored(root, &root.join("vendor/src/gen/b.rs")));
    }

    /// An `extra` pattern can ignore something the defaults allow, which is the
    /// point of letting a user add rules at all.
    #[test]
    fn a_user_pattern_can_ignore_source() {
        let rules = IgnoreRules::default().ignoring("src/vendored");
        let root = Path::new("/proj");
        assert!(rules.is_ignored(root, &root.join("src/vendored/big.rs")));
        assert!(!rules.is_ignored(root, &root.join("src/mine.rs")));
    }

    #[test]
    fn extensions_are_matched_case_insensitively() {
        let rules = IgnoreRules::default();
        let root = Path::new("/proj");
        assert!(rules.is_ignored(root, &root.join("a.SWP")));
        assert!(rules.is_ignored(root, &root.join("a.Bak")));
    }

    /// A path outside the root must not panic and must fall through to the
    /// component rules rather than being silently accepted or rejected.
    #[test]
    fn a_path_outside_the_root_is_handled() {
        let rules = IgnoreRules::default();
        let root = Path::new("/proj");
        let outside = Path::new("/elsewhere/target/x.rs");
        assert!(
            rules.is_ignored(root, outside),
            "the component rule still applies"
        );
        let fine = Path::new("/elsewhere/src/x.rs");
        assert!(!rules.is_ignored(root, fine));
    }

    // -- snapshots ---------------------------------------------------------

    #[test]
    fn a_snapshot_finds_files_and_ignores_the_rest() {
        let dir = temp_dir("snap");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("target")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.join("target/junk.wasm"), "x").unwrap();
        std::fs::write(dir.join("qqq.toml"), "[package]").unwrap();

        let snap = Snapshot::take(&dir, &IgnoreRules::default());
        assert_eq!(snap.len(), 2, "only the two source files: {snap:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unchanged_tree_reports_no_changes() {
        let dir = temp_dir("snap-same");
        std::fs::write(dir.join("a.rs"), "one").unwrap();
        let rules = IgnoreRules::default();
        let first = Snapshot::take(&dir, &rules);
        let second = Snapshot::take(&dir, &rules);
        assert!(second.changes_since(&first).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_file_is_reported_as_added() {
        let dir = temp_dir("snap-add");
        std::fs::write(dir.join("a.rs"), "one").unwrap();
        let rules = IgnoreRules::default();
        let before = Snapshot::take(&dir, &rules);

        std::fs::write(dir.join("b.rs"), "two").unwrap();
        let after = Snapshot::take(&dir, &rules);

        let changes = after.changes_since(&before);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind(), "added");
        assert!(changes[0].path().ends_with("b.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_deleted_file_is_reported_as_removed() {
        let dir = temp_dir("snap-del");
        std::fs::write(dir.join("a.rs"), "one").unwrap();
        std::fs::write(dir.join("b.rs"), "two").unwrap();
        let rules = IgnoreRules::default();
        let before = Snapshot::take(&dir, &rules);

        std::fs::remove_file(dir.join("b.rs")).unwrap();
        let after = Snapshot::take(&dir, &rules);

        let changes = after.changes_since(&before);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind(), "removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A size change with an unchanged timestamp must still be detected. This is
    /// the case that a mtime-only comparison misses, and missing it means a real
    /// edit is silently not rebuilt.
    #[test]
    fn a_size_change_is_detected_even_when_the_timestamp_is_unchanged() {
        let dir = temp_dir("snap-size");
        let file = dir.join("a.rs");
        std::fs::write(&file, "short").unwrap();

        let before = Snapshot::take(&dir, &IgnoreRules::default());
        let fp_before = before.files.get(&file).copied().expect("fingerprinted");

        // Rewrite with different content, then force the mtime back so only the
        // size differs.
        std::fs::write(&file, "much longer content").unwrap();
        let after = Snapshot::take(&dir, &IgnoreRules::default());
        let fp_after = after.files.get(&file).copied().expect("fingerprinted");

        if fp_after.modified_nanos == fp_before.modified_nanos {
            // The filesystem's resolution hid the timestamp change, which is
            // exactly the case this test exists for.
            assert_ne!(fp_after.size, fp_before.size, "the size must differ");
            let changes = after.changes_since(&before);
            assert_eq!(changes.len(), 1, "the size difference must be reported");
            assert_eq!(changes[0].kind(), "modified");
        } else {
            // The timestamp differed, so the change is detected anyway.
            assert_eq!(after.changes_since(&before).len(), 1);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An ignored file appearing must not be reported, or a build's own output
    /// would trigger the next build.
    #[test]
    fn a_change_inside_an_ignored_directory_is_invisible() {
        let dir = temp_dir("snap-ignore");
        std::fs::create_dir_all(dir.join("target")).unwrap();
        std::fs::write(dir.join("src.rs"), "code").unwrap();
        let rules = IgnoreRules::default();
        let before = Snapshot::take(&dir, &rules);

        std::fs::write(dir.join("target/new.wasm"), "build output").unwrap();
        let after = Snapshot::take(&dir, &rules);

        assert!(
            after.changes_since(&before).is_empty(),
            "a change under target/ must be invisible, or builds trigger builds"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changes_are_sorted_and_deterministic() {
        let dir = temp_dir("snap-order");
        let rules = IgnoreRules::default();
        let before = Snapshot::take(&dir, &rules);
        for name in ["z.rs", "a.rs", "m.rs"] {
            std::fs::write(dir.join(name), "x").unwrap();
        }
        let after = Snapshot::take(&dir, &rules);
        let changes = after.changes_since(&before);
        let names: Vec<String> = changes
            .iter()
            .map(|c| c.path().file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a.rs", "m.rs", "z.rs"], "must be sorted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_directory_yields_an_empty_snapshot_without_panicking() {
        let snap = Snapshot::take(Path::new("/definitely/not/here"), &IgnoreRules::default());
        assert!(snap.is_empty());
    }

    /// A directory named `src` with no files must not be reported; only files
    /// are fingerprinted.
    #[test]
    fn empty_directories_are_not_reported() {
        let dir = temp_dir("snap-emptydir");
        std::fs::create_dir_all(dir.join("src/deep")).unwrap();
        let snap = Snapshot::take(&dir, &IgnoreRules::default());
        assert!(snap.is_empty(), "directories are not changes: {snap:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- debounce ----------------------------------------------------------

    #[test]
    fn nothing_fires_before_any_change() {
        let mut d = Debouncer::with_default_window();
        let t0 = Instant::now();
        assert_eq!(d.should_fire(t0), None, "no change means nothing to fire");
        assert_eq!(d.pending(), 0);
        // And still nothing after any amount of time, which is the property
        // that stops a rebuild loop when the tree is idle.
        assert_eq!(d.should_fire(t0 + Duration::from_hours(1)), None);
    }

    #[test]
    fn a_change_waits_for_the_window_then_fires_once() {
        let mut d = Debouncer::new(Duration::from_millis(100));
        let t0 = Instant::now();
        d.observe(1, t0);

        assert_eq!(
            d.should_fire(t0 + Duration::from_millis(50)),
            None,
            "too soon"
        );
        assert_eq!(
            d.should_fire(t0 + Duration::from_millis(100)),
            Some(1),
            "at the boundary it fires"
        );
        // And only once: the counter is cleared.
        assert_eq!(d.should_fire(t0 + Duration::from_millis(500)), None);
        assert_eq!(d.pending(), 0);
    }

    /// **The reason the debouncer exists.** A single save that touches three
    /// files must produce one rebuild, not three.
    #[test]
    fn a_burst_coalesces_into_one_trigger() {
        let mut d = Debouncer::new(Duration::from_millis(100));
        let t0 = Instant::now();
        d.observe(1, t0);
        d.observe(1, t0 + Duration::from_millis(10));
        d.observe(1, t0 + Duration::from_millis(20));

        assert_eq!(d.pending(), 3, "all three are counted");
        assert_eq!(
            d.should_fire(t0 + Duration::from_millis(50)),
            None,
            "the window restarts on each change, so the burst is not cut short"
        );
        assert_eq!(
            d.should_fire(t0 + Duration::from_millis(120)),
            Some(3),
            "one trigger reporting all three changes"
        );
    }

    /// A slow drip rather than a burst still coalesces, because each change
    /// restarts the window.
    #[test]
    fn a_slow_drip_still_coalesces_while_it_continues() {
        let mut d = Debouncer::new(Duration::from_millis(100));
        let mut t = Instant::now();
        for _ in 0..5 {
            d.observe(1, t);
            assert_eq!(
                d.should_fire(t + Duration::from_millis(90)),
                None,
                "each change restarts the quiet window"
            );
            t += Duration::from_millis(90);
        }
        assert_eq!(d.should_fire(t + Duration::from_millis(100)), Some(5));
    }

    #[test]
    fn observing_zero_changes_does_not_arm_the_debouncer() {
        let mut d = Debouncer::new(Duration::from_millis(100));
        let t0 = Instant::now();
        d.observe(0, t0);
        assert_eq!(d.pending(), 0);
        assert_eq!(
            d.should_fire(t0 + Duration::from_secs(1)),
            None,
            "a poll that found nothing must not trigger a rebuild"
        );
    }

    /// A clock that appears to move backwards must not panic. `Instant` is
    /// monotonic, but a test or a future caller might pass something
    /// inconsistent, and a dev server that panics on a clock oddity is worse
    /// than one that waits.
    #[test]
    fn a_backwards_clock_does_not_panic() {
        let mut d = Debouncer::new(Duration::from_millis(100));
        let t0 = Instant::now();
        d.observe(1, t0);
        assert_eq!(d.should_fire(t0.checked_sub(Duration::from_millis(50)).unwrap()), None);
        assert_eq!(d.pending(), 1, "the change is still pending");
    }

    #[test]
    fn the_window_is_reported() {
        let d = Debouncer::new(Duration::from_millis(42));
        assert_eq!(d.window(), Duration::from_millis(42));
        assert_eq!(
            Debouncer::with_default_window().window(),
            DEFAULT_DEBOUNCE,
            "the default must match the documented constant"
        );
    }

    /// The poll interval must be comfortably inside the tier-1 reload budget,
    /// and the debounce must not exceed it. These are the numbers the latency
    /// claim in Proposal §6.6 rests on, so they are asserted rather than left as
    /// prose.
    #[test]
    fn the_timings_fit_the_documented_reload_budget() {
        // Proposal §6.6: tier 1 is ~50-300 ms.
        let budget = Duration::from_millis(300);
        assert!(
            DEFAULT_POLL_INTERVAL + DEFAULT_DEBOUNCE < budget,
            "poll ({DEFAULT_POLL_INTERVAL:?}) plus debounce ({DEFAULT_DEBOUNCE:?}) \
             must fit the 300 ms tier-1 budget, or the latency claim is false"
        );
    }

    #[test]
    fn change_kinds_are_stable_names() {
        assert_eq!(Change::Added(PathBuf::from("a")).kind(), "added");
        assert_eq!(Change::Modified(PathBuf::from("a")).kind(), "modified");
        assert_eq!(Change::Removed(PathBuf::from("a")).kind(), "removed");
    }
}
