//! The content-addressed store.
//!
//! Implements `PKG-001` (layout and verification) and `PKG-014` (offline
//! operation); Proposal §6.5.
//!
//! # Why content-addressing
//!
//! Three consequences, and the third is the one that makes it worth the
//! restructuring:
//!
//! 1. **Deduplication is free.** Two projects depending on the same artifact
//!    store one copy, with no bookkeeping beyond the digest itself.
//! 2. **Integrity is structural.** The path *is* the hash, so a corrupted or
//!    substituted artifact is detected by reading it — there is no separate
//!    checksum to check, and no way to forget to.
//! 3. **`--offline` becomes trivial.** Resolution needs the lockfile; fetching
//!    needs the store. Neither needs the network, which is what makes an
//!    air-gapped mirror a configuration change rather than a feature.
//!
//! # The layout, and why it is two levels
//!
//! ```text
//! <store>/sha256/ab/cd/abcdef0123…   the artifact
//! <store>/sha256/ab/cd/abcdef0123….meta   metadata, optional
//! ```
//!
//! The two-level fan-out is not decoration. A flat directory holding tens of
//! thousands of entries makes every lookup a linear scan on filesystems that
//! store directories as lists — which is most of them, and the reason Git uses
//! the same two-level split for its object store. Two levels of two hex
//! characters each gives 65 536 buckets, which is flat enough for any real
//! project.
//!
//! # What is *not* here
//!
//! No fetching, no hard-linking, no reflinking. Those are `PKG-002` and the
//! materialisation half of `PKG-001`, and they need the registry client to be
//! meaningful. What is here is the layout and the verification, which is what
//! everything else assumes.

use std::fmt;
use std::path::{Path, PathBuf};

use qqq_core::{Error, ErrorCode, Result};

/// The algorithm prefix used in digests.
pub const DIGEST_ALGORITHM: &str = "sha256";

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

/// A content digest.
///
/// # Why this is a type rather than a `String`
///
/// A digest used as a path component is a security boundary. A digest string
/// containing `..` or a path separator would let a crafted lockfile write
/// outside the store, and validating at every call site is a rule somebody
/// eventually forgets. Parsing once, at the boundary, means the rest of the code
/// holds a value that is *known* to be safe to join to a path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest {
    /// The lowercase hex, without the algorithm prefix.
    hex: String,
}

impl Digest {
    /// Parse a `sha256:<hex>` digest, or a bare hex string.
    ///
    /// # Errors
    ///
    /// `QQQ-5001` when the algorithm is not one we compute, or the hex is the
    /// wrong length or contains a non-hex character. Each reason is distinct,
    /// because each has a different fix.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let hex = s.strip_prefix(&format!("{DIGEST_ALGORITHM}:")).unwrap_or(s);

        // A different algorithm is refused rather than accepted. Accepting
        // `md5:` and treating the hex as opaque would mean a lockfile could
        // specify a weaker digest and nothing would notice.
        if let Some((algo, _)) = s.split_once(':') {
            if algo != DIGEST_ALGORITHM {
                return Err(Error::new(
                    ErrorCode::SignatureVerificationFailed,
                    format!("`{algo}` is not a digest algorithm QQQ verifies"),
                )
                .with_remediation(format!(
                    "only `{DIGEST_ALGORITHM}` is accepted; a weaker digest cannot be \
                     relied on for content addressing"
                )));
            }
        }

        if hex.len() != 64 {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                format!(
                    "a {DIGEST_ALGORITHM} digest is 64 hex characters, got {}",
                    hex.len()
                ),
            )
            .with_remediation("the lockfile may be corrupt; run `qqqai install`"));
        }
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                "a digest contains a non-hexadecimal character",
            )
            .with_remediation("the lockfile may be corrupt; run `qqqai install`"));
        }

        Ok(Self {
            hex: hex.to_ascii_lowercase(),
        })
    }

    /// The digest of a byte slice.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut hex = String::with_capacity(64);
        for b in out {
            use fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        Self { hex }
    }

    /// The bare hex, without the algorithm prefix.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The prefixed form, as it appears in a lockfile.
    #[must_use]
    pub fn prefixed(&self) -> String {
        format!("{DIGEST_ALGORITHM}:{}", self.hex)
    }

    /// The two-character fan-out directories, then the filename.
    ///
    /// Returns the path components rather than a joined path, so the caller
    /// chooses the root. This is what keeps the layout testable without a
    /// filesystem.
    #[must_use]
    pub fn fanout(&self) -> (&str, &str, &str) {
        (&self.hex[0..2], &self.hex[2..4], &self.hex)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.prefixed())
    }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// The store's on-disk layout.
///
/// A value rather than a set of free functions so the root is explicit at every
/// call site. A store that used a global root would be untestable without
/// mutating the environment, and tests that mutate the environment cannot run in
/// parallel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreLayout {
    root: PathBuf,
}

impl StoreLayout {
    /// A layout rooted at a directory.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where an artifact lives.
    #[must_use]
    pub fn artifact_path(&self, digest: &Digest) -> PathBuf {
        let (a, b, file) = digest.fanout();
        self.root.join(DIGEST_ALGORITHM).join(a).join(b).join(file)
    }

    /// Where an artifact's metadata lives.
    ///
    /// Beside the artifact rather than in a separate index. An index would be a
    /// second source of truth that can disagree with the store — and a metadata
    /// file that vanished while its artifact remained is a state a separate
    /// index makes possible and a side-by-side layout makes impossible.
    #[must_use]
    pub fn metadata_path(&self, digest: &Digest) -> PathBuf {
        let mut p = self.artifact_path(digest);
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        p.set_file_name(format!("{name}.meta"));
        p
    }

    /// Whether an artifact is present.
    #[must_use]
    pub fn contains(&self, digest: &Digest) -> bool {
        self.artifact_path(digest).is_file()
    }

    /// Read an artifact, verifying its digest.
    ///
    /// # Errors
    ///
    /// * `QQQ-5001` — the artifact is absent, naming the digest.
    /// * `QQQ-5006` — the bytes do not match the digest, with **both** digests in
    ///   the context so the mismatch is diagnosable rather than merely reported.
    ///
    /// # Why verification is not optional
    ///
    /// The path is the hash, which means presence is not evidence of integrity:
    /// a truncated write, a partial copy, or a substituted file all leave
    /// something at that path. Reading without verifying would make the store a
    /// cache that silently serves the wrong bytes, which is worse than no cache.
    pub fn read(&self, digest: &Digest) -> Result<Vec<u8>> {
        let path = self.artifact_path(digest);
        let bytes = std::fs::read(&path).map_err(|e| {
            Error::new(
                ErrorCode::RegistryUnreachable,
                format!("`{}` is not in the store", digest.prefixed()),
            )
            .with_cause(e.to_string())
            .with_remediation(
                "run `qqqai install` to fetch it, or `qqqai install --offline` if it \
                 should already be present",
            )
        })?;

        let actual = Digest::of(&bytes);
        if &actual != digest {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                "a stored artifact does not match its digest",
            )
            .with_context("expected", digest.prefixed())
            .with_context("actual", actual.prefixed())
            .with_context("path", path.display().to_string())
            .with_remediation(
                "the store is corrupt; remove the file and run `qqqai install` again",
            ));
        }

        Ok(bytes)
    }

    /// Write an artifact, returning the digest it was stored under.
    ///
    /// # Errors
    ///
    /// `QQQ-5006` when the directory cannot be created or the file cannot be
    /// written.
    ///
    /// # Why the digest is computed rather than supplied
    ///
    /// A caller that supplied it could supply the wrong one, and the store would
    /// then hold bytes under a path that does not describe them — permanently
    /// breaking the invariant the whole design rests on. Computing it here makes
    /// that impossible rather than merely discouraged.
    pub fn write(&self, bytes: &[u8]) -> Result<Digest> {
        let digest = Digest::of(bytes);
        let path = self.artifact_path(&digest);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::new(
                    ErrorCode::StoreCorrupted,
                    format!("could not create `{}`", parent.display()),
                )
                .with_cause(e.to_string())
            })?;
        }

        // Already present and verified: nothing to do. Re-writing would be
        // wasted I/O, and on a shared store it would be a write race.
        if self.contains(&digest) {
            return Ok(digest);
        }

        std::fs::write(&path, bytes).map_err(|e| {
            Error::new(
                ErrorCode::StoreCorrupted,
                format!("could not write `{}`", path.display()),
            )
            .with_cause(e.to_string())
        })?;
        Ok(digest)
    }

    /// Every digest present in the store, sorted.
    ///
    /// Used by `qqqai install --offline` to report what is available without
    /// reaching for the network. Sorted so the listing is deterministic, which
    /// matters because it appears in `--json` output that an agent diffs.
    #[must_use]
    pub fn list(&self) -> Vec<Digest> {
        let mut out = Vec::new();
        let algo_dir = self.root.join(DIGEST_ALGORITHM);
        let Ok(level1) = std::fs::read_dir(&algo_dir) else {
            return out;
        };

        for a in level1.flatten() {
            let Ok(level2) = std::fs::read_dir(a.path()) else {
                continue;
            };
            for b in level2.flatten() {
                let Ok(files) = std::fs::read_dir(b.path()) else {
                    continue;
                };
                for f in files.flatten() {
                    let name = f.file_name().to_string_lossy().into_owned();
                    // Skip the metadata sidecars, which share the directory.
                    // Extension comparison is case-insensitive because the store
                    // can live on a case-insensitive filesystem (macOS, Windows),
                    // where `.META` and `.meta` are the same file.
                    if std::path::Path::new(&name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("meta"))
                    {
                        continue;
                    }
                    if let Ok(d) = Digest::parse(&name) {
                        out.push(d);
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// How many artifacts are stored.
    #[must_use]
    pub fn count(&self) -> usize {
        self.list().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-store-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    /// A known-answer digest, so the test fails if the hashing changes rather
    /// than merely if it becomes non-deterministic.
    #[test]
    fn a_known_answer_digest_matches_the_published_value() {
        let d = Digest::of(b"abc");
        assert_eq!(
            d.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256(\"abc\") must match the published vector"
        );
        assert_eq!(
            d.prefixed(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_digest_round_trips_through_its_prefixed_form() {
        let d = Digest::of(b"hello");
        let parsed = Digest::parse(&d.prefixed()).expect("must parse");
        assert_eq!(d, parsed);
    }

    #[test]
    fn a_bare_hex_digest_parses() {
        let d = Digest::of(b"x");
        let parsed = Digest::parse(d.hex()).expect("must parse");
        assert_eq!(d, parsed);
    }

    /// A weaker algorithm must be refused rather than accepted as opaque hex: a
    /// lockfile specifying `md5:` would otherwise be honoured, and nothing would
    /// notice.
    #[test]
    fn a_weaker_algorithm_is_refused() {
        let md5 = "md5:".to_owned() + &"a".repeat(64);
        let e = Digest::parse(&md5).unwrap_err();
        assert_eq!(e.code, ErrorCode::SignatureVerificationFailed);
        assert!(e.remediation.is_some());
    }

    #[test]
    fn a_wrong_length_digest_is_refused() {
        for len in [0usize, 32, 63, 65, 128] {
            let s = "a".repeat(len);
            let e = Digest::parse(&s).unwrap_err();
            assert_eq!(e.code, ErrorCode::StoreCorrupted);
            assert!(
                e.message.contains(&len.to_string()),
                "the error should name the length: {}",
                e.message
            );
        }
    }

    #[test]
    fn a_non_hex_digest_is_refused() {
        let s = "z".repeat(64);
        let e = Digest::parse(&s).unwrap_err();
        assert!(e.message.contains("hexadecimal"), "got: {}", e.message);
    }

    #[test]
    fn parsing_is_case_insensitive() {
        let upper = "A".repeat(64);
        let d = Digest::parse(&upper).expect("must parse");
        assert_eq!(d.hex(), "a".repeat(64));
    }

    #[test]
    fn whitespace_is_trimmed() {
        let d = Digest::of(b"x");
        assert_eq!(Digest::parse(&format!("  {}  ", d.prefixed())).unwrap(), d);
    }

    // -- the fan-out -------------------------------------------------------

    /// The two-level split is what keeps directory lookups from becoming linear
    /// scans, and the same construction Git uses for its object store.
    #[test]
    fn the_fanout_splits_the_first_four_hex_characters() {
        let d = Digest::of(b"abc");
        let (a, b, file) = d.fanout();
        assert_eq!(a, "ba");
        assert_eq!(b, "78");
        assert_eq!(file, d.hex());
    }

    #[test]
    fn the_artifact_path_follows_the_documented_layout() {
        let root = PathBuf::from("/store");
        let layout = StoreLayout::new(&root);
        let d = Digest::of(b"abc");
        let p = layout.artifact_path(&d);
        let s = p.to_string_lossy().replace('\\', "/");
        assert!(s.ends_with(&format!("sha256/ba/78/{}", d.hex())), "got {s}");
    }

    #[test]
    fn the_metadata_path_sits_beside_the_artifact() {
        let layout = StoreLayout::new("/store");
        let d = Digest::of(b"abc");
        let artifact = layout.artifact_path(&d);
        let meta = layout.metadata_path(&d);
        assert_eq!(artifact.parent(), meta.parent(), "must share a directory");
        assert!(
            meta.to_string_lossy().ends_with(".meta"),
            "got {}",
            meta.display()
        );
    }

    // -- reading and writing -----------------------------------------------

    #[test]
    fn a_written_artifact_can_be_read_back() {
        let root = temp_root("roundtrip");
        let layout = StoreLayout::new(&root);

        let digest = layout.write(b"hello world").expect("must write");
        assert!(layout.contains(&digest));
        assert_eq!(layout.read(&digest).expect("must read"), b"hello world");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn writing_the_same_bytes_twice_is_idempotent() {
        let root = temp_root("idempotent");
        let layout = StoreLayout::new(&root);

        let a = layout.write(b"same").expect("must write");
        let b = layout.write(b"same").expect("must write again");
        assert_eq!(a, b, "identical content must produce one digest");
        assert_eq!(layout.count(), 1, "and one stored artifact");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn different_content_produces_different_digests() {
        let root = temp_root("distinct");
        let layout = StoreLayout::new(&root);
        let a = layout.write(b"one").expect("must write");
        let b = layout.write(b"two").expect("must write");
        assert_ne!(a, b);
        assert_eq!(layout.count(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reading_an_absent_artifact_names_its_digest() {
        let root = temp_root("absent");
        let layout = StoreLayout::new(&root);
        let d = Digest::of(b"never written");

        let e = layout.read(&d).unwrap_err();
        assert_eq!(e.code, ErrorCode::RegistryUnreachable);
        assert!(
            e.message.contains(d.hex()),
            "the error must name which artifact: {}",
            e.message
        );
        assert!(
            e.remediation.as_deref().unwrap_or("").contains("install"),
            "the remediation must say how to get it"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **The integrity property.** Presence at a path is not evidence of
    /// integrity: a truncated write or a substituted file both leave something
    /// there. Reading verifies, so the store cannot silently serve wrong bytes.
    #[test]
    fn a_corrupted_artifact_is_detected_on_read() {
        let root = temp_root("corrupt");
        let layout = StoreLayout::new(&root);

        let digest = layout.write(b"the original content").expect("must write");
        // Overwrite the file at its content-addressed path — what a partial
        // write or a tampering step would do.
        std::fs::write(layout.artifact_path(&digest), b"tampered!").expect("overwrite");

        let e = layout.read(&digest).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        let context: Vec<&str> = e.context.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            context.contains(&"expected") && context.contains(&"actual"),
            "both digests must be reported so the mismatch is diagnosable: {context:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A truncated artifact must be caught, which is the common real-world
    /// corruption — an interrupted write.
    #[test]
    fn a_truncated_artifact_is_detected() {
        let root = temp_root("truncated");
        let layout = StoreLayout::new(&root);

        let digest = layout
            .write(b"a reasonably long body of content")
            .expect("write");
        let path = layout.artifact_path(&digest);
        let full = std::fs::read(&path).expect("read");
        std::fs::write(&path, &full[..5]).expect("truncate");

        assert!(
            layout.read(&digest).is_err(),
            "a truncated artifact must be refused"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_empty_artifact_is_storable() {
        let root = temp_root("empty");
        let layout = StoreLayout::new(&root);
        let d = layout.write(b"").expect("must write");
        assert_eq!(layout.read(&d).expect("must read"), b"");
        // And its digest is the published SHA-256 of the empty string.
        assert_eq!(
            d.hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // -- listing -----------------------------------------------------------

    #[test]
    fn listing_an_empty_store_yields_nothing() {
        let root = temp_root("empty-list");
        let layout = StoreLayout::new(&root);
        assert!(layout.list().is_empty());
        assert_eq!(layout.count(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn listing_returns_every_artifact_sorted() {
        let root = temp_root("list");
        let layout = StoreLayout::new(&root);
        let mut expected = Vec::new();
        for i in 0..20 {
            expected.push(
                layout
                    .write(format!("content {i}").as_bytes())
                    .expect("write"),
            );
        }
        expected.sort_unstable();

        let listed = layout.list();
        assert_eq!(listed, expected, "the listing must be complete and sorted");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Metadata sidecars share the directory, so the listing must not mistake
    /// them for artifacts — a `.meta` file is not parseable as a digest, and a
    /// listing that returned it would make `--offline` report a phantom.
    #[test]
    fn listing_skips_metadata_sidecars() {
        let root = temp_root("sidecar");
        let layout = StoreLayout::new(&root);
        let d = layout.write(b"body").expect("write");
        std::fs::write(layout.metadata_path(&d), b"{}").expect("write metadata");

        let listed = layout.list();
        assert_eq!(listed, vec![d], "only real artifacts are listed");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A sidecar whose extension differs only in case is still a sidecar.
    ///
    /// The store can sit on a case-insensitive filesystem (macOS, Windows), so
    /// a `.META` file and a `.meta` file are the *same* file there. The listing
    /// must treat them alike, or `--offline` reports a phantom on one platform
    /// and not another — a divergence that only shows up on a user's machine.
    #[test]
    fn listing_treats_an_upper_case_sidecar_as_a_sidecar() {
        let root = temp_root("sidecar_case");
        let layout = StoreLayout::new(&root);
        let d = layout.write(b"body").expect("write");

        // Write the sidecar with an upper-case extension next to the artifact.
        let upper = layout.metadata_path(&d).with_extension("META");
        std::fs::write(&upper, b"{}").expect("write upper-case metadata");

        let listed = layout.list();
        assert_eq!(
            listed,
            vec![d],
            "an upper-case sidecar must not be listed as an artifact"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_store_root_lists_nothing_rather_than_failing() {
        let layout = StoreLayout::new("/definitely/not/a/store");
        assert!(layout.list().is_empty());
        assert_eq!(layout.count(), 0);
    }
}
