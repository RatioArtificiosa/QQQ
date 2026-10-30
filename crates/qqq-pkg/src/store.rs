// SPDX-License-Identifier: Apache-2.0

//! The content-addressed store.
//!
//! Implements `PKG-001` (layout, verification, and materialization) and
//! `PKG-014` (offline operation); Proposal §6.5.
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
//! No fetching and no reflinking. Fetching is `PKG-002` and needs the registry
//! client to be meaningful; reflinking (copy-on-write) is deliberately not a
//! separate path — see [`StoreLayout::materialize`] for why a hard link already
//! covers the immutable-artifact case. What is here is the layout, the
//! verification, and the materialisation, which is what everything else assumes.

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
        if let Some((algo, _)) = s.split_once(':')
            && algo != DIGEST_ALGORITHM
        {
            return Err(Error::new(
                ErrorCode::SignatureVerificationFailed,
                format!("`{algo}` is not a digest algorithm QQQ verifies"),
            )
            .with_remediation(format!(
                "only `{DIGEST_ALGORITHM}` is accepted; a weaker digest cannot be \
                     relied on for content addressing"
            )));
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
// Materialization
// ---------------------------------------------------------------------------

/// How an artifact reached its destination.
///
/// ```
/// # use qqq_pkg::store::LinkMethod;
/// assert_ne!(LinkMethod::HardLink, LinkMethod::Copied);
/// assert_ne!(LinkMethod::Copied, LinkMethod::AlreadyPresent);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMethod {
    /// Same inode as the store entry: zero-copy sharing.
    HardLink,
    /// A plain copy, used across filesystem boundaries.
    Copied,
    /// The destination already held the digest's bytes; nothing was moved.
    AlreadyPresent,
}

/// The outcome of placing one artifact.
///
/// ```
/// # use qqq_pkg::store::{LinkMethod, Materialized};
/// let m = Materialized {
///     method: LinkMethod::HardLink,
///     bytes: 12,
/// };
/// assert_eq!(m.bytes, 12);
/// assert_eq!(m.method, LinkMethod::HardLink);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Materialized {
    /// How the bytes got there.
    pub method: LinkMethod,
    /// How many bytes were placed.
    pub bytes: u64,
}

/// Hash a file without loading it, returning the digest and byte count.
///
/// Chunked reads keep a large artifact out of memory: [`StoreLayout::read`]
/// loads the whole file, which is correct for serving bytes and wrong for a
/// check that only needs the hash.
#[cfg(feature = "fs")]
fn hash_streaming(path: &Path) -> std::io::Result<(Digest, u64)> {
    use sha2::{Digest as _, Sha256};

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes: u64 = 0;
    let mut buf = [0u8; 8192];
    loop {
        use std::io::Read as _;
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        // `read` guarantees `0 < n <= buf.len()`, but a silent fallback here
        // would hash empty bytes and report a wrong digest as verified — so
        // the impossible case is a loud error, not an `unwrap_or(&[])`.
        let Some(chunk) = buf.get(..n) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "read returned more than the buffer holds",
            ));
        };
        hasher.update(chunk);
        bytes += n as u64;
    }
    let out = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in out {
        use fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    // Hashing file bytes always yields a valid digest: lowercase hex of the
    // right length parses by construction.
    let digest = Digest::parse(&hex).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("computed hash is not a valid digest: {e}"),
        )
    })?;
    Ok((digest, bytes))
}

/// Mark a placed file read-only.
///
/// See [`StoreLayout::materialize`] for why: a linked destination shares the
/// store's inode, so mutating it would corrupt the entry for every project.
/// The target is re-checked as a non-symlink regular file immediately before
/// the chmod: the check elsewhere in this file narrows the swap window, and
/// this one closes the last gap before the permission change itself — the
/// only remaining race is inside this call, which no userspace check can
/// remove without `O_NOFOLLOW`.
#[cfg(feature = "fs")]
fn make_readonly(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        Error::new(
            ErrorCode::StoreCorrupted,
            format!("could not stat `{}`", path.display()),
        )
        .with_cause(e.to_string())
    })?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            format!(
                "refusing to change permissions on `{}`: it changed under us",
                path.display()
            ),
        )
        .with_remediation("re-run `qqqai install`; investigate concurrent writers if it recurs"));
    }
    let mut perms = meta.permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(path, perms).map_err(|e| {
        Error::new(
            ErrorCode::StoreCorrupted,
            format!("placed `{}` but could not mark it read-only", path.display()),
        )
        .with_cause(e.to_string())
        .with_remediation("the file holds the right bytes but the store-sharing invariant is not enforced; fix permissions and re-run")
    })
}

/// Join a path onto the working directory without touching the filesystem.
///
/// `canonicalize` would resolve symlinks but fails on missing paths — exactly
/// the paths being placed here — so this stays lexical. Good enough for a
/// containment check, which only needs both sides in the same frame.
#[cfg(feature = "fs")]
fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().map_err(|e| {
        Error::new(
            ErrorCode::StoreCorrupted,
            "could not determine the working directory",
        )
        .with_cause(e.to_string())
    })?;
    Ok(cwd.join(path))
}

/// Remove stale temp names from a directory, best-effort.
///
/// A kill between link and rename leaves `tmp-<hex>-<pid>-<n>` behind (see
/// the link site for the exact shape, which this matches exactly — an
/// unrelated `tmp-anything` a user owns is left alone). They are never
/// load-bearing — a rerun links a fresh name — so removal failure is ignored
/// rather than failing a healthy placement. Same-directory concurrent
/// installs are not supported: a leftover name can only collide with an
/// identical one, and the loser fails loudly at link or rename time rather
/// than corrupting anything. One directory read per call.
#[cfg(feature = "fs")]
fn sweep_stale_tmps(parent: &Path) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix("tmp-") else {
            continue;
        };
        let mut parts = rest.split('-');
        // Hex is matched lowercase-only, mirroring what the link site writes
        // (`{:x}` never emits A-F), so a user file named `tmp-DEADBEEF-1-0`
        // survives the sweep.
        let matches = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(hex), Some(pid), Some(n), None) => {
                hex.len() == 8
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    && !pid.is_empty()
                    && pid.bytes().all(|b| b.is_ascii_digit())
                    && !n.is_empty()
                    && n.bytes().all(|b| b.is_ascii_digit())
            }
            _ => false,
        };
        if matches {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Whether `path` resolves to something other than a regular file.
///
/// `symlink_metadata` does not follow the final component, so a symlink —
/// dangling or not — reports as a symlink rather than as its target. Used
/// wherever a swap between check and use would turn a file operation into
/// an operation on something else.
#[cfg(feature = "fs")]
fn symlink_not_regular(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => !meta.is_file() || meta.file_type().is_symlink(),
        // Absent paths are not "something else": callers that need existence
        // check it separately, so absence here means "nothing to distrust".
        Err(_) => false,
    }
}

/// Whether a path is a symlink, following nothing.
///
/// `false` on any error: a path that cannot even be statted is handled by
/// the caller, not by this predicate.
#[cfg(feature = "fs")]
fn symlink_metadata_is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// Split a destination into its canonical parent and file name.
///
/// Both halves are needed downstream: the parent must exist for the atomic
/// rename, and the name travels separately so `..` and symlinks resolve
/// before any containment decision. Either half failing is a refusal — the
/// destination cannot be placed as named.
#[cfg(feature = "fs")]
fn canonical_place(dest: &Path) -> Result<(PathBuf, std::ffi::OsString)> {
    let Some(parent) = dest.parent() else {
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            format!(
                "cannot place `{}`: it has no parent directory",
                dest.display()
            ),
        )
        .with_remediation("choose a destination inside a directory"));
    };
    // A bare file name has an empty parent, which nothing can canonicalize:
    // it means the working directory.
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let canon_parent = std::fs::canonicalize(parent).map_err(|e| {
        Error::new(
            ErrorCode::StoreCorrupted,
            format!("cannot resolve the parent of `{}`", dest.display()),
        )
        .with_cause(e.to_string())
    })?;
    let Some(name) = dest.file_name() else {
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            format!("cannot place `{}`: it has no file name", dest.display()),
        )
        .with_remediation("choose a destination that names a file"));
    };
    Ok((canon_parent, name.to_os_string()))
}

/// Whether a canonical parent plus file name lands inside the store's
/// content tree.
///
/// Both inputs are canonical — the caller resolved them after creating the
/// directories — so symlinked parents and `..` segments are already gone and
/// `starts_with` compares real locations. The content root itself is derived
/// from the verified source path rather than the configured root string, so
/// a symlinked store root cannot disagree with it.
#[cfg(feature = "fs")]
fn dest_inside_store(src: &Path, canon_parent: &Path, name: &std::ffi::OsStr) -> Result<bool> {
    // The artifact path is root/sha256/<aa>/<bb>/<file>: three levels below
    // the content tree, so three climbs reach it. Fewer would compare
    // against a fan-out shard and miss a cousin directory.
    let Some(content) = src
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
    else {
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            "the store layout is shallower than its own fan-out",
        )
        .with_remediation("this is a bug in the store path construction; please report it"));
    };
    let canon_content = std::fs::canonicalize(content).map_err(|e| {
        Error::new(
            ErrorCode::StoreCorrupted,
            "could not resolve the store content tree",
        )
        .with_cause(e.to_string())
    })?;
    Ok(canon_parent.join(name).starts_with(&canon_content))
}

/// Commit a placed temp file to its destination.
///
/// Re-verifies the linked bytes (closing the swap window between the source
/// hash and the link), renames atomically, refuses a destination that turned
/// into a symlink in between, and marks the result read-only — removing it
/// again on any failure after the rename, so a failure never leaves a
/// suspect file behind. `bytes` is the pre-link count, carried through so
/// the happy path pays for one hash, not two, once the re-verification has
/// confirmed equality.
#[cfg(feature = "fs")]
fn commit_placed(
    digest: &Digest,
    tmp: &Path,
    dest: &Path,
    method: LinkMethod,
    bytes: u64,
) -> Result<Materialized> {
    let (placed, _) = hash_streaming(tmp).map_err(|e| {
        let _ = std::fs::remove_file(tmp);
        Error::new(
            ErrorCode::StoreCorrupted,
            "placed bytes could not be read back for verification",
        )
        .with_cause(e.to_string())
        .with_context("path", tmp.display().to_string())
    })?;
    if placed != *digest {
        let _ = std::fs::remove_file(tmp);
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            "placed bytes do not match the digest",
        )
        .with_context("expected", digest.prefixed())
        .with_context("actual", placed.prefixed())
        .with_context("path", tmp.display().to_string())
        .with_remediation(
            "the store entry changed during materialization; remove the file and run `qqqai install` again",
        ));
    }

    if let Err(e) = std::fs::rename(tmp, dest) {
        let _ = std::fs::remove_file(tmp);
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            format!("could not place `{}`", dest.display()),
        )
        .with_cause(e.to_string()));
    }
    // The rename is atomic, but the world is not quiet: a symlink swapped
    // in for the destination in this window would make the chmod below
    // follow it. Check before marking read-only, and take the destination
    // away rather than leaving a suspect file behind.
    if symlink_metadata_is_symlink(dest) {
        let _ = std::fs::remove_file(dest);
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            format!("the destination changed under us: `{}`", dest.display()),
        )
        .with_remediation("re-run `qqqai install`; investigate concurrent writers if it recurs"));
    }
    make_readonly(dest).inspect_err(|_| {
        let _ = std::fs::remove_file(dest);
    })?;

    Ok(Materialized { method, bytes })
}

/// Settle an occupied destination: no-op, replace-later, or refuse.
///
/// Returns what the destination holds: [`DestState::Absent`] means the name
/// is empty and the caller should place the artifact. A differing regular
/// file is reported, not touched — removal waits until the store entry is
/// verified, so a corrupt or absent store never costs the destination its
/// current bytes. Anything that is not a regular file is refused rather than
/// followed, removed, or written through.
/// Filesystem-backed: gated out of `core-only` builds.
#[cfg(feature = "fs")]
fn settle_destination(digest: &Digest, dest: &Path) -> Result<DestState> {
    let Ok(meta) = std::fs::symlink_metadata(dest) else {
        return Ok(DestState::Absent);
    };
    if !meta.is_file() {
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            format!(
                "`{}` is not a regular file; materialization manages regular files only and will not follow, remove, or write through directories or links",
                dest.display()
            ),
        )
        .with_remediation("remove it or choose a different destination path"));
    }
    let (actual, bytes) = hash_streaming(dest).map_err(|e| {
        Error::new(
            ErrorCode::StoreCorrupted,
            format!("could not hash `{}`", dest.display()),
        )
        .with_cause(e.to_string())
    })?;
    if actual == *digest {
        make_readonly(dest)?;
        // The hash above predates the permission change: re-read so a swap
        // in between is a loud refusal rather than a verified no-op. What
        // remains is the microsecond between this read and the return, with
        // no filesystem call left in between to hook.
        let (rechecked, _) = hash_streaming(dest).map_err(|e| {
            Error::new(
                ErrorCode::StoreCorrupted,
                format!("could not re-read `{}`", dest.display()),
            )
            .with_cause(e.to_string())
        })?;
        if rechecked != *digest {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                format!(
                    "`{}` changed under us: no longer the expected bytes",
                    dest.display()
                ),
            )
            .with_remediation(
                "re-run `qqqai install`; investigate concurrent writers if it recurs",
            ));
        }
        return Ok(DestState::Same(bytes));
    }
    Ok(DestState::Differ)
}

/// What an occupied destination holds, as found by inspection only.
///
/// `Differ` carries no bytes and deletes nothing: the caller verifies the
/// store entry first and calls [`clear_for_replace`] only afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "fs")]
enum DestState {
    /// The name is empty; proceed to place.
    Absent,
    /// The digest's bytes with this count; the caller reports a no-op.
    Same(u64),
    /// A regular file with different bytes; replace once verified.
    Differ,
}

/// Clear a differing destination for replacement: drop the read-only bit
/// (which this tool set when it placed the file) and remove the name.
///
/// Called only after the store entry verified, so a corrupt or absent store
/// never costs the destination its current bytes. Re-checks that the path
/// is still a regular file rather than trusting the settle-time metadata;
/// a swap inside this call itself remains possible (no `O_NOFOLLOW`
/// under `forbid(unsafe_code)`), narrowed to two syscalls with a refusal
/// on anything unexpected between them.
#[cfg(feature = "fs")]
#[allow(
    clippy::permissions_set_readonly_false,
    reason = "clearing the bit is the portable way to remove a file this function placed read-only; Unix mode bits via PermissionsExt would not compile on Windows"
)]
fn clear_for_replace(dest: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(dest).map_err(|e| {
        Error::new(
            ErrorCode::StoreCorrupted,
            format!("could not stat `{}` for replacement", dest.display()),
        )
        .with_cause(e.to_string())
    })?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            format!("the destination changed under us: `{}`", dest.display()),
        )
        .with_remediation("re-run `qqqai install`; investigate concurrent writers if it recurs"));
    }
    let mut perms = meta.permissions();
    perms.set_readonly(false);
    std::fs::set_permissions(dest, perms).map_err(|e| {
        Error::new(
            ErrorCode::StoreCorrupted,
            format!("could not clear `{}` for replacement", dest.display()),
        )
        .with_cause(e.to_string())
    })?;
    std::fs::remove_file(dest).map_err(|e| {
        Error::new(
            ErrorCode::StoreCorrupted,
            format!("could not clear `{}` for replacement", dest.display()),
        )
        .with_cause(e.to_string())
    })
}

/// Temp-name uniqueness across calls within one process.
///
/// Concurrent same-artifact placements into one directory would otherwise
/// share a temp name (same digest, same process id). The pid alone does not
/// separate threads of one install, so a counter does.
/// Filesystem-backed: gated out of `core-only` builds.
#[cfg(feature = "fs")]
static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Link `src` to `tmp`, falling back to a copy across filesystems.
///
/// `force_copy` exists so tests can exercise the fallback without fabricating
/// a second filesystem; production always passes false through
/// [`StoreLayout::materialize`].
///
/// A pre-existing symlink at the temp name is refused outright: `copy` would
/// write through it into someone else's file, and only something planted
/// between the sweep and this call can be here. A leftover regular file is
/// removed — by name it can only be our own stale temp. A predicted temp
/// name plus a planted link still loses to a microsecond race, so this
/// narrows the window rather than closing it; see the threat note on
/// [`StoreLayout::materialize`].
/// Filesystem-backed: gated out of `core-only` builds.
#[cfg(feature = "fs")]
fn link_or_copy(src: &Path, tmp: &Path, force_copy: bool) -> Result<LinkMethod> {
    if let Ok(meta) = std::fs::symlink_metadata(tmp) {
        if meta.file_type().is_symlink() {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                format!(
                    "refusing to write through a pre-existing link at `{}`",
                    tmp.display()
                ),
            )
            .with_remediation("remove it and re-run; investigate how it got there"));
        }
        if meta.is_file() {
            std::fs::remove_file(tmp).map_err(|e| {
                Error::new(
                    ErrorCode::StoreCorrupted,
                    format!("could not clear stale `{}`", tmp.display()),
                )
                .with_cause(e.to_string())
            })?;
        } else {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                format!(
                    "`{}` is not a regular file; refusing to link over it",
                    tmp.display()
                ),
            )
            .with_remediation("remove it and re-run"));
        }
    }
    let copy = |why: &str| {
        std::fs::copy(src, tmp).map_err(|e| {
            Error::new(
                ErrorCode::StoreCorrupted,
                format!(
                    "could not copy `{}` to `{}`{why}",
                    src.display(),
                    tmp.display()
                ),
            )
            .with_cause(e.to_string())
        })
    };
    if force_copy {
        copy("")?;
        return Ok(LinkMethod::Copied);
    }
    match std::fs::hard_link(src, tmp) {
        Ok(()) => Ok(LinkMethod::HardLink),
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            copy(" across filesystems")?;
            Ok(LinkMethod::Copied)
        }
        Err(e) => Err(Error::new(
            ErrorCode::StoreCorrupted,
            format!("could not link `{}` to `{}`", src.display(), tmp.display()),
        )
        .with_cause(e.to_string())
        .with_remediation("check that both paths are on a filesystem supporting hard links")),
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
    ///
    /// Filesystem-backed: gated out of `core-only` builds.
    #[cfg(feature = "fs")]
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
    /// Filesystem-backed: gated out of `core-only` builds.
    #[cfg(feature = "fs")]
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
    /// Filesystem-backed: gated out of `core-only` builds.
    #[cfg(feature = "fs")]
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

        // Already present: nothing to do. Presence is *not* re-verified here —
        // verification happens on read, which hashes every time, so a corrupt
        // entry fails loudly at use rather than silently at write.
        // Re-writing would be wasted I/O, and on a shared store it would be
        // a write race.
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
    /// Filesystem-backed: gated out of `core-only` builds.
    #[cfg(feature = "fs")]
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
    /// Filesystem-backed: gated out of `core-only` builds.
    #[cfg(feature = "fs")]
    pub fn count(&self) -> usize {
        self.list().len()
    }

    /// Place an artifact at a project path, verified, as a link when possible.
    ///
    /// This is the second half of `PKG-001`: the layout and verification above
    /// make the store trustworthy, and this makes it useful — a project path
    /// serving store bytes with no copy.
    ///
    /// ```
    /// use qqq_pkg::store::StoreLayout;
    /// let dir = std::env::temp_dir().join("qqq-doctest-materialize");
    /// let _ = std::fs::remove_dir_all(&dir);
    /// let store = StoreLayout::new(&dir);
    /// let digest = store.write(b"payload").unwrap();
    /// let dest = dir.join("out.bin");
    /// let m = store.materialize(&digest, &dest).unwrap();
    /// assert_eq!(std::fs::read(&dest).unwrap(), b"payload");
    /// assert_eq!(m.bytes, 7);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    ///
    /// # Errors
    ///
    /// * `QQQ-5001` — the digest is not in the store, naming it. Same shape
    ///   as [`Self::read`]: the remediation says how to get it. No
    ///   directories are created and no destination is touched on this path.
    /// * `QQQ-5006` — the stored bytes do not match the digest (with both
    ///   digests, as in [`Self::read`]); the store entry changed shape
    ///   between verification and use; the destination resolves inside the
    ///   store content tree (lexically or, after canonicalization, through a
    ///   symlinked parent or `..`); the destination directory cannot be
    ///   created; a pre-existing link blocks the temp name; the link, copy,
    ///   rename, or read-only step failed; or something that is not a regular
    ///   file blocks the destination. A refusal creates nothing new; a
    ///   pre-existing destination the check declined to touch stays as it was.
    ///
    /// # Residual races, stated plainly
    ///
    /// The checks above narrow every swap window to a single call each, and a
    /// predicted temp name plus an `O(N)` symlink plant still has to win a
    /// microsecond race the pid in the name makes unpredictable — but without
    /// `O_NOFOLLOW` (blocked by this crate's `forbid(unsafe_code)`) no
    /// check-then-act sequence on a shared filesystem closes fully. The
    /// adversary this leaves standing is a local writer racing a single
    /// install, and every outcome of losing that race is a loud refusal,
    /// never silent corruption: the placed bytes are re-verified after the
    /// link, and the destination is re-checked after the rename.
    ///
    /// Replacing a linked destination clears the read-only bit through the
    /// shared inode, so a replaced-away store entry is left writable. That
    /// is accepted rather than fixed: `read` verifies on every call and
    /// never relies on the bit, and the next materialization of that digest
    /// re-applies it. The bit is a tripwire for accidental mutation, not a
    /// security boundary.
    ///
    /// # What happens at an occupied destination
    ///
    /// The destination is a QQQ-managed output path derived from the lockfile
    /// entry, not user data — so identical bytes are a no-op
    /// ([`LinkMethod::AlreadyPresent`]) and differing bytes are replaced
    /// atomically (link to a temp name in the same directory, then rename),
    /// because re-resolution legitimately moves a path to a new digest and
    /// refusing would make upgrades impossible. A directory, symlink, or other
    /// non-regular file at the destination is refused rather than followed,
    /// removed, or written through: those are someone else's state.
    ///
    /// # Why placed files are read-only
    ///
    /// A hard-linked destination shares its inode with the store. A build
    /// mutating it in place would corrupt the store entry for every project,
    /// which is the Nix-store failure mode. The read-only bit makes that a
    /// loud permission error instead of silent corruption — on the copy path
    /// too, so a build cannot rely on mutating its inputs on any filesystem.
    ///
    /// As a side effect, the store entry itself becomes read-only the first
    /// time it is materialized through a link (same inode, one set of
    /// permissions). That is protection, not damage: reads, listings, and
    /// idempotent re-writes never need to mutate a stored artifact.
    ///
    /// # Why there is no reflink (copy-on-write) path
    ///
    /// A reflink needs either a raw `ioctl` (blocked by this crate's
    /// `forbid(unsafe_code)`) or a new dependency for one call. A hard link is
    /// already zero-copy sharing, and a store artifact is immutable, which is
    /// exactly the case where copy-on-write buys nothing over a plain link:
    /// there is never an independent mutation to isolate. A cross-device
    /// destination falls back to a plain copy, which is the only case that
    /// needs one.
    /// Filesystem-backed: gated out of `core-only` builds.
    #[cfg(feature = "fs")]
    pub fn materialize(&self, digest: &Digest, dest: &Path) -> Result<Materialized> {
        self.materialize_with(digest, dest, false)
    }

    /// [`Self::materialize`] with the link strategy exposed, so tests can
    /// force the copy fallback without fabricating a second filesystem.
    #[cfg(feature = "fs")]
    fn materialize_with(
        &self,
        digest: &Digest,
        dest: &Path,
        force_copy: bool,
    ) -> Result<Materialized> {
        // Fast lexical fence first; the sound canonical re-check happens
        // below, once the directories it needs exist.
        let root = absolutize(&self.root)?;
        let content = root.join(DIGEST_ALGORITHM);
        let outside = match absolutize(dest) {
            Ok(abs) => !abs.starts_with(&content),
            // An unresolvable destination fails loudly at placement below;
            // refusing here on a guess would be the wrong error.
            Err(_) => true,
        };
        if !outside {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                format!(
                    "cannot materialize into the store content tree: `{}`",
                    dest.display()
                ),
            )
            .with_remediation("choose a project path outside the store root"));
        }

        // An occupied destination is settled before the store is touched: a
        // refusal must not require a store entry, and a no-op must not pay
        // for a hash of bytes it will not use. A differing file is only
        // reported here — its removal waits until the store entry below
        // verifies, so a corrupt or absent store never costs the
        // destination its current bytes.
        let state = settle_destination(digest, dest)?;
        if let DestState::Same(bytes) = state {
            return Ok(Materialized {
                method: LinkMethod::AlreadyPresent,
                bytes,
            });
        }

        let (src, bytes) = self.verified_source(digest)?;

        if let Some(parent) = dest.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::new(
                    ErrorCode::StoreCorrupted,
                    format!("could not create `{}`", parent.display()),
                )
                .with_cause(e.to_string())
            })?;
        }

        // Canonical containment re-check: the lexical fence cannot see
        // through a symlinked parent or a `..` segment, so both sides are
        // resolved now that the directories exist. Either side failing to
        // resolve is a refusal — the filesystem is not in the state the
        // earlier steps established. This runs before any deletion, so a
        // destination that turns out to live inside the store is refused
        // with its bytes intact: the lexical fence is a fast path, this is
        // the sound one.
        let (canon_parent, name) = canonical_place(dest)?;
        if dest_inside_store(&src, &canon_parent, &name)? {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                format!(
                    "cannot materialize into the store content tree: `{}`",
                    dest.display()
                ),
            )
            .with_remediation("choose a project path outside the store root"));
        }
        sweep_stale_tmps(&canon_parent);

        // Now that every refusal is behind us, a differing destination can
        // be cleared: the store entry is verified and the path is outside
        // the store. `clear_for_replace` re-checks the file itself, so a
        // swap since settle is refused rather than acted on.
        if matches!(state, DestState::Differ) {
            clear_for_replace(dest)?;
        }

        // Link beside the destination so the rename below stays on one
        // filesystem (rename is only atomic within one). The digest prefix
        // keeps temp names recognizable; the process id plus a per-process
        // counter keeps them unique even for concurrent same-artifact
        // placements into one directory, where a bare digest-plus-pid name
        // would collide.
        let short = match digest.hex().get(..8) {
            Some(prefix) => prefix,
            None => digest.hex(),
        };
        let n = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = canon_parent.join(format!("tmp-{short}-{}-{n}", std::process::id()));
        let method = link_or_copy(&src, &tmp, force_copy)?;

        commit_placed(digest, &tmp, dest, method, bytes)
    }

    /// The store entry, verified, or a refusal naming it.
    ///
    /// Returns the verified path and byte count. Checking existence,
    /// hashing, comparing, and re-checking the file type happen together
    /// because each answers the same question — "is this safe to link?" —
    /// and splitting them across call sites would let a future path skip
    /// one.
    #[cfg(feature = "fs")]
    fn verified_source(&self, digest: &Digest) -> Result<(PathBuf, u64)> {
        let src = self.artifact_path(digest);
        if !src.is_file() {
            return Err(Error::new(
                ErrorCode::RegistryUnreachable,
                format!("`{}` is not in the store", digest.prefixed()),
            )
            .with_remediation(
                "run `qqqai install` to fetch it, or `qqqai install --offline` if it \
                 should already be present",
            ));
        }
        let (actual, bytes) = hash_streaming(&src).map_err(|e| {
            Error::new(
                ErrorCode::StoreCorrupted,
                "a stored artifact could not be read for verification",
            )
            .with_cause(e.to_string())
            .with_context("path", src.display().to_string())
        })?;
        if actual != *digest {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                "a stored artifact does not match its digest",
            )
            .with_context("expected", digest.prefixed())
            .with_context("actual", actual.prefixed())
            .with_context("path", src.display().to_string())
            .with_remediation(
                "the store is corrupt; remove the file and run `qqqai install` again",
            ));
        }
        // The link below must be to a regular file, not to something swapped
        // in between the hash and now.
        if symlink_not_regular(&src) {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                format!(
                    "the store entry changed under us: `{}` is no longer a regular file",
                    src.display()
                ),
            )
            .with_remediation(
                "the store is corrupt or under concurrent modification; remove the file and run `qqqai install` again",
            ));
        }
        Ok((src, bytes))
    }
}

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::*;

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
}

// Filesystem-backed tests live in their own module so the unconditional
// suite stays runnable without `std::fs` (and therefore on
// `wasm32-unknown-unknown`): nothing here may migrate upward without
// taking the `fs` gate with it.
#[cfg(all(test, feature = "fs"))]
mod fs_tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test assertions index inline vectors"
    )]
    #![allow(
        clippy::expect_used,
        reason = "test setup must create temp dirs; a Result here would trade readability for nothing (workspace F-18 convention: test modules carry reasoned allows)"
    )]
    #![allow(
        clippy::permissions_set_readonly_false,
        reason = "tests must clear the read-only bit materialize sets in order to stage stale-file and shared-inode cases; production replacement goes through settle_destination"
    )]
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-store-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
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

    // -- materialization (PKG-001) -------------------------------------------

    /// Whether two paths name the same file, i.e. a link rather than a copy.
    ///
    /// Inode comparison on Unix. On Windows the stable stdlib exposes no file
    /// index, so the check is behavioral instead (see
    /// `a_link_shares_its_inode_with_the_store`): writing through the store
    /// name must be visible through the destination name. Anywhere else the
    /// bytes and the read-only bit still prove the contract and the link
    /// check is skipped — the test documents the platform rather than
    /// failing on it.
    #[cfg(unix)]
    fn same_file(a: &Path, b: &Path) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        let (ma, mb) = (
            std::fs::metadata(a).expect("stat a"),
            std::fs::metadata(b).expect("stat b"),
        );
        ma.dev() == mb.dev() && ma.ino() == mb.ino()
    }

    /// Remove a temp tree that may contain read-only materialized files.
    ///
    /// `remove_dir_all` cannot delete read-only files on Windows, and every
    /// materialize test leaves them behind by design — so cleanup clears the
    /// bit first. Symlinks are never followed: a link is removed itself
    /// rather than recursed into or chmodded through, so a linked fixture
    /// can neither pull the walk outside the tree nor change its target's
    /// permissions. Swallowing the final error matches the existing tests:
    /// a leftover temp dir is litter, not a failure.
    fn remove_temp(root: &Path) {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(ft) = std::fs::symlink_metadata(&path).map(|m| m.file_type()) else {
                    continue;
                };
                if ft.is_symlink() {
                    let _ = std::fs::remove_file(&path);
                } else if ft.is_dir() {
                    remove_temp(&path);
                } else if let Ok(meta) = std::fs::metadata(&path) {
                    let mut perms = meta.permissions();
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(&path, perms);
                }
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// **The half that makes the store worth having.** A stored artifact must
    /// reach a project path as a link — zero-copy sharing with the store — and
    /// read back byte-identical, with the store entry intact.
    #[test]
    fn materialize_links_the_artifact_and_reads_back_identical() {
        let root = temp_root("materialize-link");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"shared bytes").expect("must write");
        let dest = root.join("proj").join("pkg.bin");

        let m = layout
            .materialize(&digest, &dest)
            .expect("must materialize");
        assert_eq!(m.bytes, 12, "twelve bytes were placed");
        assert_eq!(
            std::fs::read(&dest).expect("must read"),
            b"shared bytes",
            "the project path must serve the stored bytes"
        );
        #[cfg(unix)]
        assert!(
            same_file(&layout.artifact_path(&digest), &dest),
            "the destination must be a link, not a copy"
        );
        #[cfg(not(unix))]
        {
            // No stable inode API here, so the check is behavioral: a link
            // shares the inode, so writing through the store name must be
            // visible through the destination name (on a copy it would not
            // be). Materialization marks placed files read-only — which, on
            // a shared inode, covers the store entry too — so the bit is
            // cleared on the store name first; the temp tree is discarded
            // afterwards regardless.
            use std::io::Write as _;
            let store_path = layout.artifact_path(&digest);
            let mut perms = std::fs::metadata(&store_path)
                .expect("stat store")
                .permissions();
            perms.set_readonly(false);
            std::fs::set_permissions(&store_path, perms).expect("writable");
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&store_path)
                .expect("open store file");
            f.write_all(b"!").expect("append through the store name");
            assert_eq!(
                std::fs::read(&dest).expect("must read"),
                b"shared bytes!",
                "the write must be visible through the destination name"
            );
            // Restore the bit the check above cleared: the test below asserts
            // it, and the temp tree is removed read-only-aware regardless.
            let mut perms = std::fs::metadata(&store_path)
                .expect("stat store")
                .permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(&store_path, perms).expect("read-only again");
        }
        assert!(
            std::fs::metadata(&dest)
                .expect("stat")
                .permissions()
                .readonly(),
            "a linked file must be read-only so the shared inode cannot be mutated"
        );
        assert!(
            layout.contains(&digest),
            "the store entry must survive materialization"
        );
        remove_temp(&root);
    }

    /// Materializing twice is a no-op that reports itself: the second call
    /// must succeed without touching the store or the destination.
    #[test]
    fn materialize_is_idempotent() {
        let root = temp_root("materialize-idempotent");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"once").expect("must write");
        let dest = root.join("proj").join("pkg.bin");

        let first = layout.materialize(&digest, &dest).expect("first");
        let second = layout.materialize(&digest, &dest).expect("second");
        assert_eq!(first.bytes, second.bytes);
        assert_eq!(layout.count(), 1, "one stored artifact");
        assert_eq!(
            std::fs::read(&dest).expect("must read"),
            b"once",
            "the destination must still hold the bytes"
        );
        remove_temp(&root);
    }

    /// The destination is a QQQ-managed output path derived from the lockfile,
    /// not user data — so when it holds different bytes (a re-resolution moved
    /// the path to a new digest), materialization replaces it atomically
    /// rather than refusing and breaking upgrades.
    #[test]
    fn materialize_replaces_differing_content_at_a_managed_path() {
        let root = temp_root("materialize-replace");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"original").expect("must write");
        let dest = root.join("proj").join("pkg.bin");
        // First placement is a copy, so the destination is an independent
        // file: overwriting it below cannot reach the store entry through a
        // shared inode (which is exactly what the read-only bit prevents).
        layout
            .materialize_with(&digest, &dest, true)
            .expect("first");

        // Simulate a stale destination: clear the read-only bit the first
        // materialization set, then write different bytes.
        let mut perms = std::fs::metadata(&dest).expect("stat").permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(&dest, perms).expect("writable");
        std::fs::write(&dest, b"stale").expect("overwrite");

        let m = layout.materialize(&digest, &dest).expect("re-materialize");
        assert_eq!(m.bytes, 8, "the digest's eight bytes were placed");
        assert_eq!(
            std::fs::read(&dest).expect("must read"),
            b"original",
            "the destination must hold the digest's bytes again"
        );
        remove_temp(&root);
    }

    /// An absent digest names itself and says how to get it. The destination
    /// must not be created — a half-placed file would look installed.
    #[test]
    fn materialize_of_an_absent_digest_is_refused_by_name() {
        let root = temp_root("materialize-absent");
        let layout = StoreLayout::new(&root);
        let digest = Digest::of(b"never stored");
        let dest = root.join("proj").join("pkg.bin");

        let e = layout.materialize(&digest, &dest).unwrap_err();
        assert_eq!(e.code, ErrorCode::RegistryUnreachable);
        assert!(
            e.message.contains(digest.hex()),
            "the error must name the missing digest: {}",
            e.message
        );
        assert!(
            e.remediation.as_deref().unwrap_or("").contains("install"),
            "the remediation must say how to get it"
        );
        assert!(
            !dest.exists(),
            "a refused materialization must leave nothing behind"
        );
        remove_temp(&root);
    }

    /// Integrity is verified *before* anything is linked: a corrupted store
    /// entry must be refused with both digests, and the destination must not
    /// exist afterwards. Linking first and checking later would leave a bad
    /// file in the project on every tampered entry.
    #[test]
    fn materialize_does_not_link_a_corrupted_artifact() {
        let root = temp_root("materialize-corrupt");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"the original content").expect("write");
        std::fs::write(layout.artifact_path(&digest), b"tampered!").expect("tamper");
        let dest = root.join("proj").join("pkg.bin");

        let e = layout.materialize(&digest, &dest).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        let context: Vec<&str> = e.context.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            context.contains(&"expected") && context.contains(&"actual"),
            "both digests must be reported: {context:?}"
        );
        assert!(
            !dest.exists(),
            "a refused materialization must leave nothing behind"
        );
        remove_temp(&root);
    }

    /// The cross-device fallback (plain copy) is verified exactly like the
    /// link path: forcing it must still refuse corruption rather than copy it.
    #[test]
    fn the_copy_fallback_is_verified_like_the_link_path() {
        let root = temp_root("materialize-copy");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"copy me").expect("write");
        let dest = root.join("proj").join("pkg.bin");

        let m = layout
            .materialize_with(&digest, &dest, true)
            .expect("forced copy must work");
        assert_eq!(
            std::fs::read(&dest).expect("must read"),
            b"copy me",
            "the copy must carry the bytes"
        );
        assert!(
            std::fs::metadata(&dest)
                .expect("stat")
                .permissions()
                .readonly(),
            "a copied file must be read-only like a linked one"
        );
        assert_eq!(m.bytes, 7);

        std::fs::write(layout.artifact_path(&digest), b"tampered!").expect("tamper");
        let dest2 = root.join("proj").join("other.bin");
        let e = layout.materialize_with(&digest, &dest2, true).unwrap_err();
        assert_eq!(
            e.code,
            ErrorCode::StoreCorrupted,
            "the fallback must verify before copying"
        );
        assert!(!dest2.exists(), "a refused copy must leave nothing behind");
        remove_temp(&root);
    }

    /// A directory at the destination is refused by name. Creating a file
    /// through it, beside it, or by removing it would each be a different
    /// silent decision about user data.
    #[test]
    fn materialize_refuses_a_directory_at_the_destination() {
        let root = temp_root("materialize-isdir");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        let dest = root.join("proj");
        std::fs::create_dir_all(&dest).expect("make dir");

        let e = layout.materialize(&digest, &dest).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        assert!(
            e.message.contains("regular file"),
            "the error must say what is required: {}",
            e.message
        );
        remove_temp(&root);
    }

    /// The store entry itself is never a legal destination. Without this
    /// guard, a caller bug pointing dest at a store path would reach the
    /// replace path and delete a store entry; with it, the mistake is a named
    /// refusal and the store is untouched.
    #[test]
    fn materialize_refuses_a_destination_inside_the_store() {
        let root = temp_root("materialize-instore");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        let dest = layout.artifact_path(&digest);

        let e = layout.materialize(&digest, &dest).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        assert!(
            e.message.contains("into the store content tree"),
            "the error must name the mistake: {}",
            e.message
        );
        assert!(
            layout.contains(&digest),
            "a refused materialization must not delete a store entry"
        );
        assert_eq!(
            layout.read(&digest).expect("must read"),
            b"body",
            "the entry must still verify"
        );
        remove_temp(&root);
    }

    /// A differing destination plus a corrupt store must refuse *without*
    /// touching the destination: verification runs before any removal, so
    /// the corrupt entry cannot cost the project its current bytes.
    #[test]
    fn materialize_leaves_a_differing_dest_alone_when_the_store_is_corrupt() {
        let root = temp_root("materialize-corrupt-dest");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        let dest = root.join("proj").join("pkg.bin");
        // Independent copy, so overwriting it below cannot reach the store
        // entry through a shared inode.
        layout
            .materialize_with(&digest, &dest, true)
            .expect("first");
        // Stale the destination, then corrupt the store entry it was
        // verified against.
        let mut perms = std::fs::metadata(&dest).expect("stat").permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(&dest, perms).expect("writable");
        std::fs::write(&dest, b"stale").expect("overwrite dest");
        std::fs::write(layout.artifact_path(&digest), b"tampered!").expect("tamper store");

        let e = layout.materialize(&digest, &dest).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        assert_eq!(
            std::fs::read(&dest).expect("must read"),
            b"stale",
            "the refused replacement must leave the destination exactly as it was"
        );
        remove_temp(&root);
    }

    /// A differing destination that resolves *inside* the store is refused
    /// with its bytes intact: the canonical re-check runs before any
    /// deletion, closing the hole a symlinked parent or `..` segment would
    /// otherwise open straight through to `remove_file` on store content.
    /// Shaped with `..` so the lexical fence waves it through and only the
    /// canonical one can catch it.
    #[test]
    fn materialize_refuses_an_in_store_dest_without_touching_it() {
        let root = temp_root("materialize-instore-differ");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        // A stray regular file inside the content tree, holding other bytes,
        // addressed through `..` so only the canonical check sees where it is.
        let stray = root
            .join("proj")
            .join("..")
            .join("sha256")
            .join("ab")
            .join("stray.bin");
        std::fs::create_dir_all(stray.parent().expect("parent")).expect("mkdir");
        std::fs::write(&stray, b"junk").expect("plant stray");

        let e = layout.materialize(&digest, &stray).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        assert!(
            e.message.contains("content tree"),
            "the error must name the fence: {}",
            e.message
        );
        assert_eq!(
            std::fs::read(&stray).expect("must read"),
            b"junk",
            "the refused replacement must leave the file exactly as it was"
        );
        remove_temp(&root);
    }

    /// A kill between link and rename leaves `tmp-<hex>-<pid>` behind in the
    /// destination directory. The next materialization sweeps names of
    /// exactly that shape before linking, so a crash cannot accumulate stage
    /// survivors in the project — while an unrelated user file is never
    /// touched.
    #[test]
    fn materialize_sweeps_a_stale_temp_name() {
        let root = temp_root("materialize-sweep");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        let dest = root.join("proj").join("pkg.bin");
        std::fs::create_dir_all(dest.parent().expect("parent")).expect("mkdir");

        // Plant what a killed install would have left: a temp name of the
        // exact shape the link site writes, holding unrelated bytes — plus
        // lookalikes that must survive the sweep, including an upper-case
        // hex pretender the matcher must reject (the writer only emits
        // lowercase). The pretender uses a different pid segment so the two
        // names stay distinct files on case-insensitive filesystems.
        let stale = dest.parent().expect("parent").join("tmp-deadbeef-99999-0");
        std::fs::write(&stale, b"litter").expect("plant stale temp");
        let decoy = dest.parent().expect("parent").join("tmp-notes.txt");
        std::fs::write(&decoy, b"mine").expect("plant decoy");
        let upper = dest.parent().expect("parent").join("tmp-DEADBEEF-88888-0");
        std::fs::write(&upper, b"upper").expect("plant upper-case decoy");
        assert!(stale.is_file(), "precondition: the stale temp exists");

        let m = layout
            .materialize(&digest, &dest)
            .expect("must materialize");
        assert_eq!(m.method, crate::store::LinkMethod::HardLink);
        assert_eq!(
            std::fs::read(&dest).expect("must read"),
            b"body",
            "the destination must hold the digest's bytes"
        );
        assert!(
            !stale.exists(),
            "the stale temp name must be gone: {}",
            stale.display()
        );
        assert_eq!(
            std::fs::read(&decoy).expect("must read"),
            b"mine",
            "a user file that merely looks temporary must survive the sweep"
        );
        assert_eq!(
            std::fs::read(&upper).expect("must read"),
            b"upper",
            "an upper-case pretender must survive the sweep: only lowercase hex is ours"
        );
        remove_temp(&root);
    }

    /// A bare file name means the working directory, not a missing parent:
    /// `canonical_place` maps the empty parent to `.` instead of refusing.
    /// Pure path mapping — no files are created, so this runs anywhere.
    #[test]
    fn canonical_place_accepts_a_bare_file_name() {
        let (parent, name) = canonical_place(Path::new("out.bin")).expect("must resolve");
        assert_eq!(name.to_string_lossy(), "out.bin");
        assert!(
            parent.is_absolute(),
            "the working directory must resolve absolutely"
        );
    }

    /// A no-op refusal must not require a store entry: if the destination
    /// already holds the digest's bytes, the answer is
    /// [`LinkMethod::AlreadyPresent`] even when the store no longer has the
    /// artifact. This is what makes an offline re-install robust to a pruned
    /// store.
    #[test]
    fn materialize_is_already_present_without_a_store_entry() {
        let root = temp_root("materialize-nostore");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        let dest = root.join("proj").join("pkg.bin");
        layout.materialize(&digest, &dest).expect("first");

        std::fs::remove_file(layout.artifact_path(&digest)).expect("prune store");
        assert!(
            !layout.contains(&digest),
            "precondition: the store entry is gone"
        );

        let m = layout.materialize(&digest, &dest).expect("must succeed");
        assert_eq!(m.method, crate::store::LinkMethod::AlreadyPresent);
        assert_eq!(
            std::fs::read(&dest).expect("must read"),
            b"body",
            "the destination still serves the bytes"
        );
        remove_temp(&root);
    }

    /// A refusal creates no directories: the absent-digest error above fires
    /// before the destination's parent is touched, so a failed install leaves
    /// no empty directory tree behind.
    #[test]
    fn materialize_creates_no_directories_on_refusal() {
        let root = temp_root("materialize-nomkdir");
        let layout = StoreLayout::new(&root);
        let digest = Digest::of(b"never stored");
        let dest = root.join("proj").join("sub").join("pkg.bin");

        let e = layout.materialize(&digest, &dest).unwrap_err();
        assert_eq!(e.code, ErrorCode::RegistryUnreachable);
        assert!(
            !root.join("proj").exists(),
            "no parent directory may be created on a refused materialization"
        );
        remove_temp(&root);
    }

    /// A bare file name means the working directory: the empty parent is not
    /// a missing parent, and refusing it would make relative installs
    /// impossible. Runs wherever the test runner runs, on a temp dir entered
    /// for the duration — no repo files are touched.
    /// Ignored by default: it changes the process working directory, which
    /// parallel tests share. Run it explicitly to prove the path.
    #[test]
    #[ignore = "changes the process working directory; run explicitly"]
    fn materialize_accepts_a_bare_file_name() {
        let root = temp_root("materialize-bare");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        let previous = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&root).expect("enter temp dir");
        let placed = layout.materialize(&digest, Path::new("out.bin"));
        let _ = std::env::set_current_dir(&previous);
        let m = placed.expect("a bare name resolves against the working directory");
        assert_eq!(m.bytes, 4);
        assert_eq!(
            std::fs::read(root.join("out.bin")).expect("must read"),
            b"body",
            "the file must land in the working directory"
        );
        remove_temp(&root);
    }

    /// A `..` segment that resolves back into the store is refused by the
    /// canonical re-check, not just the lexical fence: the lexical pass sees
    /// `proj/../sha256/...` and waves it through, the canonical one resolves
    /// `proj/..` away and catches the content tree. Needs no symlinks, so it
    /// runs everywhere.
    #[test]
    fn materialize_refuses_a_dotdot_escape_into_the_store() {
        let root = temp_root("materialize-dotdot");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        // A decoy subdirectory so `..` has something to resolve through.
        std::fs::create_dir_all(root.join("proj")).expect("mkdir");
        let dest = root
            .join("proj")
            .join("..")
            .join("sha256")
            .join("ab")
            .join("evil.bin");
        std::fs::create_dir_all(dest.parent().expect("parent")).expect("mkdir");

        let e = layout.materialize(&digest, &dest).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        assert!(
            e.message.contains("content tree"),
            "the error must name the fence: {}",
            e.message
        );
        remove_temp(&root);
    }

    /// A pre-existing link at the temp name is refused, not written through:
    /// `copy` follows symlinks, so without this check a planted link would
    /// receive the store's bytes. Unix-only: Windows needs privilege the
    /// test cannot assume; the refusal arm is still covered on every
    /// platform by the non-regular-file branch below.
    #[test]
    #[cfg(unix)]
    fn link_or_copy_refuses_a_symlink_at_the_temp_name() {
        use std::os::unix::fs::symlink as symlink_path;

        let root = temp_root("link-symlink-tmp");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        let tmp = root.join("tmp-planted");
        let target = root.join("victim.bin");
        std::fs::write(&target, b"victim").expect("plant target");
        symlink_path(&target, &tmp).expect("plant link");

        let e = link_or_copy(&layout.artifact_path(&digest), &tmp, true).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        assert!(
            e.message.contains("pre-existing link"),
            "the error must name the plant: {}",
            e.message
        );
        assert_eq!(
            std::fs::read(&target).expect("must read"),
            b"victim",
            "the link target must be untouched"
        );
        assert!(
            !root.join("dest.bin").exists(),
            "a refused link must leave nothing behind"
        );
        remove_temp(&root);
    }

    /// A non-directory occupant that is not a symlink is refused: the sweep
    /// removes stale regular files, so anything left at a temp name that is
    /// not a link is someone else's state. Covered portably with a
    /// directory.
    #[test]
    fn link_or_copy_refuses_a_non_file_at_the_temp_name() {
        let root = temp_root("materialize-tmpdir");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        let tmp = root.join("tmp-occupied");
        std::fs::create_dir_all(&tmp).expect("plant dir");

        let e = link_or_copy(&layout.artifact_path(&digest), &tmp, true).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        let _ = std::fs::remove_dir_all(&tmp);
        remove_temp(&root);
    }

    /// A symlinked parent pointing into the store is refused by the canonical
    /// re-check. Unix-only: creating the symlink needs privilege Windows CI
    /// cannot assume. The lexical fence cannot see through the link; only
    /// resolution after `create_dir_all` catches it.
    #[test]
    #[cfg(unix)]
    fn materialize_refuses_a_symlinked_parent_into_the_store() {
        let root = temp_root("materialize-symparent");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"body").expect("write");
        // Point a project-looking directory at the store's first fan-out level.
        let link = root.join("linked");
        std::os::unix::fs::symlink(root.join("sha256"), &link).expect("plant link");
        let dest = link.join("ab").join("evil.bin");

        let e = layout.materialize(&digest, &dest).unwrap_err();
        assert_eq!(e.code, ErrorCode::StoreCorrupted);
        assert!(
            e.message.contains("content tree"),
            "the error must name the fence: {}",
            e.message
        );
        remove_temp(&root);
    }

    /// Read-only is a property of the placed file on both paths. A build must
    /// not mutate its inputs, whether they are linked or copied — so both
    /// paths set the bit, and this test pins both.
    #[test]
    fn materialized_files_are_read_only_on_both_paths() {
        let root = temp_root("materialize-ro");
        let layout = StoreLayout::new(&root);
        let digest = layout.write(b"locked").expect("write");

        let linked = root.join("a.bin");
        layout.materialize(&digest, &linked).expect("link");
        let copied = root.join("b.bin");
        layout
            .materialize_with(&digest, &copied, true)
            .expect("copy");
        for p in [&linked, &copied] {
            assert!(
                std::fs::metadata(p).expect("stat").permissions().readonly(),
                "placed files must be read-only: {}",
                p.display()
            );
        }
        remove_temp(&root);
    }
}
