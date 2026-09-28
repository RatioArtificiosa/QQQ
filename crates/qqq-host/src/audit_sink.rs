// SPDX-License-Identifier: Apache-2.0

//! The file the capability audit stream survives a restart in — `OBS-002`, persistence.
//!
//! # Why this module exists
//!
//! `§O-293` found the audit stream had a writer and no reader. `§O-296` built the reader. Both were
//! in-memory, and `§O-297` named the consequence: **`GuestApp` holds the stream in memory and
//! `qqqai serve` ends by process exit**, so a CLI invocation is a different process and cannot see
//! the serving process's records. A report flag wired to the in-memory stream would report zero
//! records on every real deployment — the same failure in a new place.
//!
//! This is the missing piece: an append-only file, and a load path that **verifies before it
//! resumes**.
//!
//! # The format, and why it is JSON Lines
//!
//! One record per line, exactly [`AuditRecord::to_json`](crate::audit::AuditRecord::to_json). JSON
//! Lines rather than a single JSON array because the record is **append-only**: a line can be
//! appended with one `write` and no rewrite of what precedes it, whereas an array requires
//! rewriting the closing bracket on every record — which is a read-modify-write of the whole
//! evidence file, and a crash mid-rewrite loses all of it.
//!
//! # Why a partial final line is dropped rather than refused
//!
//! A process killed mid-write leaves a truncated last line. That line is **not** a record: it has
//! no closing brace, so it was never a completed append. The loader drops it and reports the drop,
//! because the alternative — refusing to start — would make an unclean shutdown unrecoverable, and
//! the alternative of *repairing* it would fabricate a record from a fragment.
//!
//! This is safe **only** because the truncation is at the end. A malformed line in the middle is
//! refused, since nothing can explain it: the file is append-only, so an interior line cannot have
//! been half-written by a crash.
//!
//! # What this file is not
//!
//! It is not encrypted and not access-controlled. It is the **host's** record of what a guest was
//! permitted to do, so it belongs wherever the operator's other host-level evidence goes; the
//! permissions are the filesystem's, and a deployment that needs more than that needs the Fabric
//! tier's retention controls (`OBS-015`), which do not exist yet.
//!
//! # Example
//!
//! Write a record, then read it back and continue the chain — which is what a restarted server
//! does:
//!
//! ```
//! use qqq_cap::capability::Capability;
//! use qqq_host::audit::Outcome;
//! use qqq_host::audit_sink::{resume_or_start, AuditFile};
//! use qqq_host::tenant::{ComponentDigest, GrantDigest};
//!
//! let dir = std::env::temp_dir().join(format!("qqq-sink-doc-{}", std::process::id()));
//! std::fs::create_dir_all(&dir).expect("scratch");
//! let path = dir.join("audit.jsonl");
//!
//! let component = ComponentDigest::new("0011223344556677").expect("digest");
//! let grants = GrantDigest::new("aabbccdd").expect("digest");
//!
//! // First run: append one record.
//! let (mut first, _) = resume_or_start(&path, 1024).expect("fresh start");
//! assert!(first.is_empty());
//! let _ = first.record(None, &component, &grants, Capability::FsRead, "handle_request", Outcome::Granted);
//! let mut file = AuditFile::open(&path, 0).expect("open");
//! file.append(&first.records()[0]).expect("append");
//! drop(file);
//!
//! // Second run: the history is read back and the chain continues from it.
//! let (second, loaded) = resume_or_start(&path, 1024).expect("resume");
//! assert_eq!(loaded.records.len(), 1);
//! assert_eq!(second.head(), first.head());
//! let _ = std::fs::remove_dir_all(&dir);
//! ```

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::audit::{AuditRecord, AuditStream};

/// Why the audit file could not be opened, read, or written.
///
/// # Example
///
/// Every variant is a refusal, and each names the file or the line involved — because a loader that
/// said only *"the audit file is invalid"* would leave an operator with no way to find the line:
///
/// ```
/// use qqq_host::audit_sink::{resume_or_start, SinkError};
///
/// let dir = std::env::temp_dir().join(format!("qqq-sinkerr-doc-{}", std::process::id()));
/// std::fs::create_dir_all(&dir).expect("scratch");
/// let path = dir.join("audit.jsonl");
/// // A malformed INTERIOR line is refused; a truncated FINAL line is dropped instead.
/// std::fs::write(&path, "not json\n{\"sequence\":1}\n").expect("write");
///
/// match resume_or_start(&path, 1024) {
///     Err(SinkError::Malformed { line, .. }) => assert_eq!(line, 1),
///     other => panic!("an interior malformed line must be refused, got {other:?}"),
/// }
/// let _ = std::fs::remove_dir_all(&dir);
/// ```
#[derive(Debug)]
pub enum SinkError {
    /// The file could not be opened or created.
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying reason.
        reason: String,
    },
    /// A line is not a valid record.
    Malformed {
        /// The 1-based line number.
        line: usize,
        /// Why it was refused.
        reason: String,
    },
    /// The records do not form a stream — a gap, or a broken chain.
    NotAStream {
        /// Why it was refused.
        reason: String,
    },
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, reason } => {
                write!(
                    f,
                    "the audit file {} could not be used: {reason}",
                    path.display()
                )
            }
            Self::Malformed { line, reason } => {
                write!(f, "audit file line {line} is not a record: {reason}")
            }
            Self::NotAStream { reason } => write!(f, "the audit file is not a stream: {reason}"),
        }
    }
}

impl std::error::Error for SinkError {}

/// What [`load`] found, including what it had to drop.
///
/// # Example
///
/// The two facts are separate on purpose: `records` is the history, and
/// `dropped_partial_line` is a statement about **how the previous process ended** that the records
/// themselves cannot carry.
///
/// ```
/// use qqq_host::audit_sink::resume_or_start;
///
/// let dir = std::env::temp_dir().join(format!("qqq-loaded-doc-{}", std::process::id()));
/// let path = dir.join("audit.jsonl");
///
/// let (_stream, loaded) = resume_or_start(&path, 1024).expect("a missing file is a first run");
/// assert!(loaded.records.is_empty());
/// assert!(!loaded.dropped_partial_line, "nothing was written, so nothing was truncated");
/// ```
#[derive(Debug)]
pub struct Loaded {
    /// The records that were read, in order, chain intact.
    pub records: Vec<AuditRecord>,
    /// How many trailing bytes were dropped as an incomplete final line.
    ///
    /// Reported rather than silently discarded: a non-zero value means the process that wrote this
    /// file **did not shut down cleanly**, which is itself a fact an operator wants and which the
    /// records alone cannot state.
    pub dropped_partial_line: bool,
    /// The byte offset just past the last **complete** line.
    ///
    /// What [`resume_or_start`] truncates to when it dropped a fragment. **Finding #24 of
    /// `CodeRabbit`'s review**: the fragment was removed from the *stream* and left in the *file*, the
    /// next `append` wrote onto it, and the resulting line was neither valid JSON nor last -- so the
    /// loader refused it as corruption. A crash, a restart and one request produced an evidence file
    /// that could never be read again.
    pub complete_bytes: u64,
}

/// Read and verify an audit file.
///
/// # Errors
///
/// [`SinkError::Io`] when the file exists and cannot be read, [`SinkError::Malformed`] for a line
/// that is not a record, and [`SinkError::NotAStream`] when the records do not form one.
///
/// A **missing** file is not an error: it is a first run, and the caller gets an empty set.
/// The bytes a line occupies on disk, terminator included.
///
/// Zero for a line that failed to read, which the loop returns on before the value is used.
fn line_bytes_of(line: &Result<String, std::io::Error>) -> u64 {
    line.as_ref().map_or(0, |l| l.len() as u64 + 1)
}

pub(crate) fn load(path: &Path) -> Result<Loaded, SinkError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Loaded {
                records: Vec::new(),
                dropped_partial_line: false,
                complete_bytes: 0,
            })
        }
        Err(e) => {
            return Err(SinkError::Io {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
        }
    };

    let mut records = Vec::new();
    let mut dropped_partial_line = false;
    // Tracked as the loop goes rather than derived afterwards, so the offset is exact.
    let mut complete_bytes: u64 = 0;
    let mut offset: u64 = 0;
    for (i, line) in BufReader::new(file).lines().enumerate() {
        // **Advance FIRST.** At the bottom, the blank-line `continue` below would skip it and the
        // truncation point would fall inside a record -- worse than not truncating at all.
        offset += line_bytes_of(&line);
        let line = line.map_err(|e| SinkError::Io {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        if line.trim().is_empty() {
            continue;
        }
        match AuditRecord::from_json(&line) {
            Ok(record) => {
                records.push(record);
                complete_bytes = offset;
            }
            Err(reason) => {
                // A truncated FINAL line is a crash, not corruption. It is dropped and reported;
                // anything else is refused, because an append-only file cannot explain it.
                let is_last = {
                    let mut probe =
                        BufReader::new(File::open(path).map_err(|e| SinkError::Io {
                            path: path.to_path_buf(),
                            reason: e.to_string(),
                        })?);
                    let mut buf = String::new();
                    let mut n = 0;
                    while probe.read_line(&mut buf).map_err(|e| SinkError::Io {
                        path: path.to_path_buf(),
                        reason: e.to_string(),
                    })? > 0
                    {
                        n += 1;
                        buf.clear();
                    }
                    i + 1 == n
                };
                if is_last && !line.trim_end().ends_with('}') {
                    dropped_partial_line = true;
                    break;
                }
                return Err(SinkError::Malformed {
                    line: i + 1,
                    reason,
                });
            }
        }
    }

    Ok(Loaded {
        records,
        dropped_partial_line,
        complete_bytes,
    })
}

/// An open, append-only audit file.
///
/// # Example
///
/// ```
/// use qqq_cap::capability::Capability;
/// use qqq_host::audit::{AuditStream, Outcome};
/// use qqq_host::audit_sink::AuditFile;
/// use qqq_host::tenant::{ComponentDigest, GrantDigest};
///
/// let mut stream = AuditStream::with_default_capacity();
/// let component = ComponentDigest::new("0011223344556677").expect("digest");
/// let grants = GrantDigest::new("aabbccdd").expect("digest");
/// let _ = stream.record(None, &component, &grants, Capability::FsRead, "handle_request", Outcome::Granted);
///
/// let dir = std::env::temp_dir().join(format!("qqq-doc-{}", std::process::id()));
/// std::fs::create_dir_all(&dir).expect("scratch");
/// let path = dir.join("audit.jsonl");
///
/// let mut file = AuditFile::open(&path, 0).expect("open");
/// file.append(&stream.records()[0]).expect("append");
/// drop(file);
///
/// assert!(std::fs::read_to_string(&path).expect("read").starts_with("{\"sequence\":1"));
/// let _ = std::fs::remove_dir_all(&dir);
/// ```
#[derive(Debug)]
pub struct AuditFile {
    path: PathBuf,
    file: File,
    /// How many records the file already holds.
    ///
    /// # Why the opener is TOLD this rather than counting it
    ///
    /// Because counting means reading the file, and this is opened for **append**. The loader has
    /// already parsed every line, so it knows; asking it to say so is one source of truth instead of
    /// two. It is what lets a caller append *"everything after what the file has"* without a second
    /// counter that could drift from the file it describes.
    records: usize,
}

impl AuditFile {
    /// Open `path` for appending, creating it if absent.
    ///
    /// # Errors
    ///
    /// [`SinkError::Io`] when the file cannot be opened or created.
    ///
    /// # Example
    ///
    /// The parent directory is created when it is missing, so an operator can point `--audit-log`
    /// at a path that does not exist yet:
    ///
    /// ```
    /// use qqq_host::audit_sink::AuditFile;
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-open-doc-{}", std::process::id()));
    /// let path = dir.join("nested").join("audit.jsonl");
    /// let file = AuditFile::open(&path, 0).expect("the directory is created");
    /// assert!(path.exists());
    /// assert_eq!(file.records(), 0, "a fresh file holds nothing");
    /// drop(file);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    ///
    /// `already` is how many records the file holds, which the **loader** measured; see the field.
    pub fn open(path: &Path, already: usize) -> Result<Self, SinkError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| SinkError::Io {
                    path: path.to_path_buf(),
                    reason: format!("its directory could not be created: {e}"),
                })?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| SinkError::Io {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            records: already,
        })
    }

    /// Append one record and flush it.
    ///
    /// # Why it flushes every record
    ///
    /// Because the record's value is that it exists after a crash, and a buffered record does not.
    /// The cost is one `write` syscall per served request, which is the price of the guarantee; an
    /// operator who does not want to pay it should not enable the file rather than get a record
    /// that is present only when the process happens to exit cleanly.
    ///
    /// # Errors
    ///
    /// [`SinkError::Io`] when the write or the flush fails. **The caller must not swallow this.**
    /// An append that failed silently is the "control that reports healthy while measuring
    /// nothing" this module's siblings keep recording.
    ///
    /// # Example
    ///
    /// Each call appends exactly one line, and the file is flushed, so a record exists after a
    /// crash rather than only after a clean exit:
    ///
    /// ```
    /// use qqq_cap::capability::Capability;
    /// use qqq_host::audit::{AuditStream, Outcome};
    /// use qqq_host::audit_sink::AuditFile;
    /// use qqq_host::tenant::{ComponentDigest, GrantDigest};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-append-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let path = dir.join("audit.jsonl");
    ///
    /// let component = ComponentDigest::new("0011223344556677").expect("digest");
    /// let grants = GrantDigest::new("aabbccdd").expect("digest");
    /// let mut stream = AuditStream::with_default_capacity();
    /// let _ = stream.record(None, &component, &grants, Capability::FsRead, "handle_request", Outcome::Granted);
    ///
    /// let mut file = AuditFile::open(&path, 0).expect("open");
    /// file.append(&stream.records()[0]).expect("append");
    /// drop(file);
    ///
    /// assert_eq!(std::fs::read_to_string(&path).expect("read").lines().count(), 1);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    pub fn append(&mut self, record: &AuditRecord) -> Result<(), SinkError> {
        writeln!(self.file, "{}", record.to_json()).map_err(|e| SinkError::Io {
            path: self.path.clone(),
            reason: e.to_string(),
        })?;
        self.file.flush().map_err(|e| SinkError::Io {
            path: self.path.clone(),
            reason: e.to_string(),
        })?;
        // Only a SUCCESSFUL write advances the count. A failed one leaves the position where it was,
        // so the next attempt retries that record rather than skipping it -- an evidence file that
        // silently skips a row is worse than one that stops.
        self.records += 1;
        Ok(())
    }

    /// How many records this file holds.
    ///
    /// A caller appends `records().iter().skip(file.records())` -- everything the file does not have.
    ///
    /// # Example
    ///
    /// The count is what makes that skip correct, and it advances only on a write that succeeded:
    ///
    /// ```
    /// use qqq_host::audit::{AuditStream, Outcome};
    /// use qqq_host::audit_sink::AuditFile;
    /// use qqq_host::tenant::{ComponentDigest, GrantDigest};
    /// use qqq_cap::capability::Capability;
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-records-doc-{}", std::process::id()));
    /// let path = dir.join("audit.jsonl");
    /// let mut file = AuditFile::open(&path, 0).expect("open");
    /// assert_eq!(file.records(), 0);
    ///
    /// let mut stream = AuditStream::with_default_capacity();
    /// let component = ComponentDigest::new("0011223344556677").expect("digest");
    /// let grants = GrantDigest::new("aabbccdd").expect("digest");
    /// let _ = stream.record(None, &component, &grants, Capability::HttpServer, "f", Outcome::Granted);
    ///
    /// for record in stream.records().iter().skip(file.records()) {
    ///     file.append(record).expect("append");
    /// }
    /// assert_eq!(file.records(), 1, "one write, one record");
    ///
    /// // And a second pass appends nothing, because the count is the file's own.
    /// for record in stream.records().iter().skip(file.records()) {
    ///     file.append(record).expect("append");
    /// }
    /// assert_eq!(file.records(), 1);
    /// drop(file);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    #[must_use]
    pub fn records(&self) -> usize {
        self.records
    }

    /// The path this sink writes to.
    ///
    /// `pub(crate)`: no caller needs it — the sink was constructed with the path the caller
    /// already holds — and a public getter nobody calls is a public declaration that owes an
    /// example (`§O-298`).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// Load a file and resume the stream it holds, or start a fresh one.
///
/// # Errors
///
/// Any [`SinkError`] from [`load`], plus [`SinkError::NotAStream`] when the records are intact
/// individually but do not form a stream.
///
/// # Why this is the function a server calls
///
/// Because the two steps must not be separated by a caller who forgets the second: a server that
/// loaded the records and started a *new* stream would restart the sequence at 1 and chain from
/// genesis, producing a file whose second run does not join its first — a record that looks
/// continuous and is not.
///
/// # Example
///
/// A missing file is a first run, and an existing one is resumed with its chain intact:
///
/// ```
/// use qqq_host::audit::{genesis_digest, Outcome};
/// use qqq_host::audit_sink::{resume_or_start, AuditFile};
/// use qqq_cap::capability::Capability;
/// use qqq_host::tenant::{ComponentDigest, GrantDigest};
///
/// let dir = std::env::temp_dir().join(format!("qqq-resume-doc-{}", std::process::id()));
/// std::fs::create_dir_all(&dir).expect("scratch");
/// let path = dir.join("audit.jsonl");
///
/// let (mut first, _) = resume_or_start(&path, 1024).expect("first run");
/// assert_eq!(first.head(), genesis_digest(), "a fresh stream chains from genesis");
/// let component = ComponentDigest::new("0011223344556677").expect("digest");
/// let grants = GrantDigest::new("aabbccdd").expect("digest");
/// let _ = first.record(None, &component, &grants, Capability::FsRead, "handle_request", Outcome::Granted);
/// let mut file = AuditFile::open(&path, 0).expect("open");
/// file.append(&first.records()[0]).expect("append");
/// drop(file);
///
/// let (second, _) = resume_or_start(&path, 1024).expect("second run");
/// assert_eq!(second.len(), 1, "the history was read back");
/// assert_eq!(second.head(), first.head(), "and the chain continues from it");
/// let _ = std::fs::remove_dir_all(&dir);
/// ```
pub fn resume_or_start(path: &Path, capacity: usize) -> Result<(AuditStream, Loaded), SinkError> {
    let loaded = load(path)?;

    // **A fragment is removed from the FILE, not only from the stream** -- finding #24. Resuming means
    // *"continue the chain this file holds"*, and a file whose last line is half a record cannot be
    // continued: `AuditFile` opens `append`, so the next record would be written onto the fragment, and
    // the combined line would be neither valid JSON nor last -- which makes the loader refuse the whole
    // file as corruption. **An append-only log that refuses to be re-read after a crash has failed at
    // its one job.**
    if loaded.dropped_partial_line {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| SinkError::Io {
                path: path.to_path_buf(),
                reason: format!("the half-written final record could not be removed: {e}"),
            })?;
        file.set_len(loaded.complete_bytes)
            .map_err(|e| SinkError::Io {
                path: path.to_path_buf(),
                reason: format!("the half-written final record could not be removed: {e}"),
            })?;
    }

    let stream = AuditStream::resume(loaded.records.clone(), capacity)
        .map_err(|reason| SinkError::NotAStream { reason })?;
    Ok((stream, loaded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{genesis_digest, Outcome};
    use crate::tenant::{ComponentDigest, GrantDigest};
    use qqq_cap::capability::Capability;

    /// A scratch directory removed on drop, so a failing test leaves nothing behind.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "qqq-audit-sink-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("scratch");
            Self(p)
        }
        fn file(&self) -> PathBuf {
            self.0.join("audit.jsonl")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn append(stream: &mut AuditStream, outcome: Outcome) {
        let component = ComponentDigest::new("0011223344556677").expect("digest");
        let grants = GrantDigest::new("aabbccdd").expect("digest");
        let _ = stream.record(
            None,
            &component,
            &grants,
            Capability::FsRead,
            "handle_request",
            outcome,
        );
    }

    /// **A record written to the file reads back byte-identical.**
    ///
    /// The writer and the reader are both hand-written, so this is the test that keeps them
    /// inverses. A round trip is the only assertion that can catch a writer/reader pair that
    /// agrees on every field *except* one.
    #[test]
    fn a_record_round_trips_through_the_file() {
        let scratch = Scratch::new("roundtrip");
        let path = scratch.file();

        let mut stream = AuditStream::with_default_capacity();
        append(&mut stream, Outcome::Granted);
        append(&mut stream, Outcome::Denied);

        let mut sink = AuditFile::open(&path, 0).expect("open");
        for record in stream.records() {
            sink.append(record).expect("append");
        }
        drop(sink);

        let loaded = load(&path).expect("load");
        assert_eq!(loaded.records.len(), 2);
        assert!(!loaded.dropped_partial_line, "nothing was truncated");
        assert_eq!(
            loaded.records,
            *stream.records(),
            "every field must survive the round trip"
        );
    }

    /// **A restarted process continues the chain rather than starting a new one — `OBS-002`.**
    ///
    /// This is the property the whole module exists for. Before it, the stream lived in
    /// `GuestApp`'s memory and died with the process, so a record could not outlive the server it
    /// was evidence about.
    #[test]
    fn a_restart_continues_the_chain() {
        let scratch = Scratch::new("restart");
        let path = scratch.file();

        // --- the first process -------------------------------------------------
        let (mut first, _) = resume_or_start(&path, 1024).expect("first start");
        assert!(first.is_empty(), "a fresh file is an empty stream");
        append(&mut first, Outcome::Granted);
        append(&mut first, Outcome::Granted);
        let head_before = first.head().to_owned();
        {
            let mut sink = AuditFile::open(&path, 0).expect("open");
            for record in first.records() {
                sink.append(record).expect("append");
            }
        }
        assert_ne!(
            head_before,
            genesis_digest(),
            "two records moved the head off genesis"
        );

        // --- the second process ------------------------------------------------
        let (mut second, loaded) = resume_or_start(&path, 1024).expect("second start");
        assert_eq!(loaded.records.len(), 2, "the history was read back");
        assert_eq!(
            second.head(),
            head_before,
            "the resumed stream's head must be the last record's chain -- otherwise the next \
             append chains from the wrong place and the file stops being one chain"
        );

        append(&mut second, Outcome::Denied);
        let records = second.records();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records[2].previous, records[1].chain,
            "the third record must chain from the second, across the restart"
        );
        assert_eq!(
            records[2].sequence, 3,
            "sequence numbers continue, they do not restart"
        );
        assert!(
            second.verify_chain().is_ok(),
            "the whole history, written by two processes, must verify as one chain"
        );
    }

    /// **A truncated final line is dropped and reported, not repaired.**
    ///
    /// A process killed mid-write leaves a fragment. Repairing it would fabricate a record from
    /// bytes that were never a complete append, and refusing to start would make an unclean
    /// shutdown unrecoverable.
    /// **A dropped fragment must not poison the next append** -- `CodeRabbit` finding #24.
    ///
    /// # Why the existing truncation test could not have caught it
    ///
    /// `a_truncated_final_line_is_dropped_and_reported` checks that the fragment is dropped from the
    /// **stream**. It never appends afterwards, so it cannot see what the fragment does to the
    /// **file**. The two are different claims, and only the second is about the file's future.
    ///
    /// # What the failure looked like
    ///
    /// The appended record landed on the fragment's line; the combined line was not valid JSON and was
    /// no longer the last line, so the loader refused it as **corruption** rather than a crash. A
    /// crash, a restart and one request produced an evidence file that could never be read again.
    #[test]
    fn a_dropped_fragment_does_not_poison_the_next_append() {
        use std::io::Write as _;

        let scratch = Scratch::new("drop-then-append");
        let path = scratch.file();

        // A first run writes one record to the FILE, then the process dies mid-record.
        //
        // The record goes through `AuditFile`, not only into the in-memory stream: the file must
        // EXIST before the fragment can be appended to it, and a test that forgot that would fail on
        // its first `open` rather than on the claim it is about. (It did, the first time.)
        let (mut stream, _) = resume_or_start(&path, 1024).expect("first run");
        append(&mut stream, Outcome::Granted);
        {
            let mut file = AuditFile::open(&path, 0).expect("open");
            let record = stream.records().last().expect("a record").clone();
            file.append(&record).expect("write the first record");
        }
        {
            let mut raw = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("append raw");
            raw.write_all(b"{\"sequence\":2,\"comp")
                .expect("the crash fragment");
            raw.flush().expect("flush");
        }

        // A restart drops the fragment, and says so.
        let (mut stream, loaded) = resume_or_start(&path, 1024).expect("resume");
        assert!(loaded.dropped_partial_line, "the fragment must be reported");
        assert_eq!(
            loaded.records.len(),
            1,
            "and only the complete record is read"
        );

        // The resume above is what removes the fragment. Then a record is appended -- onto a file that
        // now ends at a line boundary.
        // The chain CONTINUES -- a fresh record, not a copy of the last one. Copying it was the
        // first version of this test, and the chain checker refused the file for it
        // (`record 2 is missing ... carries sequence 1`). That refusal is the loader doing its
        // job, and it is worth having written a test that met it.
        append(&mut stream, Outcome::Denied);
        let mut file = AuditFile::open(&path, loaded.records.len()).expect("open for append");
        let record = stream.records().last().expect("a record").clone();
        file.append(&record).expect("append");
        drop(file);

        // And the file must still be loadable. Before the fix it was not.
        let (_again, loaded_again) = resume_or_start(&path, 1024)
            .expect("a crash, a resume and an append must leave a file that can be read again");
        assert_eq!(
            loaded_again.records.len(),
            2,
            "the surviving record and the appended one"
        );
        assert!(
            !loaded_again.dropped_partial_line,
            "and the second load has nothing to drop"
        );
    }

    #[test]
    fn a_truncated_final_line_is_dropped_and_reported() {
        let scratch = Scratch::new("truncated");
        let path = scratch.file();

        let mut stream = AuditStream::with_default_capacity();
        append(&mut stream, Outcome::Granted);
        let mut sink = AuditFile::open(&path, 0).expect("open");
        sink.append(&stream.records()[0]).expect("append");
        drop(sink);

        // Simulate a kill mid-write: a partial line with no closing brace.
        let mut f = OpenOptions::new().append(true).open(&path).expect("reopen");
        f.write_all(b"{\"sequence\":2,\"tenant\":null,\"component\":\"0011")
            .expect("partial");
        drop(f);

        let loaded = load(&path).expect("a partial tail must not stop the load");
        assert_eq!(loaded.records.len(), 1, "the complete record survives");
        assert!(
            loaded.dropped_partial_line,
            "the drop must be REPORTED -- a non-zero value is how an operator learns the process \
             did not shut down cleanly"
        );
    }

    /// **A malformed line in the MIDDLE is refused.**
    ///
    /// The file is append-only, so an interior line cannot have been half-written by a crash.
    /// Nothing explains it, so nothing may absorb it.
    #[test]
    fn a_malformed_interior_line_is_refused() {
        let scratch = Scratch::new("interior");
        let path = scratch.file();

        let mut stream = AuditStream::with_default_capacity();
        append(&mut stream, Outcome::Granted);
        append(&mut stream, Outcome::Granted);
        std::fs::write(
            &path,
            format!(
                "{}\n{{ not json at all }}\n{}\n",
                stream.records()[0].to_json(),
                stream.records()[1].to_json()
            ),
        )
        .expect("write");

        match load(&path) {
            Err(SinkError::Malformed { line, .. }) => {
                assert_eq!(line, 2, "the refusal must name the line");
            }
            other => panic!("an interior malformed line must be refused, got {other:?}"),
        }
    }

    /// **A tampered chain is refused at load.**
    ///
    /// The point of persisting a hash chain is that a modified file is *detectable*. A loader that
    /// resumed a broken chain would append to it, and every later record would commit to a
    /// predecessor that was already wrong — extending the corruption instead of reporting it.
    #[test]
    fn a_tampered_file_is_refused_at_load() {
        let scratch = Scratch::new("tampered");
        let path = scratch.file();

        let mut stream = AuditStream::with_default_capacity();
        append(&mut stream, Outcome::Granted);
        append(&mut stream, Outcome::Denied);

        // Rewrite the second record's chain digest, leaving everything else valid.
        let mut second = stream.records()[1].to_json();
        let good = stream.records()[1].chain.clone();
        let bad = "0".repeat(good.len());
        second = second.replace(&good, &bad);
        std::fs::write(
            &path,
            format!("{}\n{second}\n", stream.records()[0].to_json()),
        )
        .expect("write");

        // The record parses -- it is well-formed JSON with a syntactically valid digest.
        let loaded = load(&path).expect("each line is a valid record");
        assert_eq!(loaded.records.len(), 2);

        // And the STREAM refuses it, because the chain no longer links.
        match resume_or_start(&path, 1024) {
            Err(SinkError::NotAStream { reason }) => assert!(
                reason.contains("broken chain"),
                "the refusal must say the chain is broken, got: {reason}"
            ),
            other => panic!("a tampered chain must be refused, got {other:?}"),
        }
    }

    /// **A missing file is a first run, not an error.**
    #[test]
    fn a_missing_file_starts_an_empty_stream() {
        let scratch = Scratch::new("missing");
        let (stream, loaded) = resume_or_start(&scratch.file(), 1024).expect("first run");
        assert!(stream.is_empty());
        assert_eq!(stream.head(), genesis_digest());
        assert!(!loaded.dropped_partial_line);
    }

    /// **A history that outgrew its capacity is refused, not silently truncated.**
    #[test]
    fn a_history_past_the_capacity_is_refused() {
        let scratch = Scratch::new("capacity");
        let path = scratch.file();
        let mut stream = AuditStream::with_default_capacity();
        append(&mut stream, Outcome::Granted);
        append(&mut stream, Outcome::Granted);
        let mut sink = AuditFile::open(&path, 0).expect("open");
        for record in stream.records() {
            sink.append(record).expect("append");
        }
        drop(sink);

        match resume_or_start(&path, 1) {
            Err(SinkError::NotAStream { reason }) => {
                assert!(reason.contains("capacity is 1"), "got: {reason}");
            }
            other => panic!("a capacity below the history must be refused, got {other:?}"),
        }
    }
}
