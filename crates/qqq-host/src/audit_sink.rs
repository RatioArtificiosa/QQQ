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
use std::io::{BufRead, BufReader, BufWriter, Write};
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

/// How the bytes reach the OS: directly, or through a userspace buffer.
///
/// The variant is the difference between the durability modes that flush
/// counts alone cannot show. A plain [`File`] hands every `write` to the OS
/// immediately, so `flush` is a passthrough and "buffered" without a buffer
/// would promise less while doing the same work. [`Durability::Buffered`]
/// therefore writes through this buffer and flushes it only when full or at
/// shutdown; the other modes write direct.
#[derive(Debug)]
enum FileWriter {
    /// Every write reaches the OS at once; `flush` is a passthrough.
    Direct(File),
    /// Bytes accumulate in userspace until the buffer fills or flushes.
    Buffered(BufWriter<File>),
}

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Direct(file) => file.write(buf),
            Self::Buffered(buffered) => buffered.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Direct(file) => file.flush(),
            Self::Buffered(buffered) => buffered.flush(),
        }
    }
}

impl FileWriter {
    /// Push userspace bytes to the OS without syncing the disk.
    fn flush_out(&mut self) -> std::io::Result<()> {
        match self {
            Self::Direct(file) => file.flush(),
            Self::Buffered(buffered) => buffered.flush(),
        }
    }

    /// Push bytes to the OS and wait until the disk holds them.
    fn sync_out(&mut self) -> std::io::Result<()> {
        match self {
            Self::Direct(file) => file.sync_all(),
            Self::Buffered(buffered) => {
                buffered.flush()?;
                buffered.get_mut().sync_all()
            }
        }
    }
}

/// Userspace bytes held back in [`Durability::Buffered`] mode.
///
/// Large enough to batch hundreds of records into one syscall, small enough
/// to bound what a process crash can take with it — and the bound is stated
/// here rather than discovered, because an unbounded buffer would convert the
/// mode from "fewer syscalls" into "unbounded loss window".
///
/// ```
/// use qqq_host::audit_sink::BUFFERED_CAPACITY;
///
/// assert_eq!(BUFFERED_CAPACITY, 64 * 1024);
/// ```
pub const BUFFERED_CAPACITY: usize = 64 * 1024;

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
    writer: FileWriter,
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
            writer: FileWriter::Direct(file),
            records: already,
        })
    }

    /// Reopen this handle with userspace buffering for [`Durability::Buffered`].
    ///
    /// Consuming rather than toggling, because a file that changed buffering
    /// mid-run would make the flush counters lie about which bytes took which
    /// path. The record count carries over untouched.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AuditFile, BUFFERED_CAPACITY};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-buffered-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let file = AuditFile::open(&dir.join("audit.jsonl"), 0).expect("open");
    /// let buffered = file.into_buffered(BUFFERED_CAPACITY);
    /// assert_eq!(buffered.records(), 0);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    #[must_use]
    pub fn into_buffered(self, capacity: usize) -> Self {
        let Self {
            path,
            writer,
            records,
        } = self;
        match writer {
            FileWriter::Direct(file) => Self {
                path,
                writer: FileWriter::Buffered(BufWriter::with_capacity(capacity, file)),
                records,
            },
            buffered @ FileWriter::Buffered(_) => Self {
                path,
                writer: buffered,
                records,
            },
        }
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
        writeln!(self.writer, "{}", record.to_json()).map_err(|e| SinkError::Io {
            path: self.path.clone(),
            reason: e.to_string(),
        })?;
        self.writer.flush().map_err(|e| SinkError::Io {
            path: self.path.clone(),
            reason: e.to_string(),
        })?;
        // Only a SUCCESSFUL write advances the count. A failed one leaves the position where it was,
        // so the next attempt retries that record rather than skipping it -- an evidence file that
        // silently skips a row is worse than one that stops.
        self.records += 1;
        Ok(())
    }
}

/// What one [`AuditFile::append_batch`] pass did to the disk.
///
/// Returned so the worker's counters can distinguish "three records, one
/// flush" from "three records, three flushes" — which is the entire
/// observable difference between the durability modes.
///
/// ```
/// use qqq_host::audit_sink::BatchReport;
///
/// let report = BatchReport { records: 3, flushes: 1, fsyncs: 0 };
/// assert_eq!((report.records, report.flushes, report.fsyncs), (3, 1, 0));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchReport {
    /// Records fully written.
    pub records: usize,
    /// `flush` calls issued.
    pub flushes: u64,
    /// `sync_all` calls issued.
    pub fsyncs: u64,
}

/// A batch that stopped at `completed` records with this I/O error.
///
/// The file's own count already covers the completed prefix, so the caller
/// knows exactly which suffix never reached the disk: no record is counted
/// as persisted unless its line is complete.
///
/// ```
/// use qqq_host::audit_sink::{BatchFailure, SinkError};
/// use std::path::PathBuf;
///
/// let failure = BatchFailure {
///     error: SinkError::Io {
///         path: PathBuf::from("audit.jsonl"),
///         reason: "disk full".to_owned(),
///     },
///     completed: 2,
/// };
/// assert_eq!(failure.completed, 2);
/// assert!(failure.error.to_string().contains("disk full"));
/// ```
#[derive(Debug)]
pub struct BatchFailure {
    /// What the failed write reported.
    pub error: SinkError,
    /// Records fully written before the failure.
    pub completed: usize,
}

impl AuditFile {
    /// Append a batch of records in one disk pass, under a durability contract.
    ///
    /// The batch must arrive in sequence order — the worker guarantees it — so
    /// the file keeps chain-linking and [`resume_or_start`] keeps verifying. The
    /// count advances per completed line: a batch that fails midway reports how
    /// far it got, and the unwritten tail belongs to the caller's failure
    /// policy rather than to a retry that would re-write the completed prefix.
    ///
    /// # Errors
    ///
    /// [`BatchFailure`] carrying the [`SinkError::Io`] and the completed count.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AuditFile, Durability};
    /// use qqq_cap::capability::Capability;
    /// use qqq_host::audit::{AuditStream, Outcome};
    /// use qqq_host::tenant::{ComponentDigest, GrantDigest};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-batch-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let mut file = AuditFile::open(&dir.join("audit.jsonl"), 0).expect("open");
    /// let mut stream = AuditStream::with_default_capacity();
    /// let component = ComponentDigest::new("0011223344556677").expect("digest");
    /// let grants = GrantDigest::new("aabbccdd").expect("digest");
    /// let _ = stream.record(None, &component, &grants, Capability::FsRead, "f", Outcome::Granted);
    /// let report = file.append_batch(stream.records(), Durability::FlushPerRecord).expect("batch");
    /// assert_eq!((report.records, report.flushes), (1, 1));
    /// assert_eq!(file.records(), 1);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    pub fn append_batch(
        &mut self,
        batch: &[AuditRecord],
        durability: Durability,
    ) -> Result<BatchReport, BatchFailure> {
        let io_error = |reason: String| SinkError::Io {
            path: self.path.clone(),
            reason,
        };
        let mut report = BatchReport {
            records: 0,
            flushes: 0,
            fsyncs: 0,
        };
        for record in batch {
            if let Err(error) = write_record_line(&mut self.writer, record) {
                return Err(BatchFailure {
                    error: io_error(error.to_string()),
                    completed: report.records,
                });
            }
            self.records += 1;
            report.records += 1;
            if durability == Durability::FlushPerRecord {
                if let Err(error) = self.writer.flush_out() {
                    return Err(BatchFailure {
                        error: io_error(error.to_string()),
                        completed: report.records,
                    });
                }
                report.flushes += 1;
            }
        }
        if durability != Durability::Buffered && durability != Durability::FlushPerRecord {
            // Buffered mode never flushes mid-run; FlushPerRecord flushed
            // every line above, so a trailing flush there would be a syscall
            // that changes nothing. Only the batch modes flush here.
            if let Err(error) = self.writer.flush_out() {
                return Err(BatchFailure {
                    error: io_error(error.to_string()),
                    completed: report.records,
                });
            }
            report.flushes += 1;
        }
        if durability == Durability::FsyncPerBatch {
            if let Err(error) = self.writer.sync_out() {
                return Err(BatchFailure {
                    error: io_error(error.to_string()),
                    completed: report.records,
                });
            }
            report.fsyncs += 1;
        }
        Ok(report)
    }

    /// Bring the file to rest at shutdown: flush always, fsync per contract.
    ///
    /// Buffered mode waives crash-safety during the run, not at a clean exit —
    /// a clean shutdown that left bytes in userspace would be a loss nobody
    /// agreed to. `sync_all` stays exclusive to [`Durability::FsyncPerBatch`],
    /// which is what that mode promises on every batch including the last.
    ///
    /// # Errors
    ///
    /// [`SinkError::Io`] when the final flush or sync fails.
    ///
    /// Buffered content reaches the disk here, not before: the batch goes in
    /// through the buffer, the file reads back empty, and only this call
    /// delivers the rows — read before the writer drops, so no destructor
    /// flush can hide a missing shutdown flush.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AuditFile, BUFFERED_CAPACITY, Durability};
    /// use qqq_cap::capability::Capability;
    /// use qqq_host::audit::{AuditStream, Outcome};
    /// use qqq_host::tenant::{ComponentDigest, GrantDigest};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-shutdown-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let path = dir.join("audit.jsonl");
    /// let mut file = AuditFile::open(&path, 0).expect("open").into_buffered(BUFFERED_CAPACITY);
    /// let mut stream = AuditStream::with_default_capacity();
    /// let component = ComponentDigest::new("0011223344556677").expect("digest");
    /// let grants = GrantDigest::new("aabbccdd").expect("digest");
    /// let _ = stream.record(None, &component, &grants, Capability::FsRead, "f", Outcome::Granted);
    /// let report = file.append_batch(stream.records(), Durability::Buffered).expect("batch");
    /// assert_eq!(report.records, 1);
    /// assert!(std::fs::read_to_string(&path).expect("read").is_empty());
    /// file.flush_for_shutdown(Durability::Buffered).expect("flush");
    /// assert_eq!(std::fs::read_to_string(&path).expect("read").lines().count(), 1);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    pub fn flush_for_shutdown(&mut self, durability: Durability) -> Result<(), SinkError> {
        let io_error = |reason: String| SinkError::Io {
            path: self.path.clone(),
            reason,
        };
        self.writer
            .flush_out()
            .map_err(|error| io_error(error.to_string()))?;
        if durability == Durability::FsyncPerBatch {
            self.writer
                .sync_out()
                .map_err(|error| io_error(error.to_string()))?;
        }
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

/// How durably one batch reaches the file before the worker takes more.
///
/// Stated as what survives what, because the previous wording promised
/// distinctions a raw [`File`] cannot keep: every `write` already reaches the
/// OS, so `flush` is a passthrough and only [`File::sync_all`] — or a real
/// userspace buffer — changes the guarantee. Crash evidence is only evidence
/// if it survives the crash, so the default is [`Durability::FlushPerRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Durability {
    /// Rows accumulate in a [`BUFFERED_CAPACITY`] userspace buffer; a process
    /// crash loses the tail, a clean shutdown loses nothing. Highest
    /// throughput, weakest promise — for deployments that keep the stream as
    /// the record and the file as a convenience copy.
    ///
    /// ```
    /// use qqq_host::audit_sink::Durability;
    ///
    /// assert_ne!(Durability::Buffered, Durability::FlushPerRecord);
    /// ```
    Buffered,
    /// Every record reaches the OS before the call returns: a process crash
    /// loses nothing. An OS or power loss can still take the OS-buffered tail
    /// — only `sync_all` bounds that, which is what the next mode buys.
    ///
    /// ```
    /// use qqq_host::audit_sink::Durability;
    ///
    /// assert_eq!(Durability::default(), Durability::FlushPerRecord);
    /// assert_ne!(Durability::FsyncPerBatch, Durability::Buffered);
    /// ```
    #[default]
    FlushPerRecord,
    /// Write each batch, then flush and `sync_all` once per batch. Bounds OS
    /// and power loss to the current batch, at one sync per batch.
    FsyncPerBatch,
}

/// How many records may wait for the worker.
///
/// Large enough to absorb a burst of concurrent requests without stalling any
/// of them — at a few hundred bytes per JSON line this bounds queued memory
/// near 200 KiB — small enough that a wedged worker converts to visible
/// backpressure quickly rather than after gigabytes of silent queue.
///
/// ```
/// use qqq_host::audit_sink::DEFAULT_APPEND_QUEUE_BOUND;
///
/// assert_eq!(DEFAULT_APPEND_QUEUE_BOUND, 1024);
/// ```
pub const DEFAULT_APPEND_QUEUE_BOUND: usize = 1024;

/// How many records one disk pass writes.
///
/// Batching amortizes the flush/fsync syscall, which is the whole point of the
/// worker. Opportunistic, not timed: the worker writes whatever arrived, so a
/// quiet server pays one pass per record exactly like the synchronous path did,
/// and a busy one pays one pass per batch.
///
/// ```
/// use qqq_host::audit_sink::DEFAULT_APPEND_BATCH;
///
/// assert_eq!(DEFAULT_APPEND_BATCH, 64);
/// ```
pub const DEFAULT_APPEND_BATCH: usize = 64;

/// Wiring for [`AuditAppender::spawn`].
///
/// ```
/// use qqq_host::audit_sink::{AppenderConfig, Durability};
/// use std::time::Duration;
///
/// let config = AppenderConfig::default();
/// assert_eq!(config.queue_bound, 1024);
/// assert_eq!(config.batch_size, 64);
/// assert_eq!(config.durability, Durability::FlushPerRecord);
/// assert_eq!(config.persist_timeout, Duration::from_secs(30));
/// assert_eq!(config.stall_timeout, Duration::from_secs(5));
/// ```
///
/// A custom wiring keeps the defaults it does not name:
///
/// ```
/// use qqq_host::audit_sink::AppenderConfig;
/// use std::time::Duration;
///
/// let config = AppenderConfig {
///     queue_bound: 16,
///     stall_timeout: Duration::from_millis(50),
///     ..AppenderConfig::default()
/// };
/// assert_eq!(config.queue_bound, 16);
/// assert_eq!(config.stall_timeout, Duration::from_millis(50));
/// assert_eq!(config.batch_size, AppenderConfig::default().batch_size);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct AppenderConfig {
    /// Records that may wait for the worker; producers block past this.
    pub queue_bound: usize,
    /// Records per disk pass.
    pub batch_size: usize,
    /// The crash promise each batch keeps.
    pub durability: Durability,
    /// How long one request waits for its own rows to persist before
    /// reporting the persist as failed. A tripwire, not a deadline: the
    /// worker drains a bounded queue, so tens of seconds without progress
    /// means it is dead, not slow.
    pub persist_timeout: std::time::Duration,
    /// Stall-skip tripwire documented on the worker; see [`append_loop`].
    pub stall_timeout: std::time::Duration,
}

impl Default for AppenderConfig {
    fn default() -> Self {
        Self {
            queue_bound: DEFAULT_APPEND_QUEUE_BOUND,
            batch_size: DEFAULT_APPEND_BATCH,
            durability: Durability::default(),
            persist_timeout: std::time::Duration::from_secs(30),
            stall_timeout: std::time::Duration::from_secs(5),
        }
    }
}

/// One item on the worker's queue.
enum Work {
    /// A row to persist, in the producer's sequence order.
    Record(AuditRecord),
    /// "Tell me when everything through this sequence is durable." The ack
    /// carries the worker's persisted count after the barrier's batch, so the
    /// request path keeps the synchronous path's promise — a returned request
    /// has its evidence on disk — while sharing batches with concurrent
    /// requests instead of flushing alone.
    Barrier {
        /// The highest sequence this barrier covers.
        through: u64,
        /// Where the worker reports.
        ack: std::sync::mpsc::Sender<BarrierAck>,
    },
}

/// What the worker reports across a barrier.
///
/// ```
/// use qqq_host::audit_sink::BarrierAck;
///
/// let ack = BarrierAck { persisted: 7 };
/// assert_eq!(ack.persisted, 7);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarrierAck {
    /// Records persisted when the barrier cleared.
    pub persisted: u64,
}

/// Counters for one appender, readable while it runs.
///
/// Atomics, because producers read them without holding the worker's locks —
/// and because a metric that needed the lock it measures would serialize the
/// path it observes.
///
/// ```
/// use qqq_host::audit_sink::AppenderStats;
///
/// let stats = AppenderStats::default();
/// let snapshot = stats.snapshot();
/// assert_eq!(snapshot.submitted, 0);
/// assert_eq!(snapshot.persisted, 0);
/// assert_eq!(snapshot.batches, 0);
/// assert_eq!(snapshot.late_after_skip, 0);
/// ```
#[derive(Debug, Default)]
pub struct AppenderStats {
    /// Records handed to the worker.
    submitted: std::sync::atomic::AtomicU64,
    /// Records written to the file.
    persisted: std::sync::atomic::AtomicU64,
    /// Disk passes completed.
    batches: std::sync::atomic::AtomicU64,
    /// `flush` calls issued across all batches.
    flushes: std::sync::atomic::AtomicU64,
    /// `sync_all` calls issued across all batches.
    fsyncs: std::sync::atomic::AtomicU64,
    /// Batches the worker refused after a write failure, with their records.
    failed_batches: std::sync::atomic::AtomicU64,
    /// Records never written because the worker had already failed.
    unpersisted_after_failure: std::sync::atomic::AtomicU64,
    /// Rows that arrived after the frontier skipped past them. Distinct from
    /// `resent_skipped` (rows the file already holds) and from
    /// `unpersisted_after_failure` (rows lost to a dead disk or dead
    /// producer): these rows existed, arrived late, and fit nowhere, because
    /// the file already wrote past their position. With the stall timeout tied
    /// to the epoch deadline this counter stays zero — a nonzero value means a
    /// guest outlived twice its preemption backstop, which is an engine
    /// failure, not an audit failure — but a zero nobody reads is not a
    /// tripwire, so the tests assert it.
    late_after_skip: std::sync::atomic::AtomicU64,
    /// Rows dropped as already persisted: at or below the file's initial
    /// count (history resends), or below a frontier this worker already
    /// wrote past. A resend is idempotent by counting, not by rewriting.
    resent_skipped: std::sync::atomic::AtomicU64,
}

/// A point-in-time copy of [`AppenderStats`].
///
/// ```
/// use qqq_host::audit_sink::AppenderStats;
///
/// let snapshot = AppenderStats::default().snapshot();
/// assert_eq!(
///     (snapshot.flushes, snapshot.fsyncs, snapshot.resent_skipped),
///     (0, 0, 0)
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppenderSnapshot {
    /// Records handed to the worker.
    pub submitted: u64,
    /// Records written to the file.
    pub persisted: u64,
    /// Disk passes completed.
    pub batches: u64,
    /// `flush` calls issued across all batches.
    pub flushes: u64,
    /// `sync_all` calls issued across all batches.
    pub fsyncs: u64,
    /// Batches refused after a write failure.
    pub failed_batches: u64,
    /// Records never written because the worker had already failed.
    pub unpersisted_after_failure: u64,
    /// Rows that arrived after the frontier skipped past them. See the counter.
    pub late_after_skip: u64,
    /// Rows dropped as already persisted (history or rewrite resends).
    pub resent_skipped: u64,
}

impl AppenderStats {
    /// Read every counter without stopping the worker.
    #[must_use]
    pub fn snapshot(&self) -> AppenderSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        AppenderSnapshot {
            submitted: self.submitted.load(Relaxed),
            persisted: self.persisted.load(Relaxed),
            batches: self.batches.load(Relaxed),
            flushes: self.flushes.load(Relaxed),
            fsyncs: self.fsyncs.load(Relaxed),
            failed_batches: self.failed_batches.load(Relaxed),
            unpersisted_after_failure: self.unpersisted_after_failure.load(Relaxed),
            late_after_skip: self.late_after_skip.load(Relaxed),
            resent_skipped: self.resent_skipped.load(Relaxed),
        }
    }
}

/// Why a record could not be handed to the audit worker.
///
/// ```
/// use qqq_host::audit_sink::AppendError;
///
/// assert_eq!(
///     AppendError::WorkerGone.to_string(),
///     "the audit append worker is gone"
/// );
/// assert!(
///     AppendError::WorkerFailed { reason: "disk full".to_owned() }
///         .to_string()
///         .contains("disk full")
/// );
/// assert!(
///     AppendError::WorkerTimeout { through: 41 }
///         .to_string()
///         .contains("41")
/// );
/// assert_ne!(
///     format!("{:?}", AppendError::WorkerGone),
///     format!("{:?}", AppendError::WorkerTimeout { through: 1 })
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendError {
    /// The worker thread is gone (it panicked, which is a bug, not a disk
    /// condition). Fails fast rather than blocking forever on a queue nobody
    /// drains — a hang here would convert a worker bug into a hung server.
    WorkerGone,
    /// The worker hit a write error and stopped; the record was not persisted.
    /// Carries the underlying reason. The caller must treat this like any
    /// persist failure: loudly, never as a silent skip.
    WorkerFailed {
        /// What the failed write reported.
        reason: String,
    },
    /// The barrier covering this sequence never cleared in time. The bounded
    /// queue drains in bounded time, so this means the worker is dead or the
    /// disk is wedged — either way the caller must not assume persistence.
    WorkerTimeout {
        /// The highest sequence the barrier covered.
        through: u64,
    },
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WorkerGone => write!(f, "the audit append worker is gone"),
            Self::WorkerFailed { reason } => {
                write!(f, "the audit append worker failed: {reason}")
            }
            Self::WorkerTimeout { through } => write!(
                f,
                "the audit append worker did not persist through sequence {through} in time"
            ),
        }
    }
}

impl std::error::Error for AppendError {}

/// What [`AuditAppender::shutdown`] found when the worker stopped.
///
/// ```
/// use qqq_host::audit_sink::{AppenderStats, ShutdownReport};
///
/// let report = ShutdownReport {
///     stats: AppenderStats::default().snapshot(),
///     drained_cleanly: true,
/// };
/// assert!(report.drained_cleanly);
/// assert_eq!(report.stats.persisted, 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// The final counters.
    pub stats: AppenderSnapshot,
    /// True when every submitted record reached the file with no failure.
    /// False means the report's `failed_batches` or
    /// `unpersisted_after_failure` is nonzero — the caller must say so, not
    /// round it to success.
    pub drained_cleanly: bool,
}

/// The file's persist path: one bounded queue, one writing thread.
///
/// # Why a thread rather than a bigger lock
///
/// The synchronous path serialized every audit-enabled request on the file
/// mutex and paid a flush per record on the request's own thread, so a slow
/// disk became slow requests and the persisted-index scan re-read the stream
/// per request. The worker inverts that: producers hand off a record with one
/// blocking send and go back to serving, and a single thread owns the only
/// file offset — which is also what makes the persisted count O(1) instead of
/// a scan.
///
/// # Why the queue blocks instead of dropping
///
/// An audit record that is dropped is a hole in the evidence that looks
/// exactly like a request that never happened. Backpressure converts "the disk
/// cannot keep up" into slow requests rather than false history; the bound
/// keeps that slowness from becoming unbounded memory. A caller that needs a
/// different tradeoff changes the bound explicitly, in the config, where the
/// choice is visible.
///
/// # Why rows leave in sequence order
///
/// [`resume_or_start`] refuses a file whose rows do not chain-link, so file
/// order is load-bearing across restarts. Concurrent producers hand records
/// in arrival order, which is not sequence order, so the worker holds a
/// reorder buffer keyed by sequence and writes only the contiguous run. Gaps
/// from ambient rows are expected, not exceptional: a request records rows
/// during its guest call and sends them only when it reaches its own persist,
/// so a slow request's rows trail the frontier while faster requests flow
/// past. The worker waits those gaps out; the stall timeout — tied to the
/// epoch deadline at attach, since guest execution is what bounds the wait —
/// covers only the producer that died between recording and sending. A gap
/// at shutdown means exactly that death, which the report surfaces rather
/// than papers
/// over.
///
/// # Why the worker stops on a write error instead of retrying
///
/// A failed disk write is near-certainly persistent (full disk, revoked
/// permission), and retrying it burns request threads on a condition that will
/// not clear. One attempt, then the failed state: queued work is counted as
/// unpersisted, later appends fail fast with the reason, and nothing is
/// silently skipped.
#[derive(Debug)]
pub struct AuditAppender {
    tx: Option<std::sync::mpsc::SyncSender<Work>>,
    stats: std::sync::Arc<AppenderStats>,
    worker: Option<std::thread::JoinHandle<()>>,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    config: AppenderConfig,
}

impl AuditAppender {
    /// Start the worker on an open file.
    ///
    /// The file keeps its own record count; the worker's persisted count starts
    /// there, so a resumed file and a fresh stream agree on what "already held"
    /// means without a second counter that could drift.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AppenderConfig, AuditAppender, AuditFile};
    /// use qqq_cap::capability::Capability;
    /// use qqq_host::audit::{AuditStream, Outcome};
    /// use qqq_host::tenant::{ComponentDigest, GrantDigest};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-spawn-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let path = dir.join("audit.jsonl");
    /// let file = AuditFile::open(&path, 0).expect("open");
    /// let appender = AuditAppender::spawn(file, AppenderConfig::default());
    /// let mut stream = AuditStream::with_default_capacity();
    /// let component = ComponentDigest::new("0011223344556677").expect("digest");
    /// let grants = GrantDigest::new("aabbccdd").expect("digest");
    /// let _ = stream.record(None, &component, &grants, Capability::FsRead, "f", Outcome::Granted);
    /// appender.append(&stream.records()[0]).expect("append");
    /// let report = appender.shutdown();
    /// assert!(report.drained_cleanly);
    /// assert_eq!(report.stats.persisted, 1);
    /// assert_eq!(std::fs::read_to_string(&path).expect("read").lines().count(), 1);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    ///
    /// # Panics
    ///
    /// When the worker thread cannot be spawned, which means the host cannot
    /// create threads — a broken process, not a full disk. The `expect` names
    /// it so the panic message states the condition instead of unwrapping
    /// silently.
    #[must_use]
    pub fn spawn(mut file: AuditFile, config: AppenderConfig) -> Self {
        if config.durability == Durability::Buffered {
            file = file.into_buffered(BUFFERED_CAPACITY);
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(config.queue_bound.max(1));
        let stats = std::sync::Arc::new(AppenderStats::default());
        let failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stats = std::sync::Arc::clone(&stats);
        let worker_failed = std::sync::Arc::clone(&failed);
        let worker = std::thread::Builder::new()
            .name("qqq-audit-append".to_owned())
            .spawn(move || {
                append_loop(&rx, &mut file, &worker_stats, &worker_failed, &config);
            })
            .expect("audit append worker must spawn");
        Self {
            tx: Some(tx),
            stats,
            worker: Some(worker),
            failed,
            config,
        }
    }

    /// Hand one record to the worker, waiting if the queue is full.
    ///
    /// Blocking is the backpressure policy: the alternative is a dropped
    /// evidence row. Fails only when the worker is gone — panicked (a bug) or
    /// stopped after a write error — and then fails fast with the reason
    /// rather than hanging on a queue nobody drains.
    ///
    /// # Errors
    ///
    /// [`AppendError::WorkerGone`] when the worker thread died;
    /// [`AppendError::WorkerFailed`] when it stopped on a write error.
    ///
    /// A record handed off is a record the shutdown report accounts for:
    /// append one row, shut down, and the report must show it persisted with
    /// the file holding its line. Counter reads alone would prove nothing —
    /// the worker updates them asynchronously — so this asserts the joined
    /// report and the file, not an immediate counter.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AppenderConfig, AuditAppender, AuditFile};
    /// use qqq_cap::capability::Capability;
    /// use qqq_host::audit::{AuditStream, Outcome};
    /// use qqq_host::tenant::{ComponentDigest, GrantDigest};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-append-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let path = dir.join("audit.jsonl");
    /// let file = AuditFile::open(&path, 0).expect("open");
    /// let appender = AuditAppender::spawn(file, AppenderConfig::default());
    /// let mut stream = AuditStream::with_default_capacity();
    /// let component = ComponentDigest::new("0011223344556677").expect("digest");
    /// let grants = GrantDigest::new("aabbccdd").expect("digest");
    /// let _ = stream.record(None, &component, &grants, Capability::FsRead, "f", Outcome::Granted);
    /// appender.append(&stream.records()[0]).expect("append");
    /// let report = appender.shutdown();
    /// assert!(report.drained_cleanly);
    /// assert_eq!(report.stats.persisted, 1);
    /// assert_eq!(std::fs::read_to_string(&path).expect("read").lines().count(), 1);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    pub fn append(&self, record: &AuditRecord) -> Result<(), AppendError> {
        if self.failed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(AppendError::WorkerFailed {
                reason: "a previous batch failed to write".to_owned(),
            });
        }
        match &self.tx {
            Some(tx) => tx
                .send(Work::Record(record.clone()))
                .map_err(|_| AppendError::WorkerGone),
            None => Err(AppendError::WorkerGone),
        }
    }

    /// Persist these rows and wait until they are durable, then report.
    ///
    /// The rows travel like [`AuditAppender::append`], then a barrier asks the
    /// worker to confirm everything through the highest sequence. The wait is
    /// what keeps the synchronous path's promise — a returned request has its
    /// evidence on disk — while the shared worker still batches concurrent
    /// requests into fewer disk passes than one flush per request each.
    ///
    /// # Errors
    ///
    /// [`AppendError`] when the worker is gone or failed, or when `timeout`
    /// expires first — a bounded queue drains in bounded time, so tens of
    /// seconds without progress means the worker is dead, not slow.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AppenderConfig, AuditAppender, AuditFile};
    /// use qqq_cap::capability::Capability;
    /// use qqq_host::audit::{AuditStream, Outcome};
    /// use qqq_host::tenant::{ComponentDigest, GrantDigest};
    /// use std::time::Duration;
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-persist-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let file = AuditFile::open(&dir.join("audit.jsonl"), 0).expect("open");
    /// let appender = AuditAppender::spawn(file, AppenderConfig::default());
    /// let mut stream = AuditStream::with_default_capacity();
    /// let component = ComponentDigest::new("0011223344556677").expect("digest");
    /// let grants = GrantDigest::new("aabbccdd").expect("digest");
    /// let _ = stream.record(None, &component, &grants, Capability::FsRead, "f", Outcome::Granted);
    /// let ack = appender.persist(stream.records(), Duration::from_secs(30)).expect("persist");
    /// assert_eq!(ack.persisted, 1);
    /// let report = appender.shutdown();
    /// assert!(report.drained_cleanly);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    pub fn persist(
        &self,
        records: &[AuditRecord],
        timeout: std::time::Duration,
    ) -> Result<BarrierAck, AppendError> {
        let through = records.iter().map(|record| record.sequence).max();
        for record in records {
            self.append(record)?;
        }
        let Some(through) = through else {
            return Ok(BarrierAck {
                persisted: self
                    .stats
                    .persisted
                    .load(std::sync::atomic::Ordering::Relaxed),
            });
        };
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        match &self.tx {
            Some(tx) => tx
                .send(Work::Barrier {
                    through,
                    ack: ack_tx,
                })
                .map_err(|_| AppendError::WorkerGone)?,
            None => return Err(AppendError::WorkerGone),
        }
        ack_rx
            .recv_timeout(timeout)
            .map_err(|_| AppendError::WorkerTimeout { through })
    }

    /// Read the worker's counters without stopping it.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AppenderConfig, AuditAppender, AuditFile};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-stats-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let file = AuditFile::open(&dir.join("audit.jsonl"), 0).expect("open");
    /// let appender = AuditAppender::spawn(file, AppenderConfig::default());
    /// assert_eq!(appender.stats().submitted, 0);
    /// assert_eq!(appender.stats().late_after_skip, 0);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    #[must_use]
    pub fn stats(&self) -> AppenderSnapshot {
        self.stats.snapshot()
    }

    /// The wiring this appender was spawned with, for tests and diagnostics.
    ///
    /// Exposed rather than asserted through behaviour because the stall and
    /// persist tripwires are configuration: a test that the attach path
    /// derives them from the epoch deadline needs the values, not a 60-second
    /// timing run.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AppenderConfig, AuditAppender, AuditFile, Durability};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-config-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let file = AuditFile::open(&dir.join("audit.jsonl"), 0).expect("open");
    /// let appender = AuditAppender::spawn(file, AppenderConfig::default());
    /// assert_eq!(appender.config().durability, Durability::FlushPerRecord);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    #[must_use]
    pub fn config(&self) -> AppenderConfig {
        self.config
    }

    /// Stop the worker after it persists everything queued, and report.
    ///
    /// The close-then-join order is the whole guarantee: closing wakes the
    /// worker's blocking receive, and joining waits out the drain, so when this
    /// returns every submitted record is either in the file or counted in the
    /// report as unpersisted. A clean report has `persisted == submitted`.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AppenderConfig, AuditAppender, AuditFile};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-shutdown-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let file = AuditFile::open(&dir.join("audit.jsonl"), 0).expect("open");
    /// let appender = AuditAppender::spawn(file, AppenderConfig::default());
    /// let report = appender.shutdown();
    /// assert!(report.drained_cleanly);
    /// assert_eq!(report.stats.submitted, 0);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    #[must_use]
    pub fn shutdown(mut self) -> ShutdownReport {
        drop(self.tx.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let stats = self.stats.snapshot();
        ShutdownReport {
            drained_cleanly: stats.failed_batches == 0
                && stats.unpersisted_after_failure == 0
                && stats.persisted == stats.submitted,
            stats,
        }
    }
}

impl Drop for AuditAppender {
    /// Best-effort drain on the way out: close the queue so the worker's
    /// blocking receive wakes, then wait out the drain. A server that exits
    /// with queued evidence loses it, and a best-effort join is strictly more
    /// evidence than a detached thread nobody waited for.
    ///
    /// ```
    /// use qqq_host::audit_sink::{AppenderConfig, AuditAppender, AuditFile};
    /// use qqq_cap::capability::Capability;
    /// use qqq_host::audit::{AuditStream, Outcome};
    /// use qqq_host::tenant::{ComponentDigest, GrantDigest};
    ///
    /// let dir = std::env::temp_dir().join(format!("qqq-drop-doc-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).expect("scratch");
    /// let path = dir.join("audit.jsonl");
    /// let file = AuditFile::open(&path, 0).expect("open");
    /// let appender = AuditAppender::spawn(file, AppenderConfig::default());
    /// let mut stream = AuditStream::with_default_capacity();
    /// let component = ComponentDigest::new("0011223344556677").expect("digest");
    /// let grants = GrantDigest::new("aabbccdd").expect("digest");
    /// let _ = stream.record(None, &component, &grants, Capability::FsRead, "f", Outcome::Granted);
    /// appender.append(&stream.records()[0]).expect("append");
    /// drop(appender);
    /// assert_eq!(std::fs::read_to_string(&path).expect("read").lines().count(), 1);
    /// let _ = std::fs::remove_dir_all(&dir);
    /// ```
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// The worker: reorder by sequence, write contiguous runs in batches.
///
/// See [`AuditAppender`] for why each of those clauses exists. The loop ends
/// when every sender is gone and the queue is empty; on a write error it
/// records the failure, counts the unwritten remainder as unpersisted, and
/// returns — later appends fail fast on the shared flag.
fn append_loop(
    rx: &std::sync::mpsc::Receiver<Work>,
    file: &mut AuditFile,
    stats: &AppenderStats,
    failed: &std::sync::atomic::AtomicBool,
    config: &AppenderConfig,
) {
    use std::sync::atomic::Ordering::Relaxed;
    let batch_size = config.batch_size.max(1);
    let mut worker = WorkerState {
        pending: std::collections::BTreeMap::new(),
        // Anchored to the file, never to the lowest row seen: anchoring to
        // seen data lets one early high row strand every lower row that
        // arrives after it — stranded rows the file can never take, which is
        // silent evidence loss wearing a clean shutdown report.
        next: Some(file.records() as u64 + 1),
        batch: Vec::with_capacity(batch_size),
        barriers: Vec::new(),
        base: file.records() as u64,
        written: file.records() as u64 + 1,
        stalled_since: None,
    };
    loop {
        let Ok(first) = rx.recv() else {
            break;
        };
        sort_work(first, &mut worker, stats);
        while let Ok(work) = rx.try_recv() {
            sort_work(work, &mut worker, stats);
            if worker.pending.len() >= batch_size.saturating_mul(2).max(1) {
                break;
            }
        }
        match write_frontier(
            file,
            &mut worker.pending,
            worker.next,
            &mut worker.batch,
            stats,
            config.durability,
        ) {
            FrontierOutcome::Wrote(cursor) => {
                worker.next = Some(cursor);
                worker.written = cursor;
                worker.stalled_since = None;
                clear_barriers(&mut worker.barriers, cursor, stats.persisted.load(Relaxed));
            }
            FrontierOutcome::GapAt(_) => {
                // A resend lands entirely behind the frontier — every sequence
                // already written — so no write happens and its barrier would
                // wait forever without this. Clearing against the standing
                // frontier answers it immediately; a barrier past the frontier
                // stays queued until its records arrive.
                if let Some(frontier) = worker.next {
                    clear_barriers(
                        &mut worker.barriers,
                        frontier,
                        stats.persisted.load(Relaxed),
                    );
                }
                let _ = note_gap(&mut worker, stats, config.stall_timeout);
            }
            FrontierOutcome::Failed(failure) => {
                fail_worker(
                    stats,
                    failed,
                    worker.pending.len(),
                    worker.batch.len(),
                    &failure,
                );
                return;
            }
        }
    }
    drain_remaining(rx, file, &mut worker, stats, failed, config.durability);
}

/// The worker's mutable state, bundled so the loop and the drain pass one
/// value rather than four parallel arguments that must stay in step.
struct WorkerState {
    /// Records received but not yet written, keyed by sequence.
    pending: std::collections::BTreeMap<u64, AuditRecord>,
    /// The next sequence the file needs. Anchored at spawn to one past the
    /// file's own count — never to the lowest sequence seen — because
    /// anchoring to seen data lets an early high row strand every lower row
    /// that arrives after it, permanently and silently. `None` only until the
    /// anchor is read, which happens before the first pull.
    next: Option<u64>,
    /// The next sequence never yet written. `next` moves past skipped rows;
    /// this one moves only across actual writes, so a row arriving between
    /// the two is recognized as skipped-past (lost, counted loudly) rather
    /// than mistaken for a harmless duplicate of filed history.
    written: u64,
    /// Scratch space for one disk pass, reused across batches.
    batch: Vec<AuditRecord>,
    /// Barriers waiting for the frontier to pass the sequence they cover.
    barriers: Vec<(u64, std::sync::mpsc::Sender<BarrierAck>)>,
    /// The file's record count at spawn. Rows at or below it are history the
    /// file already holds; resends of them are skipped, not rewritten.
    base: u64,
    /// When the current frontier gap started; a gap that outlives
    /// `stall_timeout` is a dead producer, not a slow one.
    stalled_since: Option<std::time::Instant>,
}

/// Observe one frontier gap: arm the stall timer, or skip past a dead one.
///
/// Returns whether a sequence was skipped. The timer arms only while rows
/// actually wait behind the gap — arming it on an empty buffer would measure
/// idle time, and a later real gap would then skip instantly on a stale
/// stamp, dropping a legitimate row that simply had not arrived yet. A gap
/// that outlives `stall_timeout` is a dead producer, not a slow one: the
/// missing sequence is counted loudly and the frontier moves on, or one
/// death wedges every later row and every live barrier behind it.
///
/// Extracted so the arming rule is unit-testable without timing a whole
/// worker: the three cases below (empty buffer, fresh gap, expired gap) are
/// assertions on this function, not sleeps around a thread.
fn note_gap(
    worker: &mut WorkerState,
    stats: &AppenderStats,
    stall_timeout: std::time::Duration,
) -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    if worker.pending.is_empty() {
        worker.stalled_since = None;
        return false;
    }
    let stalled = *worker
        .stalled_since
        .get_or_insert_with(std::time::Instant::now);
    if stalled.elapsed() < stall_timeout {
        return false;
    }
    if let Some(frontier) = worker.next {
        stats.unpersisted_after_failure.fetch_add(1, Relaxed);
        eprintln!(
            "error: audit sequence {frontier} never arrived; \
             skipping it as orphaned rather than wedging the log"
        );
        worker.next = Some(frontier + 1);
    }
    worker.stalled_since = None;
    true
}

/// Sort one queue item into the reorder buffer or the barrier list.
///
/// Rows at or below the file's spawn-time count, or below a frontier this
/// worker already wrote past, are history or duplicates: they are counted as
/// skipped resends rather than buffered, because buffering them would either
/// rewrite the file's history or strand them below the frontier forever —
/// the exact loss this worker exists to prevent.
///
/// Extracted so [`append_loop`] stays under the line limit; the hot loop and
/// the shutdown drain share it, because two copies of "what a message means"
/// would eventually disagree about one of them.
fn sort_work(work: Work, worker: &mut WorkerState, stats: &AppenderStats) {
    use std::sync::atomic::Ordering::Relaxed;
    match work {
        Work::Record(record) => {
            // Below the written frontier the file already holds the row: a
            // harmless duplicate. Already buffered but unwritten is the same
            // shape one step earlier: overlapping floor slices send shared
            // rows twice under concurrency, and counting both would inflate
            // `submitted` past what the file can ever hold — so the shutdown
            // report would fail clean runs. Duplicates are counted, never
            // re-queued.
            if record.sequence < worker.written || worker.pending.contains_key(&record.sequence) {
                stats.resent_skipped.fetch_add(1, Relaxed);
            } else if record.sequence < worker.next.unwrap_or(worker.base + 1) {
                stats.late_after_skip.fetch_add(1, Relaxed);
                eprintln!(
                    "error: audit sequence {} arrived after the frontier skipped past it; \
                     the row fits nowhere and is lost",
                    record.sequence
                );
            } else {
                stats.submitted.fetch_add(1, Relaxed);
                worker.pending.insert(record.sequence, record);
            }
        }
        Work::Barrier { through, ack } => worker.barriers.push((through, ack)),
    }
}

/// Answer every barrier the frontier has passed: the persisted count is
/// the proof, and a barrier answered is a request unblocked. "Passed"
/// includes a frontier that started past the barrier on a resumed file —
/// those rows are the file's history, written before this worker existed.
fn clear_barriers(
    barriers: &mut Vec<(u64, std::sync::mpsc::Sender<BarrierAck>)>,
    frontier: u64,
    persisted: u64,
) {
    let mut waiting = Vec::new();
    std::mem::swap(&mut waiting, barriers);
    for (through, ack) in waiting {
        if through < frontier {
            let _ = ack.send(BarrierAck { persisted });
        } else {
            barriers.push((through, ack));
        }
    }
}

/// Record a write failure and stop the worker.
///
/// Only the unwritten suffix counts as lost: the completed prefix is in the
/// file and the file's own count covers it. Shared by the hot loop and the
/// shutdown drain so both report the same numbers for the same condition.
fn fail_worker(
    stats: &AppenderStats,
    failed: &std::sync::atomic::AtomicBool,
    pending_len: usize,
    batch_len: usize,
    failure: &BatchFailure,
) {
    use std::sync::atomic::Ordering::Relaxed;
    let lost = pending_len + batch_len.saturating_sub(failure.completed);
    stats.failed_batches.fetch_add(1, Relaxed);
    stats
        .unpersisted_after_failure
        .fetch_add(lost as u64, Relaxed);
    failed.store(true, Relaxed);
    eprintln!(
        "error: the audit append worker failed to write: {}; {lost} records not persisted",
        failure.error
    );
}

/// Write the contiguous remainder after every sender is gone, then stop.
///
/// A gap here means a producer died mid-handoff — counted as unpersisted and
/// reported, never silently reordered past, because the file must
/// chain-link for [`resume_or_start`].
fn drain_remaining(
    rx: &std::sync::mpsc::Receiver<Work>,
    file: &mut AuditFile,
    state: &mut WorkerState,
    counters: &AppenderStats,
    failed: &std::sync::atomic::AtomicBool,
    durability: Durability,
) {
    use std::sync::atomic::Ordering::Relaxed;
    loop {
        while let Ok(work) = rx.try_recv() {
            sort_work(work, state, counters);
        }
        if state.pending.is_empty() {
            break;
        }
        match write_frontier(
            file,
            &mut state.pending,
            state.next,
            &mut state.batch,
            counters,
            durability,
        ) {
            FrontierOutcome::Wrote(cursor) => {
                state.next = Some(cursor);
                state.written = cursor;
                clear_barriers(
                    &mut state.barriers,
                    cursor,
                    counters.persisted.load(Relaxed),
                );
            }
            FrontierOutcome::GapAt(sequence) => {
                // Shutdown cannot wait the gap out — no sender remains to fill
                // it — so the missing sequence is skipped loudly, one at a
                // time, and the loop continues past it. Clearing the whole
                // buffer here would drop valid later rows along with the one
                // that never arrived.
                counters.unpersisted_after_failure.fetch_add(1, Relaxed);
                eprintln!(
                    "error: audit sequence {sequence} never arrived; \
                     skipping it as orphaned"
                );
                state.next = Some(sequence + 1);
            }
            FrontierOutcome::Failed(failure) => {
                fail_worker(
                    counters,
                    failed,
                    state.pending.len(),
                    state.batch.len(),
                    &failure,
                );
                return;
            }
        }
    }
    // Shutdown answers stragglers best-effort: every sender is gone, so no
    // waiter can arrive after this, and a waiter from before gets the final
    // persisted count rather than hanging on a queue that will never move.
    // A straggler ack is honest about what it is — the count, not a promise —
    // and the shutdown report carries the same numbers for the caller that
    // joined.
    let final_persisted = counters.persisted.load(Relaxed);
    for (_, ack) in std::mem::take(&mut state.barriers) {
        let _ = ack.send(BarrierAck {
            persisted: final_persisted,
        });
    }
    let _ = file.flush_for_shutdown(durability);
}

/// What one frontier write attempt found.
enum FrontierOutcome {
    /// A contiguous run reached `cursor` (exclusive); the frontier advances.
    Wrote(u64),
    /// Nothing at the frontier sequence: a producer died mid-handoff.
    GapAt(u64),
    /// The disk refused; carries what failed and how far the batch got, so the
    /// caller counts exactly the unwritten suffix as unpersisted.
    Failed(BatchFailure),
}

/// Write the contiguous run at the frontier, up to one batch.
///
/// Shared by the hot loop and the shutdown drain so both agree on what
/// "write" means: contiguous runs only, in sequence order, counted exactly
/// once. Returns the advanced cursor, the gap sequence, or the write error.
fn write_frontier(
    file: &mut AuditFile,
    pending: &mut std::collections::BTreeMap<u64, AuditRecord>,
    next: Option<u64>,
    batch: &mut Vec<AuditRecord>,
    stats: &AppenderStats,
    durability: Durability,
) -> FrontierOutcome {
    use std::sync::atomic::Ordering::Relaxed;
    let Some(frontier) = next else {
        return FrontierOutcome::GapAt(0);
    };
    batch.clear();
    let mut cursor = frontier;
    while let Some(record) = pending.remove(&cursor) {
        batch.push(record);
        cursor += 1;
        if batch.len() >= batch.capacity().max(1) {
            break;
        }
    }
    if batch.is_empty() {
        return FrontierOutcome::GapAt(frontier);
    }
    match file.append_batch(batch, durability) {
        Ok(report) => {
            stats.persisted.fetch_add(report.records as u64, Relaxed);
            stats.batches.fetch_add(1, Relaxed);
            stats.flushes.fetch_add(report.flushes, Relaxed);
            stats.fsyncs.fetch_add(report.fsyncs, Relaxed);
            FrontierOutcome::Wrote(cursor)
        }
        Err(failure) => FrontierOutcome::Failed(failure),
    }
}

/// Write one record line; the unit `append_batch` shares with [`AuditFile`].
fn write_record_line(
    writer: &mut impl std::io::Write,
    record: &AuditRecord,
) -> std::io::Result<()> {
    writeln!(writer, "{}", record.to_json())
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

    /// Build `count` chain-linked records across tenants round-robin, the way
    /// concurrent requests would record them into one shared stream.
    fn chained_records(count: usize, tenants: &[&str]) -> Vec<crate::audit::AuditRecord> {
        use qqq_cap::egress::TenantId;
        let component = ComponentDigest::new("0011223344556677").expect("digest");
        let grants = GrantDigest::new("aabbccdd").expect("digest");
        let ids: Vec<TenantId> = tenants
            .iter()
            .map(|name| TenantId::new(name).expect("test tenant"))
            .collect();
        let mut stream = AuditStream::with_default_capacity();
        for i in 0..count {
            let id = &ids[i % ids.len()];
            let _ = stream.record(
                Some(id),
                &component,
                &grants,
                Capability::FsRead,
                "handle_request",
                Outcome::Granted,
            );
        }
        assert_eq!(
            stream.records().len(),
            count,
            "the fixture must hold every record it claims"
        );
        stream.records().to_vec()
    }

    /// Read every sequence number from a JSONL file, in file order.
    fn file_sequences(path: &std::path::Path) -> Vec<u64> {
        let text = std::fs::read_to_string(path).expect("read file");
        text.lines()
            .map(|line| {
                let start = line.find("\"sequence\":").expect("a sequence field") + 11;
                let end = line[start..]
                    .find(',')
                    .expect("a terminator after the sequence");
                line[start..start + end]
                    .parse()
                    .expect("a numeric sequence")
            })
            .collect()
    }

    /// **PERF-AUDIT-001: concurrent producers land in sequence order, exactly once.**
    ///
    /// Eight threads submit disjoint slices of one chained record set through
    /// a queue bound of sixteen — far smaller than the record count, so the
    /// queue is full most of the run and every send exercises backpressure. The
    /// file must hold every sequence exactly once, in order, and the resumed
    /// chain must verify: arrival order is not sequence order, so anything but
    /// the reorder buffer fails this.
    #[test]
    fn concurrent_producers_land_in_sequence_order_exactly_once() {
        use std::sync::Arc;
        const COUNT: usize = 400;
        let scratch = Scratch::new("ordered-contention");
        let path = scratch.file();
        let records = Arc::new(chained_records(COUNT, &["acme", "globex"]));
        let file = AuditFile::open(&path, 0).expect("open");
        let appender = AuditAppender::spawn(
            file,
            AppenderConfig {
                queue_bound: 16,
                batch_size: 32,
                durability: Durability::Buffered,
                ..AppenderConfig::default()
            },
        );

        let mut handles = Vec::new();
        let shared = std::sync::Arc::new(appender);
        for worker in 0..8 {
            let records = Arc::clone(&records);
            let appender = std::sync::Arc::clone(&shared);
            handles.push(std::thread::spawn(move || {
                for record in records.iter().skip(worker).step_by(8) {
                    appender
                        .append(record)
                        .expect("a live worker takes every record");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("producer must not panic");
        }
        let appender = std::sync::Arc::try_unwrap(shared).expect("all producers joined");
        let report = appender.shutdown();
        assert!(
            report.drained_cleanly,
            "a clean run must drain cleanly: {:?}",
            report.stats
        );
        assert_eq!(report.stats.submitted, COUNT as u64);
        assert_eq!(report.stats.persisted, COUNT as u64);
        assert_eq!(
            report.stats.late_after_skip, 0,
            "no row may arrive after a skip on a healthy run"
        );

        let sequences = file_sequences(&path);
        let expected: Vec<u64> = (1..=COUNT as u64).collect();
        assert_eq!(
            sequences, expected,
            "the file must hold every sequence exactly once, in order"
        );
        let (_stream, loaded) = resume_or_start(&path, 65_536).expect("resume");
        assert_eq!(
            loaded.records.len(),
            COUNT,
            "the resumed history is complete"
        );
    }

    /// **The queue blocks under pressure instead of dropping.**
    ///
    /// The contention test above already proves no record is lost with a tiny
    /// bound; this one names the mechanism. A rendezvous queue (bound zero
    /// normalizes to one slot) forces every send to meet the worker, and the
    /// run still reconciles exactly — a dropping implementation cannot pass a
    /// test whose queue never holds more than one record while eight threads
    /// submit.
    #[test]
    fn a_full_queue_blocks_instead_of_dropping() {
        use std::sync::Arc;
        const COUNT: usize = 160;
        let scratch = Scratch::new("rendezvous");
        let path = scratch.file();
        let records = Arc::new(chained_records(COUNT, &["acme"]));
        let file = AuditFile::open(&path, 0).expect("open");
        let appender = AuditAppender::spawn(
            file,
            AppenderConfig {
                queue_bound: 0,
                batch_size: 64,
                durability: Durability::Buffered,
                ..AppenderConfig::default()
            },
        );
        let mut handles = Vec::new();
        let shared = std::sync::Arc::new(appender);
        for worker in 0..8 {
            let records = Arc::clone(&records);
            let appender = std::sync::Arc::clone(&shared);
            handles.push(std::thread::spawn(move || {
                for record in records.iter().skip(worker).step_by(8) {
                    appender.append(record).expect("rendezvous still delivers");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("producer must not panic");
        }
        let appender = std::sync::Arc::try_unwrap(shared).expect("all producers joined");
        let report = appender.shutdown();
        assert!(report.drained_cleanly, "{:?}", report.stats);
        assert_eq!(file_sequences(&path).len(), COUNT);
    }

    /// **Every durability mode persists identical content, with its own flush profile.**
    ///
    /// The modes differ only in crash promise, never in content: the same
    /// records through three appenders must produce byte-identical files. The
    /// stats prove the mechanism behind each promise — per-record flushes for
    /// [`Durability::FlushPerRecord`], one sync per batch for
    /// [`Durability::FsyncPerBatch`], and no flush at all before shutdown for
    /// [`Durability::Buffered`].
    #[test]
    fn durability_modes_persist_identical_content() {
        let records = chained_records(200, &["acme", "globex"]);
        let mut bytes = Vec::new();
        let mut profiles = Vec::new();
        for (tag, durability) in [
            ("buffered", Durability::Buffered),
            ("flush", Durability::FlushPerRecord),
            ("fsync", Durability::FsyncPerBatch),
        ] {
            let scratch = Scratch::new(tag);
            let path = scratch.file();
            let file = AuditFile::open(&path, 0).expect("open");
            let appender = AuditAppender::spawn(
                file,
                AppenderConfig {
                    queue_bound: 1024,
                    batch_size: 32,
                    durability,
                    ..AppenderConfig::default()
                },
            );
            for record in &records {
                appender.append(record).expect("append");
            }
            let report = appender.shutdown();
            assert!(report.drained_cleanly, "{tag}: {report:?}");
            bytes.push(std::fs::read(&path).expect("read file"));
            profiles.push((tag, report.stats));
        }
        assert_eq!(bytes[0], bytes[1], "buffered and flush-per-record agree");
        assert_eq!(bytes[1], bytes[2], "flush-per-record and fsync agree");
        let flush_stats: Vec<u64> = profiles.iter().map(|(_, s)| s.flushes).collect();
        assert_eq!(
            flush_stats[1], 200,
            "flush-per-record must flush per record, got {}",
            flush_stats[1]
        );
        assert_eq!(
            flush_stats[0], 0,
            "buffered must not flush before shutdown, got {}",
            flush_stats[0]
        );
        assert!(
            profiles[2].1.fsyncs >= 1,
            "fsync-per-batch must sync, got {:?}",
            profiles[2].1
        );
        assert_eq!(
            profiles[2].1.flushes, profiles[2].1.fsyncs,
            "each fsync batch flushes once: {:?}",
            profiles[2].1
        );
    }

    /// **A permanently missing sequence is skipped loudly, not wedged on.**
    ///
    /// Records 1, 2, 4, and 5 arrive with 3 never sent — the dead-producer
    /// shape. The worker must not wait forever (which would wedge every later
    /// row and every live barrier), and must not silently close the gap
    /// either: sequence 3 is counted as unpersisted, named on stderr, and the
    /// file holds 1, 2, 4, 5 in order. The 50 ms stall timeout keeps the test
    /// fast; production uses seconds, which is why this asserts the mechanism
    /// rather than the duration.
    #[test]
    fn a_permanently_missing_sequence_is_skipped_loudly() {
        let scratch = Scratch::new("stall-skip");
        let path = scratch.file();
        let records = chained_records(5, &["acme"]);
        let file = AuditFile::open(&path, 0).expect("open");
        let appender = AuditAppender::spawn(
            file,
            AppenderConfig {
                stall_timeout: std::time::Duration::from_millis(50),
                ..AppenderConfig::default()
            },
        );
        for record in records.iter().filter(|record| record.sequence != 3) {
            appender.append(record).expect("append");
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        let report = appender.shutdown();
        assert!(
            !report.drained_cleanly,
            "a skipped row is not a clean drain"
        );
        assert_eq!(report.stats.persisted, 4);
        assert_eq!(
            report.stats.unpersisted_after_failure, 1,
            "exactly the missing sequence is counted: {:?}",
            report.stats
        );
        assert_eq!(file_sequences(&path), vec![1, 2, 4, 5]);
    }

    /// **Buffered mode really buffers: the disk stays empty until shutdown.**
    ///
    /// Flush counts alone cannot prove the modes differ — on a raw file,
    /// `flush` is a passthrough and every mode would behave identically while
    /// reporting different numbers. This test goes through `spawn`, like
    /// production does, so the wiring that selects the buffered file is
    /// covered too: four records handed off and drained still leave nothing
    /// on disk (bytes sit in userspace), and only the shutdown flush
    /// delivers them. A regression that removed the buffer — or the spawn
    /// conversion that installs it — fails here while all flush counts stay
    /// green.
    #[test]
    fn buffered_mode_holds_bytes_in_userspace_until_shutdown() {
        let scratch = Scratch::new("buffered-holds");
        let path = scratch.file();
        let records = chained_records(4, &["acme"]);
        let file = AuditFile::open(&path, 0).expect("open");
        let appender = AuditAppender::spawn(
            file,
            AppenderConfig {
                durability: Durability::Buffered,
                ..AppenderConfig::default()
            },
        );
        for record in &records {
            appender.append(record).expect("append");
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        let on_disk = std::fs::read_to_string(&path).expect("read");
        assert!(
            on_disk.is_empty(),
            "buffered bytes must not reach the disk yet: {on_disk:?}"
        );
        let report = appender.shutdown();
        assert!(report.drained_cleanly, "{:?}", report.stats);
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("read")
                .lines()
                .count(),
            4,
            "shutdown delivers what the run held back"
        );
    }

    /// **The stall timer arms only while rows actually wait.**
    ///
    /// Three deterministic cases on `note_gap`, no threads and no sleeps: an
    /// empty buffer neither stamps nor skips; a fresh gap stamps without
    /// skipping; an expired gap skips exactly once and advances the frontier.
    /// The first case is the review finding — a stale stamp from an empty
    /// buffer would skip a legitimate row the instant a later real gap
    /// formed — so draining the buffer must clear the timer, asserted here
    /// by emptying between calls.
    #[test]
    fn stall_timer_arms_only_while_rows_wait() {
        use std::collections::BTreeMap;
        use std::time::{Duration, Instant};
        let stats = AppenderStats::default();
        let mut worker = WorkerState {
            pending: BTreeMap::new(),
            next: Some(2),
            batch: Vec::new(),
            barriers: Vec::new(),
            base: 0,
            written: 2,
            stalled_since: None,
        };
        assert!(
            !note_gap(&mut worker, &stats, Duration::from_secs(60)),
            "an empty buffer must neither stamp nor skip"
        );
        assert!(worker.stalled_since.is_none());

        let records = chained_records(3, &["acme"]);
        worker.pending.insert(3, records[2].clone());
        assert!(
            !note_gap(&mut worker, &stats, Duration::from_secs(60)),
            "a fresh gap stamps without skipping"
        );
        assert!(worker.stalled_since.is_some());
        assert_eq!(worker.next, Some(2));

        worker.pending.clear();
        assert!(
            !note_gap(&mut worker, &stats, Duration::from_secs(60)),
            "draining the buffer must clear a stale stamp, not skip on it"
        );
        assert!(worker.stalled_since.is_none());

        worker.pending.insert(3, records[2].clone());
        worker.stalled_since = Some(
            Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .expect("an hour ago is representable"),
        );
        assert!(
            note_gap(&mut worker, &stats, Duration::from_millis(50)),
            "an expired gap must skip"
        );
        assert_eq!(worker.next, Some(3));
        assert_eq!(stats.snapshot().unpersisted_after_failure, 1);
    }

    /// **A resubmitted unwritten row counts once, not twice.**
    ///
    /// Overlapping floor slices send shared rows twice under concurrency, so
    /// the worker sees duplicates of rows it has not written yet. Counting
    /// both would inflate `submitted` past what the file can ever hold, and
    /// the shutdown report would fail clean runs. Here row 3 arrives, is
    /// resent while row 2 is still missing, then row 2 completes the run:
    /// submitted counts three unique rows, the resend counts as skipped, and
    /// the drain is clean.
    #[test]
    fn a_resubmitted_unwritten_row_counts_once() {
        let scratch = Scratch::new("duplicate-inflight");
        let path = scratch.file();
        let records = chained_records(3, &["acme"]);
        let file = AuditFile::open(&path, 0).expect("open");
        let appender = AuditAppender::spawn(file, AppenderConfig::default());
        appender.append(&records[0]).expect("row 1");
        appender.append(&records[2]).expect("row 3, gap at 2");
        appender.append(&records[2]).expect("resend of row 3");
        appender.append(&records[1]).expect("row 2 fills the gap");
        let report = appender.shutdown();
        assert!(report.drained_cleanly, "{:?}", report.stats);
        assert_eq!(report.stats.submitted, 3);
        assert_eq!(report.stats.persisted, 3);
        assert_eq!(report.stats.resent_skipped, 1);
        assert_eq!(file_sequences(&path), vec![1, 2, 3]);
    }

    /// **Dropping the appender drains before returning.**    ///
    /// Servers exit through destructors, not through explicit shutdown calls —
    /// a `Drop` that detached the worker would lose the queued tail. This test
    /// never calls `shutdown`: the file must still hold every record, because
    /// the close-then-join order in `Drop` waits out the drain.
    #[test]
    fn dropping_the_appender_drains_before_return() {
        const COUNT: usize = 120;
        let scratch = Scratch::new("drop-drain");
        let path = scratch.file();
        let records = chained_records(COUNT, &["acme"]);
        {
            let file = AuditFile::open(&path, 0).expect("open");
            let appender = AuditAppender::spawn(file, AppenderConfig::default());
            for record in &records {
                appender.append(record).expect("append");
            }
        }
        assert_eq!(
            file_sequences(&path).len(),
            COUNT,
            "the drop must have waited out the drain"
        );
    }

    /// **A failing writer fails the batch with an exact count, not a guess.**
    ///
    /// The worker's failure accounting trusts the completed count, so the
    /// count itself is pinned here: a writer that dies after two lines reports
    /// exactly two, and the file holds exactly those two.
    #[test]
    fn a_failing_writer_reports_how_far_the_batch_got() {
        struct FailAfter {
            remaining: usize,
        }
        impl std::io::Write for FailAfter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.remaining == 0 {
                    return Err(std::io::Error::other("injected failure"));
                }
                let n = buf.len().min(self.remaining);
                self.remaining -= n;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let records = chained_records(4, &["acme"]);
        let first_two = records[0].to_json().len() + 1 + records[1].to_json().len() + 1;
        let mut writer = FailAfter {
            remaining: first_two,
        };
        let mut written = 0;
        for record in &records {
            match write_record_line(&mut writer, record) {
                Ok(()) => written += 1,
                Err(_) => break,
            }
        }
        assert_eq!(written, 2, "exactly two lines fit before the failure");
    }

    /// **Throughput by mode, printed as measurements — `PERF-AUDIT-001`.**
    ///
    /// Twenty thousand records through the synchronous primitive and through
    /// each worker mode, timed and printed. The assertions are functional only
    /// (every record persisted, clean drain): the numbers are evidence for the
    /// observation, not a budget, and they are not asserted because asserting
    /// them would turn a measurement into a claim about every machine.
    #[test]
    fn audit_append_throughput_by_mode() {
        const COUNT: usize = 20_000;
        let records = chained_records(COUNT, &["acme", "globex", "initech"]);
        let scratch = Scratch::new("throughput-direct");
        let direct_path = scratch.file();
        let started = std::time::Instant::now();
        {
            let mut file = AuditFile::open(&direct_path, 0).expect("open");
            for record in &records {
                file.append(record).expect("append");
            }
        }
        let direct_ms = started.elapsed().as_millis();
        println!("direct sync append (flush per record): {COUNT} records in {direct_ms} ms");
        for (tag, durability) in [
            ("buffered", Durability::Buffered),
            ("flush-per-record", Durability::FlushPerRecord),
            ("fsync-per-batch", Durability::FsyncPerBatch),
        ] {
            let scratch = Scratch::new(tag);
            let path = scratch.file();
            let file = AuditFile::open(&path, 0).expect("open");
            let appender = AuditAppender::spawn(
                file,
                AppenderConfig {
                    queue_bound: 4096,
                    batch_size: 256,
                    durability,
                    ..AppenderConfig::default()
                },
            );
            let started = std::time::Instant::now();
            for record in &records {
                appender.append(record).expect("append");
            }
            let report = appender.shutdown();
            let elapsed_ms = started.elapsed().as_millis().max(1);
            assert!(report.drained_cleanly, "{tag}: {report:?}");
            println!(
                "worker {tag}: {COUNT} records in {elapsed_ms} ms ({} records/s, {} batches)",
                COUNT as u128 * 1000 / elapsed_ms,
                report.stats.batches,
            );
        }
    }

    /// **A restarted process continues the chain rather than starting a new one — `OBS-002`.**    ///
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
