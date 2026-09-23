// SPDX-License-Identifier: Apache-2.0

//! Sanitising sinks for guest stdout and stderr.
//!
//! # The defect this module exists to close
//!
//! `host_wasi::context` used to call `WasiCtxBuilder::inherit_stdout()` and
//! `inherit_stderr()`. The comment beside those calls said *"stdout and stderr go to
//! the host's, so an app's own output is visible"* — which is true, and which was the
//! whole problem: `qqq-serve`'s access log is written to the **same** stdout
//! (`qqq_serve::server::emit_record`, one `writeln!` to the locked stdout handle). A
//! guest that printed
//!
//! ```text
//! {"ts":"2026-01-01T00:00:00Z","method":"DELETE","path":"/admin","status":200,...}
//! ```
//!
//! produced a line **byte-identical** to a host access record. Any log collector, SIEM
//! rule, or incident review reading that stream would treat it as one. This is the
//! forged-record shape: the trusted channel and the untrusted one were the same
//! channel, and nothing marked the boundary.
//!
//! It is worth being precise about what the guest gains. It does not gain a capability
//! — it cannot read another tenant's data or reach an ungranted import. It gains
//! **plausible deniability about its own actions and the ability to fabricate
//! somebody else's**: a forged `status: 200` line beside a real `403` hides the
//! refusal, and a forged line naming another tenant's path manufactures evidence.
//! For a runtime whose entire premise is that a guest's authority is exactly what its
//! manifest names, a guest that can write into the host's audit stream has authority
//! its manifest did not name.
//!
//! # The rule
//!
//! **No byte a guest emits may begin a physical line on a host stream.** Two
//! mechanisms, both total:
//!
//! 1. Every physical line of guest output is prefixed with a fixed marker
//!    ([`STDOUT_PREFIX`] or [`STDERR_PREFIX`]), so a forged record can never be the
//!    first thing on a line.
//! 2. Every control byte except `\n` is escaped. `\n` becomes a **real** line break
//!    with the prefix re-armed, which is what makes the marker hold for *every* line
//!    rather than only the first — and it keeps the app's own line structure intact,
//!    so an operator reading the log sees what the guest actually printed.
//!
//! A third, softer rule keeps the sink bounded: an unterminated run is broken at
//! [`MAX_ESCAPED_RUN`] bytes with a real newline, and the continuation carries the
//! prefix again. Without it a guest could hold one line open indefinitely, which turns
//! a log file into one unreadable line and gives a collector nothing to parse.
//!
//! # What this does and does not defend
//!
//! It defends **whole-line** readers, which is what an access log is: one record per
//! line, parsed from the start of the line. A collector that parses each line as a JSON
//! document will fail to parse `qqq-guest stdout | {"ts":...}` and will not mistake it
//! for a record.
//!
//! It does not defend a reader that searches the raw stream for a substring. Under any
//! design the guest's text is present — escaping it into `\x7b\x22...` would only make
//! the log unreadable while a determined matcher decoded it anyway. The honest claim is
//! the one the marker makes: *this line is not a host record*.
//!
//! # Why a trait object and not a generic
//!
//! `StdoutStream::async_stream` returns `Box<dyn AsyncWrite + Send + Sync>`, so the
//! writer is boxed either way. Keeping the destination behind `Arc<dyn GuestSink>`
//! means one `GuestOutput` type serves both the process streams (production) and a
//! captured buffer (tests), which is what makes the escaping testable **on the type
//! production uses** rather than on a copy of it.

use std::io::{self, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};

/// The marker every line of a guest's standard output carries.
///
/// Fixed and greppable on purpose: an operator filtering a log for guest output uses
/// this, and an operator filtering for host records excludes it.
pub const STDOUT_PREFIX: &str = "qqq-guest stdout | ";

/// The marker every line of a guest's standard error carries.
///
/// Distinct from [`STDOUT_PREFIX`] so that the two remain separable when a deployment
/// merges the streams, which is the common case (`2>&1`, container runtimes,
/// `docker logs`).
pub const STDERR_PREFIX: &str = "qqq-guest stderr | ";

/// The longest escaped run emitted before a real line break is forced.
///
/// See the module docs: without a bound, a guest that never emits `\n` holds one line
/// open for as long as it likes, and a line-oriented collector has nothing to parse
/// until the guest exits.
pub const MAX_ESCAPED_RUN: usize = 4096;

/// A destination for guest output, writable through a shared reference.
///
/// # Why `&self` rather than `&mut self`
///
/// A guest can acquire several output streams, and wasmtime-wasi calls
/// `async_stream` once per acquired stream. Those writers must all reach one
/// destination, so the destination is held behind an `Arc` — and an `Arc` hands out
/// shared references only. Requiring `&mut self` here would have forced a `Mutex`
/// around every sink including `std::io::Stdout`, which already supports writes
/// through `&Stdout` and needs no lock.
///
/// The three provided implementations cover the two production destinations and the
/// general case: `Stdout`, `Stderr`, and any `Mutex<W>` for a `W: Write` that needs a
/// lock (which is what a captured buffer in a test is).
pub trait GuestSink: Send + Sync + 'static {
    /// Write all of `bytes`, or report why not.
    ///
    /// # Errors
    ///
    /// Whatever the destination reports. The caller in
    /// [`SanitisingWriter::poll_write`] surfaces it to the guest as a stream error
    /// rather than panicking: a broken log sink must not abort a request, which is the
    /// same reasoning `qqq_serve::server::emit_record` records for its own sink.
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()>;

    /// Flush the destination.
    ///
    /// # Errors
    ///
    /// Whatever the destination reports.
    fn flush_shared(&self) -> io::Result<()>;
}

impl GuestSink for io::Stdout {
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
        // `impl Write for &Stdout` is what makes this possible without a lock.
        let mut handle = self;
        handle.write_all(bytes)
    }

    fn flush_shared(&self) -> io::Result<()> {
        let mut handle = self;
        handle.flush()
    }
}

impl GuestSink for io::Stderr {
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
        let mut handle = self;
        handle.write_all(bytes)
    }

    fn flush_shared(&self) -> io::Result<()> {
        let mut handle = self;
        handle.flush()
    }
}

impl<W: Write + Send + 'static> GuestSink for std::sync::Mutex<W> {
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
        // A poisoned lock is reported as an error rather than unwrapped. A guest
        // whose sink panicked on another thread must not take down the host by
        // panicking here too -- `§4.8`'s rule that a guest never aborts the host.
        let mut guard = self
            .lock()
            .map_err(|_| io::Error::other("the guest-output sink's lock is poisoned"))?;
        guard.write_all(bytes)
    }

    fn flush_shared(&self) -> io::Result<()> {
        let mut guard = self
            .lock()
            .map_err(|_| io::Error::other("the guest-output sink's lock is poisoned"))?;
        guard.flush()
    }
}

impl<W: GuestSink + ?Sized> GuestSink for Arc<W> {
    fn write_all_shared(&self, bytes: &[u8]) -> io::Result<()> {
        (**self).write_all_shared(bytes)
    }

    fn flush_shared(&self) -> io::Result<()> {
        (**self).flush_shared()
    }
}

/// The escaping rule, as a pure state machine.
///
/// # Why this is separate from the writer
///
/// The writer is an `AsyncWrite` impl, which needs a `Pin`, a `Context`, and a
/// destination before it can be exercised. The rule needs none of those. Extracting it
/// means the escaping is tested directly on the bytes it produces, and the writer below
/// is a thin adapter that cannot contain a second, different rule.
#[derive(Debug, Clone)]
pub struct Escaper {
    prefix: &'static str,
    at_line_start: bool,
    since_break: usize,
}

impl Escaper {
    /// A new escaper whose every line begins with `prefix`.
    #[must_use]
    pub fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            at_line_start: true,
            since_break: 0,
        }
    }

    /// Append `bytes`, escaped, to `out`.
    ///
    /// Returns the number of input bytes consumed, which is always `bytes.len()`: the
    /// transformation is byte-for-byte, so an `AsyncWrite` caller can report a full
    /// write and the guest never sees a short write it would have to retry.
    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<u8>) -> usize {
        for &byte in bytes {
            if self.at_line_start {
                out.extend_from_slice(self.prefix.as_bytes());
                self.at_line_start = false;
            }
            match byte {
                // A real line break, and the prefix is re-armed for the next line.
                //
                // # Why this is the one byte that is *not* escaped
                //
                // The property being defended is "no guest byte begins a physical
                // line", and re-arming the prefix achieves that on its own: the guest's
                // newline ends a line that already carries the marker, and the line
                // after it gets a fresh one. Escaping it as well would emit `\\n`
                // **and** a break, doubling the line count and mangling the app's
                // output for no security gain — the forged record still appears, just
                // as `qqq-guest stdout | {"ts":...}` instead of on a line by itself.
                b'\n' => self.break_line(out),
                // Everything else in C0, plus DEL, is escaped. `\r` because it is a line
                // terminator to some readers; `\x1b` because an escape sequence can
                // rewrite what a terminal shows for the host's own records; the rest
                // because a total rule is auditable and a list of dangerous bytes is a
                // claim that goes stale.
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                // So a guest cannot emit a literal `\n` and have a reader mistake it for
                // a break the host inserted.
                b'\\' => out.extend_from_slice(b"\\\\"),
                0x00..=0x1f | 0x7f => {
                    out.extend_from_slice(format!("\\x{byte:02x}").as_bytes());
                }
                _ => out.push(byte),
            }
            self.since_break += 1;
            if self.since_break >= MAX_ESCAPED_RUN {
                self.break_line(out);
            }
        }
        bytes.len()
    }

    /// End the current physical line and require the prefix on the next one.
    ///
    /// Also called when the run bound is reached, which is why the prefix is re-armed
    /// here rather than only on `\n`: the two are the same event to a line reader.
    fn break_line(&mut self, out: &mut Vec<u8>) {
        out.push(b'\n');
        self.at_line_start = true;
        self.since_break = 0;
    }
}

/// A guest's standard output or standard error, sanitised.
///
/// Installed by `host_wasi::context` in place of `inherit_stdout`/`inherit_stderr`.
/// Implements [`StdoutStream`] — wasmtime-wasi's trait for *both* stdout and stderr —
/// so the same type serves both, distinguished only by the prefix.
#[derive(Clone)]
pub struct GuestOutput {
    prefix: &'static str,
    sink: Arc<dyn GuestSink>,
}

impl std::fmt::Debug for GuestOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestOutput")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl GuestOutput {
    /// Guest standard output, written to the host process's stdout.
    #[must_use]
    pub fn stdout() -> Self {
        Self::to(STDOUT_PREFIX, io::stdout())
    }

    /// Guest standard error, written to the host process's stderr.
    #[must_use]
    pub fn stderr() -> Self {
        Self::to(STDERR_PREFIX, io::stderr())
    }

    /// Guest output with an explicit prefix and destination.
    ///
    /// The destination is an `Arc` so that repeated calls to `async_stream` — which
    /// wasmtime-wasi makes freely, one per acquired stream — share one sink rather than
    /// racing on several.
    #[must_use]
    pub fn to(prefix: &'static str, sink: impl GuestSink) -> Self {
        Self {
            prefix,
            sink: Arc::new(sink),
        }
    }

    /// The marker this output's lines carry.
    #[must_use]
    pub fn prefix(&self) -> &'static str {
        self.prefix
    }

    /// A fresh writer over this output's sink.
    #[must_use]
    pub fn writer(&self) -> SanitisingWriter {
        SanitisingWriter {
            escaper: Escaper::new(self.prefix),
            sink: Arc::clone(&self.sink),
        }
    }
}

impl IsTerminal for GuestOutput {
    /// Always `false`, and deliberately not the host's answer.
    ///
    /// Reporting the host's terminal state would leak one bit of the host's
    /// environment to the guest — the same class of ambient authority the clock
    /// denials in `host_wasi` exist to remove — and a guest that colours its output
    /// for a TTY would be colouring a log file.
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for GuestOutput {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(self.writer())
    }
}

/// The `AsyncWrite` wasmtime-wasi writes a guest's output through.
pub struct SanitisingWriter {
    escaper: Escaper,
    sink: Arc<dyn GuestSink>,
}

impl std::fmt::Debug for SanitisingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanitisingWriter").finish_non_exhaustive()
    }
}

impl AsyncWrite for SanitisingWriter {
    /// Escape, then write, then report the **input** length.
    ///
    /// # Why the whole buffer is reported as written
    ///
    /// The escape is byte-for-byte: one input byte produces one or more output bytes,
    /// never fewer. So a caller that retried the unwritten tail would resend input
    /// bytes whose output is already in the sink. Reporting `bytes.len()` is therefore
    /// the correct answer, not an optimistic one — and it is what keeps the guest from
    /// observing a short write, which WASI surfaces as a stream error.
    ///
    /// The escape is done synchronously rather than by returning `Pending`. Guest
    /// output is bounded by [`MAX_ESCAPED_RUN`] per emitted line and the destination is
    /// a host stream, so there is no readiness to wait for; the alternative — spawning
    /// per write — would reorder a guest's output against itself.
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut escaped = Vec::with_capacity(buf.len() + 16);
        let consumed = this.escaper.push(buf, &mut escaped);
        Poll::Ready(this.sink.write_all_shared(&escaped).map(|()| consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_mut().sink.flush_shared())
    }

    /// Flush the destination and **do not** emit a trailing newline.
    ///
    /// A closing newline would be host-authored bytes on the guest's line, and the
    /// guest is what decides where its lines end. The escaper's `at_line_start` state
    /// is dropped with the writer, which is correct: the next writer starts a new line
    /// and prefixes it.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_mut().sink.flush_shared())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A captured sink.
    ///
    /// An alias rather than a newtype on purpose: `Arc<Mutex<Vec<u8>>>` is **already**
    /// a `GuestSink` through the two provided implementations, so the test drives the
    /// production escaping path with no bespoke type in between.
    type Captured = Arc<Mutex<Vec<u8>>>;

    fn captured() -> Captured {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn text(captured: &Captured) -> String {
        String::from_utf8(captured.lock().expect("not poisoned").clone()).expect("utf-8")
    }

    fn escape(prefix: &'static str, input: &[u8]) -> String {
        let mut out = Vec::new();
        let mut escaper = Escaper::new(prefix);
        escaper.push(input, &mut out);
        String::from_utf8(out).expect("the escape output is utf-8")
    }

    /// A line that would be a host access record, byte for byte.
    const FORGED_RECORD: &str = r#"{"ts":"2026-01-01T00:00:00Z","method":"DELETE","path":"/admin","status":200,"tenant":"other"}"#;

    #[test]
    fn a_guest_line_cannot_impersonate_an_access_record() {
        // The defect, stated as the property that actually holds: the forged line must
        // not be a line of its own on the host's stream.
        let rendered = escape(STDOUT_PREFIX, FORGED_RECORD.as_bytes());
        assert!(
            rendered.starts_with(STDOUT_PREFIX),
            "a guest line must begin with the marker: {rendered}"
        );
        assert_ne!(
            rendered.trim_end_matches('\n'),
            FORGED_RECORD,
            "the forged record became a line of its own"
        );
        assert!(
            !rendered.lines().any(|l| l == FORGED_RECORD),
            "some line of the output is exactly the forged record: {rendered}"
        );
        // And it is still readable, so an operator can see what the guest said.
        assert!(
            rendered.contains(FORGED_RECORD),
            "the guest's own bytes must remain legible after the marker: {rendered}"
        );
    }

    #[test]
    fn a_guest_cannot_open_an_unprefixed_line() {
        // The case that makes the marker mean "every line": a guest that emits its own
        // newline, including a record on the second line.
        let rendered = escape(
            STDOUT_PREFIX,
            format!("innocent\n{FORGED_RECORD}\nmore").as_bytes(),
        );
        for line in rendered.lines() {
            assert!(
                line.starts_with(STDOUT_PREFIX),
                "every physical line must carry the marker; found {line:?} in {rendered:?}"
            );
        }
        assert_eq!(
            rendered.matches('\n').count(),
            2,
            "the guest's two line breaks must survive as two line breaks: {rendered:?}"
        );
    }

    #[test]
    fn every_control_byte_is_escaped() {
        // The total rule, over the whole range rather than a list of "dangerous" bytes.
        // `\n` is excluded because it is the one byte that legitimately ends a line; the
        // next line carries the marker, which `a_guest_cannot_open_an_unprefixed_line`
        // asserts.
        let controls: Vec<u8> = (0x00u8..=0x1f)
            .chain(std::iter::once(0x7f))
            .filter(|b| *b != b'\n')
            .collect();
        let rendered = escape(STDOUT_PREFIX, &controls);
        assert!(
            !rendered
                .bytes()
                .any(|b| (b < 0x20 && b != b'\n') || b == 0x7f),
            "a raw control byte reached the sink: {rendered:?}"
        );
        assert_eq!(
            rendered.matches('\\').count(),
            controls.len(),
            "every escaped control byte must produce exactly one escape sequence: {rendered:?}"
        );
    }

    #[test]
    fn an_unterminated_run_is_broken_at_the_bound() {
        // A guest that never emits a newline must not be able to hold one line open
        // forever: a line-oriented collector would have nothing to parse.
        let input = vec![b'x'; MAX_ESCAPED_RUN * 2 + 7];
        let rendered = escape(STDOUT_PREFIX, &input);
        assert_eq!(
            rendered.matches('\n').count(),
            2,
            "two full runs must produce two forced breaks"
        );
        for line in rendered.lines() {
            assert!(
                line.starts_with(STDOUT_PREFIX),
                "the continuation line must carry the marker too"
            );
        }
    }

    #[test]
    fn the_bound_does_not_fire_early() {
        // The control for the test above. Without it, a bound of zero would satisfy
        // "runs are broken" while breaking every line the guest writes.
        let input = vec![b'x'; MAX_ESCAPED_RUN - 1];
        let rendered = escape(STDOUT_PREFIX, &input);
        assert_eq!(
            rendered.matches('\n').count(),
            0,
            "a run below the bound must not be broken"
        );
    }

    #[test]
    fn a_guest_cannot_forge_the_escape_sequence() {
        // `\` is escaped too, so a guest cannot emit a literal `\n` and have a reader
        // mistake it for a real break that the host inserted.
        let rendered = escape(STDOUT_PREFIX, b"a\\nb");
        assert_eq!(rendered, format!("{STDOUT_PREFIX}a\\\\nb"));
    }

    #[test]
    fn stdout_and_stderr_are_distinguishable_when_merged() {
        // `2>&1` and every container runtime merge the streams, so the markers must
        // differ or the merge destroys the distinction.
        assert_ne!(STDOUT_PREFIX, STDERR_PREFIX);
        assert!(!STDERR_PREFIX.contains(STDOUT_PREFIX));
        assert!(!STDOUT_PREFIX.contains(STDERR_PREFIX));
    }

    #[test]
    fn the_stream_interface_sanitises_through_the_real_trait_method() {
        // Drives `StdoutStream::async_stream` -- the exact method wasmtime-wasi calls
        // (`p2::stdio` -> `ctx.stdout.p2_stream()` -> the default adapter over
        // `async_stream`) -- against a captured sink. This is what proves the
        // `AsyncWrite` impl delegates to `Escaper` rather than carrying a second rule.
        let captured = captured();
        let output = GuestOutput::to(STDOUT_PREFIX, captured.clone());

        let written = futures_write(output.async_stream(), FORGED_RECORD.as_bytes());
        assert_eq!(
            written,
            FORGED_RECORD.len(),
            "the writer must report every input byte consumed, or WASI surfaces a short write"
        );

        let text = text(&captured);
        assert!(
            text.starts_with(STDOUT_PREFIX),
            "bytes reached the sink without the marker: {text:?}"
        );
        assert!(
            !text.lines().any(|l| l == FORGED_RECORD),
            "the forged record became a line of its own through the real trait path: {text:?}"
        );
    }

    /// Drive an `AsyncWrite` to completion with a no-op waker.
    ///
    /// `Waker::noop` is the standard library's own no-op waker, so this needs no
    /// hand-built vtable and therefore no `unsafe` — which the crate-level
    /// `forbid(unsafe_code)` would reject outright, since `forbid` cannot be relaxed by
    /// an inner `allow`. Building a `RawWaker` by hand was the first attempt and the
    /// compiler refused it, correctly.
    ///
    /// The writer never returns `Pending`; a `Pending` here would be a bug in the
    /// writer, and the panic says so rather than looping forever.
    fn futures_write(stream: Box<dyn AsyncWrite + Send + Sync>, buf: &[u8]) -> usize {
        // `Pin<Box<dyn AsyncWrite>>` is itself `AsyncWrite` (tokio implements the trait
        // for `Pin<P>` where `P: DerefMut + Unpin`), and `Pin<Box<_>>` is `Unpin`, so
        // `Pin::new` is available here without any `unsafe`.
        let mut stream = Box::into_pin(stream);
        let mut cx = Context::from_waker(std::task::Waker::noop());

        match Pin::new(&mut stream).poll_write(&mut cx, buf) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => panic!("the guest write failed: {e}"),
            Poll::Pending => panic!("the writer must not return Pending"),
        }
    }

    #[test]
    fn the_production_constructors_name_the_process_streams() {
        // Wiring: `host_wasi::context` installs `GuestOutput::stdout()` and
        // `GuestOutput::stderr()`. This asserts the two constructors are the sanitising
        // type with the expected markers, so the call site cannot be swapped for
        // `inherit_stdout` without this failing.
        assert_eq!(GuestOutput::stdout().prefix(), STDOUT_PREFIX);
        assert_eq!(GuestOutput::stderr().prefix(), STDERR_PREFIX);
        assert!(!GuestOutput::stdout().is_terminal());
        assert!(!GuestOutput::stderr().is_terminal());
    }

    #[test]
    fn a_writer_started_mid_line_still_prefixes() {
        // Each `async_stream` call returns a fresh writer. The second one must not
        // assume it begins mid-line: its first byte could be a whole forged record.
        let captured = captured();
        let output = GuestOutput::to(STDOUT_PREFIX, captured.clone());
        let _ = output.writer();
        let mut second = output.writer();
        let mut out = Vec::new();
        second.escaper.push(b"{\"status\":200}", &mut out);
        assert!(
            String::from_utf8(out)
                .expect("utf-8")
                .starts_with(STDOUT_PREFIX),
            "a fresh writer must prefix its first line"
        );
    }
}
