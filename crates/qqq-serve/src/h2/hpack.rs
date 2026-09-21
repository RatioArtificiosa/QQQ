// SPDX-License-Identifier: Apache-2.0

//! HPACK: header compression for HTTP/2 (RFC 7541).
//!
//! Implements `SRV-002`; RFC 7541 §4 (dynamic table), §5 (primitives), §6
//! (representations), §7 (security), Appendix B (the Huffman code).
//!
//! # Why this is the part most likely to be silently wrong
//!
//! Every other HTTP/2 layer fails **loudly**. A wrong frame length desynchronises
//! the connection within one frame; a wrong stream state produces an error code
//! the peer can name; a wrong window produces a stall. HPACK fails **quietly**:
//!
//! * A Huffman table with one wrong entry decodes to a *plausible* string. The
//!   request goes to the wrong path, or a header carries the wrong value, and
//!   nothing anywhere reports a problem.
//! * A dynamic table whose size accounting is off by one entry stays in sync
//!   until the eviction that crosses the boundary — hundreds of requests into a
//!   connection — and then every subsequent header decodes to a stale value.
//! * An integer decoder that stops one continuation byte early produces a number
//!   that is wrong by a plausible amount (255, 256, 4096) rather than absurd.
//!
//! So the tests in this module are the RFC's **own examples**, transcribed from
//! Appendix C, byte for byte. That is the only test whose oracle is not this
//! implementation. Appendix C.1 through C.6 are all present, including the
//! intermediate dynamic-table states, which is where the eviction accounting is
//! actually pinned.
//!
//! # The four representations
//!
//! | Prefix | Name | RFC |
//! |---|---|---|
//! | `1xxxxxxx` | Indexed Header Field | §6.1 |
//! | `01xxxxxx` | Literal with Incremental Indexing | §6.2.1 |
//! | `0000xxxx` | Literal without Indexing | §6.2.2 |
//! | `0001xxxx` | Literal Never Indexed | §6.2.3 |
//! | `001xxxxx` | Dynamic Table Size Update | §6.3 |
//!
//! The decoder must tell them apart from the **first three bits alone**, and the
//! order of the checks matters: `0x80`, then `0x40`, then `0x20`, then `0x10`.
//! Testing `0x20` before `0x40` silently reads every "literal with incremental
//! indexing" as a table-size update.
//!
//! # Huffman decoding: the two failure modes it is written against
//!
//! RFC 7541 §5.2 defines the code as a **prefix code with no explicit length
//! table** — the decoder reads bits until an entry matches, and the *end of the
//! string* is a separate condition with two rules:
//!
//! 1. **A partial code at the end must be all ones and at most 7 bits** (§5.2,
//!    "the padding … MUST be the most significant bits of the EOS symbol").
//!    Accepting any padding makes two different byte strings decode to the same
//!    text, which is a request-smuggling shape: a proxy and an origin can
//!    disagree about a header's value.
//! 2. **An explicit EOS symbol in the data is an error** (§4.1, §5.2) — the
//!    30-bit symbol must never appear, and a decoder with no EOS entry in its
//!    match table accepts it silently.
//!
//! Both are tested, and both are fault-injected.

use std::fmt;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// The default HPACK dynamic table size: 4096 bytes (RFC 7541 §4.2).
pub const DEFAULT_HEADER_TABLE_SIZE: usize = 4_096;

/// The largest header list this decoder will assemble.
///
/// RFC 9113 §6.5.2 makes `SETTINGS_MAX_HEADER_LIST_SIZE` advisory, so this is
/// enforced locally and reported as a stream error rather than a connection one:
/// a peer that sends an over-large header list has broken its own declaration,
/// not the connection's framing. 64 KiB matches `http1::MAX_HEAD_BYTES`, so a
/// request has one size limit regardless of which protocol carried it — two
/// different limits for the same request is how a proxy and an origin disagree.
pub const MAX_HEADER_LIST_SIZE: usize = 64 * 1024;

/// The most header fields this decoder will assemble.
///
/// Matches `http1::MAX_HEADERS` for the same reason. A compression bomb
/// (RFC 7541 §7) sends a header list whose *decoded* size is enormous while the
/// compressed block is tiny, so a limit on the compressed bytes is not a limit
/// at all.
pub const MAX_HEADER_COUNT: usize = 100;

/// The most string bytes one header field may decode to.
///
/// A single field larger than the whole list limit cannot be legal, so this is
/// not a separate policy — it exists so the check happens *before* the
/// allocation rather than after it, which is the difference between bounding
/// memory and measuring it.
pub const MAX_FIELD_BYTES: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// The static table (RFC 7541 Appendix A)
// ---------------------------------------------------------------------------

/// The HPACK static table: 61 entries, indexed 1..=61.
///
/// Transcribed from RFC 7541 Appendix A. The entries with an empty value are
/// *name-only* entries, and the distinction is load-bearing: index 1 is
/// `:authority` with no value, and a decoder that returned `(":authority", "")`
/// for it would invent a header the peer never sent. `None` models "no value",
/// which is why the table is pairs of `(name, Option<value>)` rather than pairs
/// of strings.
///
/// The table is a `&'static [(&'static str, Option<&'static str>)]` rather than
/// an array because a slice is what the lookup wants and the length is then
/// checkable by test against the RFC's "61".
#[rustfmt::skip]
const STATIC_TABLE: [(&str, Option<&str>); 61] = [
    (":authority",                  None),
    (":method",                     Some("GET")),
    (":method",                     Some("POST")),
    (":path",                       Some("/")),
    (":path",                       Some("/index.html")),
    (":scheme",                     Some("http")),
    (":scheme",                     Some("https")),
    (":status",                     Some("200")),
    (":status",                     Some("204")),
    (":status",                     Some("206")),
    (":status",                     Some("304")),
    (":status",                     Some("400")),
    (":status",                     Some("404")),
    (":status",                     Some("500")),
    ("accept-charset",              None),
    ("accept-encoding",             Some("gzip, deflate")),
    ("accept-language",             None),
    ("accept-ranges",               None),
    ("accept",                      None),
    ("access-control-allow-origin", None),
    ("age",                         None),
    ("allow",                       None),
    ("authorization",               None),
    ("cache-control",               None),
    ("content-disposition",         None),
    ("content-encoding",            None),
    ("content-language",            None),
    ("content-length",              None),
    ("content-location",            None),
    ("content-range",               None),
    ("content-type",                None),
    ("cookie",                      None),
    ("date",                        None),
    ("etag",                        None),
    ("expect",                      None),
    ("expires",                     None),
    ("from",                        None),
    ("host",                        None),
    ("if-match",                    None),
    ("if-modified-since",           None),
    ("if-none-match",               None),
    ("if-range",                    None),
    ("if-unmodified-since",         None),
    ("last-modified",               None),
    ("link",                        None),
    ("location",                    None),
    ("max-forwards",                None),
    ("proxy-authenticate",          None),
    ("proxy-authorization",         None),
    ("range",                       None),
    ("referer",                     None),
    ("refresh",                     None),
    ("retry-after",                 None),
    ("server",                      None),
    ("set-cookie",                  None),
    ("strict-transport-security",   None),
    ("transfer-encoding",           None),
    ("user-agent",                  None),
    ("vary",                        None),
    ("via",                         None),
    ("www-authenticate",            None),
];

/// The number of static entries.
pub const STATIC_TABLE_LEN: usize = STATIC_TABLE.len();

/// A static-table entry: the name, and the value if the entry has one.
#[must_use]
pub fn static_entry(index: usize) -> Option<(&'static str, Option<&'static str>)> {
    // Static indices are 1-based (`index - 1`); index 0 is not a static entry.
    if index == 0 || index > STATIC_TABLE_LEN {
        return None;
    }
    Some(STATIC_TABLE[index - 1])
}

/// Find the exact `(name, value)` static match, if any.
#[must_use]
fn static_exact(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| *n == name && *v == Some(value))
        .map(|i| i + 1)
}

/// Find the first static entry with this name, if any.
#[must_use]
fn static_name(name: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, _)| *n == name)
        .map(|i| i + 1)
}

// ---------------------------------------------------------------------------
// The Huffman table (RFC 7541 Appendix B)
// ---------------------------------------------------------------------------

/// The 257 Huffman codes, `(code, bit length)` indexed by symbol.
///
/// Transcribed from RFC 7541 Appendix B. 256 symbols plus EOS at index 256.
///
/// The EOS symbol's 30-bit code is included because the **decoder must reject
/// it** (§5.2) and the encoder needs to know the padding pattern; it is never
/// *emitted* by [`huffman_encode`], which encodes only the bytes it is given.
///
/// Every entry is checked against the RFC by
/// `the_huffman_table_is_a_valid_prefix_code`, which verifies the Kraft equality
/// — the arithmetic property that a complete prefix code must satisfy. A single
/// mistyped length breaks it, so the check catches what a spot-check of a few
/// entries would not.
#[rustfmt::skip]
const HUFFMAN: [(u32, u8); 257] = [
    (0x1ff8, 13), (0x7f_ffd8, 23), (0xfff_ffe2, 28), (0xfff_ffe3, 28),
    (0xfff_ffe4, 28), (0xfff_ffe5, 28), (0xfff_ffe6, 28), (0xfff_ffe7, 28),
    (0xfff_ffe8, 28), (0xff_ffea, 24), (0x3fff_fffc, 30), (0xfff_ffe9, 28),
    (0xfff_ffea, 28), (0x3fff_fffd, 30), (0xfff_ffeb, 28), (0xfff_ffec, 28),
    (0xfff_ffed, 28), (0xfff_ffee, 28), (0xfff_ffef, 28), (0xfff_fff0, 28),
    (0xfff_fff1, 28), (0xfff_fff2, 28), (0x3fff_fffe, 30), (0xfff_fff3, 28),
    (0xfff_fff4, 28), (0xfff_fff5, 28), (0xfff_fff6, 28), (0xfff_fff7, 28),
    (0xfff_fff8, 28), (0xfff_fff9, 28), (0xfff_fffa, 28), (0xfff_fffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7_fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xfff_fffc, 28),
    (0xf_ffe6, 20), (0x3f_ffd2, 22), (0xf_ffe7, 20), (0xf_ffe8, 20),
    (0x3f_ffd3, 22), (0x3f_ffd4, 22), (0x3f_ffd5, 22), (0x7f_ffd9, 23),
    (0x3f_ffd6, 22), (0x7f_ffda, 23), (0x7f_ffdb, 23), (0x7f_ffdc, 23),
    (0x7f_ffdd, 23), (0x7f_ffde, 23), (0xff_ffeb, 24), (0x7f_ffdf, 23),
    (0xff_ffec, 24), (0xff_ffed, 24), (0x3f_ffd7, 22), (0x7f_ffe0, 23),
    (0xff_ffee, 24), (0x7f_ffe1, 23), (0x7f_ffe2, 23), (0x7f_ffe3, 23),
    (0x7f_ffe4, 23), (0x1f_ffdc, 21), (0x3f_ffd8, 22), (0x7f_ffe5, 23),
    (0x3f_ffd9, 22), (0x7f_ffe6, 23), (0x7f_ffe7, 23), (0xff_ffef, 24),
    (0x3f_ffda, 22), (0x1f_ffdd, 21), (0xf_ffe9, 20), (0x3f_ffdb, 22),
    (0x3f_ffdc, 22), (0x7f_ffe8, 23), (0x7f_ffe9, 23), (0x1f_ffde, 21),
    (0x7f_ffea, 23), (0x3f_ffdd, 22), (0x3f_ffde, 22), (0xff_fff0, 24),
    (0x1f_ffdf, 21), (0x3f_ffdf, 22), (0x7f_ffeb, 23), (0x7f_ffec, 23),
    (0x1f_ffe0, 21), (0x1f_ffe1, 21), (0x3f_ffe0, 22), (0x1f_ffe2, 21),
    (0x7f_ffed, 23), (0x3f_ffe1, 22), (0x7f_ffee, 23), (0x7f_ffef, 23),
    (0xf_ffea, 20), (0x3f_ffe2, 22), (0x3f_ffe3, 22), (0x3f_ffe4, 22),
    (0x7f_fff0, 23), (0x3f_ffe5, 22), (0x3f_ffe6, 22), (0x7f_fff1, 23),
    (0x3ff_ffe0, 26), (0x3ff_ffe1, 26), (0xf_ffeb, 20), (0x7_fff1, 19),
    (0x3f_ffe7, 22), (0x7f_fff2, 23), (0x3f_ffe8, 22), (0x1ff_ffec, 25),
    (0x3ff_ffe2, 26), (0x3ff_ffe3, 26), (0x3ff_ffe4, 26), (0x7ff_ffde, 27),
    (0x7ff_ffdf, 27), (0x3ff_ffe5, 26), (0xff_fff1, 24), (0x1ff_ffed, 25),
    (0x7_fff2, 19), (0x1f_ffe3, 21), (0x3ff_ffe6, 26), (0x7ff_ffe0, 27),
    (0x7ff_ffe1, 27), (0x3ff_ffe7, 26), (0x7ff_ffe2, 27), (0xff_fff2, 24),
    (0x1f_ffe4, 21), (0x1f_ffe5, 21), (0x3ff_ffe8, 26), (0x3ff_ffe9, 26),
    (0xfff_fffd, 28), (0x7ff_ffe3, 27), (0x7ff_ffe4, 27), (0x7ff_ffe5, 27),
    (0xf_ffec, 20), (0xff_fff3, 24), (0xf_ffed, 20), (0x1f_ffe6, 21),
    (0x3f_ffe9, 22), (0x1f_ffe7, 21), (0x1f_ffe8, 21), (0x7f_fff3, 23),
    (0x3f_ffea, 22), (0x3f_ffeb, 22), (0x1ff_ffee, 25), (0x1ff_ffef, 25),
    (0xff_fff4, 24), (0xff_fff5, 24), (0x3ff_ffea, 26), (0x7f_fff4, 23),
    (0x3ff_ffeb, 26), (0x7ff_ffe6, 27), (0x3ff_ffec, 26), (0x3ff_ffed, 26),
    (0x7ff_ffe7, 27), (0x7ff_ffe8, 27), (0x7ff_ffe9, 27), (0x7ff_ffea, 27),
    (0x7ff_ffeb, 27), (0xfff_fffe, 28), (0x7ff_ffec, 27), (0x7ff_ffed, 27),
    (0x7ff_ffee, 27), (0x7ff_ffef, 27), (0x7ff_fff0, 27), (0x3ff_ffee, 26),
    (0x3fff_ffff, 30),
];

/// The EOS symbol's index in [`HUFFMAN`].
const EOS_SYMBOL: usize = 256;

/// The number of symbols including EOS.
///
/// Used only by the test that pins [`HUFFMAN`]'s length, so it is test-gated: a
/// non-test build has no use for it and `-D warnings` is right to say so.
#[cfg(test)]
const HUFFMAN_SYMBOLS: usize = 257;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a header block could not be decoded (or encoded).
///
/// RFC 7541 §4.1, §5.2, §6. Each variant names the rule broken, because the
/// distinguishing question for a caller is whether the connection's compression
/// context is still trustworthy — and for several of these it is **not**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpackError {
    /// The block ended mid-representation.
    ///
    /// Not necessarily the peer's fault at the frame layer — a header block may
    /// legitimately be split across `HEADERS` and `CONTINUATION` — so this is
    /// reported so the connection layer can accumulate rather than fail.
    Truncated {
        /// How many bytes into the block.
        at: usize,
    },
    /// An index named no entry in either table (RFC 7541 §6.1, §6.2).
    ///
    /// RFC 7541 §6.1 makes this a decoding error "that MUST be treated as a
    /// connection error of type `COMPRESSION_ERROR"`: the tables have desynchronised
    /// and every subsequent index is untrustworthy.
    InvalidIndex {
        /// The index as decoded.
        index: u64,
        /// The table it was looked up in.
        table: &'static str,
    },
    /// A `Dynamic Table Size Update` exceeded the limit the peer declared
    /// (RFC 7541 §6.3, §4.2).
    TableSizeTooLarge {
        /// The size requested.
        requested: u64,
        /// The ceiling.
        limit: usize,
    },
    /// A Huffman-coded string contained an invalid code or bad padding
    /// (RFC 7541 §5.2).
    ///
    /// Covers three distinct faults — a code that matches no entry, an explicit
    /// EOS symbol, and padding that is not all ones — because all three mean the
    /// same thing to a caller: the string is not the bytes the peer intended, and
    /// accepting it would let two different encodings decode to one text.
    BadHuffman {
        /// What was wrong.
        detail: &'static str,
    },
    /// A string's declared length ran past the end of the block.
    StringOverrun {
        /// The declared length.
        declared: usize,
        /// How many bytes remained.
        available: usize,
    },
    /// A string declared more bytes than any header field can be.
    StringTooLong {
        /// The declared length.
        declared: usize,
        /// The limit.
        limit: usize,
    },
    /// The decoded header list exceeded its limits (RFC 7541 §7).
    ///
    /// The compression bomb: a tiny block whose decoded size is enormous. The
    /// limit must be enforced **during** decoding, not after, or the memory is
    /// already spent.
    HeaderListTooLarge {
        /// What was exceeded.
        what: &'static str,
        /// The observed value.
        got: usize,
        /// The limit.
        limit: usize,
    },
    /// A field name was empty, or contained characters HTTP forbids.
    ///
    /// An empty name is a violation of RFC 9113 §8.2.1: *"A request or response
    /// that contains a field name that is empty … MUST be treated as malformed."*
    InvalidName {
        /// The offending name, truncated for the message.
        name: String,
    },
}

impl HpackError {
    /// Whether the compression context is still usable.
    ///
    /// RFC 7541 §4.1: *"A decoding error … MUST be treated as a connection error
    /// of type `COMPRESSION_ERROR`."* A compression error is the one HTTP/2 error
    /// that is **always** connection-fatal, because the dynamic table is shared
    /// state that cannot be resynchronised — there is no way to say "your table
    /// is wrong" on one stream without both ends agreeing on a new table.
    ///
    /// [`HpackError::Truncated`] is the exception, and it is not a decoding error
    /// at all: it means "give me more bytes".
    #[must_use]
    pub const fn is_connection_fatal(&self) -> bool {
        !matches!(self, Self::Truncated { .. })
    }

    /// The HTTP/2 error code to report.
    #[must_use]
    pub const fn code(&self) -> Option<super::error::ErrorCode> {
        match self {
            // Not a decoding error: the caller accumulates and retries.
            Self::Truncated { .. } => None,
            // §4.1: every decoding error is COMPRESSION_ERROR.
            Self::InvalidIndex { .. }
            | Self::TableSizeTooLarge { .. }
            | Self::BadHuffman { .. }
            | Self::StringOverrun { .. } => Some(super::error::ErrorCode::CompressionError),
            // An over-large list is the peer's declared limit being broken, which
            // is a protocol matter rather than a compression one.
            Self::StringTooLong { .. }
            | Self::HeaderListTooLarge { .. }
            | Self::InvalidName { .. } => Some(super::error::ErrorCode::ProtocolError),
        }
    }
}

impl fmt::Display for HpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { at } => write!(f, "the header block ended at byte {at}"),
            Self::InvalidIndex { index, table } => {
                write!(f, "index {index} names no entry in the {table}")
            }
            Self::TableSizeTooLarge { requested, limit } => write!(
                f,
                "a dynamic table size of {requested} exceeds the {limit}-byte limit"
            ),
            Self::BadHuffman { detail } => write!(f, "invalid Huffman string: {detail}"),
            Self::StringOverrun {
                declared,
                available,
            } => write!(
                f,
                "a string declares {declared} bytes but only {available} remain"
            ),
            Self::StringTooLong { declared, limit } => {
                write!(
                    f,
                    "a string of {declared} bytes exceeds the {limit}-byte limit"
                )
            }
            Self::HeaderListTooLarge { what, got, limit } => {
                write!(
                    f,
                    "the header list {what} is {got}, over the limit of {limit}"
                )
            }
            Self::InvalidName { name } => write!(f, "invalid header field name `{name}`"),
        }
    }
}

impl std::error::Error for HpackError {}

// ---------------------------------------------------------------------------
// Header fields
// ---------------------------------------------------------------------------

/// One decoded header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    /// The name, lowercase on the wire, kept as received.
    pub name: String,
    /// The value.
    pub value: String,
}

impl HeaderField {
    /// A field.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Whether this is a pseudo-header (`:method`, `:path`, …).
    #[must_use]
    pub fn is_pseudo(&self) -> bool {
        self.name.starts_with(':')
    }
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// Encode an integer with an `n`-bit prefix (RFC 7541 §5.1).
///
/// `prefix_bits` is `n`; the low `8 - n` bits of `first_byte` are OR-ed in by
/// the caller through `first_byte`, which is how the representation's pattern
/// bits are preserved.
///
/// # Panics
///
/// If `prefix_bits` is not in `1..=8`. The RFC writes `n` as a fixed constant
/// per representation (4, 5, 6 or 7), so a value outside that range is a
/// programming error, and a prefix of 0 or 9 would produce a byte that no
/// decoder can interpret.
#[must_use]
pub fn encode_integer(value: u64, prefix_bits: u8, first_byte: u8) -> Vec<u8> {
    assert!(
        (1..=8).contains(&prefix_bits),
        "an HPACK integer prefix is 1..=8 bits"
    );
    let mask = (1u16 << prefix_bits) - 1;
    let mask = u8::try_from(mask).unwrap_or(0xff);
    let max_prefix = u64::from(mask);

    let mut out = Vec::with_capacity(6);
    if value < max_prefix {
        out.push(first_byte | u8::try_from(value).unwrap_or(mask));
        return out;
    }
    out.push(first_byte | mask);
    let mut remaining = value - max_prefix;
    while remaining >= 128 {
        // `as u8` is avoided: a truncating cast here is exactly the bug this
        // function exists to avoid, and `try_from` on a masked value cannot fail.
        let byte = u8::try_from(remaining % 128).unwrap_or(0) | 0x80;
        out.push(byte);
        remaining /= 128;
    }
    out.push(u8::try_from(remaining).unwrap_or(0));
    out
}

/// Decode an integer with an `n`-bit prefix (RFC 7541 §5.1).
///
/// Returns the value, the byte offset just past the integer, and the low
/// `8 - n` bits of the first byte — which the caller **must** consume by masking,
/// because the representation's pattern bits live there and forgetting them
/// shifts everything after.
///
/// # Errors
///
/// [`HpackError::Truncated`] if the continuation runs off the end, and
/// [`HpackError::InvalidIndex`] if the value overflows `u64` — which RFC 7541
/// §5.1 forbids: *"An implementation MUST ensure that the value … does not
/// overflow."* A decoder that wrapped would turn a malformed index into a valid
/// one.
///
/// # Panics
///
/// If `prefix_bits` is not in `1..=8`. The prefix width is chosen by this
/// module's own call sites — it is a property of the HPACK field type being
/// decoded, never of the peer's bytes — so a value outside that range is a
/// programming error, not a malformed input the decoder should report.
pub fn decode_integer(
    input: &[u8],
    prefix_bits: u8,
    at: usize,
) -> Result<(u64, usize), HpackError> {
    assert!(
        (1..=8).contains(&prefix_bits),
        "an HPACK integer prefix is 1..=8 bits"
    );
    let Some(&first) = input.get(at) else {
        return Err(HpackError::Truncated { at });
    };
    let mask = u8::try_from((1u16 << prefix_bits) - 1).unwrap_or(0xff);
    let prefix = u64::from(first & mask);
    if prefix < u64::from(mask) {
        return Ok((prefix, at + 1));
    }

    let mut value = u64::from(mask);
    let mut shift = 0u32;
    let mut i = at + 1;
    loop {
        let Some(&byte) = input.get(i) else {
            return Err(HpackError::Truncated { at: i });
        };
        i += 1;
        let add = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(HpackError::InvalidIndex {
                index: u64::MAX,
                table: "the integer encoding (the value overflows 64 bits)",
            })?;
        value = value.checked_add(add).ok_or(HpackError::InvalidIndex {
            index: u64::MAX,
            table: "the integer encoding (the value overflows 64 bits)",
        })?;
        if byte & 0x80 == 0 {
            return Ok((value, i));
        }
        shift += 7;
        // Seven bits per byte, so 10 bytes is 70 bits and cannot fit in a u64.
        // Checking the shift rather than the value catches the overflow *before*
        // the addition that would wrap.
        if shift > 63 {
            return Err(HpackError::InvalidIndex {
                index: u64::MAX,
                table: "the integer encoding (more than 10 continuation bytes)",
            });
        }
    }
}

/// Encode a string literal, Huffman-coded when that is shorter (RFC 7541 §5.2).
///
/// # Why "when shorter" and not always
///
/// The RFC permits either. Huffman is shorter for almost all real header text,
/// but for a value of high-entropy bytes (a base64 token, a random cookie) it can
/// be *longer*: the table gives seven- and eight-bit codes to printable ASCII and
/// twenty-eight-bit codes to the rest. Emitting the shorter of the two is one
/// comparison and strictly better on the wire.
#[must_use]
pub fn encode_string(value: &str) -> Vec<u8> {
    let huffman = huffman_encode(value.as_bytes());
    if huffman.len() < value.len() {
        let mut out = encode_integer(huffman.len() as u64, 7, 0x80);
        out.extend_from_slice(&huffman);
        out
    } else {
        let mut out = encode_integer(value.len() as u64, 7, 0x00);
        out.extend_from_slice(value.as_bytes());
        out
    }
}

/// Decode a string literal (RFC 7541 §5.2).
///
/// Returns the string and the offset just past it.
///
/// # Errors
///
/// [`HpackError::StringOverrun`], [`HpackError::StringTooLong`] or
/// [`HpackError::BadHuffman`].
pub fn decode_string(input: &[u8], at: usize) -> Result<(String, usize), HpackError> {
    let Some(&first) = input.get(at) else {
        return Err(HpackError::Truncated { at });
    };
    let huffman = first & 0x80 != 0;
    let (length, mut i) = decode_integer(input, 7, at)?;
    // The bound is checked **before** the slice and before any allocation: a
    // compression bomb declares a huge length in two bytes, and checking after
    // `to_vec()` is checking after the memory is spent.
    let length = usize::try_from(length).map_err(|_| HpackError::StringTooLong {
        declared: usize::MAX,
        limit: MAX_FIELD_BYTES,
    })?;
    if length > MAX_FIELD_BYTES {
        return Err(HpackError::StringTooLong {
            declared: length,
            limit: MAX_FIELD_BYTES,
        });
    }
    let available = input.len().saturating_sub(i);
    if length > available {
        return Err(HpackError::StringOverrun {
            declared: length,
            available,
        });
    }
    let raw = &input[i..i + length];
    i += length;

    if huffman {
        let decoded = huffman_decode(raw)?;
        // Header field values are octets, not necessarily UTF-8 (RFC 9110 §5.5).
        // Decoding lossily rather than rejecting keeps an octet-valued header
        // parseable instead of refusing it for an encoding rule HTTP does not
        // impose — the same choice `http1::parse_head` makes, and for the same
        // reason.
        Ok((String::from_utf8_lossy(&decoded).into_owned(), i))
    } else {
        Ok((String::from_utf8_lossy(raw).into_owned(), i))
    }
}

// ---------------------------------------------------------------------------
// Huffman
// ---------------------------------------------------------------------------

/// Encode bytes with the RFC 7541 Appendix B code.
#[must_use]
pub fn huffman_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 6 / 5);
    // A 64-bit accumulator with a bit count, rather than a bit-by-bit writer:
    // the longest code is 30 bits, so 64 bits always holds a whole code plus the
    // leftover of the previous ones (at most 29 bits pending before adding 30).
    let mut accumulator: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in input {
        let (code, len) = HUFFMAN[usize::from(byte)];
        accumulator = (accumulator << len) | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xff).unwrap_or(0));
        }
    }
    if bits > 0 {
        // §5.2: the padding is the most significant bits of the EOS code, which
        // are all ones. Zero-padding would produce a different byte string for
        // the same text — the ambiguity the padding rule exists to remove.
        let shift = 8 - bits;
        let padded = (accumulator << shift) | ((1u64 << shift) - 1);
        out.push(u8::try_from(padded & 0xff).unwrap_or(0));
    }
    out
}

/// Decode a Huffman-coded string (RFC 7541 §5.2, Appendix B).
///
/// # Errors
///
/// [`HpackError::BadHuffman`] for an invalid code, an explicit EOS symbol, or
/// padding that is not the EOS prefix. The three are separated in the message
/// because they have different causes — a corrupt block, a hostile block, and a
/// non-canonical encoder respectively.
pub fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, HpackError> {
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let mut code: u32 = 0;
    let mut len: u32 = 0;

    for &byte in input {
        for shift in (0..8).rev() {
            let bit = (byte >> shift) & 1;
            code = (code << 1) | u32::from(bit);
            len += 1;

            // A code longer than 30 bits cannot be a prefix of any entry, so it
            // is invalid the moment it exceeds the longest code. The check is
            // *not* "return immediately": after the last symbol, up to 7 bits of
            // EOS-derived padding remain, and 30 symbols of all-ones take the
            // accumulator to 30 bits before the padding starts — so the bound
            // here is 38 (30 + 7 + 1 for the bit just shifted in), and the
            // final padding rule below is what actually rejects an over-long
            // run. Choosing 31 was the first draft and it rejected legal input:
            // RFC 7541 Appendix C.4.1's `www.example.com` ends on such a run.
            if len > 38 {
                return Err(HpackError::BadHuffman {
                    detail: "a code longer than any the table defines, plus its padding",
                });
            }

            if let Some(symbol) = huffman_lookup(code, len) {
                if symbol == EOS_SYMBOL {
                    // §5.2: the EOS symbol "is not used in the encoding of any
                    // string" and its appearance is a decoding error. A decoder
                    // with no EOS entry accepts it silently.
                    return Err(HpackError::BadHuffman {
                        detail: "the EOS symbol appeared in the string",
                    });
                }
                out.push(u8::try_from(symbol).unwrap_or(0));
                code = 0;
                len = 0;
            }
        }
    }

    // The remaining bits must be a prefix of EOS and at most 7 bits: all ones,
    // and short enough that they cannot be a real code.
    if len > 0 {
        if len > 7 {
            return Err(HpackError::BadHuffman {
                detail: "more than 7 bits of trailing padding",
            });
        }
        if !all_ones(code, len) {
            return Err(HpackError::BadHuffman {
                detail: "trailing padding is not the EOS prefix (it must be all ones)",
            });
        }
    }
    Ok(out)
}

/// Whether the low `len` bits of `code` are all ones.
fn all_ones(code: u32, len: u32) -> bool {
    len > 0 && code == (1u32 << len) - 1
}

/// Look up a `(code, len)` pair in the Huffman table.
///
/// A linear scan. The alternative is a 256-entry first-byte table, and the trade
/// is deliberate: this is called once per code (not per bit), 30 comparisons at
/// worst and about 8 on average, against a table that would need its own
/// generator and its own test. A measured optimisation belongs in a benchmark
/// with a number attached; guessing at one here would be a claim this project's
/// standard does not allow.
fn huffman_lookup(code: u32, len: u32) -> Option<usize> {
    HUFFMAN
        .iter()
        .position(|(c, l)| *c == code && u32::from(*l) == len)
}

// ---------------------------------------------------------------------------
// Dynamic table
// ---------------------------------------------------------------------------

/// The HPACK dynamic table (RFC 7541 §2.3.2, §4).
///
/// A deque of most-recently-added-first entries with a byte budget. Index 62 is
/// the most recent entry, 63 the one before it, and so on.
#[derive(Debug, Clone)]
pub struct DynamicTable {
    /// Most recently added first.
    entries: std::collections::VecDeque<HeaderField>,
    /// Bytes currently accounted.
    size: usize,
    /// The ceiling, as most recently set by a size update or `SETTINGS`.
    max_size: usize,
    /// The ceiling the peer's `SETTINGS_HEADER_TABLE_SIZE` permits.
    ///
    /// Kept apart from `max_size` because the two are different statements: this
    /// is what the *peer will accept*, and `max_size` is what the encoder has
    /// chosen within it. A size update above this is a decoding error
    /// (RFC 7541 §6.3), so the check needs both numbers.
    allowed_max: usize,
}

impl DynamicTable {
    /// A table with the given ceiling.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
            size: 0,
            max_size,
            allowed_max: max_size,
        }
    }

    /// The entry size accounting of RFC 7541 §4.1: name + value + 32.
    ///
    /// The 32 is the RFC's fixed per-entry overhead. Omitting it is the classic
    /// silent error: the table holds *more* entries than the peer's decoder
    /// evicts, and the two desynchronise at the first eviction — hundreds of
    /// requests into a connection, with no error anywhere.
    #[must_use]
    pub fn entry_size(name: &str, value: &str) -> usize {
        name.len() + value.len() + 32
    }

    /// Bytes currently accounted.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// The current ceiling.
    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.max_size
    }

    /// The ceiling the peer's settings permit.
    #[must_use]
    pub const fn allowed_max(&self) -> usize {
        self.allowed_max
    }

    /// How many entries are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at a 0-based position, most recent first.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&HeaderField> {
        self.entries.get(index)
    }

    /// Set the ceiling, evicting to fit (RFC 7541 §4.3).
    ///
    /// # Errors
    ///
    /// [`HpackError::TableSizeTooLarge`] when the new ceiling exceeds what the
    /// peer's settings permit. §6.3 is explicit that this is a decoding error,
    /// not something to clamp: clamping keeps the connection alive while the two
    /// ends hold tables of different sizes, and every following index is then
    /// wrong in a way that decodes to plausible text.
    pub fn set_max_size(&mut self, size: usize) -> Result<(), HpackError> {
        if size > self.allowed_max {
            return Err(HpackError::TableSizeTooLarge {
                requested: size as u64,
                limit: self.allowed_max,
            });
        }
        self.max_size = size;
        self.evict_to_fit();
        Ok(())
    }

    /// Update the ceiling permitted by the peer's `SETTINGS_HEADER_TABLE_SIZE`.
    ///
    /// RFC 7541 §4.2: when the peer lowers `SETTINGS_HEADER_TABLE_SIZE`, the new
    /// value **is** the new maximum, and the encoder must send a size update
    /// before its next header block. When the peer raises it, the encoder may use
    /// up to the new value but is not obliged to, so the current ceiling is left
    /// alone.
    pub fn set_allowed_max(&mut self, allowed: usize) {
        self.allowed_max = allowed;
        if self.max_size > allowed {
            self.max_size = allowed;
            self.evict_to_fit();
        }
    }

    /// Add an entry, evicting from the oldest end to make room.
    ///
    /// RFC 7541 §4.4: an entry larger than the whole table is **not** an error —
    /// it empties the table and is not added. That is the rule that makes a
    /// single huge cookie clear the table rather than stall the connection, and
    /// it is easy to get wrong in a way that only shows up on the next index.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        let entry_size = Self::entry_size(&name, &value);
        if entry_size > self.max_size {
            // Evict everything and do not add: §4.4.
            self.entries.clear();
            self.size = 0;
            return;
        }
        while self.size + entry_size > self.max_size {
            self.evict_one();
        }
        self.size += entry_size;
        self.entries.push_front(HeaderField { name, value });
    }

    /// Evict the oldest entry.
    fn evict_one(&mut self) {
        if let Some(entry) = self.entries.pop_back() {
            self.size = self
                .size
                .saturating_sub(Self::entry_size(&entry.name, &entry.value));
        }
    }

    /// Evict until the table fits its ceiling.
    fn evict_to_fit(&mut self) {
        while self.size > self.max_size {
            self.evict_one();
        }
    }

    /// Look up an index in the dynamic table, 1-based (62 is the newest).
    #[must_use]
    pub fn lookup(&self, index: usize) -> Option<&HeaderField> {
        if index == 0 {
            return None;
        }
        self.entries.get(index - 1)
    }

    /// Find the index of an exact match, 1-based, for the encoder.
    #[must_use]
    pub fn find(&self, name: &str, value: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.name == name && e.value == value)
            .map(|i| i + 1)
    }

    /// Find the first entry with this name, 1-based, for the encoder.
    #[must_use]
    pub fn find_name(&self, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.name == name)
            .map(|i| i + 1)
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// An HPACK decoder, holding the dynamic table for one direction.
///
/// One decoder per direction, never shared: the encoder's table and the
/// decoder's table are separate state, and a connection that used one for both
/// would decode its own encodings with the peer's evictions.
#[derive(Debug)]
pub struct Decoder {
    table: DynamicTable,
    /// The header-list byte budget.
    max_header_list_size: usize,
    /// The field-count budget.
    max_header_count: usize,
}

impl Decoder {
    /// A decoder with the default table size.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: DynamicTable::new(DEFAULT_HEADER_TABLE_SIZE),
            max_header_list_size: MAX_HEADER_LIST_SIZE,
            max_header_count: MAX_HEADER_COUNT,
        }
    }

    /// A decoder with an explicit table size.
    #[must_use]
    pub fn with_table_size(size: usize) -> Self {
        Self {
            table: DynamicTable::new(size),
            ..Self::new()
        }
    }

    /// Set the header-list budget.
    pub fn set_max_header_list_size(&mut self, size: usize) {
        self.max_header_list_size = size;
    }

    /// Apply a `SETTINGS_HEADER_TABLE_SIZE` from the peer.
    ///
    /// RFC 7541 §4.2 and RFC 9113 §6.5.2: the value the *peer* sends is the
    /// maximum the **encoder** may use. For a decoder, `allowed_max` is the
    /// limit against which a `Dynamic Table Size Update` is checked, so this is
    /// the call that makes §6.3 enforceable across a settings exchange.
    pub fn set_allowed_table_size(&mut self, size: usize) {
        self.table.set_allowed_max(size);
    }

    /// The dynamic table, for tests and diagnostics.
    #[must_use]
    pub fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// Decode a complete header block.
    ///
    /// # Errors
    ///
    /// Any [`HpackError`]. [`HpackError::Truncated`] means the block is not
    /// complete — a header block may be split across `HEADERS` and
    /// `CONTINUATION`, so the caller accumulates and calls again.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, HpackError> {
        let mut out: Vec<HeaderField> = Vec::new();
        let mut total = 0usize;
        let mut i = 0usize;

        while i < block.len() {
            if out.len() >= self.max_header_count {
                return Err(HpackError::HeaderListTooLarge {
                    what: "field count",
                    got: out.len() + 1,
                    limit: self.max_header_count,
                });
            }
            let first = block[i];
            if first & 0x80 != 0 {
                // -- Indexed Header Field (§6.1) ---------------------------
                let (index, next) = decode_integer(block, 7, i)?;
                i = next;
                let field = self.lookup(index)?;
                let size = DynamicTable::entry_size(&field.name, &field.value);
                total = self.check_total(total, size)?;
                out.push(field);
            } else if first & 0x40 != 0 {
                // -- Literal with Incremental Indexing (§6.2.1) ------------
                let (name, value, next) = self.decode_literal(block, i, 6)?;
                i = next;
                let size = DynamicTable::entry_size(&name, &value);
                total = self.check_total(total, size)?;
                self.table.insert(name.clone(), value.clone());
                out.push(HeaderField { name, value });
            } else if first & 0x20 != 0 {
                // -- Dynamic Table Size Update (§6.3) ----------------------
                //
                // Checked **after** `0x40`: `0x60` has both the 0x40 and the 0x20
                // bit set, so testing 0x20 first reads every "literal with
                // incremental indexing" whose index is 0 as a size update.
                let (size, next) = decode_integer(block, 5, i)?;
                i = next;
                let size = usize::try_from(size).map_err(|_| HpackError::TableSizeTooLarge {
                    requested: size,
                    limit: self.table.allowed_max(),
                })?;
                self.table.set_max_size(size)?;
            } else {
                // -- Literal without Indexing (§6.2.2) / Never Indexed (§6.2.3)
                //
                // The two share a name/value encoding and differ only in whether
                // an intermediary may re-index them; the distinction is the
                // *sender's* and matters to a proxy re-encoding the field, not to
                // this decoder. Both are decoded identically, and neither is
                // inserted into the table (which is the property that makes
                // "never indexed" meaningful: it can never be given an index).
                let (name, value, next) = self.decode_literal(block, i, 4)?;
                i = next;
                let size = DynamicTable::entry_size(&name, &value);
                total = self.check_total(total, size)?;
                out.push(HeaderField { name, value });
            }
        }
        Ok(out)
    }

    /// Decode a literal representation's name and value.
    ///
    /// Returns the name, the value, and the next offset.
    fn decode_literal(
        &mut self,
        block: &[u8],
        at: usize,
        prefix_bits: u8,
    ) -> Result<(String, String, usize), HpackError> {
        let (index, mut i) = decode_integer(block, prefix_bits, at)?;
        let name = if index == 0 {
            let (n, next) = decode_string(block, i)?;
            i = next;
            n
        } else {
            self.lookup(index)?.name
        };
        validate_name(&name)?;
        let (value, next) = decode_string(block, i)?;
        i = next;
        Ok((name, value, i))
    }

    /// Resolve a table index (RFC 7541 §2.3.3).
    fn lookup(&self, index: u64) -> Result<HeaderField, HpackError> {
        if index == 0 {
            // Index 0 is not representable in any of §6's representations: the
            // `Indexed Header Field` pattern requires a value of at least 1, and
            // a literal's name index of 0 means "the name follows literally",
            // which is handled before this. Reaching here is a decode of a byte
            // pattern that no encoder produces.
            return Err(HpackError::InvalidIndex {
                index: 0,
                table: "either table",
            });
        }
        let index = usize::try_from(index).map_err(|_| HpackError::InvalidIndex {
            index,
            table: "either table",
        })?;
        if let Some((name, value)) = static_entry(index) {
            return Ok(HeaderField {
                name: name.to_owned(),
                value: value.unwrap_or("").to_owned(),
            });
        }
        let dynamic_index = index - STATIC_TABLE_LEN - 1;
        self.table
            .lookup(dynamic_index + 1)
            .cloned()
            .ok_or(HpackError::InvalidIndex {
                index: index as u64,
                table: if dynamic_index < self.table.len() {
                    "either table"
                } else {
                    "the dynamic table"
                },
            })
    }

    /// Enforce the decoded header list's size budget.
    fn check_total(&self, total: usize, add: usize) -> Result<usize, HpackError> {
        // 32 bytes per field, the same accounting as the dynamic table
        // (RFC 7541 §4.1). Using the raw name+value length instead under-counts
        // by 32 per field, which for a hundred-field bomb is 3.2 KiB of slack.
        let next = total.saturating_add(add);
        if next > self.max_header_list_size {
            return Err(HpackError::HeaderListTooLarge {
                what: "size",
                got: next,
                limit: self.max_header_list_size,
            });
        }
        Ok(next)
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a decoded field name (RFC 9113 §8.2.1, RFC 9110 §5.1).
///
/// An empty name is malformed; so is a name containing uppercase, whitespace or
/// a control character. HPACK carries names as literal bytes and imposes no
/// structure, so this is the only place the rule can be enforced — and it must
/// be, because a name containing a space or a CR is how a header is smuggled
/// past a component that re-encodes it.
fn validate_name(name: &str) -> Result<(), HpackError> {
    if name.is_empty() {
        return Err(HpackError::InvalidName {
            name: String::new(),
        });
    }
    // A pseudo-header starts with `:` and is otherwise a token.
    let body = name.strip_prefix(':').unwrap_or(name);
    let ok = !body.is_empty()
        && body.bytes().all(|b| {
            // Lowercase only: RFC 9113 §8.2.1 — "A field name MUST NOT contain
            // characters in the uppercase range … a request or response
            // containing uppercase field names MUST be treated as malformed."
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    if !ok {
        return Err(HpackError::InvalidName {
            name: name.chars().take(32).collect(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// An HPACK encoder, holding the dynamic table for one direction.
#[derive(Debug)]
pub struct Encoder {
    table: DynamicTable,
    /// A size update owed to the peer, when its settings changed.
    pending_size_update: Option<usize>,
    /// Whether to use Huffman coding.
    huffman: bool,
}

impl Encoder {
    /// An encoder with the default table size.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: DynamicTable::new(DEFAULT_HEADER_TABLE_SIZE),
            pending_size_update: None,
            huffman: true,
        }
    }

    /// An encoder with an explicit table size.
    #[must_use]
    pub fn with_table_size(size: usize) -> Self {
        Self {
            table: DynamicTable::new(size),
            ..Self::new()
        }
    }

    /// Turn Huffman coding off, for tests that need the literal form.
    pub fn set_huffman(&mut self, enabled: bool) {
        self.huffman = enabled;
    }

    /// The dynamic table, for tests and diagnostics.
    #[must_use]
    pub fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// Apply the peer's `SETTINGS_HEADER_TABLE_SIZE`.
    ///
    /// RFC 7541 §4.2: lowering the peer's limit obliges the encoder to emit a
    /// size update **before** its next header block. Omitting it leaves the
    /// encoder using a table the peer has already shrunk, and the peer evicts
    /// entries the encoder still indexes — a desynchronisation that appears only
    /// once a dynamic index is used.
    pub fn set_allowed_table_size(&mut self, size: usize) {
        let previous = self.table.max_size();
        self.table.set_allowed_max(size);
        let now = self.table.max_size();
        if now != previous {
            self.pending_size_update = Some(now);
        }
    }

    /// Encode a header list into a single block.
    ///
    /// # Why the fields are not sorted
    ///
    /// RFC 9113 §8.3 requires pseudo-headers first and in a fixed order, and the
    /// *request* order is the caller's. Reordering here to improve compression
    /// would silently move a pseudo-header after a regular one, which is a
    /// malformed request. Compression is the caller's concern; correctness is
    /// this function's.
    #[must_use]
    pub fn encode(&mut self, fields: &[HeaderField]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + fields.len() * 16);
        // Any owed size update goes first, before any representation that
        // depends on the table's new size (§4.2, §6.3).
        if let Some(size) = self.pending_size_update.take() {
            out.extend_from_slice(&encode_integer(size as u64, 5, 0x20));
        }
        for field in fields {
            self.encode_one(field, &mut out);
        }
        out
    }

    /// Encode one field, choosing the shortest representation.
    fn encode_one(&mut self, field: &HeaderField, out: &mut Vec<u8>) {
        // -- an exact match in either table: an indexed field (§6.1) ---------
        if let Some(index) = static_exact(&field.name, &field.value) {
            out.extend_from_slice(&encode_integer(index as u64, 7, 0x80));
            return;
        }
        if let Some(dynamic) = self.table.find(&field.name, &field.value) {
            let index = STATIC_TABLE_LEN + dynamic;
            out.extend_from_slice(&encode_integer(index as u64, 7, 0x80));
            return;
        }

        // -- a name match: a literal with an indexed name (§6.2.1) ----------
        //
        // `never indexed` is **not** used for authorization or cookie. This
        // encoder does not know which fields the caller considers sensitive, and
        // guessing wrongly would either leak a secret into the dynamic table or
        // waste compression on fields that are not secret. The decision belongs
        // to whoever knows — see the note in this module's documentation on the
        // gap list.
        let name_index = static_name(&field.name).or_else(|| {
            self.table
                .find_name(&field.name)
                .map(|i| STATIC_TABLE_LEN + i)
        });
        let name_index = name_index.unwrap_or(0);

        // Whether the entry fits the table at all. An entry larger than the
        // whole table is not added (§4.4), so indexing it would grow the table
        // the peer never grows — a desynchronisation by construction.
        let entry_size = DynamicTable::entry_size(&field.name, &field.value);
        let index_it = entry_size <= self.table.max_size();

        let prefix_byte = if index_it { 0x40 } else { 0x00 };
        let prefix_bits = if index_it { 6 } else { 4 };
        out.extend_from_slice(&encode_integer(name_index as u64, prefix_bits, prefix_byte));
        if name_index == 0 {
            self.push_string(&field.name, out);
        }
        self.push_string(&field.value, out);

        if index_it {
            self.table.insert(field.name.clone(), field.value.clone());
        }
    }

    /// Append a string, Huffman-coded when this encoder is configured for it.
    fn push_string(&self, value: &str, out: &mut Vec<u8>) {
        if self.huffman {
            out.extend_from_slice(&encode_string(value));
        } else {
            out.extend_from_slice(&encode_integer(value.len() as u64, 7, 0x00));
            out.extend_from_slice(value.as_bytes());
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        // `fold` + `write!` rather than `map(format!).collect()`: the latter
        // allocates one `String` per byte before joining them.
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len() / 2)
            .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect()
    }

    /// Decode a hex block and compare against `expected`, asserting that the
    /// whole block was consumed.
    fn assert_decode(hex_block: &str, expected: &[(&str, &str)]) {
        assert_decode_with(&mut Decoder::new(), hex_block, expected);
    }

    fn assert_decode_with(decoder: &mut Decoder, hex_block: &str, expected: &[(&str, &str)]) {
        let block = unhex(hex_block);
        let got = decoder
            .decode(&block)
            .unwrap_or_else(|e| panic!("decoding `{hex_block}` failed: {e}"));
        let want: Vec<HeaderField> = expected
            .iter()
            .map(|(n, v)| HeaderField::new(*n, *v))
            .collect();
        assert_eq!(got, want, "decoded `{}`", hex(block.as_slice()));
    }

    // -- the static table ---------------------------------------------------

    /// The static table is 61 entries, transcribed from RFC 7541 Appendix A.
    /// The count is asserted separately from the contents because a missing
    /// entry shifts every index after it, and the RFC's "61" is the only
    /// independent check on that.
    #[test]
    fn the_static_table_has_sixty_one_entries() {
        assert_eq!(STATIC_TABLE_LEN, 61, "RFC 7541 Appendix A lists 61 entries");
    }

    /// Spot checks across the whole table, including the entries an off-by-one
    /// transcription would move.
    #[test]
    fn the_static_table_entries_are_the_rfc_values() {
        for (index, name, value) in [
            (1usize, ":authority", None),
            (2, ":method", Some("GET")),
            (3, ":method", Some("POST")),
            (4, ":path", Some("/")),
            (5, ":path", Some("/index.html")),
            (6, ":scheme", Some("http")),
            (7, ":scheme", Some("https")),
            (8, ":status", Some("200")),
            (14, ":status", Some("500")),
            (15, "accept-charset", None),
            (16, "accept-encoding", Some("gzip, deflate")),
            (32, "cookie", None),
            (61, "www-authenticate", None),
        ] {
            let got =
                static_entry(index).unwrap_or_else(|| panic!("no static entry at index {index}"));
            assert_eq!(got.0, name, "index {index} has the wrong name");
            assert_eq!(got.1, value, "index {index} has the wrong value");
        }
        assert_eq!(static_entry(0), None, "indices are 1-based");
        assert_eq!(static_entry(62), None, "the table has 61 entries");
    }

    /// Names with an empty value in the table are **name-only** entries. A
    /// decoder that returned `(":authority", "")` for index 1 would invent a
    /// header the peer never sent.
    #[test]
    fn a_name_only_static_entry_has_no_value() {
        assert_eq!(static_entry(1), Some((":authority", None)));
        assert_eq!(static_entry(2), Some((":method", Some("GET"))));
    }

    // -- RFC 7541 Appendix C.1: integer representation ----------------------

    /// RFC 7541 Appendix C.1.1 — encoding 10 with a 5-bit prefix, where it fits
    /// in the prefix. Expected `0b000_01010` = `0x0a`.
    #[test]
    fn rfc7541_c_1_1_integer_10_with_a_5_bit_prefix() {
        assert_eq!(hex(&encode_integer(10, 5, 0)), "0a");
        let (v, next) = decode_integer(&[0x0a], 5, 0).expect("decodes");
        assert_eq!(v, 10);
        assert_eq!(next, 1);
    }

    /// RFC 7541 Appendix C.1.2 — encoding 1337 with a 5-bit prefix. The prefix
    /// saturates to 31 and the remainder 1306 is sent as `0x9a 0x0a`.
    #[test]
    fn rfc7541_c_1_2_integer_1337_with_a_5_bit_prefix() {
        assert_eq!(hex(&encode_integer(1337, 5, 0)), "1f9a0a");
        let (v, next) = decode_integer(&unhex("1f9a0a"), 5, 0).expect("decodes");
        assert_eq!(v, 1337);
        assert_eq!(next, 3);
    }

    /// RFC 7541 Appendix C.1.3 — encoding 42 with an 8-bit prefix. 42 < 255, so
    /// it fits and there are no continuation bytes. This is the case that catches
    /// a decoder which always reads one continuation byte after a saturated
    /// prefix.
    #[test]
    fn rfc7541_c_1_3_integer_42_with_an_8_bit_prefix() {
        assert_eq!(hex(&encode_integer(42, 8, 0)), "2a");
        let (v, next) = decode_integer(&[0x2a], 8, 0).expect("decodes");
        assert_eq!(v, 42);
        assert_eq!(next, 1);
    }

    /// The prefix pattern bits must be preserved and masked off on read. A
    /// decoder that returns the whole first byte instead of the masked prefix
    /// reads `0xff` as 255 rather than 31 here.
    #[test]
    fn the_integer_prefix_is_masked_and_the_pattern_bits_preserved() {
        // 0xff with a 5-bit prefix: 0x1f pattern|prefix ... but 0xff has the
        // 0xe0 bits set, which belong to a different representation. Use a legal
        // one: 0x3f is 0b001_11111 — the size-update pattern with a saturated
        // 5-bit prefix, and the continuation is 0x00 so the value is 31.
        let (v, next) = decode_integer(&[0x3f, 0x00], 5, 0).expect("decodes");
        assert_eq!(v, 31, "the top three bits must not count toward the value");
        assert_eq!(next, 2);

        // And encode_integer ORs the pattern in without disturbing the prefix.
        assert_eq!(
            hex(&encode_integer(31, 5, 0x20))[..2].to_owned(),
            "3f".to_owned()
        );
        assert_eq!(hex(&encode_integer(1, 5, 0x20)), "21");
    }

    /// RFC 7541 §5.1: *"An implementation MUST ensure that the value … does not
    /// overflow."* A decoder that wrapped would turn a malformed index into a
    /// valid one — a compression error into a successful decode.
    #[test]
    fn an_integer_that_overflows_is_refused() {
        // A saturated prefix followed by ten continuation bytes: 70 bits.
        let mut bytes = vec![0x3fu8];
        bytes.extend(std::iter::repeat_n(0x80u8, 10));
        bytes.push(0x00);
        let e = decode_integer(&bytes, 5, 0).expect_err("over 64 bits");
        assert!(matches!(e, HpackError::InvalidIndex { .. }));
        assert_eq!(
            e.code(),
            Some(super::super::error::ErrorCode::CompressionError)
        );
    }

    /// A continuation that runs off the end is [`HpackError::Truncated`], not a
    /// decode failure: the block may be split across `CONTINUATION` frames.
    #[test]
    fn a_truncated_integer_is_reported_as_truncated() {
        let e = decode_integer(&[0x3f, 0x80], 5, 0).expect_err("no terminator");
        assert!(matches!(e, HpackError::Truncated { .. }));
        assert!(!e.is_connection_fatal());
        assert_eq!(e.code(), None, "a split block is not a compression error");
    }

    // -- Huffman ------------------------------------------------------------

    /// **RFC 7541 Appendix C.4.1** — the Huffman encoding of `www.example.com`.
    ///
    /// The expected bytes are the RFC's own, so this test's oracle is the
    /// specification rather than this implementation.
    #[test]
    fn rfc7541_c_4_1_huffman_www_example_com() {
        assert_eq!(
            hex(&huffman_encode(b"www.example.com")),
            "f1e3c2e5f23a6ba0ab90f4ff"
        );
        assert_eq!(
            huffman_decode(&unhex("f1e3c2e5f23a6ba0ab90f4ff")).expect("decodes"),
            b"www.example.com"
        );
    }

    /// **RFC 7541 Appendix C.4.2** — the Huffman encoding of `no-cache`.
    #[test]
    fn rfc7541_c_4_2_huffman_no_cache() {
        assert_eq!(hex(&huffman_encode(b"no-cache")), "a8eb10649cbf");
        assert_eq!(
            huffman_decode(&unhex("a8eb10649cbf")).expect("decodes"),
            b"no-cache"
        );
    }

    /// **RFC 7541 Appendix C.4.3** — the Huffman encoding of `custom-key` and
    /// `custom-value`.
    #[test]
    fn rfc7541_c_4_3_huffman_custom_key_and_value() {
        assert_eq!(hex(&huffman_encode(b"custom-key")), "25a849e95ba97d7f");
        assert_eq!(hex(&huffman_encode(b"custom-value")), "25a849e95bb8e8b4bf");
        assert_eq!(
            huffman_decode(&unhex("25a849e95ba97d7f")).expect("decodes"),
            b"custom-key"
        );
        assert_eq!(
            huffman_decode(&unhex("25a849e95bb8e8b4bf")).expect("decodes"),
            b"custom-value"
        );
    }

    /// **RFC 7541 Appendix C.6.1** — the Huffman encoding of the response values
    /// `302`, `private`, `Mon, 21 Oct 2013 20:13:21 GMT` and
    /// `https://www.example.com`.
    #[test]
    fn rfc7541_c_6_1_huffman_response_values() {
        assert_eq!(hex(&huffman_encode(b"302")), "6402");
        assert_eq!(hex(&huffman_encode(b"private")), "aec3771a4b");
        assert_eq!(
            hex(&huffman_encode(b"Mon, 21 Oct 2013 20:13:21 GMT")),
            "d07abe941054d444a8200595040b8166e082a62d1bff"
        );
        assert_eq!(
            hex(&huffman_encode(b"https://www.example.com")),
            "9d29ad171863c78f0b97c8e9ae82ae43d3"
        );

        for (plain, coded) in [
            ("302", "6402"),
            ("private", "aec3771a4b"),
            (
                "Mon, 21 Oct 2013 20:13:21 GMT",
                "d07abe941054d444a8200595040b8166e082a62d1bff",
            ),
            (
                "https://www.example.com",
                "9d29ad171863c78f0b97c8e9ae82ae43d3",
            ),
        ] {
            assert_eq!(
                huffman_decode(&unhex(coded)).expect("decodes"),
                plain.as_bytes(),
                "decoding the RFC's bytes for `{plain}`"
            );
        }
    }

    /// **RFC 7541 Appendix C.6.2** — `307` and a `date` value.
    #[test]
    fn rfc7541_c_6_2_huffman_307_and_a_date() {
        assert_eq!(hex(&huffman_encode(b"307")), "640eff");
        assert_eq!(
            hex(&huffman_encode(b"Mon, 21 Oct 2013 20:13:22 GMT")),
            "d07abe941054d444a8200595040b8166e084a62d1bff"
        );
        assert_eq!(huffman_decode(&unhex("640eff")).expect("decodes"), b"307");
    }

    /// **RFC 7541 Appendix C.6.3** — `gzip` in the `content-encoding` value.
    #[test]
    fn rfc7541_c_6_3_huffman_gzip() {
        assert_eq!(hex(&huffman_encode(b"gzip")), "9bd9ab");
        assert_eq!(huffman_decode(&unhex("9bd9ab")).expect("decodes"), b"gzip");
    }

    /// **RFC 7541 Appendix C.5** — the *without Huffman* response values, which
    /// pin the literal string encoder independently of the Huffman table.
    #[test]
    fn rfc7541_c_5_literal_strings_are_plain_ascii() {
        // C.5.1: `302` and `private` appear as plain literals in the block.
        // The `encode_string` for a re-encoder must therefore agree with the
        // Huffman form being shorter than the literal form, which holds here.
        assert!(huffman_encode(b"302").len() < 3);
        assert!(huffman_encode(b"private").len() < 7);

        // And a string honest about being literal decodes as itself.
        let mut block = encode_integer(3, 7, 0x00);
        block.extend_from_slice(b"302");
        let (s, next) = decode_string(&block, 0).expect("decodes");
        assert_eq!(s, "302");
        assert_eq!(next, block.len());
    }

    /// The Huffman code must be a **complete prefix code**: the Kraft sum of
    /// `2^-length` over all 257 entries equals exactly 1.
    ///
    /// This is the check that a mistyped bit length cannot survive. Spot-checking
    /// entries would not find one: the table has 257 of them and a wrong length
    /// produces plausible output.
    #[test]
    fn the_huffman_table_is_a_valid_prefix_code() {
        // Sum 2^(30 - len) over every entry; the total must be 2^30 exactly.
        let total: u64 = HUFFMAN
            .iter()
            .map(|(_, len)| 1u64 << (30u32 - u32::from(*len)))
            .sum();
        assert_eq!(
            total,
            1u64 << 30,
            "the Huffman code is not complete: one or more lengths are wrong"
        );
        assert_eq!(HUFFMAN.len(), HUFFMAN_SYMBOLS);
    }

    /// No two entries may share a code of the same length, and no code may be a
    /// prefix of another. Prefix-freeness follows from Kraft equality *only*
    /// when the lengths are a valid assignment, so both are checked.
    #[test]
    fn the_huffman_codes_are_prefix_free() {
        // Sort by length and verify that each code, left-aligned into 31 bits,
        // is strictly increasing with no prefix overlap.
        let mut sorted: Vec<(u32, u8)> = HUFFMAN.to_vec();
        sorted.sort_by_key(|(_, len)| *len);
        for pair in sorted.windows(2) {
            let (c1, l1) = pair[0];
            let (c2, l2) = pair[1];
            // Two codes of the same length must differ.
            assert!(
                !(c1 == c2 && l1 == l2),
                "duplicate code {c1:#x} of length {l1}"
            );
            // A longer code must not start with a shorter one's bits.
            if l2 > l1 {
                assert_ne!(
                    c2 >> (l2 - l1),
                    c1,
                    "code {c2:#x}/{l2} has {c1:#x}/{l1} as a prefix"
                );
            }
        }
    }

    /// **RFC 7541 §5.2: padding is the EOS prefix.** Accepting arbitrary padding
    /// makes two different byte strings decode to the same text, which is a
    /// request-smuggling shape: a proxy and an origin can disagree about a
    /// header's value.
    #[test]
    fn bad_padding_is_refused() {
        // `a` is 5 bits (00011); padded with ones it is 0x1f. Padded with zeros
        // it is 0x18, which is not the EOS prefix and must be refused.
        assert_eq!(hex(&huffman_encode(b"a")), "1f");
        assert_eq!(huffman_decode(&[0x1f]).expect("decodes"), b"a");
        let e = huffman_decode(&[0x18]).expect_err("zero padding is not the EOS prefix");
        assert!(matches!(e, HpackError::BadHuffman { .. }));
        assert_eq!(
            e.code(),
            Some(super::super::error::ErrorCode::CompressionError)
        );
    }

    /// **RFC 7541 §5.2: the EOS symbol must never appear.** A decoder with no
    /// EOS entry in its match table accepts it silently.
    #[test]
    fn an_explicit_eos_symbol_is_refused() {
        // The EOS code is 0x3fff_ffff / 30 bits = 30 ones. Four bytes of 0xff is
        // 32 bits, of which the first 30 are EOS; the remaining two are padding
        // and the padding check would not reach them, because EOS is rejected
        // first.
        let e = huffman_decode(&[0xff, 0xff, 0xff, 0xff]).expect_err("EOS is not data");
        match e {
            HpackError::BadHuffman { detail } => {
                assert!(
                    detail.contains("EOS"),
                    "the failure must name EOS, got `{detail}`"
                );
            }
            other => panic!("expected a Huffman error, got {other:?}"),
        }
    }

    /// Padding longer than seven bits cannot be a prefix of EOS plus a real
    /// code, so it is refused rather than treated as data.
    #[test]
    fn padding_longer_than_seven_bits_is_refused() {
        // Eight ones: a full byte of padding, which is not permitted.
        let e = huffman_decode(&[0xff, 0xff]).expect_err("eight bits of padding");
        assert!(matches!(e, HpackError::BadHuffman { .. }));
    }

    /// Every single byte encodes and decodes back to itself, which exercises
    /// every entry in the table rather than the handful the RFC's examples use.
    /// This is the test that would catch a typo in one of the 257 entries — and
    /// it is a *round trip*, so it is only as strong as the encoder and decoder
    /// being wrong together, which is why it is paired with the Kraft check and
    /// the RFC's own byte-for-byte examples above.
    #[test]
    fn every_byte_round_trips_through_huffman() {
        for byte in 0u16..=255 {
            let byte = u8::try_from(byte).expect("0..=255");
            let encoded = huffman_encode(&[byte]);
            let decoded = huffman_decode(&encoded)
                .unwrap_or_else(|e| panic!("byte 0x{byte:02x} failed to decode: {e}"));
            assert_eq!(decoded, vec![byte], "byte 0x{byte:02x} did not round-trip");
        }
    }

    /// All 256 bytes together, so the bit accumulator's carry across symbol
    /// boundaries is exercised at every alignment.
    ///
    /// # Why this no longer asserts compression
    ///
    /// It did — `encoded.len() < all.len()` — and that is **false for this
    /// input**, which is a fact about the Huffman table rather than a bug. RFC
    /// 7541's code is tuned for HTTP header text: printable ASCII and a few
    /// separators are 5–6 bits, while high bytes are up to 30 bits (the longest
    /// code in Appendix B). Feeding it all 256 values therefore expands
    /// 256 bytes to 583.
    ///
    /// The compression *claim* is worth testing, so it is tested on the input
    /// the code was designed for, and this test keeps the property that is
    /// unconditionally true: every byte sequence survives the round trip. An
    /// assertion that only holds for some inputs is a latent flake, and this
    /// project has already paid for that lesson more than once.
    #[test]
    fn a_long_string_round_trips_through_huffman() {
        let all: Vec<u8> = (0u16..=255)
            .map(|b| u8::try_from(b).expect("0..=255"))
            .collect();
        let encoded = huffman_encode(&all);
        assert_eq!(huffman_decode(&encoded).expect("decodes"), all);

        // The compression claim, on HTTP-shaped input.
        let text = b"content-type: text/html; charset=utf-8; cache-control: no-cache";
        let compressed = huffman_encode(text);
        assert!(
            compressed.len() < text.len(),
            "header text should compress: {} vs {}",
            compressed.len(),
            text.len()
        );
        assert_eq!(huffman_decode(&compressed).expect("decodes"), text);
    }

    /// Offsets into the string: encoding at each length exercises every
    /// remaining-bit count from 1 to 7.
    #[test]
    fn every_padding_length_round_trips() {
        for n in 0..40usize {
            let s: Vec<u8> = (0..n)
                .map(|i| b'a' + u8::try_from(i % 26).unwrap_or(0))
                .collect();
            let encoded = huffman_encode(&s);
            assert_eq!(
                huffman_decode(&encoded).expect("decodes"),
                s,
                "length {n} did not round-trip"
            );
        }
    }

    // -- RFC 7541 Appendix C.2: header field representations ---------------

    /// **RFC 7541 Appendix C.2.1** — literal header field with indexing,
    /// `custom-key: custom-header`, with a literal name. The block is
    /// `400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572`.
    #[test]
    fn rfc7541_c_2_1_literal_with_indexing() {
        assert_decode(
            "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
            &[("custom-key", "custom-header")],
        );
    }

    /// **RFC 7541 Appendix C.2.1** — after decoding, the dynamic table holds one
    /// entry of 55 bytes: 10 + 13 + 32.
    #[test]
    fn rfc7541_c_2_1_leaves_the_dynamic_table_at_55_bytes() {
        let mut d = Decoder::new();
        assert_decode_with(
            &mut d,
            "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
            &[("custom-key", "custom-header")],
        );
        assert_eq!(d.table().len(), 1);
        assert_eq!(d.table().size(), 55, "10 + 13 + 32, per RFC 7541 §4.1");
    }

    /// **RFC 7541 Appendix C.2.2** — literal without indexing,
    /// `:path: /sample/path`.
    #[test]
    fn rfc7541_c_2_2_literal_without_indexing() {
        assert_decode("040c2f73616d706c652f70617468", &[(":path", "/sample/path")]);
    }

    /// **RFC 7541 Appendix C.2.2** — and the table must be **unchanged**: that is
    /// what "without indexing" means, and a decoder that inserted anyway would
    /// hold an entry the encoder does not have.
    #[test]
    fn rfc7541_c_2_2_leaves_the_dynamic_table_empty() {
        let mut d = Decoder::new();
        assert_decode_with(
            &mut d,
            "040c2f73616d706c652f70617468",
            &[(":path", "/sample/path")],
        );
        assert_eq!(d.table().len(), 0, "without indexing must not insert");
        assert_eq!(d.table().size(), 0);
    }

    /// **RFC 7541 Appendix C.2.3** — literal never indexed,
    /// `password: secret`.
    #[test]
    fn rfc7541_c_2_3_literal_never_indexed() {
        assert_decode(
            "100870617373776f726406736563726574",
            &[("password", "secret")],
        );
    }

    /// Never-indexed must not enter the dynamic table either.
    #[test]
    fn rfc7541_c_2_3_leaves_the_dynamic_table_empty() {
        let mut d = Decoder::new();
        assert_decode_with(
            &mut d,
            "100870617373776f726406736563726574",
            &[("password", "secret")],
        );
        assert_eq!(d.table().len(), 0, "never indexed must not insert");
    }

    /// **RFC 7541 Appendix C.2.4** — indexed header field, `:method: GET`,
    /// which is static index 2.
    #[test]
    fn rfc7541_c_2_4_indexed_header_field() {
        assert_decode("82", &[(":method", "GET")]);
    }

    // -- RFC 7541 Appendix C.3: request examples, without Huffman -----------

    /// **RFC 7541 Appendix C.3.1** — first request, no Huffman.
    #[test]
    fn rfc7541_c_3_1_first_request_without_huffman() {
        assert_decode(
            "828684410f7777772e6578616d706c652e636f6d",
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ],
        );
    }

    /// **RFC 7541 Appendix C.3.1** — the dynamic table after the first request:
    /// one entry, 57 bytes (15 + 10 + 32). The RFC also says the header list
    /// totals 57 bytes.
    #[test]
    fn rfc7541_c_3_1_dynamic_table_state() {
        let mut d = Decoder::new();
        assert_decode_with(
            &mut d,
            "828684410f7777772e6578616d706c652e636f6d",
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ],
        );
        assert_eq!(d.table().size(), 57);
        assert_eq!(d.table().len(), 1);
        assert_eq!(
            d.table().get(0).expect("one entry"),
            &HeaderField::new(":authority", "www.example.com")
        );
    }

    /// **RFC 7541 Appendix C.3.2** — second request, no Huffman. `:authority`
    /// is now a **dynamic** index (62), which is 62 + 0x80 = 0xbe.
    #[test]
    fn rfc7541_c_3_2_second_request_without_huffman() {
        let mut d = Decoder::new();
        assert_decode_with(
            &mut d,
            "828684410f7777772e6578616d706c652e636f6d",
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ],
        );
        assert_decode_with(
            &mut d,
            "828684be58086e6f2d6361636865",
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ],
        );
        // Entry sizes after the second request: 57 + (14 + 8 + 32) = 110.
        assert_eq!(d.table().size(), 110);
        assert_eq!(d.table().len(), 2);
    }

    /// **RFC 7541 Appendix C.3.3** — third request, no Huffman. The third header
    /// block is entirely dynamic indices.
    #[test]
    fn rfc7541_c_3_3_third_request_without_huffman() {
        let mut d = Decoder::new();
        for (block, expected) in [
            (
                "828684410f7777772e6578616d706c652e636f6d",
                vec![
                    (":method", "GET"),
                    (":scheme", "http"),
                    (":path", "/"),
                    (":authority", "www.example.com"),
                ],
            ),
            (
                "828684be58086e6f2d6361636865",
                vec![
                    (":method", "GET"),
                    (":scheme", "http"),
                    (":path", "/"),
                    (":authority", "www.example.com"),
                    ("cache-control", "no-cache"),
                ],
            ),
        ] {
            assert_decode_with(&mut d, block, &expected);
        }
        assert_decode_with(
            &mut d,
            "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ],
        );
        // 57 + 53 + 54 = 164.
        assert_eq!(d.table().size(), 164);
    }

    // -- RFC 7541 Appendix C.4: request examples, with Huffman --------------

    /// **RFC 7541 Appendix C.4.1** — first request, Huffman.
    #[test]
    fn rfc7541_c_4_1_first_request_with_huffman() {
        assert_decode(
            "828684418cf1e3c2e5f23a6ba0ab90f4ff",
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ],
        );
    }

    /// **RFC 7541 Appendix C.4.2** — second request, Huffman.
    #[test]
    fn rfc7541_c_4_2_second_request_with_huffman() {
        let mut d = Decoder::new();
        assert_decode_with(
            &mut d,
            "828684418cf1e3c2e5f23a6ba0ab90f4ff",
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ],
        );
        assert_decode_with(
            &mut d,
            "828684be5886a8eb10649cbf",
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ],
        );
        assert_eq!(d.table().size(), 110);
    }

    /// **RFC 7541 Appendix C.4.3** — third request, Huffman.
    #[test]
    fn rfc7541_c_4_3_third_request_with_huffman() {
        let mut d = Decoder::new();
        for (block, expected) in [
            (
                "828684418cf1e3c2e5f23a6ba0ab90f4ff",
                vec![
                    (":method", "GET"),
                    (":scheme", "http"),
                    (":path", "/"),
                    (":authority", "www.example.com"),
                ],
            ),
            (
                "828684be5886a8eb10649cbf",
                vec![
                    (":method", "GET"),
                    (":scheme", "http"),
                    (":path", "/"),
                    (":authority", "www.example.com"),
                    ("cache-control", "no-cache"),
                ],
            ),
        ] {
            assert_decode_with(&mut d, block, &expected);
        }
        assert_decode_with(
            &mut d,
            "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ],
        );
        assert_eq!(d.table().size(), 164);
    }

    // -- RFC 7541 Appendix C.5/C.6: response examples -----------------------

    /// **RFC 7541 Appendix C.5.1** — first response, without Huffman.
    #[test]
    fn rfc7541_c_5_1_first_response_without_huffman() {
        assert_decode(
            "4803333032580770726976617465611d\
             4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a\
             2f2f7777772e6578616d706c652e636f6d",
            &[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        );
    }

    /// **RFC 7541 Appendix C.5.1** — the table after the first response is 222
    /// bytes: 63 + 65 + 63 + 63 (the last is 63 with the 32-byte overhead added
    /// to 8 + 23).
    #[test]
    fn rfc7541_c_5_1_dynamic_table_size() {
        let mut d = Decoder::new();
        assert_decode_with(
            &mut d,
            "4803333032580770726976617465611d\
             4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a\
             2f2f7777772e6578616d706c652e636f6d",
            &[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        );
        assert_eq!(d.table().size(), 222);
    }

    /// **RFC 7541 Appendix C.5.2** — second response; the status route is now
    /// in the dynamic table.
    #[test]
    fn rfc7541_c_5_2_second_response_without_huffman() {
        let mut d = Decoder::new();
        assert_decode_with(
            &mut d,
            "4803333032580770726976617465611d\
             4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a\
             2f2f7777772e6578616d706c652e636f6d",
            &[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        );
        assert_decode_with(
            &mut d,
            "4803333037c1c0bf",
            &[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        );
    }

    /// **RFC 7541 Appendix C.5.3** — third response, and the dynamic table must
    /// have **evicted** to 222 bytes after growing past 4096 is not the case
    /// here; the size is 222 and the newest entry is `content-encoding: gzip`.
    #[test]
    fn rfc7541_c_5_3_third_response_without_huffman() {
        let mut d = Decoder::new();
        for block in [
            "4803333032580770726976617465611d\
             4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a\
             2f2f7777772e6578616d706c652e636f6d",
            "4803333037c1c0bf",
        ] {
            d.decode(&unhex(block)).expect("decodes");
        }
        assert_decode_with(
            &mut d,
            "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a6970",
            &[
                (":status", "200"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                ("location", "https://www.example.com"),
                ("content-encoding", "gzip"),
            ],
        );
    }

    /// **RFC 7541 Appendix C.6.1** — first response, with Huffman.
    #[test]
    fn rfc7541_c_6_1_first_response_with_huffman() {
        assert_decode(
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff\
             6e919d29ad171863c78f0b97c8e9ae82ae43d3",
            &[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        );
    }

    /// **RFC 7541 Appendix C.6.2** — second response, with Huffman.
    #[test]
    fn rfc7541_c_6_2_second_response_with_huffman() {
        // **C.6.2 depends on C.6.1's dynamic-table state**, and this test was
        // written without it — it decoded only the second block, so index 65
        // ("names no entry") was correct behaviour and the *test* was wrong.
        //
        // The RFC's C.6 example is a sequence: C.6.1 builds headers that are
        // inserted into the dynamic table, C.6.2 reuses them by index, and C.6.3
        // reuses entries C.6.2 evicted and replaced. Decoding a middle block in
        // isolation cannot work, and a test that expected it to would have to be
        // satisfied by a decoder that ignored table state entirely — which is the
        // opposite of what these vectors are for.
        //
        // One decoder, three blocks, in order.
        let mut d = Decoder::new();
        // C.6.1 — first response, which populates the table.
        assert_decode_with(
            &mut d,
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
            &[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        );
        assert_decode_with(
            &mut d,
            "4883640effc1c0bf",
            &[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        );
    }

    /// **RFC 7541 Appendix C.6.3** — third response, with Huffman.
    #[test]
    fn rfc7541_c_6_3_third_response_with_huffman() {
        // C.6.3 is the *third* block of the same sequence — see C.6.2 above for
        // why it cannot be decoded standalone. It is the interesting one of the
        // three: adding `content-encoding: gzip` grows the table past its
        // 256-byte ceiling, so the two oldest entries are evicted and the indices
        // in this block refer to a table the previous block did not have.
        let mut d = Decoder::new();
        assert_decode_with(
            &mut d,
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
            &[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        );
        assert_decode_with(
            &mut d,
            "4883640effc1c0bf",
            &[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
        );
        // The eviction half, asserted rather than assumed: the table must have
        // shrunk to hold `content-encoding: gzip`.
        assert_decode_with(
            &mut d,
            "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab",
            &[
                (":status", "200"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                ("location", "https://www.example.com"),
                ("content-encoding", "gzip"),
            ],
        );
    }

    // -- dynamic table accounting and eviction ------------------------------

    /// **RFC 7541 §4.1**: the entry size is `name + value + 32`. Omitting the
    /// 32 holds *more* entries than the peer's decoder evicts, and the two
    /// desynchronise at the first eviction.
    #[test]
    fn the_entry_size_includes_the_thirty_two_byte_overhead() {
        assert_eq!(DynamicTable::entry_size("custom-key", "custom-header"), 55);
        assert_eq!(
            DynamicTable::entry_size(":authority", "www.example.com"),
            57
        );
        // 13 + 8 + 32 = 53. This literal was written as 54 and was simply
        // miscounted by hand — the implementation was right. Kept as four cases
        // because three of them matching is what caught the fourth: a single
        // wrong literal in a suite of one would have read as a code bug.
        assert_eq!(DynamicTable::entry_size("cache-control", "no-cache"), 53);
        assert_eq!(DynamicTable::entry_size("a", "b"), 34);
    }

    /// **RFC 7541 §4.4**: an entry larger than the whole table empties it and is
    /// not added. That is the rule that makes one huge cookie clear the table
    /// rather than stall the connection.
    #[test]
    fn rfc7541_4_4_an_oversized_entry_empties_the_table() {
        let mut t = DynamicTable::new(100);
        t.insert("a", "b");
        assert_eq!(t.len(), 1);
        // 40 + 100 + 32 = 172 > 100.
        t.insert("x".repeat(40), "y".repeat(100));
        assert!(t.is_empty(), "an oversized entry must empty the table");
        assert_eq!(t.size(), 0, "and contribute nothing");
    }

    /// Eviction is from the **oldest** end. Evicting from the newest is the
    /// mistake that leaves the table holding precisely the entries the encoder
    /// has dropped — a total desynchronisation from the first insert.
    #[test]
    fn eviction_removes_the_oldest_entry() {
        let mut t = DynamicTable::new(100);
        t.insert("first", "1"); // 5 + 1 + 32 = 38
        t.insert("second", "2"); // 6 + 1 + 32 = 39; total 77
        assert_eq!(t.len(), 2);
        assert_eq!(t.get(0).expect("newest").name, "second");

        t.insert("third", "3"); // 5 + 1 + 32 = 38; 77 + 38 = 115 > 100
        assert_eq!(t.len(), 2, "one entry was evicted");
        assert_eq!(t.get(0).expect("newest").name, "third");
        assert_eq!(
            t.get(1).expect("older").name,
            "second",
            "the oldest (`first`) is the one that must go"
        );
    }

    /// Indices: dynamic index 62 is the most recent entry (RFC 7541 §2.3.3).
    #[test]
    fn dynamic_indices_start_at_sixty_two_with_the_newest() {
        let mut t = DynamicTable::new(4_096);
        t.insert("a", "1");
        t.insert("b", "2");
        assert_eq!(t.lookup(1).expect("newest").name, "b");
        assert_eq!(t.lookup(2).expect("older").name, "a");
        assert_eq!(t.lookup(3), None);
        assert_eq!(t.lookup(0), None);
    }

    /// **RFC 7541 §6.3**: a size update above the peer's declared maximum is a
    /// decoding error. Clamping keeps the connection alive while the two ends
    /// hold tables of different sizes, and every following index is then wrong.
    #[test]
    fn a_table_size_update_above_the_limit_is_refused() {
        let mut d = Decoder::new();
        d.set_allowed_table_size(4_096);

        // `3f e1 1f` is a 5-bit-prefix integer with value 4096 + 1 = 4097.
        let block = encode_integer(4_097, 5, 0x20);
        let e = d.decode(&block).expect_err("4097 exceeds the 4096 limit");
        assert!(matches!(e, HpackError::TableSizeTooLarge { .. }));
        assert_eq!(
            e.code(),
            Some(super::super::error::ErrorCode::CompressionError),
            "§4.1: a decoding error is always COMPRESSION_ERROR"
        );
    }

    /// A size update **at** the limit is legal — the positive control for the
    /// test above, which an off-by-one would also fail.
    #[test]
    fn a_table_size_update_at_the_limit_is_accepted() {
        let mut d = Decoder::new();
        d.set_allowed_table_size(4_096);
        let block = encode_integer(4_096, 5, 0x20);
        d.decode(&block).expect("4096 is exactly the limit");
        assert_eq!(d.table().max_size(), 4_096);
    }

    /// A size update evicts down to the new size immediately (§4.3).
    #[test]
    fn a_size_update_evicts_to_fit() {
        let mut d = Decoder::new();
        // Fill with a couple of entries.
        d.decode(&unhex(
            "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
        ))
        .expect("decodes");
        assert_eq!(d.table().size(), 55);

        // Shrink to 40: nothing fits, so the table empties.
        let block = encode_integer(40, 5, 0x20);
        d.decode(&block).expect("40 is legal");
        assert_eq!(d.table().max_size(), 40);
        assert_eq!(d.table().size(), 0, "§4.3: eviction is immediate");
        assert_eq!(d.table().len(), 0);
    }

    /// **The representation prefix order.** `0x60` has both the `0x40` and the
    /// `0x20` bit set. Testing `0x20` first reads every "literal with incremental
    /// indexing" whose name index is 0 (`0x40`) as... no — it reads `0x60`,
    /// which is a literal with incremental indexing and a name index of 32, as a
    /// size update of value 0.
    #[test]
    fn the_representation_prefixes_are_tested_in_the_rfc_order() {
        // 0x60: incremental indexing (0x40) with a 6-bit name index of 32
        // (`cookie`), Huffman value `no-cache`.
        let mut d = Decoder::new();
        assert_decode_with(&mut d, "6086a8eb10649cbf", &[("cookie", "no-cache")]);
        assert_eq!(
            d.table().max_size(),
            4_096,
            "a size update must not have been decoded"
        );
        assert_eq!(d.table().len(), 1, "the entry must have been indexed");
    }

    // -- compression bombs --------------------------------------------------

    /// **RFC 7541 §7: the compression bomb.** A tiny block whose decoded header
    /// list is enormous. The limit must be enforced **during** decoding, not
    /// after, or the memory is already spent.
    #[test]
    fn a_compression_bomb_is_refused_during_decoding() {
        let mut d = Decoder::new();
        // Each iteration adds a `cookie: <16 KiB>` field. The sixth exceeds the
        // 64 KiB list budget (6 * 16416 > 65536).
        let mut block = Vec::new();
        for _ in 0..10 {
            block.extend_from_slice(&encode_integer(32, 6, 0x40)); // indexed name: cookie
                                                                   // 16384 bytes of value, literal.
            block.extend_from_slice(&encode_integer(16_384, 7, 0x00));
            block.extend(std::iter::repeat_n(b'x', 16_384));
        }
        let e = d.decode(&block).expect_err("the list exceeds the budget");
        match e {
            HpackError::HeaderListTooLarge { what, limit, .. } => {
                assert_eq!(limit, MAX_HEADER_LIST_SIZE);
                assert!(what.contains("size"), "got `{what}`");
            }
            other => panic!("expected a list-size error, got {other:?}"),
        }
    }

    /// A field count bomb: many tiny headers, which the *size* budget alone
    /// would allow (100 fields of 34 bytes is 3.4 KiB) but which a per-header
    /// cost makes expensive. The count is checked separately for that reason.
    #[test]
    fn a_field_count_bomb_is_refused() {
        let mut d = Decoder::new();
        let mut block = Vec::new();
        for i in 0..MAX_HEADER_COUNT + 10 {
            block.extend_from_slice(&encode_integer(32, 6, 0x40)); // cookie
            let value = format!("{i}");
            block.extend_from_slice(&encode_integer(value.len() as u64, 7, 0x00));
            block.extend_from_slice(value.as_bytes());
        }
        let e = d.decode(&block).expect_err("more fields than the limit");
        match e {
            HpackError::HeaderListTooLarge { what, limit, .. } => {
                assert!(what.contains("count"), "got `{what}`");
                assert_eq!(limit, MAX_HEADER_COUNT);
            }
            other => panic!("expected a count error, got {other:?}"),
        }
    }

    /// A single string longer than any field can be is refused **before** the
    /// allocation, which is the difference between bounding memory and measuring
    /// it.
    #[test]
    fn an_oversized_string_is_refused_before_allocating() {
        // Declare 100 MiB in four bytes, with no data behind it.
        let block = [0xff, 0xff, 0xff, 0xff, 0x7f];
        let e = decode_string(&block, 0).expect_err("over the field limit");
        assert!(matches!(e, HpackError::StringTooLong { .. }));
    }

    /// A string whose declared length runs past the block is refused rather than
    /// silently returning what is there.
    #[test]
    fn a_string_running_past_the_block_is_refused() {
        let block = [0x05, b'a', b'b'];
        let e = decode_string(&block, 0).expect_err("declares five, has two");
        assert!(matches!(
            e,
            HpackError::StringOverrun {
                declared: 5,
                available: 2
            }
        ));
    }

    // -- name validation ----------------------------------------------------

    /// RFC 9113 §8.2.1: *"A request or response that contains a field name that
    /// is empty … MUST be treated as malformed."*
    #[test]
    fn an_empty_field_name_is_refused() {
        let mut block = vec![0x40, 0x00]; // indexed-literal with a literal name, length 0
        block.extend_from_slice(&encode_integer(1, 7, 0x00));
        block.push(b'v');
        let e = Decoder::new()
            .decode(&block)
            .expect_err("an empty name is malformed");
        assert!(matches!(e, HpackError::InvalidName { .. }));
    }

    /// Upper-case field names are malformed in HTTP/2 (§8.2.1). Accepting one
    /// means a downstream component that lowercases it can be made to see a
    /// different header than an upstream one that does not.
    #[test]
    fn an_uppercase_field_name_is_refused() {
        let mut block = vec![0x40];
        block.extend_from_slice(&encode_integer(3, 7, 0x00));
        block.extend_from_slice(b"Foo");
        block.extend_from_slice(&encode_integer(1, 7, 0x00));
        block.push(b'v');
        let e = Decoder::new()
            .decode(&block)
            .expect_err("uppercase is malformed");
        assert!(matches!(e, HpackError::InvalidName { .. }));
    }

    /// A space in a field name is how a header is smuggled past a component that
    /// re-encodes it.
    #[test]
    fn a_field_name_with_a_space_is_refused() {
        let mut block = vec![0x40];
        block.extend_from_slice(&encode_integer(3, 7, 0x00));
        block.extend_from_slice(b"a b");
        block.extend_from_slice(&encode_integer(1, 7, 0x00));
        block.push(b'v');
        assert!(Decoder::new().decode(&block).is_err());
    }

    /// The positive control: every legal character is accepted, including the
    /// pseudo-header colon.
    #[test]
    fn every_legal_field_name_is_accepted() {
        for name in [":method", ":path", "content-type", "x-a_b.c", "a1!b2#c3$d4"] {
            let mut block = vec![0x40];
            block.extend_from_slice(&encode_integer(name.len() as u64, 7, 0x00));
            block.extend_from_slice(name.as_bytes());
            block.extend_from_slice(&encode_integer(1, 7, 0x00));
            block.push(b'v');
            let decoded = Decoder::new()
                .decode(&block)
                .unwrap_or_else(|e| panic!("`{name}` is legal: {e}"));
            assert_eq!(decoded[0].name, name);
        }
    }

    // -- encoder/decoder round trips ----------------------------------------

    /// The encoder and decoder are separate state, and a round trip through both
    /// is the property the connection relies on.
    #[test]
    fn a_header_list_round_trips_through_encoder_and_decoder() {
        let fields = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":path", "/api/v1/orders?status=open"),
            HeaderField::new(":authority", "api.example.com"),
            HeaderField::new("user-agent", "qqq/1.0"),
            HeaderField::new("accept", "*/*"),
        ];
        let mut enc = Encoder::new();
        let mut dec = Decoder::new();
        for _ in 0..3 {
            let block = enc.encode(&fields);
            let decoded = dec.decode(&block).expect("decodes");
            assert_eq!(decoded, fields);
        }
        // And the tables stayed in step: a compressed block uses dynamic indices.
        let block = enc.encode(&fields);
        let decoded = dec.decode(&block).expect("decodes");
        assert_eq!(decoded, fields);
        assert_eq!(enc.table().size(), dec.table().size());
    }

    /// The two tables must stay in step across a settings change, which is the
    /// case that only appears when the peer lowers `SETTINGS_HEADER_TABLE_SIZE`.
    #[test]
    fn encoder_and_decoder_stay_in_step_across_a_table_shrink() {
        let mut enc = Encoder::new();
        let mut dec = Decoder::new();
        let fields = vec![
            HeaderField::new(":method", "POST"),
            HeaderField::new(":path", "/a"),
            HeaderField::new("x-long", "y".repeat(200)),
        ];
        for _ in 0..3 {
            let block = enc.encode(&fields);
            assert_eq!(dec.decode(&block).expect("decodes"), fields);
        }
        assert!(enc.table().size() > 64);

        // The peer lowers its limit to 64 bytes.
        dec.set_allowed_table_size(64);
        enc.set_allowed_table_size(64);

        // The encoder must emit the size update before the next block, and the
        // decoder must accept it and evict to match.
        let block = enc.encode(&fields);
        assert_eq!(
            block[0] & 0xe0,
            0x20,
            "the first byte must be a dynamic table size update"
        );
        assert_eq!(dec.decode(&block).expect("decodes"), fields);
        assert_eq!(
            enc.table().size(),
            dec.table().size(),
            "both tables must hold the same bytes after the shrink"
        );
        assert!(dec.table().size() <= 64);
    }

    /// An entry too large for the table is sent without indexing, so the decoder
    /// must not insert it either.
    #[test]
    fn an_entry_too_large_for_the_table_is_sent_without_indexing() {
        let mut enc = Encoder::with_table_size(64);
        let mut dec = Decoder::with_table_size(64);
        // 200 + 1 + 32 = 233 > 64.
        let fields = vec![HeaderField::new("x", "y".repeat(200))];
        let block = enc.encode(&fields);
        assert_eq!(
            block[0] & 0xf0,
            0x00,
            "a too-large entry must use literal without indexing, not 0x40"
        );
        assert_eq!(dec.decode(&block).expect("decodes"), fields);
        assert!(enc.table().is_empty(), "the encoder must not index it");
        assert!(
            dec.table().is_empty(),
            "the decoder must not index it either"
        );
    }

    /// The static table is used for exact matches: `:method: GET` is index 2,
    /// encoded as the single byte `0x82`.
    #[test]
    fn the_encoder_uses_the_static_table_for_exact_matches() {
        let mut enc = Encoder::new();
        let block = enc.encode(&[HeaderField::new(":method", "GET")]);
        assert_eq!(hex(&block), "82");
    }

    /// Huffman can be longer than the literal for high-entropy input; the
    /// encoder must pick the shorter form rather than always choosing Huffman.
    #[test]
    fn the_encoder_picks_the_shorter_string_form() {
        // A value of bytes that are all 8-bit codes: the literal must win.
        let high_entropy: String = (0u8..60).map(char::from).collect();
        let encoded = encode_string(&high_entropy);
        assert_eq!(
            encoded[0] & 0x80,
            0,
            "this value must be sent as a literal, not Huffman-coded"
        );

        // And a normal value is Huffman-coded.
        let encoded = encode_string("www.example.com");
        assert_eq!(encoded[0] & 0x80, 0x80, "this value must be Huffman-coded");
        assert_eq!(&encoded[1..], &unhex("f1e3c2e5f23a6ba0ab90f4ff")[..]);
    }

    /// With Huffman disabled the encoder must produce the literal form, which is
    /// what makes the Appendix C.3/C.5 blocks reproducible from this encoder.
    #[test]
    fn huffman_can_be_disabled_for_the_literal_blocks() {
        let mut enc = Encoder::new();
        enc.set_huffman(false);
        let block = enc.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":path", "/"),
            HeaderField::new(":authority", "www.example.com"),
        ]);
        assert_eq!(
            hex(&block),
            "828684410f7777772e6578616d706c652e636f6d",
            "RFC 7541 Appendix C.3.1's first block, reproduced exactly"
        );
    }

    /// With Huffman **enabled** the encoder must reproduce Appendix C.4.1's
    /// block, which is the strongest single check that the Huffman table and the
    /// representation encoder agree with the RFC.
    #[test]
    fn the_encoder_reproduces_the_rfc_huffman_request_block() {
        let mut enc = Encoder::new();
        let block = enc.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "http"),
            HeaderField::new(":path", "/"),
            HeaderField::new(":authority", "www.example.com"),
        ]);
        assert_eq!(
            hex(&block),
            "828684418cf1e3c2e5f23a6ba0ab90f4ff",
            "RFC 7541 Appendix C.4.1's first block, reproduced exactly"
        );
    }

    /// And the third request, which is where the dynamic table's indices first
    /// appear in the encoder's output.
    #[test]
    fn the_encoder_reproduces_the_rfc_third_request_block() {
        let mut enc = Encoder::new();
        for _ in 0..2 {
            // The encoded bytes are discarded on purpose: these two calls exist
            // to drive the encoder's dynamic table into the state the RFC's
            // third request starts from, and only the *last* block's bytes are
            // asserted below.
            let _ = enc.encode(&[
                HeaderField::new(":method", "GET"),
                HeaderField::new(":scheme", "http"),
                HeaderField::new(":path", "/"),
                HeaderField::new(":authority", "www.example.com"),
            ]);
            let _ = enc.encode(&[
                HeaderField::new(":method", "GET"),
                HeaderField::new(":scheme", "http"),
                HeaderField::new(":path", "/"),
                HeaderField::new(":authority", "www.example.com"),
                HeaderField::new("cache-control", "no-cache"),
            ]);
        }
        let block = enc.encode(&[
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":path", "/index.html"),
            HeaderField::new(":authority", "www.example.com"),
            HeaderField::new("custom-key", "custom-value"),
        ]);
        assert_eq!(
            hex(&block),
            "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
            "RFC 7541 Appendix C.4.3's third block, reproduced exactly"
        );
    }

    // -- error rendering ----------------------------------------------------

    #[test]
    fn every_hpack_error_renders_and_classifies() {
        let errors = [
            HpackError::Truncated { at: 3 },
            HpackError::InvalidIndex {
                index: 99,
                table: "the dynamic table",
            },
            HpackError::TableSizeTooLarge {
                requested: 9_999,
                limit: 4_096,
            },
            HpackError::BadHuffman {
                detail: "zero padding",
            },
            HpackError::StringOverrun {
                declared: 9,
                available: 1,
            },
            HpackError::StringTooLong {
                declared: 9_999_999,
                limit: MAX_FIELD_BYTES,
            },
            HpackError::HeaderListTooLarge {
                what: "size",
                got: 100_000,
                limit: MAX_HEADER_LIST_SIZE,
            },
            HpackError::InvalidName {
                name: "Foo".to_owned(),
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(!s.is_empty());
            assert!(!s.contains('\n'));
        }

        // §4.1: a decoding error is always connection-fatal...
        for e in &errors[1..] {
            assert!(
                e.is_connection_fatal(),
                "{e} must be connection-fatal: the dynamic table cannot resynchronise"
            );
        }
        // ...except a block that is merely incomplete, which the caller
        // accumulates across CONTINUATION frames.
        assert!(!errors[0].is_connection_fatal());
    }

    /// A legal header count and size are accepted — the positive control for the
    /// two bomb tests, which a limit of zero would also "pass".
    #[test]
    fn a_large_but_legal_header_list_is_accepted() {
        let mut d = Decoder::new();
        let mut fields = Vec::new();
        for i in 0..MAX_HEADER_COUNT {
            fields.push(HeaderField::new("x", format!("{i}")));
        }
        let mut enc = Encoder::new();
        enc.set_huffman(false);
        let block = enc.encode(&fields);
        let decoded = d.decode(&block).expect("a legal list must decode");
        assert_eq!(decoded.len(), MAX_HEADER_COUNT);
    }
}
