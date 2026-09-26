// SPDX-License-Identifier: Apache-2.0

//! The capability audit stream — `CAP-015`, and Proposal §10.1's fourth signal.
//!
//! # The claim §10.1 makes, and the three words that carry it
//!
//! > **The QQQ-specific fourth signal: the capability audit stream.** Every
//! > capability use — granted, denied, and *attempted* — is recorded with
//! > tenant, component digest, manifest revision, function, and outcome. This is
//! > not a log; it is an **evidence record, append-only, hash-chained**,
//! > exportable as SARIF and as a compliance report.
//!
//! Each of the three emphasised words is a property that a *log* does not have,
//! and each fails in a specific way when it is not implemented:
//!
//! | Property | What a log does instead | What this module does |
//! |---|---|---|
//! | **Append-only** | Rotates, truncates, drops under pressure | A record can be added and never removed; there is no `clear`, no `truncate`, and a full ring *refuses* rather than overwrites |
//! | **Hash-chained** | Each line is independent | Every record carries the digest of its predecessor, so removing or editing any record changes every later digest |
//! | **Evidence** | Best-effort, sampled, lossy | Counters are split `recorded` / `dropped` so a gap is **visible as a value**, never silent |
//!
//! # "Granted, denied, and *attempted*" — the word that changes the shape
//!
//! Most systems record two outcomes. The proposal names three, and *attempted*
//! is the one that makes the record evidence, because it is the only one that
//! can show an intent that was **not** realised. A stream holding only grants
//! and denials cannot distinguish "the guest never tried to read `/etc/passwd`"
//! from "the guest tried and the record was lost", and the second is exactly
//! what an incident responder needs to rule out.
//!
//! [`Outcome`] therefore has a variant for each, and the third is modelled
//! explicitly rather than as a denied-with-a-flag: a denied call reached the
//! host and was refused *by policy*, while an attempted-and-blocked call is one
//! the host refused *before* policy because the capability was absent from the
//! linker (see [`crate::linker`]). Those are different events and collapsing
//! them loses the distinction between "your policy said no" and "your code
//! cannot do this at all".
//!
//! # Why the chain is `SHA-256(prev ‖ fields)` and not a Merkle tree
//!
//! Because the threat is **retroactive editing**, not efficient inclusion
//! proofs. A Merkle tree gives O(log n) proofs of membership to a third party,
//! which is the wrong cost model for a stream that is written once and read
//! whole. A hash chain gives one property — *any* mutation of *any* record
//! invalidates *every* later digest — in one comparison per record, and that
//! property is what "append-only" has to mean if it is to mean anything.
//!
//! The chain is verified by [`AuditStream::verify_chain`], which returns the
//! **index of the first break**, not a boolean. A boolean tells a responder that
//! something is wrong; an index tells them where, which is the difference
//! between an alarm and an investigation.
//!
//! # Why the ring refuses instead of overwriting
//!
//! §10.1 says append-only, and a bounded in-memory ring is the obvious
//! implementation — but a ring that overwrites converts "append-only" into
//! "append-only until it matters". Under the exact condition an audit stream is
//! needed (a hostile guest, a busy server), the oldest records would be the
//! ones evicted, and the *start* of an incident is precisely the interesting
//! part.
//!
//! So [`AuditStream::record`] returns [`Append::Full`] when the capacity is
//! reached, and the caller decides. Refusing is strictly better than
//! overwriting for an evidence record, because a refusal is observable: the
//! caller can stop the guest, flush to durable storage, or refuse the request.
//! An overwrite is not observable by anyone, including the operator reading the
//! stream later and seeing a plausible, complete-looking record of the wrong
//! window.
//!
//! # Why accounting is per capability *and* per tenant
//!
//! §10.2's Capability row is *"uses by capability, denials by capability, by
//! tenant"* — three dimensions. The tenant dimension is not a convenience: §7.1
//! names a compromised tenant as an adversary, and the question a responder asks
//! first is *"which tenant is this?"*. A total count answers nothing about that,
//! and a per-tenant count that sums across capabilities cannot show which
//! authority was probed.
//!
//! [`Ledger`] holds both, keyed by a [`Capability`] and an optional tenant, so
//! the same structure answers "how many times was `fs.read` used" and "how many
//! times did tenant `acme` try to use `fs.read`".
//!
//! # Cardinality, again
//!
//! §10.2's cardinality rule applies here as it does to metrics, and the type
//! system enforces it the same way: a record's tenant is a [`TenantId`] and its
//! capability is a [`Capability`], neither of which can be constructed from an
//! arbitrary string. There is no `with_label(&str)` and no free-form `detail`
//! field. A caller who needs a new dimension adds a typed field, and that is a
//! visible change to this file rather than a quiet one at a call site.

use std::collections::BTreeMap;
use std::fmt;

use qqq_cap::capability::Capability;
use qqq_cap::egress::TenantId;
use sha2::{Digest as _, Sha256};

use crate::tenant::{ComponentDigest, GrantDigest};

/// How many records a stream holds before it refuses to accept more.
///
/// # Why a bound at all
///
/// Because an unbounded in-memory evidence record is a memory-exhaustion vector
/// driven by exactly the adversary the record exists to document: a guest in a
/// loop calling a capability would grow the host's heap without limit. The
/// bound has to exist; what matters is what happens at it, and this module
/// refuses rather than overwrites.
///
/// 65,536 records is chosen to be comfortably larger than a single request's
/// plausible capability use (a few hundred at most) while staying small enough
/// that the whole stream is a few megabytes — the size an operator can flush to
/// durable storage on demand without a streaming protocol.
pub const DEFAULT_CAPACITY: usize = 65_536;

/// The most recent record in the chain, as a digest.
///
/// # Why the empty chain has a defined hash rather than `None`
///
/// Because `None` would make the first record's chain field a special case in
/// every verifier, and the special case is where a verifier gets it wrong. The
/// genesis digest is SHA-256 of the ASCII string `"qqq:audit:genesis"`, which is
/// a value no record's own digest can plausibly equal — so a stream whose first
/// record claims the genesis predecessor is indistinguishable from a legitimately
/// empty-prefixed one, and a stream whose first record claims *any other*
/// predecessor is caught by [`AuditStream::verify_chain`] immediately.
#[must_use]
pub fn genesis_digest() -> String {
    let mut h = Sha256::new();
    h.update(b"qqq:audit:genesis");
    hex(&h.finalize())
}

/// What happened to one capability use.
///
/// # Why three variants and not two
///
/// §10.1 names *"granted, denied, and attempted"*. The third is the one that
/// makes the record evidence: it is the only outcome that can show an intent
/// that was **not** realised. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// The capability was granted and the call completed.
    Granted,
    /// The capability was granted but the call failed for its own reasons —
    /// a denied egress destination, an exhausted quota, a boundary rejection.
    ///
    /// # Why this is a separate variant from `Denied`
    ///
    /// Because the two answer different questions. `Denied` means *the guest
    /// was not permitted*; `Failed` means *the guest was permitted and the
    /// operation did not succeed*. A policy review reading `Failed` rows learns
    /// that the grant is real but something downstream is broken, which is a
    /// different remediation from adding a grant.
    Failed,
    /// The capability was not granted, and the call was refused **by policy**.
    ///
    /// This is reachable only through the call-time re-check
    /// ([`crate::linker::recheck`]), which runs *after* an instance exists —
    /// so a `Denied` row means the instance was built with the capability
    /// absent and a host bug let the call through far enough to be re-checked.
    /// It is therefore the most interesting row in the stream.
    Denied,
    /// The guest attempted the call and the capability was **absent**, so the
    /// attempt was refused before policy was consulted.
    ///
    /// # Why this exists at all, when a component cannot even import an absent
    /// interface
    ///
    /// Because the *host* can observe the attempt. A guest that imports
    /// `qqq:fs` under a linker that does not bind it fails at instantiation,
    /// and that failure is the moment the attempt was made and blocked. Without
    /// this variant the stream would begin only after a successful
    /// instantiation, and the most common real event — *"a component was
    /// deployed that needs authority the manifest does not grant"* — would
    /// leave no record.
    Attempted,
}

impl Outcome {
    /// Every outcome, for exhaustiveness tests and the report.
    pub const ALL: [Self; 4] = [Self::Granted, Self::Failed, Self::Denied, Self::Attempted];

    /// The stable lowercase name used in JSON, SARIF and the reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Attempted => "attempted",
        }
    }

    /// Whether this outcome represents an authority the guest did **not** get.
    ///
    /// # Why this is a method and not a match at each call site
    ///
    /// Because the two sites that need it — the report's denial count and the
    /// SARIF severity — must agree, and a third site added later would
    /// reimplement the classification. `Failed` is deliberately **not** a
    /// refusal: the authority was exercised.
    #[must_use]
    pub const fn is_refusal(self) -> bool {
        matches!(self, Self::Denied | Self::Attempted)
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One recorded capability use.
///
/// # Why every field is a typed value rather than a string
///
/// §10.2's cardinality rule, applied to the fourth signal. A record with a
/// free-form `detail: String` would let a guest-controlled path become an audit
/// field, which makes the stream a storage-exhaustion vector and a
/// log-injection vector at once. Every field here has a bounded domain, and
/// [`AuditRecord::chain`] is the only `String`, computed by this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// 1-based position in the stream. The first record is 1, not 0, so a
    /// missing record is visible as a gap rather than an off-by-one.
    pub sequence: u64,
    /// Which tenant the use belongs to, when the request is tenant-scoped.
    ///
    /// `None` for the single-tenant `qqqai run` path, which is the same
    /// distinction [`crate::tenant::StoreData::tenant`] makes — and it is a
    /// refusal rather than a wildcard for the same reason.
    pub tenant: Option<TenantId>,
    /// The artifact that made the call.
    pub component: ComponentDigest,
    /// The grant set the instance was built against (§10.1's "manifest
    /// revision").
    pub grants: GrantDigest,
    /// The capability used, or attempted.
    pub capability: Capability,
    /// The host function, e.g. `read`. Bounded by the interface's own WIT.
    pub function: &'static str,
    /// What happened.
    pub outcome: Outcome,
    /// The digest of the preceding record.
    pub previous: String,
    /// This record's digest: `SHA-256` over every field above, in order.
    pub chain: String,
}

/// The fields a record's digest covers, as one named value.
///
/// # Why a struct and not eight arguments
///
/// Because eight positional arguments to a hash function is eight chances to
/// pass the right values in the wrong order, and the only thing preventing it
/// was that the types happened to differ. Named fields make the call site
/// readable and the mistake impossible. It is also the type
/// [`AuditRecord::compute_chain`] documents as the input the digest is a
/// function of.
#[derive(Debug, Clone, Copy)]
pub struct AuditFields<'a> {
    /// 1-based position in the stream.
    pub sequence: u64,
    /// The tenant, when the use is tenant-scoped.
    pub tenant: Option<&'a TenantId>,
    /// The artifact that made the call.
    pub component: &'a ComponentDigest,
    /// The grant set the instance was built against.
    pub grants: &'a GrantDigest,
    /// The capability used or attempted.
    pub capability: Capability,
    /// The host function.
    pub function: &'a str,
    /// What happened.
    pub outcome: Outcome,
    /// The digest of the preceding record.
    pub previous: &'a str,
}

impl AuditRecord {
    /// This record's own fields, for re-hashing during verification.
    #[must_use]
    pub fn fields(&self) -> AuditFields<'_> {
        AuditFields {
            sequence: self.sequence,
            tenant: self.tenant.as_ref(),
            component: &self.component,
            grants: &self.grants,
            capability: self.capability,
            function: self.function,
            outcome: self.outcome,
            previous: &self.previous,
        }
    }
}

impl AuditRecord {
    /// Compute the digest a record with these fields would carry.
    ///
    /// # Why the fields are hashed with a length prefix
    ///
    /// Because a bare concatenation is ambiguous: `("ab", "c")` and `("a",
    /// "bc")` produce the same input. With attacker-influenced fields that is a
    /// real collision — a guest that controls a function name could construct
    /// two different records with one digest, which defeats the chain. Length
    /// prefixes make the encoding injective, so the digest is a function of the
    /// field set and nothing else.
    ///
    /// # Why the fields travel as a struct rather than as arguments
    ///
    /// The first version took them positionally, which worked only because the
    /// types happened to differ enough to make a transposition a compile error.
    /// A named struct removes the question: `fields.tenant` cannot be passed
    /// where `fields.component` belongs, and a caller reading the call site can
    /// see which value is which.
    #[must_use]
    pub fn compute_chain(fields: &AuditFields<'_>) -> String {
        let mut h = Sha256::new();
        field(&mut h, &fields.sequence.to_string());
        field(&mut h, fields.tenant.map_or("", TenantId::as_str));
        field(&mut h, fields.component.as_str());
        field(&mut h, fields.grants.as_str());
        field(&mut h, fields.capability.name());
        field(&mut h, fields.function);
        field(&mut h, fields.outcome.as_str());
        field(&mut h, fields.previous);
        hex(&h.finalize())
    }

    /// Render one record as a JSON object.
    ///
    /// # Why hand-written rather than `serde`
    ///
    /// Because the field order is part of the evidence. Two records of the same
    /// event must render identically on two hosts for a digest comparison to
    /// mean anything, and a derived `Serialize` gives no such guarantee across
    /// a refactor. The order here is fixed by this function and tested.
    #[must_use]
    pub fn to_json(&self) -> String {
        let tenant = match &self.tenant {
            Some(t) => format!("\"{}\"", json_escape(t.as_str())),
            None => "null".to_owned(),
        };
        format!(
            "{{\"sequence\":{},\"tenant\":{},\"component\":\"{}\",\
             \"grants\":\"{}\",\"capability\":\"{}\",\"function\":\"{}\",\
             \"outcome\":\"{}\",\"previous\":\"{}\",\"chain\":\"{}\"}}",
            self.sequence,
            tenant,
            self.component.as_str(),
            self.grants.as_str(),
            self.capability.name(),
            json_escape(self.function),
            self.outcome.as_str(),
            self.previous,
            self.chain,
        )
    }
}

impl fmt::Display for AuditRecord {
    /// The human-readable form: one line, stable column order.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:>6} {} {:<7} {:<16} {}",
            self.sequence,
            self.tenant.as_ref().map_or("-", TenantId::as_str),
            self.outcome,
            self.capability.name(),
            self.function,
        )
    }
}

/// Reverse [`json_escape`] for the escapes that function produces.
///
/// # Why this refuses rather than guessing
///
/// An unterminated escape, an unknown escape letter, or a lone surrogate is **not** repaired
/// here — it returns `None`, and the caller refuses the record. This is a parser for an evidence
/// record: a lenient one would let a corrupted line become a plausible-looking record, which is
/// the failure the whole module exists to prevent. `\uXXXX` is decoded only for the control
/// range `json_escape` emits, so the two are exact inverses over the values this type produces.
fn json_unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let hex: String = chars.by_ref().take(4).collect();
                if hex.len() != 4 {
                    return None;
                }
                let code = u32::from_str_radix(&hex, 16).ok()?;
                out.push(char::from_u32(code)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Extract a JSON string field, or `None` when the key is absent or malformed.
///
/// # Why a hand-written scan and not a JSON library
///
/// Because the format is flat — every value is a number, `null`, or a string — and the parser must
/// be an **exact inverse of `to_json`**, which is itself hand-written for the reason its own doc
/// gives: a derived serialiser gives no cross-version stability guarantee, and a digest comparison
/// depends on one. Pairing a hand-written writer with a library reader would put the stability
/// guarantee on one side only.
fn json_string_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    // Walk to the closing quote, honouring escapes -- a value may contain `\"`.
    let mut escaped = false;
    for (i, c) in rest.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return json_unescape(&rest[..i]);
        }
    }
    None
}

/// Extract a JSON integer field.
fn json_u64_field(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    rest[..end].parse().ok()
}

impl AuditRecord {
    /// Parse one record from its [`to_json`](Self::to_json) form.
    ///
    /// # Errors
    ///
    /// A sentence naming the field that was absent, malformed, or unrepresentable. **Every field
    /// is required** and an unknown capability or outcome is refused rather than defaulted: a
    /// record whose capability could not be read is not a record with no capability, and treating
    /// it as one would silently drop the authority a row is *about*.
    ///
    /// # Why `sequence` is checked here and the chain is not
    ///
    /// This function reads one record. Whether the records form an unbroken chain is
    /// [`AuditStream::verify_chain`]'s job, over the whole set, because a single record cannot
    /// answer it. Keeping the two separate is what lets a caller report *which* record broke the
    /// chain rather than that one of them did.
    pub(crate) fn from_json(json: &str) -> Result<Self, String> {
        let sequence = json_u64_field(json, "sequence")
            .ok_or_else(|| "an audit record must carry an integer `sequence`".to_owned())?;

        // `tenant` is the one field that may be JSON `null`, so absence and nullness differ:
        // `"tenant":null` is a legitimate unscoped record, while no `tenant` key at all is a
        // malformed line. Checking for the key before the value keeps those apart.
        if !json.contains("\"tenant\":") {
            return Err(
                "an audit record must carry a `tenant` key, even when it is null".to_owned(),
            );
        }
        let tenant = if json.contains("\"tenant\":null") {
            None
        } else {
            let raw = json_string_field(json, "tenant")
                .ok_or_else(|| "`tenant` must be a string or null".to_owned())?;
            Some(TenantId::new(&raw).map_err(|e| format!("`tenant` is invalid: {e}"))?)
        };

        let component = json_string_field(json, "component")
            .ok_or_else(|| "an audit record must carry a `component` digest".to_owned())?;
        let component =
            ComponentDigest::new(&component).map_err(|e| format!("`component` is invalid: {e}"))?;

        let grants = json_string_field(json, "grants")
            .ok_or_else(|| "an audit record must carry a `grants` digest".to_owned())?;
        let grants = GrantDigest::new(&grants).map_err(|e| format!("`grants` is invalid: {e}"))?;

        let capability_name = json_string_field(json, "capability")
            .ok_or_else(|| "an audit record must name its `capability`".to_owned())?;
        let capability = Capability::from_name(&capability_name).ok_or_else(|| {
            format!(
                "`{capability_name}` is not a capability this build knows; refusing rather than \
                 reading the record as capability-less"
            )
        })?;

        let outcome_name = json_string_field(json, "outcome")
            .ok_or_else(|| "an audit record must state its `outcome`".to_owned())?;
        let outcome = Outcome::ALL
            .into_iter()
            .find(|o| o.as_str() == outcome_name)
            .ok_or_else(|| format!("`{outcome_name}` is not an audit outcome"))?;

        let function = json_string_field(json, "function")
            .ok_or_else(|| "an audit record must name its `function`".to_owned())?;
        // `function` is `&'static str` in the record, so a parsed value must be interned. The set
        // of host function names is bounded by the interfaces' own WIT, and an unknown one is
        // refused rather than leaked -- `Box::leak` here would be a memory leak driven by file
        // content, which is an unbounded allocation an attacker controls.
        let function = match function.as_str() {
            "handle_request" => "handle_request",
            other => {
                return Err(format!(
                    "`{other}` is not a host function this build records; refusing rather than \
                     leaking a string whose length the file controls"
                ))
            }
        };

        let previous = json_string_field(json, "previous")
            .ok_or_else(|| "an audit record must carry its `previous` digest".to_owned())?;
        let chain = json_string_field(json, "chain")
            .ok_or_else(|| "an audit record must carry its `chain` digest".to_owned())?;

        Ok(Self {
            sequence,
            tenant,
            component,
            grants,
            capability,
            function,
            outcome,
            previous,
            chain,
        })
    }
}

/// Hash one field with a length prefix, so the encoding is injective.
fn field(h: &mut Sha256, value: &str) {
    h.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    h.update(value.as_bytes());
}

/// Lowercase hex of a digest.
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// Escape the characters that would break a hand-written JSON string.
///
/// # Why a hand-written escaper is safe here
///
/// Because the only field that reaches it is a `&'static str` from a
/// `func_wrap` registration in this workspace, and a `TenantId`, which
/// [`TenantId::new`] already refuses to build from a string containing control
/// characters. This function is defence in depth for the one field that could
/// ever come from elsewhere (`function`), and it is exhaustive over the JSON
/// string escapes rather than a partial set — a partial escaper is how a log
/// becomes a parser's problem.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// What happened when a record was offered to the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Append {
    /// The record was added, and is at this 1-based sequence number.
    Recorded(u64),
    /// The stream is at capacity and **refused**. The caller decides.
    ///
    /// See the module docs: refusing is observable and overwriting is not, and
    /// an evidence record that silently loses its oldest entries is a record
    /// that looks complete and is not.
    Full,
}

impl Append {
    /// Whether the record was accepted.
    #[must_use]
    pub const fn was_recorded(self) -> bool {
        matches!(self, Self::Recorded(_))
    }
}

/// Counts of what has been offered, so a gap is a value rather than a silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AppendCounters {
    /// Records accepted.
    pub recorded: u64,
    /// Records refused because the stream was full.
    pub refused: u64,
}

impl AppendCounters {
    /// Whether any record was refused.
    #[must_use]
    pub const fn has_gaps(self) -> bool {
        self.refused > 0
    }
}

/// An append-only, hash-chained record of capability use — `CAP-015`.
#[derive(Debug)]
pub struct AuditStream {
    capacity: usize,
    records: Vec<AuditRecord>,
    counters: AppendCounters,
    head: String,
}

impl AuditStream {
    /// A stream holding at most `capacity` records.
    ///
    /// # Errors
    ///
    /// Refuses a capacity of zero. A zero-capacity stream accepts nothing, so
    /// every record is refused — a configuration that produces a permanently
    /// empty record while reporting itself healthy. The caller that wants no
    /// audit stream should not construct one, which is a different and visible
    /// decision.
    pub fn new(capacity: usize) -> Result<Self, String> {
        if capacity == 0 {
            return Err(
                "an audit stream must hold at least one record; a zero-capacity \
                 stream refuses every append while reporting itself healthy, so \
                 omit the stream instead of sizing it to nothing"
                    .to_owned(),
            );
        }
        Ok(Self {
            capacity,
            records: Vec::new(),
            counters: AppendCounters::default(),
            head: genesis_digest(),
        })
    }

    /// A stream at the default capacity.
    ///
    /// # Panics
    ///
    /// Never — [`DEFAULT_CAPACITY`] is non-zero, and the check is in the type's
    /// own constructor rather than here.
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY).expect("DEFAULT_CAPACITY is non-zero")
    }

    /// Continue an existing record — `OBS-002`, persistence.
    ///
    /// # Errors
    ///
    /// A sentence when the records cannot form a stream: an empty capacity, more records than the
    /// capacity allows, a record out of sequence, or **a chain that does not verify**.
    ///
    /// # Why a resumed stream must verify before it is handed out
    ///
    /// A stream that resumed a broken chain would append to it, and every record it added would
    /// commit to a predecessor that was already wrong — so the corruption would be **extended
    /// rather than detected**, and the file would look healthy from the point the server
    /// restarted. Refusing at load is the only moment the corruption can still be reported as
    /// what it is.
    ///
    /// # Why `capacity` is checked against the length
    ///
    /// Because the alternative is a stream that silently refuses every new append while reporting
    /// itself healthy — the same defect [`Self::new`] refuses for zero capacity. A history that
    /// has outgrown its configured bound is a decision the operator has to make, not something to
    /// absorb.
    pub(crate) fn resume(records: Vec<AuditRecord>, capacity: usize) -> Result<Self, String> {
        if capacity == 0 {
            return Err(
                "an audit stream must hold at least one record; a zero-capacity stream refuses \
                 every append while reporting itself healthy"
                    .to_owned(),
            );
        }
        if records.len() > capacity {
            return Err(format!(
                "the existing record holds {} record(s) and the capacity is {capacity}; raise the \
                 capacity or rotate the file rather than starting a stream that refuses every \
                 append",
                records.len()
            ));
        }

        // Sequence numbers must be contiguous from 1, because a gap is exactly what an append-only
        // record is supposed to make impossible. `verify_chain` checks the links; this checks the
        // numbering, and the two are different claims.
        for (i, record) in records.iter().enumerate() {
            let expected = u64::try_from(i).unwrap_or(u64::MAX) + 1;
            if record.sequence != expected {
                return Err(format!(
                    "record {expected} is missing: the file's {i}-th record carries sequence {}",
                    record.sequence
                ));
            }
        }

        let head = records
            .last()
            .map_or_else(genesis_digest, |r| r.chain.clone());
        let recorded = u64::try_from(records.len()).unwrap_or(u64::MAX);
        let stream = Self {
            capacity,
            records,
            counters: AppendCounters {
                recorded,
                refused: 0,
            },
            head,
        };
        if let Err((sequence, reason)) = stream.verify_chain() {
            return Err(format!(
                "refusing to resume a broken chain: record {sequence} does not verify -- {reason}"
            ));
        }
        Ok(stream)
    }

    /// Record one capability use.
    ///
    /// Returns [`Append::Full`] when the capacity is reached; see the module
    /// docs for why refusing beats overwriting.
    pub fn record(
        &mut self,
        tenant: Option<&TenantId>,
        component: &ComponentDigest,
        grants: &GrantDigest,
        capability: Capability,
        function: &'static str,
        outcome: Outcome,
    ) -> Append {
        if self.records.len() >= self.capacity {
            self.counters.refused += 1;
            return Append::Full;
        }
        let sequence = self.records.len() as u64 + 1;
        let chain = AuditRecord::compute_chain(&AuditFields {
            sequence,
            tenant,
            component,
            grants,
            capability,
            function,
            outcome,
            previous: &self.head,
        });
        self.records.push(AuditRecord {
            sequence,
            tenant: tenant.cloned(),
            component: component.clone(),
            grants: grants.clone(),
            capability,
            function,
            outcome,
            previous: self.head.clone(),
            chain: chain.clone(),
        });
        self.head = chain;
        self.counters.recorded += 1;
        Append::Recorded(sequence)
    }

    /// The records, in order.
    #[must_use]
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// How many records the stream holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the stream holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The configured capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Accepted and refused counts.
    #[must_use]
    pub const fn counters(&self) -> AppendCounters {
        self.counters
    }

    /// The current head digest — the value the next record will chain from.
    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Recompute every digest and report the first inconsistency.
    ///
    /// # Returns the index, not a boolean
    ///
    /// A boolean tells a responder that something is wrong; an index tells them
    /// **where**, which is the difference between an alarm and an
    /// investigation. The `Err` carries the 1-based sequence number of the
    /// first bad record and a sentence naming which check failed — a broken
    /// link to its predecessor, or a digest that does not match the record's
    /// own fields.
    ///
    /// # Errors
    ///
    /// Returns `(sequence, reason)` for the first record that fails.
    pub fn verify_chain(&self) -> Result<(), (u64, String)> {
        let mut expected_previous = genesis_digest();
        for record in &self.records {
            if record.previous != expected_previous {
                return Err((
                    record.sequence,
                    format!(
                        "record {} chains from `{}` but its predecessor's digest \
                         is `{}`; a record was removed, reordered or replaced",
                        record.sequence, record.previous, expected_previous
                    ),
                ));
            }
            let recomputed = AuditRecord::compute_chain(&record.fields());
            if recomputed != record.chain {
                return Err((
                    record.sequence,
                    format!(
                        "record {} has digest `{}` but its fields hash to `{}`; \
                         a field was edited after it was written",
                        record.sequence, record.chain, recomputed
                    ),
                ));
            }
            expected_previous.clone_from(&record.chain);
        }
        Ok(())
    }

    /// Every record as a JSON object, one per line (JSON Lines).
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::ChainBroken`] when [`verify_chain`] fails, so an
    /// export can never silently emit a corrupted record. That is the whole
    /// point of an evidence record: the export path is where a corrupted stream
    /// would otherwise become a plausible-looking document.
    ///
    /// [`verify_chain`]: AuditStream::verify_chain
    pub fn to_jsonl(&self) -> Result<String, LedgerError> {
        self.verify_chain()
            .map_err(|(sequence, reason)| LedgerError::ChainBroken { sequence, reason })?;
        let mut out = String::new();
        for record in &self.records {
            out.push_str(&record.to_json());
            out.push('\n');
        }
        Ok(out)
    }

    /// The accounting summary — §10.2's Capability row.
    #[must_use]
    pub fn ledger(&self) -> Ledger {
        let mut ledger = Ledger::new();
        for record in &self.records {
            ledger.count(record.tenant.as_ref(), record.capability, record.outcome);
        }
        ledger
    }

    /// Mutable access to the records, **for tests only**.
    ///
    /// # Why this exists rather than a `pub` accessor
    ///
    /// `audit_export`'s tests need to tamper with a chain to prove the exporters refuse a broken
    /// one, and they live in a different module so they cannot reach the private field the way
    /// this module's own tests do.
    ///
    /// The alternative was making `records` public, which would let any caller rewrite an
    /// evidence record — in the type whose whole purpose is that rewriting is detectable. **A
    /// test-only accessor is the narrower hole**, and `cfg(test)` means it does not exist in the
    /// shipped library at all.
    #[cfg(test)]
    pub(crate) fn records_mut_for_test(&mut self) -> &mut Vec<AuditRecord> {
        &mut self.records
    }
}

/// Why an export could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// The chain does not verify.
    ChainBroken {
        /// The 1-based sequence number of the first bad record.
        sequence: u64,
        /// Why it failed.
        reason: String,
    },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainBroken { sequence, reason } => {
                write!(f, "audit chain broken at record {sequence}: {reason}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

/// Capability-use counts, by capability, by tenant, by outcome — §10.2.
///
/// # Why three dimensions and not one total
///
/// Because §10.2 asks for *"uses by capability, denials by capability, by
/// tenant"*, and each answers a different question. A total tells an operator
/// the server is busy; a per-capability count tells them which authority is
/// exercised; a per-tenant count tells them **who**. §7.1 names a compromised
/// tenant as an adversary, and *"which tenant is this?"* is the first question a
/// responder asks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    total: BTreeMap<Capability, [u64; 4]>,
    per_tenant: BTreeMap<(TenantId, Capability), [u64; 4]>,
    unscoped: BTreeMap<Capability, [u64; 4]>,
}

impl Ledger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one use.
    pub fn count(&mut self, tenant: Option<&TenantId>, capability: Capability, outcome: Outcome) {
        let slot = outcome_slot(outcome);
        let entry = self.total.entry(capability).or_insert([0; 4]);
        entry[slot] += 1;
        if let Some(t) = tenant {
            let entry = self
                .per_tenant
                .entry((t.clone(), capability))
                .or_insert([0; 4]);
            entry[slot] += 1;
        } else {
            let entry = self.unscoped.entry(capability).or_insert([0; 4]);
            entry[slot] += 1;
        }
    }

    /// The four counts for one capability across all tenants.
    #[must_use]
    pub fn for_capability(&self, capability: Capability) -> [u64; 4] {
        self.total.get(&capability).copied().unwrap_or([0; 4])
    }

    /// The four counts for one tenant's use of one capability.
    #[must_use]
    pub fn for_tenant(&self, tenant: &TenantId, capability: Capability) -> [u64; 4] {
        self.per_tenant
            .get(&(tenant.clone(), capability))
            .copied()
            .unwrap_or([0; 4])
    }

    /// The four counts for uses with no tenant.
    #[must_use]
    pub fn for_unscoped(&self, capability: Capability) -> [u64; 4] {
        self.unscoped.get(&capability).copied().unwrap_or([0; 4])
    }

    /// Every capability that appears, in canonical order.
    #[must_use]
    pub fn capabilities(&self) -> Vec<Capability> {
        self.total.keys().copied().collect()
    }

    /// Every tenant that appears, in canonical order.
    #[must_use]
    pub fn tenants(&self) -> Vec<&TenantId> {
        let mut seen: Vec<&TenantId> = self
            .per_tenant
            .keys()
            .map(|(t, _)| t)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    }

    /// Total uses recorded.
    #[must_use]
    pub fn total_uses(&self) -> u64 {
        self.total.values().map(|c| c.iter().sum::<u64>()).sum()
    }

    /// Total refusals — `Denied` plus `Attempted`.
    ///
    /// # Why `Failed` is excluded
    ///
    /// Because the authority *was* exercised. Counting it as a refusal would
    /// make a broken downstream service look like a policy denial, and an
    /// operator chasing that would look in the wrong place.
    #[must_use]
    pub fn total_refusals(&self) -> u64 {
        self.total
            .values()
            .map(|c| c[outcome_slot(Outcome::Denied)] + c[outcome_slot(Outcome::Attempted)])
            .sum()
    }

    /// Render the summary an operator reads first.
    ///
    /// # Why the refused/failed split is always shown, even at zero
    ///
    /// Because a report that omits a zero row is indistinguishable from one
    /// that lost it, and the reader cannot tell whether the question was asked.
    /// Every outcome column appears for every capability, so "no denials" is
    /// stated rather than implied.
    #[must_use]
    pub fn render(&self) -> String {
        use fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{:<18} {:>8} {:>8} {:>8} {:>10}",
            "capability", "granted", "failed", "denied", "attempted"
        );
        for capability in self.capabilities() {
            let c = self.for_capability(capability);
            let _ = writeln!(
                out,
                "{:<18} {:>8} {:>8} {:>8} {:>10}",
                capability.name(),
                c[0],
                c[1],
                c[2],
                c[3]
            );
        }
        let _ = writeln!(
            out,
            "\ntotal uses: {}  refusals: {}",
            self.total_uses(),
            self.total_refusals()
        );
        for tenant in self.tenants() {
            let _ = writeln!(out, "tenant {tenant}:");
            for capability in self.capabilities() {
                let c = self.for_tenant(tenant, capability);
                if c.iter().any(|n| *n > 0) {
                    let _ = writeln!(
                        out,
                        "  {:<16} {:>8} {:>8} {:>8} {:>10}",
                        capability.name(),
                        c[0],
                        c[1],
                        c[2],
                        c[3]
                    );
                }
            }
        }
        out
    }
}

/// The array slot for an outcome.
///
/// # Why an array and not four named fields
///
/// Because the four are always read together (see [`Ledger::render`]), and four
/// parallel maps would let a caller update three of them. An array indexed by a
/// single function makes "add one to this outcome" one operation with no way to
/// forget a column.
const fn outcome_slot(outcome: Outcome) -> usize {
    match outcome {
        Outcome::Granted => 0,
        Outcome::Failed => 1,
        Outcome::Denied => 2,
        Outcome::Attempted => 3,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(name: &str) -> TenantId {
        TenantId::new(name).expect("test tenant")
    }

    /// Shared fixture values, so [`fields`] can borrow them and the tests do
    /// not rebuild a digest per call.
    static COMPONENT: std::sync::LazyLock<ComponentDigest> =
        std::sync::LazyLock::new(|| ComponentDigest::new("0011223344556677").expect("digest"));
    static GRANTS: std::sync::LazyLock<GrantDigest> =
        std::sync::LazyLock::new(|| GrantDigest::new("aabbccdd").expect("digest"));

    fn component() -> ComponentDigest {
        COMPONENT.clone()
    }

    fn grants() -> GrantDigest {
        GrantDigest::new("aabbccdd").expect("test digest")
    }

    fn stream(capacity: usize) -> AuditStream {
        AuditStream::new(capacity).expect("test capacity")
    }

    /// A payload field set with fixed identity, for the digest-coverage tests.
    fn fields<'a>(
        capability: Capability,
        function: &'a str,
        outcome: Outcome,
        previous: &'a str,
    ) -> String {
        AuditRecord::compute_chain(&AuditFields {
            sequence: 1,
            tenant: None,
            component: &COMPONENT,
            grants: &GRANTS,
            capability,
            function,
            outcome,
            previous,
        })
    }

    /// The identity half of [`AuditFields`], for the struct-update form.
    fn identity_base(previous: &str) -> AuditFields<'_> {
        AuditFields {
            sequence: 1,
            tenant: Some(&ACME),
            component: &COMPONENT,
            grants: &GRANTS,
            capability: Capability::FsRead,
            function: "read",
            outcome: Outcome::Granted,
            previous,
        }
    }

    static ACME: std::sync::LazyLock<TenantId> =
        std::sync::LazyLock::new(|| TenantId::new("acme").expect("tenant"));

    fn push(s: &mut AuditStream, outcome: Outcome) -> Append {
        s.record(
            Some(&tenant("acme")),
            &component(),
            &grants(),
            Capability::FsRead,
            "read",
            outcome,
        )
    }

    // -- Construction -----------------------------------------------------

    #[test]
    fn a_zero_capacity_stream_is_refused_with_the_reason() {
        let e = AuditStream::new(0).expect_err("must refuse");
        assert!(e.contains("zero-capacity"), "{e}");
        assert!(e.contains("omit the stream"), "{e}");
    }

    #[test]
    fn a_new_stream_is_empty_and_starts_at_the_genesis_digest() {
        let s = stream(8);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.capacity(), 8);
        assert_eq!(s.head(), genesis_digest());
        assert!(s.verify_chain().is_ok());
        assert_eq!(s.counters(), AppendCounters::default());
    }

    /// The genesis digest must be a real digest and must not be the hash of an
    /// empty input, which is what a naive implementation would produce.
    #[test]
    fn the_genesis_digest_is_domain_separated_from_the_empty_hash() {
        let g = genesis_digest();
        assert_eq!(g.len(), 64);
        assert!(g.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(
            g, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "the genesis digest must not be SHA-256 of the empty input"
        );
    }

    // -- Recording --------------------------------------------------------

    #[test]
    fn a_record_is_accepted_and_chains_from_the_genesis() {
        let mut s = stream(4);
        let append = push(&mut s, Outcome::Granted);
        assert_eq!(append, Append::Recorded(1));
        assert!(append.was_recorded());
        assert_eq!(s.len(), 1);
        assert_eq!(s.counters().recorded, 1);
        assert_eq!(s.counters().refused, 0);
        assert!(!s.counters().has_gaps());

        let first = &s.records()[0];
        assert_eq!(first.sequence, 1);
        assert_eq!(first.previous, genesis_digest());
        assert_eq!(s.head(), first.chain);
        assert!(s.verify_chain().is_ok());
    }

    #[test]
    fn each_record_chains_from_the_one_before_it() {
        let mut s = stream(4);
        for _ in 0..3 {
            push(&mut s, Outcome::Granted);
        }
        let r = s.records();
        assert_eq!(r[1].previous, r[0].chain);
        assert_eq!(r[2].previous, r[1].chain);
        assert_eq!(s.head(), r[2].chain);
        assert!(s.verify_chain().is_ok());
    }

    /// Sequence numbers start at 1 and increase by one, so a missing record is
    /// a visible gap rather than an off-by-one.
    #[test]
    fn sequence_numbers_start_at_one_and_are_contiguous() {
        let mut s = stream(4);
        for expected in 1..=3 {
            let append = push(&mut s, Outcome::Granted);
            assert_eq!(append, Append::Recorded(expected));
        }
        let seqs: Vec<u64> = s.records().iter().map(|r| r.sequence).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    /// **The refusal, which is the whole reason the ring is not a ring.**
    ///
    /// A full stream refuses and *counts the refusal*; it does not overwrite.
    #[test]
    fn a_full_stream_refuses_rather_than_overwriting() {
        let mut s = stream(2);
        assert!(push(&mut s, Outcome::Granted).was_recorded());
        assert!(push(&mut s, Outcome::Denied).was_recorded());
        assert_eq!(push(&mut s, Outcome::Granted), Append::Full);

        assert_eq!(s.len(), 2, "the stream must not have grown");
        assert_eq!(
            s.records()[0].outcome,
            Outcome::Granted,
            "the oldest record must survive -- this is what append-only means"
        );
        assert_eq!(s.records()[1].outcome, Outcome::Denied);
        assert_eq!(s.counters().recorded, 2);
        assert_eq!(s.counters().refused, 1);
        assert!(s.counters().has_gaps(), "a gap must be visible as a value");
        // The chain is still intact: a refusal changes nothing.
        assert!(s.verify_chain().is_ok());
    }

    #[test]
    fn a_capacity_of_one_accepts_exactly_one_record() {
        let mut s = stream(1);
        assert!(push(&mut s, Outcome::Granted).was_recorded());
        assert_eq!(push(&mut s, Outcome::Granted), Append::Full);
        assert_eq!(s.len(), 1);
    }

    // -- The chain --------------------------------------------------------

    /// **The central property: editing a field breaks the chain.**
    #[test]
    fn editing_a_record_field_breaks_the_chain_at_that_record() {
        let mut s = stream(8);
        for _ in 0..3 {
            push(&mut s, Outcome::Granted);
        }
        assert!(s.verify_chain().is_ok());

        // Edit the middle record's outcome, leaving its stored digest alone --
        // exactly what an attacker with write access would do.
        s.records[1].outcome = Outcome::Denied;
        let (sequence, reason) = s.verify_chain().expect_err("must detect the edit");
        assert_eq!(sequence, 2, "the broken record must be named");
        assert!(reason.contains("edited after it was written"), "{reason}");
    }

    /// **Removing a record breaks the chain at the record that followed it.**
    #[test]
    fn removing_a_record_breaks_the_chain_at_the_next_one() {
        let mut s = stream(8);
        for _ in 0..3 {
            push(&mut s, Outcome::Granted);
        }
        s.records.remove(1);
        // Sequence numbers are now 1, 3 -- the gap is visible on its own, and
        // the chain link is the second, independent detection.
        assert_eq!(s.records[1].sequence, 3);
        let (sequence, reason) = s.verify_chain().expect_err("must detect the removal");
        assert_eq!(sequence, 3);
        assert!(
            reason.contains("removed, reordered or replaced"),
            "{reason}"
        );
    }

    /// Reordering two records is detected, even though the set is unchanged.
    #[test]
    fn reordering_records_breaks_the_chain() {
        let mut s = stream(8);
        for _ in 0..3 {
            push(&mut s, Outcome::Granted);
        }
        s.records.swap(0, 1);
        assert!(
            s.verify_chain().is_err(),
            "a reordered stream must not verify"
        );
    }

    /// The identity fields -- sequence, tenant, component, grants -- each
    /// participate in the digest.
    ///
    /// Split from the capability/function/outcome/previous half because one
    /// function covering eight variants is how a completeness test grows past
    /// the point where a reader can see which variant failed. Together the two
    /// cover every field of [`AuditFields`].
    #[test]
    fn the_identity_fields_are_covered_by_the_digest() {
        let base = AuditRecord::compute_chain(&AuditFields {
            sequence: 1,
            tenant: Some(&tenant("acme")),
            component: &COMPONENT,
            grants: &GRANTS,
            capability: Capability::FsRead,
            function: "read",
            outcome: Outcome::Granted,
            previous: &genesis_digest(),
        });
        let other_tenant = tenant("globex");
        let other_component = ComponentDigest::new("ffeeddcc").expect("digest");
        let other_grants = GrantDigest::new("12345678").expect("digest");
        let genesis = genesis_digest();

        let variants = [
            // sequence
            AuditRecord::compute_chain(&AuditFields {
                sequence: 2,
                ..AuditFields {
                    sequence: 1,
                    tenant: Some(&tenant("acme")),
                    component: &COMPONENT,
                    grants: &GRANTS,
                    capability: Capability::FsRead,
                    function: "read",
                    outcome: Outcome::Granted,
                    previous: &genesis,
                }
            }),
            // tenant
            AuditRecord::compute_chain(&AuditFields {
                tenant: Some(&other_tenant),
                previous: &genesis,
                ..identity_base(&genesis)
            }),
            // tenant absent rather than present
            AuditRecord::compute_chain(&AuditFields {
                tenant: None,
                previous: &genesis,
                ..identity_base(&genesis)
            }),
            // component
            AuditRecord::compute_chain(&AuditFields {
                component: &other_component,
                previous: &genesis,
                ..identity_base(&genesis)
            }),
            // grants
            AuditRecord::compute_chain(&AuditFields {
                grants: &other_grants,
                previous: &genesis,
                ..identity_base(&genesis)
            }),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(&base, v, "identity variant {i} collided with the base");
        }
    }

    /// The payload fields -- capability, function, outcome, previous -- each
    /// participate in the digest.
    #[test]
    fn the_payload_fields_are_covered_by_the_digest() {
        let base = fields(
            Capability::FsRead,
            "read",
            Outcome::Granted,
            &genesis_digest(),
        );
        let variants = [
            fields(
                Capability::FsWrite,
                "read",
                Outcome::Granted,
                &genesis_digest(),
            ),
            fields(
                Capability::FsRead,
                "write",
                Outcome::Granted,
                &genesis_digest(),
            ),
            fields(
                Capability::FsRead,
                "read",
                Outcome::Denied,
                &genesis_digest(),
            ),
            fields(
                Capability::FsRead,
                "read",
                Outcome::Attempted,
                &genesis_digest(),
            ),
            fields(
                Capability::FsRead,
                "read",
                Outcome::Failed,
                &genesis_digest(),
            ),
            fields(
                Capability::FsRead,
                "read",
                Outcome::Granted,
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(&base, v, "payload variant {i} collided with the base");
        }
    }

    /// The length-prefixed encoding must be injective: two different field
    /// splits must not collide, or a guest controlling a function name could
    /// forge a record.
    #[test]
    fn the_field_encoding_is_injective_across_a_split() {
        let split = |component: &str, grants: &str| {
            AuditRecord::compute_chain(&AuditFields {
                sequence: 1,
                tenant: None,
                component: &ComponentDigest::new(component).expect("digest"),
                grants: &GrantDigest::new(grants).expect("digest"),
                capability: Capability::FsRead,
                function: "read",
                outcome: Outcome::Granted,
                previous: "p",
            })
        };
        let a = split("ab", "c");
        let b = split("a", "bc");
        assert_ne!(a, b, "`ab`+`c` must not hash the same as `a`+`bc`");
    }

    #[test]
    fn an_empty_stream_verifies() {
        assert!(stream(4).verify_chain().is_ok());
    }

    // -- The three outcomes -----------------------------------------------

    /// §10.1 names *granted, denied and attempted*. All three must be
    /// representable, and the fourth (`Failed`) must be distinct from both.
    #[test]
    fn all_four_outcomes_are_representable_and_distinct() {
        assert_eq!(Outcome::ALL.len(), 4);
        let names: std::collections::BTreeSet<&str> =
            Outcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(names.len(), 4, "outcome names must be unique: {names:?}");

        let mut s = stream(8);
        for outcome in Outcome::ALL {
            assert!(push(&mut s, outcome).was_recorded());
        }
        for (record, expected) in s.records().iter().zip(Outcome::ALL) {
            assert_eq!(record.outcome, expected);
        }
        assert!(s.verify_chain().is_ok());
    }

    /// `Failed` is not a refusal: the authority *was* exercised.
    #[test]
    fn failed_is_not_classified_as_a_refusal() {
        assert!(!Outcome::Failed.is_refusal());
        assert!(Outcome::Denied.is_refusal());
        assert!(Outcome::Attempted.is_refusal());
        assert!(!Outcome::Granted.is_refusal());
    }

    /// The three named outcomes must reach the ledger as three separate
    /// columns. This is the executable form of §10.1's "and *attempted*".
    #[test]
    fn the_ledger_keeps_granted_denied_and_attempted_separate() {
        let mut s = stream(8);
        push(&mut s, Outcome::Granted);
        push(&mut s, Outcome::Granted);
        push(&mut s, Outcome::Denied);
        push(&mut s, Outcome::Attempted);
        push(&mut s, Outcome::Failed);

        let l = s.ledger();
        assert_eq!(l.for_capability(Capability::FsRead), [2, 1, 1, 1]);
        assert_eq!(l.total_uses(), 5);
        assert_eq!(l.total_refusals(), 2, "denied + attempted, not failed");
    }

    // -- The ledger -------------------------------------------------------

    #[test]
    fn an_empty_stream_has_an_empty_ledger() {
        let l = stream(4).ledger();
        assert_eq!(l.total_uses(), 0);
        assert_eq!(l.total_refusals(), 0);
        assert!(l.capabilities().is_empty());
        assert!(l.tenants().is_empty());
        assert_eq!(l.for_capability(Capability::FsRead), [0; 4]);
    }

    #[test]
    fn the_ledger_separates_capabilities_and_tenants() {
        let mut s = stream(16);
        s.record(
            Some(&tenant("acme")),
            &component(),
            &grants(),
            Capability::FsRead,
            "read",
            Outcome::Granted,
        );
        s.record(
            Some(&tenant("globex")),
            &component(),
            &grants(),
            Capability::FsRead,
            "read",
            Outcome::Denied,
        );
        s.record(
            Some(&tenant("acme")),
            &component(),
            &grants(),
            Capability::HttpClient,
            "get",
            Outcome::Granted,
        );
        s.record(
            None,
            &component(),
            &grants(),
            Capability::FsRead,
            "read",
            Outcome::Attempted,
        );

        let l = s.ledger();
        assert_eq!(l.for_capability(Capability::FsRead), [1, 0, 1, 1]);
        assert_eq!(l.for_capability(Capability::HttpClient), [1, 0, 0, 0]);
        assert_eq!(
            l.for_tenant(&tenant("acme"), Capability::FsRead),
            [1, 0, 0, 0]
        );
        assert_eq!(
            l.for_tenant(&tenant("globex"), Capability::FsRead),
            [0, 0, 1, 0]
        );
        assert_eq!(l.for_unscoped(Capability::FsRead), [0, 0, 0, 1]);
        assert_eq!(
            l.for_tenant(&tenant("globex"), Capability::HttpClient),
            [0; 4],
            "a tenant that never used a capability has zero, not a missing row"
        );
        assert_eq!(l.total_uses(), 4);
    }

    #[test]
    fn the_ledger_lists_capabilities_and_tenants_in_deterministic_order() {
        let mut s = stream(16);
        for name in ["globex", "acme"] {
            s.record(
                Some(&tenant(name)),
                &component(),
                &grants(),
                Capability::FsRead,
                "read",
                Outcome::Granted,
            );
        }
        let l = s.ledger();
        let tenants: Vec<&str> = l.tenants().iter().map(|t| t.as_str()).collect();
        assert_eq!(tenants, vec!["acme", "globex"], "sorted, so reports diff");
        let caps = l.capabilities();
        assert_eq!(caps, vec![Capability::FsRead]);
    }

    #[test]
    fn the_ledger_renders_every_outcome_column_even_at_zero() {
        let mut s = stream(4);
        push(&mut s, Outcome::Granted);
        let text = s.ledger().render();
        for outcome in Outcome::ALL {
            assert!(
                text.contains(outcome.as_str()),
                "the report must name `{outcome}` even when it is zero: {text}"
            );
        }
        assert!(text.contains("fs.read"), "{text}");
        assert!(text.contains("total uses: 1"), "{text}");
        assert!(text.contains("refusals: 0"), "{text}");
    }

    #[test]
    fn the_ledger_report_names_each_tenant_with_its_capabilities() {
        let mut s = stream(4);
        s.record(
            Some(&tenant("acme")),
            &component(),
            &grants(),
            Capability::FsRead,
            "read",
            Outcome::Granted,
        );
        let text = s.ledger().render();
        assert!(text.contains("tenant acme:"), "{text}");
    }

    /// A tenant with no uses must not appear in the report at all, rather than
    /// appearing with a zero row -- a zero row for every capability times every
    /// tenant is how a report becomes unreadable.
    #[test]
    fn the_report_omits_tenants_with_no_uses() {
        let mut s = stream(4);
        push(&mut s, Outcome::Granted);
        let text = s.ledger().render();
        assert!(!text.contains("tenant globex"), "{text}");
        assert!(text.contains("tenant acme"), "{text}");
    }

    // -- Export -----------------------------------------------------------

    #[test]
    fn the_export_is_one_json_object_per_line_and_verifies_its_chain_first() {
        let mut s = stream(8);
        push(&mut s, Outcome::Granted);
        push(&mut s, Outcome::Denied);
        let jsonl = s.to_jsonl().expect("chain is intact");
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
        }
        assert!(lines[0].contains("\"sequence\":1"), "{}", lines[0]);
        assert!(lines[1].contains("\"outcome\":\"denied\""), "{}", lines[1]);
        assert!(lines[0].contains("\"tenant\":\"acme\""), "{}", lines[0]);
        assert!(
            lines[0].contains("\"capability\":\"fs.read\""),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains("\"function\":\"read\""), "{}", lines[0]);
    }

    /// **The export must refuse a corrupted stream.** Emitting a corrupted
    /// evidence record as a valid-looking document is the worst outcome
    /// available to this module.
    #[test]
    fn the_export_refuses_a_stream_whose_chain_is_broken() {
        let mut s = stream(8);
        push(&mut s, Outcome::Granted);
        push(&mut s, Outcome::Granted);
        s.records[0].capability = Capability::FsWrite;
        let e = s.to_jsonl().expect_err("must refuse a broken chain");
        let text = e.to_string();
        // Borrow the fields rather than moving them, so `e` stays usable for
        // the `Display` check below.
        match &e {
            LedgerError::ChainBroken { sequence, reason } => {
                assert_eq!(*sequence, 1);
                assert!(reason.contains("edited"), "{reason}");
            }
        }
        assert!(text.contains("record 1"), "{text}");
    }

    #[test]
    fn an_unscoped_record_renders_a_null_tenant() {
        let mut s = stream(4);
        s.record(
            None,
            &component(),
            &grants(),
            Capability::FsRead,
            "read",
            Outcome::Granted,
        );
        let jsonl = s.to_jsonl().expect("intact");
        assert!(jsonl.contains("\"tenant\":null"), "{jsonl}");
    }

    /// The JSON escaper is exhaustive over the escapes that would break a
    /// parser. A partial escaper is how a log becomes an injection vector.
    #[test]
    fn the_json_escaper_covers_every_breaking_character() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\rb"), "a\\rb");
        assert_eq!(json_escape("a\tb"), "a\\tb");
        assert_eq!(json_escape("a\u{0}b"), "a\\u0000b");
        assert_eq!(json_escape("a\u{1f}b"), "a\\u001fb");
        // Non-control unicode passes through unchanged.
        assert_eq!(json_escape("café"), "café");
    }

    /// Two records of the same event must render identically, or a digest
    /// comparison between hosts means nothing.
    #[test]
    fn two_identical_events_render_identically() {
        let mut a = stream(4);
        let mut b = stream(4);
        push(&mut a, Outcome::Granted);
        push(&mut b, Outcome::Granted);
        assert_eq!(a.records()[0].to_json(), b.records()[0].to_json());
        assert_eq!(a.head(), b.head());
    }

    #[test]
    fn the_display_form_is_one_line_and_names_the_tenant_and_outcome() {
        let mut s = stream(4);
        push(&mut s, Outcome::Granted);
        let line = s.records()[0].to_string();
        assert!(!line.contains('\n'), "{line}");
        assert!(line.contains("acme"), "{line}");
        assert!(line.contains("granted"), "{line}");
        assert!(line.contains("fs.read"), "{line}");
    }

    /// An unscoped record displays `-` for its tenant, so a single-tenant
    /// deployment's lines are still aligned.
    #[test]
    fn an_unscoped_record_displays_a_dash_for_its_tenant() {
        let mut s = stream(4);
        s.record(
            None,
            &component(),
            &grants(),
            Capability::FsRead,
            "read",
            Outcome::Granted,
        );
        assert!(
            s.records()[0].to_string().contains(" - "),
            "{}",
            s.records()[0]
        );
    }

    /// **A full stream's refusals must be visible in the counters**, because a
    /// caller that cannot tell "nothing happened" from "everything was refused"
    /// has no way to escalate.
    #[test]
    fn refusals_accumulate_in_the_counters_and_survive_a_successful_append() {
        let mut s = stream(1);
        assert!(push(&mut s, Outcome::Granted).was_recorded());
        for _ in 0..5 {
            assert_eq!(push(&mut s, Outcome::Granted), Append::Full);
        }
        assert_eq!(s.counters().refused, 5);
        assert_eq!(s.counters().recorded, 1);
        assert!(s.counters().has_gaps());
        assert_eq!(s.len(), 1);
        assert!(s.verify_chain().is_ok());
    }

    /// The default capacity is the documented constant.
    ///
    /// # Why the non-zero check is a `const` block and not an `assert!`
    ///
    /// Because `DEFAULT_CAPACITY > 0` is a constant expression: a runtime
    /// assertion of it can never fail, so it carries no information
    /// (`§M-006`, found twice in this workspace already). A `const` block is
    /// evaluated at compile time, which is *stronger* — it fails the build
    /// rather than a test — and it says honestly when the check happens.
    #[test]
    fn the_default_capacity_is_the_documented_value() {
        const {
            assert!(
                DEFAULT_CAPACITY > 0,
                "a zero default would refuse everything"
            );
        };
        assert_eq!(DEFAULT_CAPACITY, 65_536);
        let s = AuditStream::with_default_capacity();
        assert_eq!(s.capacity(), DEFAULT_CAPACITY);
    }
}
