# Security advisories

The public record of every security issue that has affected a QQQ release, and
every advisory we have assessed. Published here so a user can answer *"am I
affected?"* without waiting for a release note.

## The format, and why this one

Each advisory is one file in this directory named
`QQQ-YYYY-NNN.md`, where `NNN` is a zero-padded sequence number that is **never
reused**. The file is the record; anything else (a GitHub Security Advisory, a
release note, a mailing-list post) is a notification *about* it.

The identifier matters more than it looks. A reused or renumbered advisory makes
two different problems share one name, and the first thing anyone does with a
security report is search for the identifier they were given. Sequence numbers are
allocated in `INDEX.md` and never recycled, even if an advisory is withdrawn.

## The index

[`INDEX.md`](INDEX.md) lists every advisory with its identifier, severity, affected
versions, and fixed version. It is the file to read first, and the file a
downstream tool would parse — there is a check in the test suite that keeps it in
sync with the individual files, so it cannot silently drift.

## What counts as an advisory

The classes are defined in [`/SECURITY.md`](../SECURITY.md), and they are the same
list a reporter is pointed at. In short: sandbox escape, capability bypass, limit
bypass, secret disclosure, supply chain, audit integrity, and host memory safety.

Two things are worth stating explicitly, because they are where advisory feeds
usually go wrong:

* **An advisory is published even when the fix is trivial.** The instinct is to
  treat "we fixed it in an hour" as not worth an entry. It is worth an entry,
  because the question users have is not how hard the fix was but *whether their
  deployment was affected for three weeks*.
* **An advisory is published when the outcome is "not affected".** An upstream
  advisory that turns out not to apply, or a report that turns out to be intended
  behaviour, still gets an entry when it was plausibly a QQQ issue. Silence is
  indistinguishable from not having looked.

## What an advisory contains

Every file has the same sections, and the required ones are enforced by
`tools/check_advisories.py` rather than by convention:

| Section | Why it is required |
|---|---|
| **Identifier** | The searchable name; matches the filename |
| **Published** | The date the *advisory* was published, not when the issue was found — the gap between them is itself information |
| **Severity** | One of `critical`, `high`, `medium`, `low`; must match the index |
| **Affected versions** | A range a user can test their deployment against. `>=0.3.0, <0.3.2`, not "0.3.x" |
| **Fixed in** | The version that contains the fix, or `not fixed` with a reason |
| **Summary** | One sentence, in plain language, that a non-specialist can act on |
| **Impact** | What an attacker gains. Written as a consequence, not as a mechanism |
| **Mitigation** | What to do *before* upgrading, if anything. `none available` is a valid answer and is better than silence |
| **Credit** | Who reported it, unless they asked not to be named |
| **Details** | The technical narrative, including what we got wrong |

## The two dates, stated separately

`Published` and the find-date are different, and the gap is deliberately visible
(see the table in [`INDEX.md`](INDEX.md)). A project that reports only the publish
date makes its response time unauditable, and a project that reports only the
find-date hides how long users were exposed. Both are needed to answer *"was I at
risk, and for how long?"*

## Embargoes

We follow a **90-day** coordinated-disclosure window from the reporter's first
contact, shortened when the reporter prefers it and extended only with their
agreement. Exceptions, both directions:

* **Shorter**, if the issue is being exploited in the wild or is already public.
  A 90-day clock is a courtesy to us, not a licence to leave users exposed.
* **Longer**, at the reporter's request, and we say so in the advisory.

If a fix is ready before the window closes, we publish early rather than sitting on
it. The embargo exists to give us time to fix, not to give us time to schedule a
press release.

## Relationship to GitHub Security Advisories

Where a GitHub Security Advisory exists, it links here and this file links there.
This directory is authoritative for **content**; GitHub is authoritative for
**notification**, because that is where the ecosystem's tooling already looks. A
repository that kept its advisories only in GitHub's database would lose them if the
project moved, which is a strange thing to accept for the one class of document
whose whole purpose is durable attribution.
