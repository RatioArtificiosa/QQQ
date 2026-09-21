# Advisory index

Every published QQQ security advisory. Read this first; each row links to the full
record.

**Current:** no advisories have been published for any QQQ release.

| Identifier | Published | Found | Severity | Affected | Fixed in | Summary |
|---|---|---|---|---|---|---|
| _(none)_ | | | | | | |

The table being empty is the accurate state of the project: QQQ has not yet been
released, so there is no released version for an advisory to affect. It is written
as an explicit empty table with a `(none)` row rather than left out, so that
"nothing here" reads as a statement someone made rather than a section someone
forgot — and so the parser in `tools/check_advisories.py` has something to find.

## How this file is kept honest

`tools/check_advisories.py` runs in CI and fails when:

1. An advisory file exists in this directory but has no row here.
2. A row here names an advisory file that does not exist.
3. An identifier is defined twice, in this file or among the filenames.
4. An advisory is missing a required section.
5. A severity in a file disagrees with the severity in its row.
6. An identifier breaks the `QQQ-YYYY-NNN` format, or `NNN` is not unique.
7. The "Found" date is later than the "Published" date.

The check exists because an index maintained by hand drifts, and a drifted security
index is worse than none: it tells a reader they are unaffected when the file
sitting next to it says otherwise. `§O-085` and `§O-088` in
`QQQ-Observations-and-Memories.md` are both records of a control that was installed
and never fired; an index with no check is the same shape.

## Adding an advisory

1. Write `QQQ-YYYY-NNN.md` using the sections in [`README.md`](README.md).
2. Add its row here.
3. Run `python tools/check_advisories.py` — it fails if the two disagree.
4. `NNN` is never reused, including after a withdrawal. A withdrawn advisory stays
   in the index with `withdrawn` as its fixed-in value and a reason, because a
   user who was told to act on it needs to be told to stop.
