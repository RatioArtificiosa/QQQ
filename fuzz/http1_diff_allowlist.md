# `http1_diff` allow-list — `I-07`

The differential target (`fuzz/fuzz_targets/http1_diff.rs`) aborts on two
shapes: a field disagreement when both parsers accept, and any input QQQ
accepts that `httparse` rejects. This file names every **intentional**
difference so a run stays silent on policy and loud on bugs.

## Comparison rules (not allow-list entries)

These normalise before comparing and never abort:

* **Method** compares case-insensitively. `Method::parse` trims and
  uppercases, so `get` and `GET` are one method to QQQ while `httparse`
  returns the raw token. Anything QQQ accepts maps to one of the nine
  known uppercase tokens; an unknown method is refused (`UnknownMethod`)
  and never reaches the comparison.
* **Header values** compare after OWS trimming on both sides. QQQ stores
  values trimmed; `httparse` returns raw spans.
* **Header names** compare case-insensitively, order-sensitively, with
  equal counts. Both sides preserve every header including framing ones.
* **Framing** compares `(content_length, chunked)` derived from the
  header lists with the same rule: the single `Content-Length` parsed as
  `u64`, `Transfer-Encoding: chunked` (case-insensitive) as the flag.
  QQQ refuses duplicates, conflicts and non-chunked encodings, so both
  sides reaching the comparison own at most one of each.

## Allow-listed arm-2 inputs (QQQ accepts, `httparse` rejects)

Empty. Every entry needs the byte shape, the rule that makes it
intentional, and the observation that recorded it.

## Deliberately NOT allow-listed (QQQ rejects, `httparse` accepts)

These land in arm 3 by design and need no entry: unknown methods,
absolute-URI and non-ASCII targets, over-long and over-count heads,
obs-fold, duplicate `Host`/`Content-Length`/`Transfer-Encoding`,
conflicting framing, unsupported encodings and versions, and every
`F-04` refusal row. QQQ is the stricter parser; strictness is logged
nowhere because at fuzz throughput the log would be the signal's grave.
