# QQQ deprecation ledger

Every `@deprecated` annotation in `wit/` has exactly one row here, and every
row names a `@deprecated` annotation that exists. `tools/check_wit_deprecated.py`
enforces both directions, so the ledger cannot drift from the interfaces and
the interfaces cannot deprecate silently.

## Format

| Item | Deprecated in | Remove in | Replacement |
|---|---|---|---|
| `<namespace>:<package>.<interface>.<member>` | `X.Y.Z` | `X.Y+2+.Z` or later | what to use instead |

Item shapes: a function or type is `<namespace>:<package>.<interface>.<member>`;
a resource method adds its resource (`<namespace>:<package>.<interface>.<resource>.<method>`);
a whole interface is `<namespace>:<package>.<interface>` and a whole resource is
`<namespace>:<package>.<interface>.<resource>`.

- **Item** names the deprecated member precisely enough to find it.
- **Deprecated in** repeats the annotation's version (a mismatch is an error).
- **Remove in** is at least two minor versions after deprecation within the
  same major version (NN-8) — a new major version satisfies the window.
- **Replacement** names the migration target. `none` is allowed only with a
  reason appended (`none — the capability is withdrawn because ...`).

## Entries

| Item | Deprecated in | Remove in | Replacement |
|---|---|---|---|
| *(none — no interface item is currently deprecated)* | | | |
