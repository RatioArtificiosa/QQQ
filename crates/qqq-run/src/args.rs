// SPDX-License-Identifier: Apache-2.0

//! CLI argument pre-expansion: `--flag=value` into `--flag value`.
//!
//! The two spellings are one contract — every value flag accepts both — so
//! the expansion lives here, once, instead of as a `strip_prefix` arm in
//! every parser. A parser lists the flags that take values; anything else
//! keeps its spelling so the unknown-flag error names what the user typed.
//!
//! ```
//! let expanded = qqq_run::args::expand_equals(
//!     &["--target=x".to_owned()],
//!     &["--target"],
//! );
//! assert_eq!(expanded, vec!["--target".to_owned(), "x".to_owned()]);
//! ```

/// Split `--flag=value` into `--flag value` for the flags that take a value.
///
/// Only the listed flags split. Anything else — including a `--flag=` whose
/// flag takes no value — keeps its spelling, so the parser's unknown-flag
/// arm still names the user's actual input.
///
/// An empty value (`--flag=`) expands to the bare flag, so the parser's
/// missing-value error fires: an empty path, name, or key never names
/// anything real, and accepting it would defer the failure to a confusing
/// downstream error.
///
/// ```
/// let expanded = qqq_run::args::expand_equals(
///     &["--target=x".to_owned(), "--release".to_owned(), "--bogus=y".to_owned()],
///     &["--target"],
/// );
/// assert_eq!(
///     expanded,
///     vec!["--target".to_owned(), "x".to_owned(), "--release".to_owned(), "--bogus=y".to_owned()]
/// );
/// let empty = qqq_run::args::expand_equals(&["--target=".to_owned()], &["--target"]);
/// assert_eq!(empty, vec!["--target".to_owned()]);
/// ```
#[must_use]
pub fn expand_equals(args: &[String], value_flags: &[&str]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") && value_flags.contains(&flag) => {
                out.push(flag.to_owned());
                // An empty value is a missing value: pushing the bare flag
                // lets the parser's `missing_value` fire instead of a
                // downstream error about an empty path.
                if !value.is_empty() {
                    out.push(value.to_owned());
                }
            }
            _ => out.push(arg.clone()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only listed flags split; everything else keeps its spelling for the
    /// unknown-flag error.
    #[test]
    fn only_listed_flags_split() {
        let expanded = expand_equals(
            &[
                "--target=x".to_owned(),
                "--release".to_owned(),
                "--bogus=y".to_owned(),
                "positional".to_owned(),
            ],
            &["--target"],
        );
        assert_eq!(
            expanded,
            vec![
                "--target".to_owned(),
                "x".to_owned(),
                "--release".to_owned(),
                "--bogus=y".to_owned(),
                "positional".to_owned(),
            ]
        );
    }

    /// A single `=` in a value is not a flag boundary: only the first split
    /// counts, and values keep the rest.
    #[test]
    fn values_keep_their_equals() {
        let expanded = expand_equals(&["--filter=a=b".to_owned()], &["--filter"]);
        assert_eq!(expanded, vec!["--filter".to_owned(), "a=b".to_owned()]);
    }

    /// Short flags never split, even when listed behaviour would suggest it:
    /// `-f=x` is not a spelling any parser accepts.
    #[test]
    fn short_flags_never_split() {
        let expanded = expand_equals(&["-f=x".to_owned()], &["-f"]);
        assert_eq!(expanded, vec!["-f=x".to_owned()]);
    }
}
