// SPDX-License-Identifier: Apache-2.0

//! Manifest loading: locating, parsing and normalizing `qqq.toml`.
//!
//! Shared by every command that needs to know what a project is allowed to do.
//! Centralised because the *search* behaviour must be identical everywhere: a
//! command that found a different manifest than another would produce a
//! capability report that disagrees with what the runtime enforces.
//!
//! # Why the search is explicit, not magic
//!
//! `qqqai` looks for `qqq.toml` in the **current directory only**, not walking
//! upward. Monorepo-style upward search is convenient and ambiguous: in a
//! directory nested under two projects, which manifest applies? NN-5 says
//! nothing important is inferred, so the rule is one directory and an explicit
//! `--manifest` flag for anything else.

use std::path::{Path, PathBuf};

use qqq_cap::manifest::Manifest;
use qqq_core::{Error, ErrorCode, Result};

/// The conventional manifest filename.
pub const MANIFEST_NAME: &str = "qqq.toml";

/// A loaded manifest together with where it came from.
#[derive(Debug, Clone)]
pub struct LoadedManifest {
    /// The parsed manifest.
    pub manifest: Manifest,
    /// The path it was read from.
    pub path: PathBuf,
    /// The raw text, retained so an error can quote the offending line.
    pub source: String,
}

impl LoadedManifest {
    /// Load from an explicit path.
    ///
    /// # Errors
    ///
    /// * `QQQ-2001` — the file could not be read.
    /// * `QQQ-2001` / `QQQ-2002` — the manifest is syntactically or
    ///   semantically invalid. The error names the offending field.
    pub fn load(path: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(path).map_err(|e| {
            Error::new(
                ErrorCode::ManifestSyntaxInvalid,
                format!("could not read `{}`", path.display()),
            )
            .with_cause(e.to_string())
            .with_remediation(format!(
                "run `{} new <name>` to create a project, or pass --manifest <path>",
                qqq_core::BINARY_NAME
            ))
        })?;

        let manifest = Manifest::parse(&source).map_err(|e| {
            let code = match e {
                qqq_cap::manifest::ManifestError::Syntax { .. } => ErrorCode::ManifestSyntaxInvalid,
                qqq_cap::manifest::ManifestError::LimitOutOfRange { .. } => {
                    ErrorCode::LimitOutOfRange
                }
                _ => ErrorCode::ManifestSchemaViolation,
            };
            Error::new(code, e.to_string())
                .with_context("manifest", path.display().to_string())
                .with_remediation("run `qqqai schema --command manifest` for the expected shape")
        })?;

        Ok(Self {
            manifest,
            path: path.to_path_buf(),
            source,
        })
    }

    /// Locate and load the manifest for a command.
    ///
    /// # Errors
    ///
    /// `QQQ-2001` when no manifest is found in `dir`.
    pub fn discover(dir: &Path, explicit: Option<&Path>) -> Result<Self> {
        if let Some(p) = explicit {
            return Self::load(p);
        }
        let candidate = dir.join(MANIFEST_NAME);
        if candidate.exists() {
            return Self::load(&candidate);
        }
        Err(Error::new(
            ErrorCode::ManifestSyntaxInvalid,
            format!("no `{MANIFEST_NAME}` in `{}`", dir.display()),
        )
        .with_remediation(format!(
            "run `{} new <name>` here, or pass --manifest <path>",
            qqq_core::BINARY_NAME
        )))
    }

    /// The project name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.manifest.package.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-manifest-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    #[test]
    fn loads_a_valid_manifest() {
        let dir = temp_dir("valid");
        let path = dir.join(MANIFEST_NAME);
        std::fs::write(&path, "[package]\nname = \"app\"\nversion = \"0.1.0\"\n").unwrap();

        let loaded = LoadedManifest::load(&path).expect("must load");
        assert_eq!(loaded.name(), "app");
        assert_eq!(loaded.path, path);
        assert!(!loaded.source.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_gives_an_actionable_error() {
        let dir = temp_dir("missing");
        let path = dir.join("nope.toml");
        let e = LoadedManifest::load(&path).unwrap_err();
        assert_eq!(e.code, ErrorCode::ManifestSyntaxInvalid);
        assert!(e.remediation.is_some());
        assert!(e.render().contains("qqqai new"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_invalid_manifest_names_the_offending_field() {
        let dir = temp_dir("invalid");
        let path = dir.join(MANIFEST_NAME);
        // Missing the required version field.
        std::fs::write(&path, "[package]\nname = \"app\"\n").unwrap();

        let e = LoadedManifest::load(&path).unwrap_err();
        assert!(
            e.message.contains("package.version"),
            "the error must name the field: {}",
            e.message
        );
        assert!(e.remediation.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovery_finds_the_manifest_in_the_directory() {
        let dir = temp_dir("discover");
        std::fs::write(
            dir.join(MANIFEST_NAME),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let loaded = LoadedManifest::discover(&dir, None).expect("must discover");
        assert_eq!(loaded.name(), "app");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovery_does_not_walk_upward() {
        let parent = temp_dir("nowalk");
        std::fs::write(
            parent.join(MANIFEST_NAME),
            "[package]\nname = \"parent\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let child = parent.join("nested");
        std::fs::create_dir_all(&child).unwrap();

        // A manifest in the parent must NOT be found from the child: upward
        // search is ambiguous in a monorepo and NN-5 forbids inferring it.
        let e = LoadedManifest::discover(&child, None).unwrap_err();
        assert!(e.message.contains("no `qqq.toml`"), "got: {}", e.message);
        assert!(e
            .remediation
            .as_deref()
            .unwrap_or("")
            .contains("--manifest"));

        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn an_explicit_path_overrides_discovery() {
        let dir = temp_dir("explicit");
        std::fs::write(
            dir.join("custom.toml"),
            "[package]\nname = \"custom\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let loaded =
            LoadedManifest::discover(&dir, Some(&dir.join("custom.toml"))).expect("must load");
        assert_eq!(loaded.name(), "custom");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
