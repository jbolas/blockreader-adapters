//! Reading `fixtures/out/manifest.json`, which `fixtures/generate.sh` writes.

use std::path::PathBuf;

use blockreader::{Location, SectorSize, SectorSizeBasis, UnknownCause};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{Expected, UnknownExpectation, UnknownRange};

/// The whole manifest.
#[derive(Debug, Deserialize)]
pub struct Manifest {
    /// The reference image.
    pub raw: Raw,
    /// Every image converted from it.
    pub fixtures: Vec<Fixture>,
    /// A VMDK delta whose parent is absent; it must fail to open.
    pub missing_parent: String,
}

/// The reference image.
#[derive(Debug, Deserialize)]
pub struct Raw {
    /// Relative to `fixtures/out/`.
    pub path: String,
    /// In bytes.
    pub size: u64,
    /// Lowercase hex.
    pub sha256: String,
}

/// One converted image.
#[derive(Debug, Deserialize)]
pub struct Fixture {
    /// A short name for messages.
    pub name: String,
    /// Relative to `fixtures/out/`.
    pub path: String,
    /// `"e01"`, `"vmdk"`, or `"aff4"`.
    pub format: String,
    /// The sector size the adapter must report.
    pub sector_bytes: u32,
    /// `"assumed"`, `"recorded"`, or `"asserted"`.
    pub sector_basis: String,
    /// Which ranges must be reported as unknown.
    pub unknown: Unknown,
}

/// The manifest's form of [`UnknownExpectation`].
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Unknown {
    /// None.
    None,
    /// Exactly one chunk.
    OneChunk {
        /// The chunk size in bytes.
        chunk_bytes: u64,
        /// See [`cause`].
        cause: String,
    },
    /// Exactly these ranges.
    Ranges {
        /// In address order.
        ranges: Vec<Range>,
    },
}

/// One expected unknown range.
#[derive(Debug, Deserialize)]
pub struct Range {
    /// Where it begins.
    pub offset: u64,
    /// How long it is.
    pub len: u64,
    /// See [`cause`].
    pub cause: String,
}

/// `fixtures/out/`, from this crate's directory.
#[must_use]
pub fn out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/out")
}

impl Manifest {
    /// Load the manifest.
    ///
    /// # Panics
    ///
    /// If it is missing or unreadable: a gated test must fail, never skip,
    /// when its fixtures are absent.
    #[must_use]
    pub fn load() -> Self {
        let path = out_dir().join("manifest.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}. The fixture tests need generated fixtures: run \
                 fixtures/generate.sh first",
                path.display()
            )
        });
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: not a valid manifest: {e}", path.display()))
    }

    /// The reference image's bytes, after checking them against the manifest.
    ///
    /// # Panics
    ///
    /// If the file is missing or its size or SHA-256 differs.
    #[must_use]
    pub fn raw_bytes(&self) -> Vec<u8> {
        let path = out_dir().join(&self.raw.path);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(
            bytes.len() as u64,
            self.raw.size,
            "raw image size differs from the manifest"
        );
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(
            digest, self.raw.sha256,
            "raw image SHA-256 differs from the manifest"
        );
        bytes
    }
}

impl Fixture {
    /// Where this fixture lives.
    #[must_use]
    pub fn location(&self) -> Location {
        Location::Path(out_dir().join(&self.path))
    }

    /// What the adapter must serve for this fixture.
    ///
    /// # Panics
    ///
    /// On a manifest value this code does not know.
    #[must_use]
    pub fn expected<'a>(&'a self, reference: &'a [u8]) -> Expected<'a> {
        let basis = match self.sector_basis.as_str() {
            "assumed" => SectorSizeBasis::Assumed,
            "recorded" => SectorSizeBasis::Recorded,
            "asserted" => SectorSizeBasis::Asserted,
            other => panic!("{}: unknown sector basis {other:?}", self.name),
        };
        let unknown = match &self.unknown {
            Unknown::None => UnknownExpectation::None,
            Unknown::OneChunk {
                chunk_bytes,
                cause: c,
            } => UnknownExpectation::OneChunk {
                chunk_size: *chunk_bytes,
                cause: cause(c),
            },
            Unknown::Ranges { ranges } => UnknownExpectation::Exactly(
                ranges
                    .iter()
                    .map(|r| UnknownRange {
                        offset: r.offset,
                        len: r.len,
                        cause: cause(&r.cause),
                    })
                    .collect(),
            ),
        };
        Expected {
            reference,
            unknown,
            format: &self.format,
            location: Some(self.location()),
            sector_size: SectorSize::new(self.sector_bytes, basis)
                .unwrap_or_else(|e| panic!("{}: {e}", self.name)),
        }
    }
}

/// The manifest's spelling of each [`UnknownCause`].
///
/// # Panics
///
/// On an unknown spelling.
#[must_use]
pub fn cause(text: &str) -> UnknownCause {
    match text {
        "not-acquired" => UnknownCause::NotAcquired,
        "unreadable-at-acquisition" => UnknownCause::UnreadableAtAcquisition,
        "failed-integrity" => UnknownCause::FailedIntegrity,
        other => panic!("unknown cause {other:?}"),
    }
}
