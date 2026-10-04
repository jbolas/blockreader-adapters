//! Reads E01 (EWF) disk images through the [`blockreader::BlockReader`]
//! trait, using the `e01-rs` reader from imagereader-rs.
//!
//! # A note on unknown content:
//! A chunk that fails to decompress or fails its checksum is reported as
//! [`blockreader::Error::UnknownContent`] with cause
//! [`UnknownCause::FailedIntegrity`], covering exactly that chunk. It is never
//! served as zeros. The reader is opened with `CorruptChunkPolicy::Error`.
//!
//! # Warning on use of asynchronous code
//! Each reader owns a tokio runtime and blocks on it for every read. Calling
//! [`BlockReader::read_at`] from inside an async task panics. Call it from
//! ordinary threads.

#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unused_must_use
)]
#![warn(missing_docs, clippy::pedantic)]

use std::path::PathBuf;

use blockreader::{
    BlockReader, Error, Location, Result, SectorSize, SectorSizeBasis, SourceDescription,
    UnknownCause,
};
use e01::e01_reader::{
    CacheMode, CorruptChunkPolicy, CorruptSectionPolicy, E01Reader, E01ReaderOptions, ReadError,
    ReadErrorKind,
};

/// The default cache budget, in MiB.
///
/// imagereader's own default is 1 GiB, sized for a server. A filesystem walk
/// over a local file needs far less.
pub const DEFAULT_CACHE_MEM_MIB: usize = 64;

/// How to open an E01 image.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The memory budget of imagereader's block cache, in MiB.
    pub cache_mem_mib: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            cache_mem_mib: DEFAULT_CACHE_MEM_MIB,
        }
    }
}

/// A [`BlockReader`] over an E01 image and its segments (`.E01`, `.E02`, …).
pub struct E01Source {
    reader: E01Reader,
    path: PathBuf,
    size: u64,
    chunk_size: u64,
    sector_size: SectorSize,
}

/// Why an E01 image was not opened, when the reason is this adapter's own.
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

impl E01Source {
    /// Open the E01 image whose segment `location` names, with the default
    /// [`Options`]. Later segments are found beside it.
    ///
    /// # Errors
    ///
    /// As [`E01Source::open_with`].
    pub fn open(location: &Location) -> Result<Self> {
        Self::open_with(location, &Options::default())
    }

    /// Open the E01 image whose segment `location` names.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] if `location` is a URL (not supported yet) or a path
    /// that is not valid UTF-8, or if `e01-rs` cannot open the image.
    /// [`Error::InvalidSectorSize`] if the image records a sector size that is
    /// zero or not a power of two: partition arithmetic would be wrong, and
    /// substituting a value would be a silent correction.
    pub fn open_with(location: &Location, options: &Options) -> Result<Self> {
        let path = match location {
            Location::Path(p) => p.clone(),
            Location::Url(u) => {
                return Err(Error::backend(Refused(format!(
                    "{u}: opening a URL is not supported yet; name a local file"
                ))));
            }
            other => {
                return Err(Error::backend(Refused(format!(
                    "{other}: this kind of location is not supported"
                ))));
            }
        };
        let text = path.to_str().ok_or_else(|| {
            Error::backend(Refused(format!(
                "{}: the path is not valid UTF-8, which e01-rs requires",
                path.display()
            )))
        })?;

        let reader =
            E01Reader::open_glob(text, &reader_options(options)).map_err(Error::backend)?;
        let bytes = u32::try_from(reader.sector_size)
            .map_err(|_| Error::InvalidSectorSize { bytes: u32::MAX })?;
        let sector_size = SectorSize::new(bytes, SectorSizeBasis::Recorded)?;

        Ok(Self {
            size: reader.image_size,
            chunk_size: reader.chunk_size as u64,
            reader,
            path,
            sector_size,
        })
    }
}

/// The `e01-rs` options for a local file.
fn reader_options(options: &Options) -> E01ReaderOptions {
    E01ReaderOptions {
        // Unknown content is an error, never zeros. Upstream defaults the
        // chunk policy to zero-filling, so this must be explicit.
        corrupt_chunk_policy: CorruptChunkPolicy::Error,
        corrupt_section_policy: CorruptSectionPolicy::Error,
        // A local file gains nothing from the disk tier or a metadata cache.
        cache_mode: CacheMode::SingleMemory,
        cache_mem_mib: options.cache_mem_mib,
        // A filesystem walk is scattered, so readahead would fetch unwanted
        // bytes. The block and fetch sizes keep upstream's equal 1 MiB
        // defaults, and parallel decompression its measured 4 threads.
        foyer_readahead: 0,
        // The I/O log distorts what it measures.
        io_log: None,
        ..E01ReaderOptions::default()
    }
}

impl std::fmt::Debug for E01Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("E01Source")
            .field("path", &self.path)
            .field("size", &self.size)
            .field("chunk_size", &self.chunk_size)
            .field("sector_size", &self.sector_size)
            .finish_non_exhaustive()
    }
}

impl BlockReader for E01Source {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let mut want = buf.len();
        loop {
            match self.reader.read_at_offset(offset, &mut buf[..want]) {
                Ok(n) => return Ok(n),
                Err(e) => {
                    let Some(chunk) = failed_chunk(&e) else {
                        return Err(Error::backend(e));
                    };
                    let start = (chunk as u64).saturating_mul(self.chunk_size);
                    let end = start.saturating_add(self.chunk_size).min(self.size);
                    if start > offset {
                        // Serve the good bytes before the bad chunk: an honest
                        // short read. This repeats because parallel
                        // decompression can report a later bad chunk before an
                        // earlier one; `want` shrinks every time, since the
                        // failed chunk lies inside the range just requested.
                        want = usize::try_from(start - offset).map_or(want, |w| w.min(want));
                        continue;
                    }
                    return Err(Error::UnknownContent {
                        offset: start,
                        len: end - start,
                        cause: UnknownCause::FailedIntegrity,
                    });
                }
            }
        }
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn sector_size(&self) -> SectorSize {
        self.sector_size
    }

    fn describe(&self) -> SourceDescription {
        SourceDescription::new(
            Some(Location::Path(self.path.clone())),
            Some("e01".to_string()),
        )
    }
}

/// The chunk whose stored bytes failed an integrity check, if that is what
/// `e` reports.
fn failed_chunk(e: &ReadError) -> Option<usize> {
    let kind = std::error::Error::source(e)?.downcast_ref::<ReadErrorKind>()?;
    match kind {
        ReadErrorKind::BadChecksum(chunk, ..)
        | ReadErrorKind::DecompressionFailed(chunk, _)
        | ReadErrorKind::TooShort(chunk, _)
        | ReadErrorKind::BadChunkBounds { chunk, .. } => Some(*chunk),
        ReadErrorKind::OffsetBeyondEnd(..) | ReadErrorKind::IoError(_) => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_url_is_refused_for_now() {
        let err = E01Source::open(&Location::Url("s3://bucket/disk.E01".into())).unwrap_err();
        assert!(err.to_string().contains("not supported yet"), "{err}");
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let err =
            E01Source::open(&Location::Path("/nonexistent/evidence/disk.E01".into())).unwrap_err();
        assert!(matches!(err, Error::Backend(_)), "{err:?}");
    }

    #[test]
    fn a_file_that_is_not_e01_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fake.E01");
        std::fs::write(&p, b"this is not an EWF segment file").unwrap();
        assert!(E01Source::open(&Location::Path(p)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff.E01"));
        let err = E01Source::open(&Location::Path(p)).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }

    #[test]
    fn options_default_to_a_64_mib_cache() {
        assert_eq!(Options::default().cache_mem_mib, 64);
        let o = reader_options(&Options::default());
        assert_eq!(o.cache_mem_mib, 64);
        assert_eq!(o.corrupt_chunk_policy, CorruptChunkPolicy::Error);
        assert_eq!(o.corrupt_section_policy, CorruptSectionPolicy::Error);
        assert_eq!(o.foyer_readahead, 0);
        assert!(matches!(o.cache_mode, CacheMode::SingleMemory));
        assert!(o.io_log.is_none());
    }

    #[test]
    fn e01_source_is_a_shareable_block_reader() {
        fn check<T: BlockReader + Send + Sync + 'static>() {}
        check::<E01Source>();
    }
}
