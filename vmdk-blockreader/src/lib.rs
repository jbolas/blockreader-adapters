//! Reads VMDK disk images through the [`blockreader::BlockReader`] trait,
//! using the `vmdk-rs` reader from imagereader-rs.
//!
//! # Content the format defines:
//! An unallocated grain reads as zeros, or as the parent disk's data in a
//! delta chain. That content is defined by the format, so it
//! is returned as data. VMDK carries no integrity data, so this adapter never
//! reports [`blockreader::Error::UnknownContent`]. A grain that fails to
//! decompress is an ordinary error.
//!
//! # Sector size
//! VMDK counts in 512-byte sectors, but that is the format's addressing unit,
//! not the acquired device's sector size, so the size is reported as assumed.
//!
//! # Warning against use of asynchronous code
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

use blockreader::{BlockReader, Error, Location, Result, SourceDescription};
use vmdkrs::vmdk_reader::{CacheMode, VmdkReader, VmdkReaderOptions};

/// The default cache budget, in MiB. imagereader's own default is 256 MiB.
pub const DEFAULT_CACHE_MEM_MIB: usize = 64;

/// How to open a VMDK image.
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

/// A [`BlockReader`] over a VMDK image: a descriptor and its extents, or a
/// monolithic file, including delta disks and their parents.
pub struct VmdkSource {
    reader: VmdkReader,
    path: PathBuf,
    size: u64,
}

/// Why a VMDK image was not opened, when the reason is this adapter's own.
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

impl VmdkSource {
    /// Open the VMDK image `location` names, with the default [`Options`].
    ///
    /// # Errors
    ///
    /// As [`VmdkSource::open_with`].
    pub fn open(location: &Location) -> Result<Self> {
        Self::open_with(location, &Options::default())
    }

    /// Open the VMDK image `location` names. Extents and parent disks are
    /// found relative to it.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] if `location` is a URL (not supported yet) or a path
    /// that is not valid UTF-8, or if `vmdk-rs` cannot open the image,
    /// including a delta disk whose parent is missing. Also if the image
    /// describes no data at all, which `vmdk-rs` would present as a 0-byte
    /// disk.
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
                "{}: the path is not valid UTF-8, which vmdk-rs requires",
                path.display()
            )))
        })?;

        let reader = VmdkReader::open_with_options(text, &reader_options(options))
            .map_err(Error::backend)?;
        // vmdk-rs opens some malformed inputs, such as a sparse header whose
        // fields are all zero or a descriptor naming no extents, as a 0-byte
        // disk. Presenting that as an empty disk would hide the defect.
        if reader.image_size == 0 {
            return Err(Error::backend(Refused(format!(
                "{}: the VMDK header or descriptor describes no data; refusing it rather \
                 than presenting an empty disk",
                path.display()
            ))));
        }
        Ok(Self {
            size: reader.image_size,
            reader,
            path,
        })
    }
}

/// The `vmdk-rs` options for a local file.
fn reader_options(options: &Options) -> VmdkReaderOptions {
    VmdkReaderOptions {
        // A local file gains nothing from the disk tier or a metadata cache.
        cache_mode: CacheMode::SingleMemory,
        cache_mem_mib: options.cache_mem_mib,
        // Scattered reads: fetch only what is asked for. The block and fetch
        // sizes keep upstream's equal 1 MiB defaults.
        foyer_readahead: 0,
        // The I/O log distorts what it measures.
        io_log: None,
        ..VmdkReaderOptions::default()
    }
}

impl std::fmt::Debug for VmdkSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmdkSource")
            .field("path", &self.path)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl BlockReader for VmdkSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        self.reader
            .read_at_offset(offset, buf)
            .map_err(Error::backend)
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn describe(&self) -> SourceDescription {
        SourceDescription::new(
            Some(Location::Path(self.path.clone())),
            Some("vmdk".to_string()),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_url_is_refused_for_now() {
        let err = VmdkSource::open(&Location::Url("s3://bucket/disk.vmdk".into())).unwrap_err();
        assert!(err.to_string().contains("not supported yet"), "{err}");
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let err = VmdkSource::open(&Location::Path("/nonexistent/evidence/disk.vmdk".into()))
            .unwrap_err();
        assert!(matches!(err, Error::Backend(_)), "{err:?}");
    }

    #[test]
    fn a_file_that_is_not_vmdk_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fake.vmdk");
        std::fs::write(&p, b"this is not a VMDK").unwrap();
        assert!(VmdkSource::open(&Location::Path(p)).is_err());
    }

    /// vmdk-rs opens these malformed inputs as 0-byte disks. The adapter must
    /// refuse them, not present an empty disk.
    #[test]
    fn a_vmdk_that_describes_no_data_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for (name, head) in [
            // A sparse header whose every field is zero: version 0, capacity 0,
            // grain size 0.
            ("zero-header.vmdk", &b"KDMV"[..]),
            // A descriptor that names no extents.
            (
                "no-extents.vmdk",
                &b"# Disk DescriptorFile\nversion=1\n"[..],
            ),
        ] {
            let p = dir.path().join(name);
            let mut bytes = head.to_vec();
            bytes.resize(4096, 0);
            std::fs::write(&p, &bytes).unwrap();
            let err = VmdkSource::open(&Location::Path(p)).unwrap_err();
            assert!(matches!(err, Error::Backend(_)), "{name}: {err:?}");
            assert!(
                err.to_string().contains("describes no data"),
                "{name}: {err}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff.vmdk"));
        let err = VmdkSource::open(&Location::Path(p)).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }

    #[test]
    fn options_default_to_a_64_mib_cache() {
        assert_eq!(Options::default().cache_mem_mib, 64);
        let o = reader_options(&Options::default());
        assert_eq!(o.cache_mem_mib, 64);
        assert_eq!(o.foyer_readahead, 0);
        assert!(matches!(o.cache_mode, CacheMode::SingleMemory));
        assert!(o.io_log.is_none());
    }

    #[test]
    fn vmdk_source_is_a_shareable_block_reader() {
        fn check<T: BlockReader + Send + Sync + 'static>() {}
        check::<VmdkSource>();
    }
}
