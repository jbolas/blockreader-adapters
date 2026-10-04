//! Reads AFF4 evidence containers through the [`blockreader::BlockReader`]
//! trait, so a filesystem parser can consume one without depending on the AFF4
//! library's own API.
//!
//! Opening is [`aff4tools::disk_image`]'s: naming any part of a multi-part set
//! opens the whole set, and a container with several disk images must be told
//! which one to open. Regions the container records as `aff4:UnknownData` or
//! `aff4:UnreadableData` are reported as
//! [`blockreader::Error::UnknownContent`], never served as their placeholder
//! bytes.

#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unused_must_use
)]
#![warn(missing_docs, clippy::pedantic)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use aff4tools::disk_image::{self, DiskImageHandle};
use aff4tools::stream::Residency;
use aff4tools::{Arn, Locus, UnknownKind, UnknownRegions};
use blockreader::{BlockReader, Error as BrError, Location, SourceDescription, UnknownCause};

/// The mutable half, behind one lock.
///
/// A read needs `&mut` on the volume set and on the resident bevy, so both
/// live under one lock rather than two that could be taken in either order.
struct Inner {
    handle: DiskImageHandle,
    resident: Option<(Arn, Residency)>,
}

/// A [`BlockReader`] over an AFF4 container's disk image.
///
/// # Read cost
///
/// The library decompresses stored data one bevy at a time. The resident bevy
/// is kept between reads, so a run of small reads inside one bevy
/// decompresses it once.
///
/// # Concurrency
///
/// Reads serialize on an internal lock, because `aff4tools` needs `&mut`
/// access to the volume set to read. For parallel reads, give each worker its
/// own handle from [`Aff4Source::reopen`].
pub struct Aff4Source {
    inner: Mutex<Inner>,
    locus: Locus,
    primary: PathBuf,
    image: Arn,
    size: u64,
}

impl Aff4Source {
    /// Open the one disk image in the container or multi-part set that `path`
    /// belongs to.
    ///
    /// # Errors
    ///
    /// [`BrError::Backend`] wrapping the [`aff4tools::Error`], which keeps the
    /// distinction between a malformed container and an unsupported capability,
    /// and names a container holding no disk image or several.
    pub fn open(path: impl AsRef<Path>) -> blockreader::Result<Self> {
        let handle = disk_image::open(path.as_ref()).map_err(BrError::backend)?;
        Ok(Self::from_handle(handle))
    }

    /// Open the image named `arn`, for a container holding several.
    ///
    /// # Errors
    ///
    /// As [`Aff4Source::open`].
    pub fn open_arn(path: impl AsRef<Path>, arn: &Arn) -> blockreader::Result<Self> {
        let handle = disk_image::open_arn(path.as_ref(), arn).map_err(BrError::backend)?;
        Ok(Self::from_handle(handle))
    }

    /// A second, independent handle on the same image.
    ///
    /// Reopening re-parses the container, so this is not free.
    ///
    /// # Errors
    ///
    /// As [`Aff4Source::open`].
    pub fn reopen(&self) -> blockreader::Result<Self> {
        Self::open_arn(&self.primary, &self.image)
    }

    fn from_handle(handle: DiskImageHandle) -> Self {
        let primary = handle.primary.clone();
        let image = handle.image.arn().clone();
        let size = handle.image.size();
        Self {
            locus: Locus::new(&primary),
            inner: Mutex::new(Inner {
                handle,
                resident: None,
            }),
            primary,
            image,
            size,
        }
    }
}

impl std::fmt::Debug for Aff4Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately shallow: the container behind the lock is large and
        // printing it would say nothing useful.
        f.debug_struct("Aff4Source")
            .field("primary", &self.primary)
            .field("image", &self.image.as_str())
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl BlockReader for Aff4Source {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> blockreader::Result<usize> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        // A poisoned lock means another thread panicked mid-read. The container
        // is unharmed, so recover rather than propagate.
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let Inner { handle, resident } = &mut *inner;
        match handle.image.read_at_in_set_cached_with(
            handle.container.volumes_mut(),
            offset,
            buf,
            &self.locus,
            resident,
            UnknownRegions::Report,
        ) {
            Ok(n) => Ok(n),
            Err(aff4tools::Error::UnknownRegion {
                offset,
                length,
                kind,
                ..
            }) => Err(BrError::UnknownContent {
                offset,
                len: length,
                cause: cause_of(kind),
            }),
            Err(e) => Err(BrError::backend(e)),
        }
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn describe(&self) -> SourceDescription {
        SourceDescription::new(
            Some(Location::Path(self.primary.clone())),
            Some("aff4".to_string()),
        )
    }
}

/// The cause a consumer sees for each kind of unknown region.
fn cause_of(kind: UnknownKind) -> UnknownCause {
    match kind {
        UnknownKind::NotAcquired => UnknownCause::NotAcquired,
        UnknownKind::Unreadable => UnknownCause::UnreadableAtAcquisition,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use aff4tools::model::HashAlgorithm;
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::guard::SourceRegistry;
    use aff4tools::write::map_writer::{MapEntry, write_map};
    use aff4tools::write::stream_writer::{StreamOptions, write_image_stream};
    use aff4tools::{Codec, Locus};
    use blockreader::{SectorSize, read_exact_at};

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    /// A container whose image is `body`, with bytes 4096..5120 recorded as
    /// `aff4:UnreadableData`.
    fn write_container(path: &std::path::Path, body: &[u8]) {
        let registry = SourceRegistry::new();
        let locus = Locus::new(path);
        let mut writer = ContainerWriter::create(path, &registry).unwrap();
        let mut src = body;
        let written = write_image_stream(
            &mut writer,
            &mut src,
            StreamOptions {
                chunk_size: 4096,
                chunks_per_segment: 4,
                codec: Codec::Lz4,
                block_hashes: true,
                block_algorithm: None,
            },
            &[HashAlgorithm::Sha256],
            &locus,
        )
        .unwrap();
        let entries = [
            MapEntry {
                mapped_offset: 0,
                length: 4096,
                target_offset: 0,
                target_id: 0,
            },
            MapEntry {
                mapped_offset: 4096,
                length: 1024,
                target_offset: 0,
                target_id: 1,
            },
            MapEntry {
                mapped_offset: 5120,
                length: written.size - 5120,
                target_offset: 5120,
                target_id: 0,
            },
        ];
        write_map(
            &mut writer,
            &entries,
            &[
                written.arn.clone(),
                "http://aff4.org/Schema#UnreadableData".to_owned(),
            ],
            written.size,
            &[],
            &locus,
        )
        .unwrap();
        writer.finish().unwrap();
    }

    #[test]
    fn a_missing_container_is_a_backend_error() {
        let err = Aff4Source::open("/nonexistent/evidence/x.aff4").unwrap_err();
        assert!(matches!(err, BrError::Backend(_)), "{err:?}");
    }

    #[test]
    fn a_non_aff4_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("not-aff4.bin");
        std::fs::write(&p, b"not a zip archive").unwrap();
        assert!(Aff4Source::open(&p).is_err());
    }

    #[test]
    fn reads_the_image_and_reports_the_unreadable_region() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unreadable.aff4");
        let body = pattern(20_480);
        write_container(&path, &body);

        let src = Aff4Source::open(&path).unwrap();
        assert_eq!(src.size(), 20_480);
        assert_eq!(src.sector_size(), SectorSize::DEFAULT);
        let d = src.describe();
        assert_eq!(d.location, Some(Location::Path(path.clone())));
        assert_eq!(d.format.as_deref(), Some("aff4"));

        // Before the region: a short read ending where it begins.
        let mut buf = vec![0u8; 8192];
        assert_eq!(src.read_at(0, &mut buf).unwrap(), 4096);
        assert_eq!(&buf[..4096], &body[..4096]);

        // Inside it: the whole range, with its cause.
        let err = src.read_at(4500, &mut buf).unwrap_err();
        assert!(
            matches!(
                err,
                BrError::UnknownContent {
                    offset: 4096,
                    len: 1024,
                    cause: UnknownCause::UnreadableAtAcquisition
                }
            ),
            "{err:?}"
        );

        // read_exact_at surfaces the cause rather than an end-of-file.
        let err = read_exact_at(&src, 4000, &mut buf[..200]).unwrap_err();
        assert!(matches!(err, BrError::UnknownContent { .. }), "{err:?}");

        // After it: data again, and nothing at or past the end.
        assert_eq!(src.read_at(5120, &mut buf[..64]).unwrap(), 64);
        assert_eq!(&buf[..64], &body[5120..5184]);
        assert_eq!(src.read_at(20_480, &mut buf).unwrap(), 0);
    }

    #[test]
    fn both_unknown_kinds_map_to_their_causes() {
        assert_eq!(
            cause_of(UnknownKind::NotAcquired),
            UnknownCause::NotAcquired
        );
        assert_eq!(
            cause_of(UnknownKind::Unreadable),
            UnknownCause::UnreadableAtAcquisition
        );
    }

    #[test]
    fn reopen_gives_an_independent_handle_on_the_same_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.aff4");
        let body = pattern(20_480);
        write_container(&path, &body);
        let a = Aff4Source::open(&path).unwrap();
        let b = a.reopen().unwrap();
        let mut buf = [0u8; 16];
        read_exact_at(&b, 100, &mut buf).unwrap();
        assert_eq!(&buf, &body[100..116]);
    }
}
