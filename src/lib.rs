//! Reads AFF4 evidence containers through the [`blockreader::BlockReader`]
//! trait, so a filesystem parser can consume one without depending on the
//! AFF4 library's own API.

#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unused_must_use
)]
#![warn(missing_docs, clippy::pedantic)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aff4tools::stream::Residency;
use aff4tools::zip::Volume as _;
use aff4tools::{Arn, Container, Image, Locus, ObjectRole};
use blockreader::{BlockReader, Error as BrError, SourceDescription};

/// The mutable half, behind one lock.
///
/// The read call needs `&mut` on both the volume set and the residency, so
/// both live under one lock rather than two that could be taken in either
/// order.
struct Inner {
    container: Container,
    resident: Option<(Arn, Residency)>,
}

/// A [`BlockReader`] over an AFF4 container's disk image.
///
/// # Read cost
///
/// The underlying library decompresses stored data in chunks grouped into
/// bevies, caching both. Caching only pays off if the resident bevy
/// survives between reads, so this type holds the residency and passes it
/// back on every call.
pub struct Aff4Source {
    inner: Mutex<Inner>,
    image: Image,
    locus: Locus,
    path: PathBuf,
    size: u64,
    sector_size: u32,
    sector_size_assumed: bool,
}

/// Add every other part of `path`'s split set to `container`.
///
/// A container that is not part of a set is left alone. A sibling that
/// cannot be opened is skipped rather than failing the open; a short read
/// is reported later by the stream that needs the missing bytes.
fn attach_siblings(container: &mut Container, path: &Path) {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    if aff4tools::multi_part::part_number(name).is_none() {
        return;
    }
    let Some(dir) = path.parent() else {
        return;
    };
    let Ok(set) = aff4tools::multi_part::discover(dir) else {
        return;
    };

    for part in set.parts {
        if part == path {
            continue;
        }
        let Ok(mut volume) = aff4tools::zip::ZipVolume::open(&part) else {
            continue;
        };
        let graph = match volume.read_segment(aff4tools::container::METADATA_SEGMENT) {
            Ok(bytes) => {
                let locus = volume.locus(Some(aff4tools::container::METADATA_SEGMENT));
                aff4tools::rdf::Graph::parse(&bytes, &locus).unwrap_or_default()
            }
            Err(_) => aff4tools::rdf::Graph::default(),
        };
        container.add_volume(
            volume,
            graph,
            aff4tools::zip_volume_set::VolumeOrigin::Named,
        );
    }
}

/// Every part's metadata, parsed into one graph.
///
/// Falls back to the primary's graph alone when nothing else can be read, so
/// a single-file container behaves exactly as before.
fn merged_graph(
    container: &mut Container,
    path: &Path,
    locus: &Locus,
) -> Result<aff4tools::rdf::Graph, aff4tools::Error> {
    let mut bytes: Vec<u8> = Vec::new();
    let count = container.volumes().len();
    for i in 0..count {
        let volume = container.volumes_mut().volume_at_mut(i);
        if let Ok(part) = volume.read_segment(aff4tools::container::METADATA_SEGMENT) {
            bytes.extend_from_slice(&part);
            bytes.push(b'\n');
        }
    }
    if bytes.is_empty() {
        let _ = path;
        return container.graph();
    }
    aff4tools::rdf::Graph::parse(&bytes, locus)
}

impl Aff4Source {
    /// Open a container and resolve its disk image.
    ///
    /// # Errors
    ///
    /// Returns a message naming what failed if the container cannot be
    /// opened or holds no readable disk image.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let locus = Locus::new(&path);

        let mut container =
            Container::open(&path).map_err(|e| format!("opening {}: {e}", path.display()))?;

        // An acquisition split across several files declares one image whose
        // data spans them all. Naming any part must open the whole set, or
        // the image reads short with no indication which bytes are missing.
        attach_siblings(&mut container, &path);

        let summary = container
            .summarize()
            .map_err(|e| format!("reading metadata from {}: {e}", path.display()))?;

        // Disk images are declared under several types. Prefer the most
        // specific, but accept the others: an acquisition typed only
        // `DiscontiguousImage` is a disk image too.
        let images = summary.images();
        let arn = [
            ObjectRole::DiskImage,
            ObjectRole::DiscontiguousImage,
            ObjectRole::ContiguousImage,
        ]
        .iter()
        .find_map(|role| {
            images
                .iter()
                .find(|o| o.role == *role)
                .map(|o| o.arn.clone())
        })
        .ok_or_else(|| format!("{} holds no disk image", path.display()))?;

        // A split set declares its streams across all its parts: the primary
        // carries stubs for data that lives in a sibling. Parsing every
        // part's metadata together gives the whole picture; the primary's
        // alone declares no size for a sibling's stream.
        let graph = merged_graph(&mut container, &path, &locus)
            .map_err(|e| format!("reading metadata from {}: {e}", path.display()))?;
        let lexicon = container.lexicon();
        let mapping = container.name_mapping();
        let image = Image::open(
            &arn,
            container.volume_mut(),
            &graph,
            lexicon,
            mapping,
            &locus,
        )
        .map_err(|e| format!("opening image {arn}: {e}"))?;
        let size = image.size();

        Ok(Self {
            inner: Mutex::new(Inner {
                container,
                resident: None,
            }),
            image,
            locus,
            path,
            size,
            // A container records no sector size for the acquired device.
            sector_size: blockreader::DEFAULT_SECTOR_SIZE,
            sector_size_assumed: true,
        })
    }

    /// Declare the real sector size, clearing the assumed flag.
    #[must_use]
    pub fn with_sector_size(mut self, bytes: u32) -> Self {
        self.sector_size = bytes;
        self.sector_size_assumed = false;
        self
    }

    /// A second handle on the same container, opened independently.
    ///
    /// Sharing one source across threads is safe but serializes reads on
    /// its lock. Where parallel throughput is wanted, give each worker its
    /// own. Reopening re-parses the container, so this is not free.
    ///
    /// # Errors
    ///
    /// As [`Aff4Source::open`].
    pub fn reopen(&self) -> Result<Self, String> {
        let mut s = Self::open(&self.path)?;
        if !self.sector_size_assumed {
            s = s.with_sector_size(self.sector_size);
        }
        Ok(s)
    }
}

impl std::fmt::Debug for Aff4Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately shallow: the container behind the lock is large and
        // printing it would say nothing useful.
        f.debug_struct("Aff4Source")
            .field("path", &self.path)
            .field("size", &self.size)
            .field("sector_size", &self.sector_size)
            .finish_non_exhaustive()
    }
}

impl BlockReader for Aff4Source {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> blockreader::Result<usize> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        // A poisoned lock means another thread panicked mid-read. The
        // container itself is unharmed, so recover rather than propagate.
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Inner {
            container,
            resident,
        } = &mut *inner;
        self.image
            .read_at_in_set_cached(container.volumes_mut(), offset, buf, &self.locus, resident)
            .map_err(BrError::backend)
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn describe(&self) -> SourceDescription {
        SourceDescription {
            path: Some(self.path.clone()),
            format: Some("aff4".to_string()),
            sector_size_assumed: self.sector_size_assumed,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_container_is_an_error_not_a_panic() {
        assert!(Aff4Source::open("/nonexistent/evidence/x.aff4").is_err());
    }

    #[test]
    fn a_non_aff4_file_is_rejected_with_a_message() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("aff4-blockreader-not-aff4-{}", std::process::id()));
        std::fs::write(&p, b"not a zip archive").unwrap();
        let e = Aff4Source::open(&p).unwrap_err();
        assert!(!e.is_empty(), "the failure names what went wrong");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sector_size_defaults_to_512_and_reports_itself_assumed() {
        // A container records no sector size for the acquired device, so
        // the value is assumed and consumers must be told.
        assert_eq!(blockreader::DEFAULT_SECTOR_SIZE, 512);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod split_tests {
    use super::*;

    /// A container this test can reach, from the environment.
    fn split_part() -> Option<PathBuf> {
        std::env::var_os("AFF4_TEST_SPLIT_PART").map(Into::into)
    }

    #[test]
    fn a_split_set_reports_the_whole_image_not_one_part() {
        // Naming one part must open them all. Reporting the part's own size
        // would present a truncated image as a complete one.
        let Some(part) = split_part() else { return };
        let file_len = std::fs::metadata(&part).unwrap().len();
        let source = Aff4Source::open(&part).expect("a split set opens from any part");
        assert!(
            source.size() > file_len,
            "image is {} bytes but the part is {file_len}; siblings were not attached",
            source.size()
        );
    }

    #[test]
    fn a_split_set_reads_past_the_first_part() {
        let Some(part) = split_part() else { return };
        let source = Aff4Source::open(&part).unwrap();
        let file_len = std::fs::metadata(&part).unwrap().len();

        // An offset beyond the first part's length can only be served by a
        // sibling.
        let mut buf = vec![0u8; 512];
        let n = source.read_at(file_len + 4096, &mut buf).unwrap();
        assert_eq!(n, 512, "a read into a sibling returned {n} bytes");
    }
}
