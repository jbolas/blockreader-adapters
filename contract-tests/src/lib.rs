//! The `BlockReader` contract, checked against any implementation.
//!
//! [`check_contract`] reads a source every way the contract allows and
//! compares each byte with a reference image, so one function holds every
//! adapter to the same rules: honest short reads, `Ok(0)` at the end, unknown
//! content reported with its exact range and cause, safe sharing across
//! threads, and a truthful description.

use blockreader::{BlockReader, Error, Location, SectorSize, UnknownCause};

pub mod manifest;

/// Open `location` with the adapter for `format`: `"aff4"`, `"e01"`,
/// `"vmdk"`, or `"raw"`.
///
/// # Errors
///
/// Whatever the adapter returns.
///
/// # Panics
///
/// On an unknown format name.
pub fn open(format: &str, location: &Location) -> blockreader::Result<Box<dyn BlockReader>> {
    Ok(match format {
        "aff4" => {
            let Location::Path(p) = location else {
                panic!("AFF4 fixtures are local paths")
            };
            Box::new(aff4_blockreader::Aff4Source::open(p)?)
        }
        "e01" => Box::new(e01_blockreader::E01Source::open(location)?),
        "vmdk" => Box::new(vmdk_blockreader::VmdkSource::open(location)?),
        "raw" => {
            let Location::Path(p) = location else {
                panic!("raw fixtures are local paths")
            };
            Box::new(blockreader::FileSource::open(p)?)
        }
        other => panic!("unknown format {other:?}"),
    })
}

/// A range whose content a source reports as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownRange {
    /// Where it begins.
    pub offset: u64,
    /// How long it is.
    pub len: u64,
    /// Why it is unknown.
    pub cause: UnknownCause,
}

/// Which unknown ranges a source must report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownExpectation {
    /// None.
    None,
    /// Exactly these, in address order.
    Exactly(Vec<UnknownRange>),
    /// Exactly one, aligned to `chunk_size` and one chunk long (shorter only at
    /// the image's end), with `cause`. For a fixture corrupted at an offset
    /// chosen when it was generated.
    OneChunk {
        /// The container's chunk size in bytes.
        chunk_size: u64,
        /// The cause the range must carry.
        cause: UnknownCause,
    },
}

/// What a source must serve.
#[derive(Debug)]
pub struct Expected<'a> {
    /// The image's true bytes.
    pub reference: &'a [u8],
    /// Which ranges must be reported as unknown.
    pub unknown: UnknownExpectation,
    /// `describe().format`, or `""` to skip the check.
    pub format: &'a str,
    /// `describe().location`, or `None` to skip the check.
    pub location: Option<Location>,
    /// `sector_size()`, value and basis.
    pub sector_size: SectorSize,
}

/// Read sizes that land on and across every internal boundary the adapters
/// have: 4 KiB pages, 1 MiB cache blocks, and an odd size that aligns with
/// nothing.
const PIECES: [usize; 3] = [4096, 1024 * 1024, 4093];

/// Check `source` against `expected`, panicking with a precise message on any
/// violation. Returns the unknown ranges found.
///
/// # Panics
///
/// On any departure from the contract. This is a test helper.
pub fn check_contract(source: &dyn BlockReader, expected: &Expected<'_>) -> Vec<UnknownRange> {
    let size = expected.reference.len() as u64;
    assert_eq!(
        source.size(),
        size,
        "size() differs from the reference image"
    );

    check_end(source, size);

    let mut found = Vec::new();
    for (i, piece) in PIECES.into_iter().enumerate() {
        let ranges = walk(source, expected.reference, piece);
        if i == 0 {
            found = ranges;
        } else {
            assert_eq!(
                ranges, found,
                "reading in {piece}-byte pieces reported different unknown ranges"
            );
        }
    }
    check_unknown(&found, &expected.unknown, size);
    for r in &found {
        check_short_read_before(source, expected.reference, r);
    }

    check_threads(source, expected.reference);
    check_description(source, expected);
    found
}

/// A read at or past the end returns `Ok(0)`; one straddling the end is short.
fn check_end(source: &dyn BlockReader, size: u64) {
    let mut buf = [0u8; 64];
    for at in [size, size + 1, u64::MAX] {
        match source.read_at(at, &mut buf) {
            Ok(0) => {}
            other => panic!("a read at {at}, at or past the end ({size}), returned {other:?}"),
        }
    }
    if size >= 10 {
        match source.read_at(size - 10, &mut buf) {
            Ok(10) | Err(Error::UnknownContent { .. }) => {}
            other => {
                panic!("a read straddling the end returned {other:?}, not a 10-byte short read")
            }
        }
    }
}

/// Read the whole image in `piece`-byte reads, comparing every byte, and
/// return the unknown ranges met.
fn walk(source: &dyn BlockReader, reference: &[u8], piece: usize) -> Vec<UnknownRange> {
    let size = reference.len() as u64;
    let mut buf = vec![0u8; piece];
    let mut ranges: Vec<UnknownRange> = Vec::new();
    let mut offset = 0u64;
    while offset < size {
        let want = usize::try_from((size - offset).min(piece as u64)).unwrap_or(piece);
        match source.read_at(offset, &mut buf[..want]) {
            Ok(0) => panic!("read_at({offset}) returned 0 inside the image (size {size})"),
            Ok(n) => {
                assert!(
                    n <= want,
                    "read_at({offset}) claimed {n} bytes of a {want}-byte buffer"
                );
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                if let Some(i) = (0..n).find(|&i| buf[i] != reference[start + i]) {
                    panic!(
                        "byte {} differs from the reference: read {:#04x}, expected {:#04x} \
                         ({piece}-byte reads)",
                        offset + i as u64,
                        buf[i],
                        reference[start + i]
                    );
                }
                offset += n as u64;
            }
            Err(Error::UnknownContent {
                offset: o,
                len,
                cause,
            }) => {
                assert!(
                    o <= offset && offset < o.saturating_add(len),
                    "UnknownContent {o}..{} does not contain the offset read, {offset}",
                    o.saturating_add(len)
                );
                let r = UnknownRange {
                    offset: o,
                    len,
                    cause,
                };
                if ranges.last() != Some(&r) {
                    ranges.push(r);
                }
                offset = o.saturating_add(len);
            }
            Err(other) => panic!("read_at({offset}) failed: {other}"),
        }
    }
    ranges
}

fn check_unknown(found: &[UnknownRange], expected: &UnknownExpectation, size: u64) {
    match expected {
        UnknownExpectation::None => {
            if let Some(r) = found.first() {
                panic!("unexpected unknown range: {r:?}");
            }
        }
        UnknownExpectation::Exactly(ranges) => {
            assert_eq!(found, ranges.as_slice(), "unexpected unknown range set");
        }
        UnknownExpectation::OneChunk { chunk_size, cause } => {
            assert_eq!(
                found.len(),
                1,
                "expected exactly one unknown chunk, found {found:?}"
            );
            let r = found[0];
            assert_eq!(
                r.offset % chunk_size,
                0,
                "the unknown range is not chunk-aligned: {r:?}"
            );
            let expected_len = (*chunk_size).min(size - r.offset);
            assert_eq!(
                r.len, expected_len,
                "the unknown range is not one chunk: {r:?}"
            );
            assert_eq!(
                r.cause, *cause,
                "the unknown range has the wrong cause: {r:?}"
            );
        }
    }
}

/// A read starting 10 bytes before an unknown range returns exactly those 10.
fn check_short_read_before(source: &dyn BlockReader, reference: &[u8], r: &UnknownRange) {
    if r.offset < 10 {
        return;
    }
    let mut buf = [0u8; 64];
    let at = r.offset - 10;
    match source.read_at(at, &mut buf) {
        Ok(10) => {
            let s = usize::try_from(at).unwrap_or(usize::MAX);
            assert_eq!(
                &buf[..10],
                &reference[s..s + 10],
                "the short read before {r:?} is wrong"
            );
        }
        other => {
            panic!("a read 10 bytes before {r:?} returned {other:?}, not a 10-byte short read")
        }
    }
}

/// Four threads sharing one source each read the whole image correctly.
fn check_threads(source: &dyn BlockReader, reference: &[u8]) {
    std::thread::scope(|scope| {
        for t in 0..4u64 {
            scope.spawn(move || {
                // Each thread starts at a different quarter, so reads interleave.
                let size = reference.len() as u64;
                let start = size / 4 * t;
                let mut buf = vec![0u8; 65_536];
                let mut offset = start;
                let mut read = 0u64;
                while read < size {
                    let want = usize::try_from((size - offset).min(65_536)).unwrap_or(65_536);
                    let step = match source.read_at(offset, &mut buf[..want]) {
                        Ok(0) => {
                            panic!("thread {t}: read_at({offset}) returned 0 inside the image")
                        }
                        Ok(n) => {
                            let s = usize::try_from(offset).unwrap_or(usize::MAX);
                            assert_eq!(
                                &buf[..n],
                                &reference[s..s + n],
                                "thread {t}: bytes at {offset} differ"
                            );
                            n as u64
                        }
                        Err(Error::UnknownContent { offset: o, len, .. }) => {
                            o.saturating_add(len) - offset
                        }
                        Err(e) => panic!("thread {t}: read_at({offset}) failed: {e}"),
                    };
                    read += step;
                    offset += step;
                    if offset >= size {
                        offset = 0;
                    }
                }
            });
        }
    });
}

fn check_description(source: &dyn BlockReader, expected: &Expected<'_>) {
    assert_eq!(
        source.sector_size(),
        expected.sector_size,
        "sector size, value or basis, differs"
    );
    let d = source.describe();
    if !expected.format.is_empty() {
        assert_eq!(
            d.format.as_deref(),
            Some(expected.format),
            "describe().format differs"
        );
    }
    if let Some(location) = &expected.location {
        assert_eq!(
            d.location.as_ref(),
            Some(location),
            "describe().location differs"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use blockreader::{FileSource, SectorSizeBasis};

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    /// An in-memory source with optional unknown ranges, following the rules.
    struct Mem {
        data: Vec<u8>,
        unknown: Vec<UnknownRange>,
        max_read: usize,
    }

    impl BlockReader for Mem {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> blockreader::Result<usize> {
            let size = self.data.len() as u64;
            if offset >= size || buf.is_empty() {
                return Ok(0);
            }
            if let Some(r) = self
                .unknown
                .iter()
                .find(|r| (r.offset..r.offset + r.len).contains(&offset))
            {
                return Err(Error::UnknownContent {
                    offset: r.offset,
                    len: r.len,
                    cause: r.cause,
                });
            }
            let mut end = (offset + buf.len().min(self.max_read) as u64).min(size);
            for r in &self.unknown {
                if offset < r.offset && end > r.offset {
                    end = r.offset;
                }
            }
            let n = usize::try_from(end - offset).unwrap();
            let s = usize::try_from(offset).unwrap();
            buf[..n].copy_from_slice(&self.data[s..s + n]);
            Ok(n)
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    #[test]
    fn a_plain_file_satisfies_the_contract() {
        let data = pattern(3 * 1024 * 1024 + 17);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raw.img");
        std::fs::write(&path, &data).unwrap();
        let src = FileSource::open(&path).unwrap();
        let found = check_contract(
            &src,
            &Expected {
                reference: &data,
                unknown: UnknownExpectation::None,
                format: "raw",
                location: Some(Location::Path(path.clone())),
                sector_size: SectorSize::DEFAULT,
            },
        );
        assert!(found.is_empty());
    }

    #[test]
    fn expected_unknown_ranges_are_found_exactly() {
        let data = pattern(200_000);
        let range = UnknownRange {
            offset: 65_536,
            len: 32_768,
            cause: UnknownCause::FailedIntegrity,
        };
        let src = Mem {
            data: data.clone(),
            unknown: vec![range],
            max_read: 7_000,
        };
        let found = check_contract(
            &src,
            &Expected {
                reference: &data,
                unknown: UnknownExpectation::OneChunk {
                    chunk_size: 32_768,
                    cause: UnknownCause::FailedIntegrity,
                },
                format: "",
                location: None,
                sector_size: SectorSize::DEFAULT,
            },
        );
        assert_eq!(found, vec![range]);
    }

    #[test]
    #[should_panic(expected = "differs from the reference")]
    fn a_wrong_byte_is_caught() {
        let data = pattern(10_000);
        let mut served = data.clone();
        served[5_000] ^= 0xFF;
        let src = Mem {
            data: served,
            unknown: vec![],
            max_read: usize::MAX,
        };
        check_contract(
            &src,
            &Expected {
                reference: &data,
                unknown: UnknownExpectation::None,
                format: "",
                location: None,
                sector_size: SectorSize::DEFAULT,
            },
        );
    }

    #[test]
    #[should_panic(expected = "unexpected unknown range")]
    fn an_unexpected_unknown_range_is_caught() {
        let data = pattern(10_000);
        let src = Mem {
            data: data.clone(),
            unknown: vec![UnknownRange {
                offset: 4096,
                len: 512,
                cause: UnknownCause::NotAcquired,
            }],
            max_read: usize::MAX,
        };
        check_contract(
            &src,
            &Expected {
                reference: &data,
                unknown: UnknownExpectation::None,
                format: "",
                location: None,
                sector_size: SectorSize::DEFAULT,
            },
        );
    }

    #[test]
    #[should_panic(expected = "sector size")]
    fn a_wrong_sector_basis_is_caught() {
        let data = pattern(1000);
        let src = Mem {
            data: data.clone(),
            unknown: vec![],
            max_read: usize::MAX,
        };
        check_contract(
            &src,
            &Expected {
                reference: &data,
                unknown: UnknownExpectation::None,
                format: "",
                location: None,
                sector_size: SectorSize::new(512, SectorSizeBasis::Recorded).unwrap(),
            },
        );
    }
}
