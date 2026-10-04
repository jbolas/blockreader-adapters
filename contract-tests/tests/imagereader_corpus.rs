//! Every adapter against imagereader-rs's own test images, read in place.
//!
//! Set IMAGEREADER_DATA to a local clone of imagereader-rs at the pinned
//! revision. The expected SHA-1 values are imagereader's recorded ones
//! (`e01/src/test_data.rs`, `vmdk/src/test_data.rs`), ported as test cases.
//! With the feature on and the variable unset, every test fails: a gated test
//! that skipped would report coverage it did not have.

#![cfg(feature = "imagereader-corpus")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use blockreader::{BlockReader, Error, Location, SectorSizeBasis, UnknownCause};
use e01_blockreader::E01Source;
use sha1::{Digest, Sha1};
use vmdk_blockreader::VmdkSource;

fn data(relative: &str) -> Location {
    let root = std::env::var_os("IMAGEREADER_DATA").unwrap_or_else(|| {
        panic!(
            "IMAGEREADER_DATA is not set. Point it at a local imagereader-rs clone, \
             for example: IMAGEREADER_DATA=~/code/df-refs/imagereader-rs"
        )
    });
    let path = PathBuf::from(root).join(relative);
    assert!(path.exists(), "{} does not exist", path.display());
    Location::Path(path)
}

/// SHA-1 of the whole image, with any unknown range read as zeros; also
/// returns the unknown ranges met.
fn sha1_with_zeroed_unknowns(source: &dyn BlockReader) -> (String, Vec<(u64, u64, UnknownCause)>) {
    let size = source.size();
    let mut hasher = Sha1::new();
    let mut unknown = Vec::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut offset = 0u64;
    while offset < size {
        let want = usize::try_from((size - offset).min(buf.len() as u64)).unwrap();
        match source.read_at(offset, &mut buf[..want]) {
            Ok(0) => panic!("read_at({offset}) returned 0 inside the image"),
            Ok(n) => {
                hasher.update(&buf[..n]);
                offset += n as u64;
            }
            Err(Error::UnknownContent {
                offset: o,
                len,
                cause,
            }) => {
                assert_eq!(
                    o, offset,
                    "an unknown range must begin where the short read stopped"
                );
                hasher.update(vec![0u8; usize::try_from(len).unwrap()]);
                unknown.push((o, len, cause));
                offset = o + len;
            }
            Err(e) => panic!("read_at({offset}) failed: {e}"),
        }
    }
    (hex::encode(hasher.finalize()), unknown)
}

fn check_e01(relative: &str, size: u64, sha1: &str) {
    let source = E01Source::open(&data(relative)).unwrap();
    assert_eq!(source.size(), size);
    assert_eq!(source.sector_size().bytes(), 512);
    assert_eq!(source.sector_size().basis(), SectorSizeBasis::Recorded);
    let (digest, unknown) = sha1_with_zeroed_unknowns(&source);
    assert!(
        unknown.is_empty(),
        "{relative}: unexpected unknown ranges {unknown:?}"
    );
    assert_eq!(digest, sha1, "{relative}");
}

fn check_vmdk(relative: &str, size: u64, sha1: &str) {
    let source = VmdkSource::open(&data(relative)).unwrap();
    assert_eq!(source.size(), size);
    assert_eq!(source.sector_size().basis(), SectorSizeBasis::Assumed);
    let (digest, unknown) = sha1_with_zeroed_unknowns(&source);
    assert!(
        unknown.is_empty(),
        "{relative}: VMDK never reports unknown content"
    );
    assert_eq!(digest, sha1, "{relative}");
}

#[test]
fn e01_image() {
    check_e01(
        "e01/data/image.E01",
        1_321_472,
        "e5c6c296485b1146fead7ad552e1c3ccfc00bfab",
    );
}

#[test]
fn e01_two_segments_opened_from_the_first() {
    check_e01(
        "e01/data/mimage.E01",
        884_736,
        "f8677bd8a38a12476ae655a9f9f5336c287603f7",
    );
}

/// imagereader's own `bad_chunk.E01`. With its zeroing policy it hashes to
/// `18e70fca…`. Here, reading each reported unknown range as zeros must give
/// exactly that value: that shows the adapter reported exactly the corrupt
/// chunks, and every other byte is right.
#[test]
fn e01_bad_chunk_is_reported_not_zeroed() {
    let source = E01Source::open(&data("e01/data/bad_chunk.E01")).unwrap();
    let (digest, unknown) = sha1_with_zeroed_unknowns(&source);
    assert!(!unknown.is_empty(), "the corrupt chunk was served as data");
    for (offset, len, cause) in &unknown {
        assert_eq!(*cause, UnknownCause::FailedIntegrity);
        assert_eq!(offset % 32_768, 0, "not chunk-aligned");
        assert!(*len <= 32_768, "longer than a chunk");
    }
    assert_eq!(digest, "18e70fcac21668a2ee849cdb815d45dab107f0fc");
}

#[test]
fn vmdk_vmfs_thick() {
    check_vmdk(
        "vmdk/data/vmfs_thick.vmdk",
        2_097_152,
        "17eaf058191c5f2639d8f983ca7633e4f47087d1",
    );
}

#[test]
fn vmdk_vmfs_thick_delta_with_its_parent() {
    check_vmdk(
        "vmdk/data/vmfs_thick-000001.vmdk",
        2_097_152,
        "2ccf34d146ef98204d1889fc44e94ad94e0b1cb6",
    );
}

#[test]
fn vmdk_two_gb_max_extent_sparse() {
    check_vmdk(
        "vmdk/data/twoGbMaxExtentSparse.vmdk",
        10_485_760,
        "dd2fade471d68658b2ebbff7474f5d0a99da8989",
    );
}

#[test]
fn vmdk_two_gb_max_extent_flat() {
    check_vmdk(
        "vmdk/data/twoGbMaxExtentFlat.vmdk",
        10_485_760,
        "dd2fade471d68658b2ebbff7474f5d0a99da8989",
    );
}

#[test]
fn vmdk_stream_optimized() {
    check_vmdk(
        "vmdk/data/streamOptimized.vmdk",
        10_485_760,
        "dd2fade471d68658b2ebbff7474f5d0a99da8989",
    );
}

#[test]
fn vmdk_monolithic_sparse() {
    check_vmdk(
        "vmdk/data/monolithicSparse.vmdk",
        10_485_760,
        "dd2fade471d68658b2ebbff7474f5d0a99da8989",
    );
}

#[test]
fn vmdk_monolithic_flat() {
    check_vmdk(
        "vmdk/data/monolithicFlat.vmdk",
        10_485_760,
        "dd2fade471d68658b2ebbff7474f5d0a99da8989",
    );
}

#[test]
fn vmdk_stream_optimized_with_markers() {
    check_vmdk(
        "vmdk/data/streamOptimizedWithMarkers.vmdk",
        1_048_576,
        "b6fd01dd1b93b3589e6d76f7507af55c589ef69d",
    );
}
