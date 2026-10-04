//! Every adapter against the generated fixtures. Needs `fixtures/generate.sh`
//! to have run; fails, never skips, without it.

#![cfg(feature = "fixtures")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use blockreader::{Location, UnknownCause};
use contract_tests::manifest::{Manifest, out_dir};
use contract_tests::{UnknownExpectation, check_contract, open};
use sha2::{Digest, Sha256};

fn run(name: &str) {
    let manifest = Manifest::load();
    let raw = manifest.raw_bytes();
    let fixture = manifest
        .fixtures
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("the manifest has no fixture named {name}"));
    let source = open(&fixture.format, &fixture.location())
        .unwrap_or_else(|e| panic!("{name}: open failed: {e}"));
    let found = check_contract(source.as_ref(), &fixture.expected(&raw));
    eprintln!("{name}: unknown ranges {found:?}");
}

#[test]
fn e01_single_segment() {
    run("e01");
}

#[test]
fn e01_multi_segment_opened_from_the_first() {
    run("e01-multi");
}

#[test]
fn e01_with_a_corrupt_chunk_reports_exactly_that_chunk() {
    run("e01-corrupt");
}

#[test]
fn vmdk_monolithic_sparse() {
    run("vmdk-sparse");
}

#[test]
fn vmdk_monolithic_flat() {
    run("vmdk-flat");
}

#[test]
fn vmdk_stream_optimized() {
    run("vmdk-stream");
}

#[test]
fn aff4() {
    run("aff4");
}

#[test]
fn aff4_with_an_unreadable_region() {
    run("aff4-unreadable");
}

#[test]
fn a_vmdk_delta_without_its_parent_fails_to_open() {
    let manifest = Manifest::load();
    let location = Location::Path(out_dir().join(&manifest.missing_parent));
    match open("vmdk", &location) {
        Err(_) => {}
        Ok(source) => panic!(
            "a delta whose parent is missing opened as {} bytes; vmdk-rs must refuse it \
             rather than read the parent's range as zeros. Report this upstream.",
            source.size()
        ),
    }
}

/// The same image through every format, byte for byte.
#[test]
fn every_format_serves_the_same_image() {
    let manifest = Manifest::load();
    let raw = manifest.raw_bytes();
    let want = hex::encode(Sha256::digest(&raw));
    let raw_source = open("raw", &Location::Path(out_dir().join(&manifest.raw.path))).unwrap();
    let mut sources = vec![("raw".to_owned(), raw_source)];
    for f in &manifest.fixtures {
        if matches!(f.expected(&raw).unknown, UnknownExpectation::None) {
            sources.push((f.name.clone(), open(&f.format, &f.location()).unwrap()));
        }
    }
    for (name, source) in &sources {
        let mut all = vec![0u8; raw.len()];
        blockreader::read_exact_at(source.as_ref(), 0, &mut all)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            hex::encode(Sha256::digest(&all)),
            want,
            "{name} differs from the raw image"
        );
    }
    assert!(sources.len() >= 7, "expected raw plus six clean fixtures");
}

#[test]
fn the_corrupt_chunk_is_an_integrity_finding() {
    let manifest = Manifest::load();
    let f = manifest
        .fixtures
        .iter()
        .find(|f| f.name == "e01-corrupt")
        .unwrap();
    let raw = manifest.raw_bytes();
    let source = open(&f.format, &f.location()).unwrap();
    let found = check_contract(source.as_ref(), &f.expected(&raw));
    assert!(
        found
            .iter()
            .all(|r| r.cause == UnknownCause::FailedIntegrity)
    );
}
