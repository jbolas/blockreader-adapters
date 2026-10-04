//! Write an AFF4 container whose image is a raw file's bytes, except one range
//! the map records as `aff4:UnreadableData`.
//!
//! No tool writes `aff4:UnreadableData` map entries (aff4tools' device
//! acquisition stores the placeholder in the stream instead), so this builds
//! the map directly.
//!
//! Usage: `make_unreadable_aff4 <RAW> <OUTPUT.aff4> <OFFSET> <LENGTH>`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use aff4tools::model::HashAlgorithm;
use aff4tools::write::container_writer::ContainerWriter;
use aff4tools::write::guard::SourceRegistry;
use aff4tools::write::map_writer::{MapEntry, write_map};
use aff4tools::write::stream_writer::{StreamOptions, write_image_stream};
use aff4tools::{Codec, Locus};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        5,
        "usage: make_unreadable_aff4 <RAW> <OUTPUT.aff4> <OFFSET> <LENGTH>"
    );
    let raw = std::path::Path::new(&args[1]);
    let out = std::path::Path::new(&args[2]);
    let offset: u64 = args[3].parse().expect("OFFSET is a byte count");
    let length: u64 = args[4].parse().expect("LENGTH is a byte count");

    let body = std::fs::read(raw).expect("read the raw image");
    let size = body.len() as u64;
    assert!(
        offset + length <= size,
        "the range must lie inside the image"
    );

    // Registered, so the writer refuses to write over the source.
    let mut registry = SourceRegistry::new();
    registry.register(raw).expect("register the source");
    let locus = Locus::new(out);
    let mut writer = ContainerWriter::create(out, &registry).expect("create the container");
    let mut src = &body[..];
    let written = write_image_stream(
        &mut writer,
        &mut src,
        StreamOptions {
            chunk_size: 32 * 1024,
            chunks_per_segment: 1024,
            codec: Codec::Lz4,
            block_hashes: true,
            block_algorithm: None,
        },
        &[HashAlgorithm::Sha256],
        &locus,
    )
    .expect("write the image stream");

    let entries = [
        MapEntry {
            mapped_offset: 0,
            length: offset,
            target_offset: 0,
            target_id: 0,
        },
        MapEntry {
            mapped_offset: offset,
            length,
            target_offset: 0,
            target_id: 1,
        },
        MapEntry {
            mapped_offset: offset + length,
            length: size - offset - length,
            target_offset: offset + length,
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
        size,
        &[],
        &locus,
    )
    .expect("write the map");
    writer.finish().expect("finish the container");
}
