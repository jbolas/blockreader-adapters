//! Times scattered small reads against a container, to confirm the
//! resident bevy is kept resident between calls.
//!
//! A result in the low tens of MiB/s means the residency is being dropped
//! between reads; hundreds or better means it is being carried.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aff4_blockreader::Aff4Source;
use blockreader::BlockReader;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: read_bench <container.aff4>");
        return;
    };
    let src = match Aff4Source::open(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("open failed: {e}");
            return;
        }
    };
    let size = src.size();
    if size == 0 {
        eprintln!("image is empty");
        return;
    }
    let mut buf = vec![0u8; 4096];

    // Reads clustered in the first 64 MiB: the access pattern a metadata
    // walk produces, and the one residency is meant to serve.
    let span = (64 * 1024 * 1024u64).min(size);
    let start = std::time::Instant::now();
    let mut n = 0u64;
    let mut failed = 0u32;
    for i in 0..2000u64 {
        let off = (i * 4096 * 7) % span;
        match src.read_at(off, &mut buf) {
            Ok(got) => n += got as u64,
            Err(_) => failed += 1,
        }
    }
    let elapsed = start.elapsed();
    if failed > 0 {
        eprintln!("{failed} of 2000 reads failed");
    }
    println!(
        "2000 clustered 4 KiB reads: {n} bytes in {elapsed:?} ({:.1} MiB/s)",
        (n as f64 / 1_048_576.0) / elapsed.as_secs_f64()
    );
}
