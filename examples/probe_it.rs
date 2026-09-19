//! Reads the first bytes of a container's image, to confirm the backend
//! resolves and reads real evidence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aff4_blockreader::Aff4Source;
use blockreader::BlockReader;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: probe_it <container.aff4>");
        return;
    };
    match Aff4Source::open(&path) {
        Ok(src) => {
            println!("opened: {} bytes", src.size());
            println!("describe: {:?}", src.describe());
            let mut buf = vec![0u8; 64];
            match src.read_at(0, &mut buf) {
                Ok(n) => println!("read {n} bytes at 0: {:02X?}", &buf[..n.min(16)]),
                Err(e) => println!("read failed: {e}"),
            }
        }
        Err(e) => println!("open failed: {e}"),
    }
}
