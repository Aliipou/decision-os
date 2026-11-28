//! Differential-test driver for `dos_core::canon` (see crates/dos-core/tests/jcs/).
//! Reads one hex-encoded input per line; writes `ok <hex>` or `err <code>` per line.

use std::io::{self, BufRead, BufWriter, Write};

fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect()
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let Some(input) = from_hex(line.trim()) else {
            writeln!(out, "err bad_hex")?;
            continue;
        };
        match dos_core::canon::canonicalize(&input) {
            Ok(bytes) => {
                write!(out, "ok ")?;
                for b in bytes {
                    write!(out, "{b:02x}")?;
                }
                writeln!(out)?;
            }
            Err(e) => writeln!(out, "err {}", e.code())?,
        }
    }
    out.flush()
}
