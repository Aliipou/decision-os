//! Fuzz `dos_core::canon`: never panic, never overflow the stack; on success the output
//! is a fixed point (canonical bytes canonicalize to themselves) and is valid UTF-8.
#![no_main]

use dos_core::canon;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(out) = canon::canonicalize(data) {
        assert!(core::str::from_utf8(&out).is_ok(), "output is not UTF-8");
        assert_eq!(canon::canonicalize(&out), Ok(out.clone()), "not idempotent");
        // Parsing the canonical bytes gives a value whose serialization is the same bytes.
        let reparsed = canon::parse_strict(&out);
        assert!(
            reparsed.is_ok_and(|v| canon::to_jcs(&v) == Ok(out)),
            "reparse mismatch"
        );
    }
});
