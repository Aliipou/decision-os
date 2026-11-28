//! Arbitrary strings into every text parser: no panic; accepted hex is exactly
//! the lowercase encoding of its bytes; from_tag is exact.
#![no_main]
use dos_core::sign::{Domain, Kid, Signature, VerifyingKey, hex_decode, hex_encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else { return };
    if let Ok(v) = hex_decode(s) {
        assert_eq!(hex_encode(&v), s);
    }
    if let Ok(k) = Kid::from_hex(s) {
        assert_eq!(k.to_hex(), s);
    }
    if let Ok(sig) = Signature::from_hex(s) {
        assert_eq!(sig.to_hex(), s);
    }
    if let Ok(vk) = VerifyingKey::from_hex(s) {
        assert_eq!(vk.to_hex(), s);
    }
    if let Ok(d) = Domain::from_tag(s) {
        assert_eq!(d.tag(), s);
    }
});
