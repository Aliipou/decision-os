#![no_main]
//! The verifier must never panic on arbitrary log bytes, with or without compat mode.
use dos_audit::{VerifyOptions, verify_bytes};
use dos_core::store::{KeyStore, StoreError};
use libfuzzer_sys::fuzz_target;

struct NoKeys;
impl KeyStore for NoKeys {
    fn verifying_key(&self, _: &str, _: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok(None)
    }
}

fuzz_target!(|data: &[u8]| {
    for python_compat in [false, true] {
        let opts = VerifyOptions {
            keys: &NoKeys,
            now_unix_ms: 0,
            python_compat,
            anchor: None,
        };
        let _ = verify_bytes(data, &opts);
    }
});
