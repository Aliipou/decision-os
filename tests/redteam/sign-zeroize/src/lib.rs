//! H12: after `drop`, the bytes where a `SigningKey` lived must not contain
//! the secret. Run: cargo test --manifest-path tests/redteam/sign-zeroize/Cargo.toml

#[cfg(test)]
mod tests {
    use dos_core::sign::{Domain, SigningKey};
    use std::mem::{MaybeUninit, size_of};

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn dropped_signing_key_leaves_no_secret_in_place() {
        let secret = [0x5au8; 32];
        let mut slot = MaybeUninit::<SigningKey>::uninit();
        slot.write(SigningKey::from_bytes(&secret));
        // Use it, so nothing is optimized away.
        // SAFETY: initialized just above.
        let sig = unsafe { slot.assume_init_ref() }.sign(Domain::Decision, b"x");
        assert_eq!(sig.to_bytes().len(), 64);
        let p = slot.as_mut_ptr();
        // SAFETY: p points to an initialized SigningKey; it is dropped once here
        // and never used as a SigningKey again.
        unsafe { std::ptr::drop_in_place(p) };
        // SAFETY: reading the raw bytes of the (now dropped) slot as u8.
        let bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(p as *const u8, size_of::<SigningKey>()).to_vec()
        };
        assert!(contains(&bytes, &[0u8; 32]), "no zeroed region at all: {bytes:?}");
        assert!(!contains(&bytes, &secret), "secret still in memory after drop");
    }

    #[test]
    fn control_without_drop_secret_is_present() {
        // Proves the probe can see the secret: without drop it is there.
        let secret = [0x5au8; 32];
        let mut slot = MaybeUninit::<SigningKey>::uninit();
        slot.write(SigningKey::from_bytes(&secret));
        let p = slot.as_mut_ptr();
        // SAFETY: initialized, not dropped.
        let bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(p as *const u8, size_of::<SigningKey>()).to_vec()
        };
        assert!(contains(&bytes, &secret));
        // SAFETY: drop exactly once.
        unsafe { std::ptr::drop_in_place(p) };
    }
}
