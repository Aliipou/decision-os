//! Ed25519 signatures with domain separation, strict verification and key ids.
//!
//! Spec: `spec/sign.md`. Design: `design/sign.md`.
//!
//! - The signed message is `"decision-os/v1/" || tag || 0x00 || payload`; raw
//!   payload bytes are never signed.
//! - Verification is `verify_strict` only, after our own key checks (canonical
//!   encoding, not small order) and signature check (canonical `S`).
//! - No RNG, no I/O: a signing key is built from caller-supplied secret bytes.
//!   The secret is zeroized on drop and never printed.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};

/// Version prefix of every signed message and of the kid hash input.
const PREFIX: &[u8] = b"decision-os/v1/";
/// Separates the tag from what follows. No tag contains it.
const TERMINATOR: u8 = 0x00;
/// Tag of the kid hash input (not a signing domain).
const KID_TAG: &[u8] = b"kid";

/// RFC 8032 section 7.1 TEST 1 public key: the fixed conformance test key.
const CONFORMANCE_TEST_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// What a signature is for. Part of every signed message, so a signature made
/// for one domain never verifies under another. Only `Decision` is used today;
/// the others are reserved so their tags can never be reused for something else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Domain {
    Decision,
    Capability,
    Revocation,
    Consent,
    AuditHead,
}

impl Domain {
    pub const ALL: [Domain; 5] = [
        Domain::Decision,
        Domain::Capability,
        Domain::Revocation,
        Domain::Consent,
        Domain::AuditHead,
    ];

    /// The ASCII tag written into the signed message.
    pub fn tag(self) -> &'static str {
        match self {
            Domain::Decision => "decision",
            Domain::Capability => "capability",
            Domain::Revocation => "revocation",
            Domain::Consent => "consent",
            Domain::AuditHead => "audit-head",
        }
    }

    /// Exact, case-sensitive inverse of [`Domain::tag`].
    pub fn from_tag(tag: &str) -> Result<Domain, SignError> {
        Domain::ALL
            .into_iter()
            .find(|d| d.tag() == tag)
            .ok_or(SignError::UnknownDomain)
    }
}

/// The exact bytes that are signed for `payload` in `domain`:
/// `"decision-os/v1/" || tag || 0x00 || payload`.
pub fn signed_message(domain: Domain, payload: &[u8]) -> Vec<u8> {
    let tag = domain.tag().as_bytes();
    let mut msg = Vec::with_capacity(PREFIX.len() + tag.len() + 1 + payload.len());
    msg.extend_from_slice(PREFIX);
    msg.extend_from_slice(tag);
    msg.push(TERMINATOR);
    msg.extend_from_slice(payload);
    msg
}

/// Every refusal of this module. `code()` strings are stable (conformance).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// Not lowercase hex, or odd length.
    BadHex,
    /// Valid hex, wrong number of bytes.
    BadLength,
    /// Public key bytes are not a curve point.
    InvalidKey,
    /// Public key encoding is not the canonical one for its point.
    NonCanonicalKey,
    /// Public key is a small-order point.
    WeakKey,
    /// Signature `S` is not below the group order L.
    NonCanonicalSignature,
    /// Strict verification failed.
    BadSignature,
    /// The expected kid is not the kid of the key.
    KidMismatch,
    /// Domain tag not in the closed set.
    UnknownDomain,
}

impl SignError {
    pub fn code(self) -> &'static str {
        match self {
            SignError::BadHex => "bad_hex",
            SignError::BadLength => "bad_length",
            SignError::InvalidKey => "invalid_key",
            SignError::NonCanonicalKey => "non_canonical_key",
            SignError::WeakKey => "weak_key",
            SignError::NonCanonicalSignature => "non_canonical_signature",
            SignError::BadSignature => "bad_signature",
            SignError::KidMismatch => "kid_mismatch",
            SignError::UnknownDomain => "unknown_domain",
        }
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

fn nibble_char(n: u8) -> char {
    let n = n & 0x0f;
    char::from(if n < 10 { b'0' + n } else { b'a' + (n - 10) })
}

fn char_nibble(c: u8) -> Result<u8, SignError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(SignError::BadHex),
    }
}

/// Lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble_char(b >> 4));
        s.push(nibble_char(*b));
    }
    s
}

/// Lowercase hex only. Uppercase, odd length or any other character: `bad_hex`.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, SignError> {
    let chunks = s.as_bytes().chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(SignError::BadHex);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in chunks {
        match pair {
            [hi, lo] => out.push((char_nibble(*hi)? << 4) | char_nibble(*lo)?),
            _ => return Err(SignError::BadHex),
        }
    }
    Ok(out)
}

/// [`hex_decode`], then exactly `N` bytes, else `bad_length`.
pub fn hex_decode_array<const N: usize>(s: &str) -> Result<[u8; N], SignError> {
    <[u8; N]>::try_from(hex_decode(s)?).map_err(|_| SignError::BadLength)
}

/// Key id: first 16 bytes of `SHA-256("decision-os/v1/kid" || 0x00 || A)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Kid([u8; 16]);

impl Kid {
    fn of(public_key: &[u8; 32]) -> Kid {
        let digest = Sha256::new()
            .chain_update(PREFIX)
            .chain_update(KID_TAG)
            .chain_update([TERMINATOR])
            .chain_update(public_key)
            .finalize();
        let mut kid = [0u8; 16];
        for (k, d) in kid.iter_mut().zip(digest.iter()) {
            *k = *d;
        }
        Kid(kid)
    }

    pub fn from_bytes(bytes: &[u8; 16]) -> Kid {
        Kid(*bytes)
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        self.0
    }

    pub fn from_hex(s: &str) -> Result<Kid, SignError> {
        hex_decode_array::<16>(s).map(Kid)
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

/// An Ed25519 signature `R || S` whose `S` is canonical (`S < L`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Refuses a non-canonical `S` (`non_canonical_signature`).
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Signature, SignError> {
        let s = bytes
            .last_chunk::<32>()
            .ok_or(SignError::NonCanonicalSignature)?;
        if bool::from(Scalar::from_canonical_bytes(*s).is_some()) {
            Ok(Signature(*bytes))
        } else {
            Err(SignError::NonCanonicalSignature)
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    pub fn from_hex(s: &str) -> Result<Signature, SignError> {
        Signature::from_bytes(&hex_decode_array::<64>(s)?)
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

/// A public key that passed every check of `spec/sign.md`: on the curve,
/// canonically encoded, not of small order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Refuses, in order: `invalid_key`, `non_canonical_key`, `weak_key`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, SignError> {
        let point = CompressedEdwardsY(*bytes)
            .decompress()
            .ok_or(SignError::InvalidKey)?;
        if point.compress().to_bytes() != *bytes {
            return Err(SignError::NonCanonicalKey);
        }
        if point.is_small_order() {
            return Err(SignError::WeakKey);
        }
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| SignError::InvalidKey)?;
        // Defense in depth: the library's own weak-key test must agree.
        if vk.is_weak() {
            return Err(SignError::WeakKey);
        }
        Ok(VerifyingKey(vk))
    }

    pub fn from_hex(s: &str) -> Result<VerifyingKey, SignError> {
        VerifyingKey::from_bytes(&hex_decode_array::<32>(s)?)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn to_hex(&self) -> String {
        hex_encode(self.0.as_bytes())
    }

    pub fn kid(&self) -> Kid {
        Kid::of(self.0.as_bytes())
    }

    /// True for the RFC 8032 TEST 1 key used by conformance. A production key
    /// store must refuse such a key (`spec/CONFORMANCE.md`).
    pub fn is_conformance_test_key(&self) -> bool {
        self.0.to_bytes() == CONFORMANCE_TEST_PUBLIC_KEY
    }

    /// Strict verification of `sig` over `signed_message(domain, payload)`.
    pub fn verify(&self, domain: Domain, payload: &[u8], sig: &Signature) -> Result<(), SignError> {
        let msg = signed_message(domain, payload);
        let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        self.0
            .verify_strict(&msg, &sig)
            .map_err(|_| SignError::BadSignature)
    }

    /// [`VerifyingKey::verify`], after refusing a kid that is not this key's.
    pub fn verify_with_kid(
        &self,
        domain: Domain,
        payload: &[u8],
        sig: &Signature,
        expected: &Kid,
    ) -> Result<(), SignError> {
        if self.kid() != *expected {
            return Err(SignError::KidMismatch);
        }
        self.verify(domain, payload, sig)
    }
}

/// A secret signing key. Zeroized on drop (`ed25519-dalek` `zeroize`); its
/// `Debug` shows only the kid. Not `Clone`, so the secret is not copied around.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Builds the key from 32 caller-supplied secret bytes (RFC 8032 secret
    /// key). The caller owns and must wipe its own copy of `secret`.
    pub fn from_bytes(secret: &[u8; 32]) -> SigningKey {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(secret))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    pub fn kid(&self) -> Kid {
        Kid::of(self.0.verifying_key().as_bytes())
    }

    /// Deterministic Ed25519 signature over `signed_message(domain, payload)`.
    pub fn sign(&self, domain: Domain, payload: &[u8]) -> Signature {
        Signature(self.0.sign(&signed_message(domain, payload)).to_bytes())
    }
}

// The only field is an `ed25519_dalek::SigningKey`, which is `ZeroizeOnDrop`.
impl zeroize::ZeroizeOnDrop for SigningKey {}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid().to_hex())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::format;
    use alloc::vec;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use proptest::prelude::*;

    /// RFC 8032 section 7.1: (name, secret, public, message, signature), parsed
    /// from rfc8032.txt by a script (see status/sign.md), lengths checked.
    const RFC8032_7_1: [(&str, &str, &str, &str, &str); 5] = [
        (
            "1",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "2",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "3",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "1024",
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        ),
        (
            "SHA(abc)",
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    ];

    const TEST1_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TEST1_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    /// Computed independently: Python hashlib, sha256(b"decision-os/v1/kid\0" + A)[:16].
    const TEST1_KID: &str = "b1f1515d964ca23d4f37283c507551d3";

    /// The 8 small-order points, canonical encodings. Cross-checked against
    /// curve25519_dalek::constants::EIGHT_TORSION in `small_order_list_is_complete`.
    const SMALL_ORDER: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    /// L, little endian.
    const L_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    fn arr<const N: usize>(s: &str) -> Result<[u8; N], SignError> {
        hex_decode_array::<N>(s)
    }

    fn test_key() -> Result<SigningKey, SignError> {
        Ok(SigningKey::from_bytes(&arr::<32>(TEST1_SECRET)?))
    }

    /// p + i, little endian (p = 2^255 - 19). For i in 1..=18 this is a
    /// non-canonical encoding of y = i.
    fn p_plus(i: u8) -> [u8; 32] {
        let mut b = [0xffu8; 32];
        if let Some(first) = b.first_mut() {
            *first = 0xedu8.wrapping_add(i);
        }
        if let Some(last) = b.last_mut() {
            *last = 0x7f;
        }
        b
    }

    /// S + L for the S half of a signature (fits: S < L < 2^253).
    fn add_l_to_s(sig: [u8; 64]) -> [u8; 64] {
        let mut out = sig;
        let mut carry = 0u16;
        for (o, l) in out.iter_mut().skip(32).zip(L_LE.iter()) {
            let v = u16::from(*o) + u16::from(*l) + carry;
            *o = (v & 0xff) as u8;
            carry = v >> 8;
        }
        out
    }

    fn flip(bytes: &mut [u8], bit: usize) {
        if let Some(b) = bytes.get_mut(bit / 8) {
            *b ^= 1u8 << (bit % 8);
        }
    }

    // ---- raw primitive: RFC 8032 section 7.1 ----

    #[test]
    fn rfc8032_7_1_vectors_raw_primitive() -> Result<(), SignError> {
        use ed25519_dalek::Signer;
        for (name, sk_hex, pk, msg, sig) in RFC8032_7_1 {
            let sk = ed25519_dalek::SigningKey::from_bytes(&arr::<32>(sk_hex)?);
            let msg = hex_decode(msg)?;
            assert_eq!(
                hex_encode(sk.verifying_key().as_bytes()),
                pk,
                "TEST {name}: public key"
            );
            let got = sk.sign(&msg);
            assert_eq!(hex_encode(&got.to_bytes()), sig, "TEST {name}: signature");
            assert!(
                sk.verifying_key().verify_strict(&msg, &got).is_ok(),
                "TEST {name}"
            );
            // Our key type accepts every RFC public key.
            let vk = VerifyingKey::from_bytes(&arr::<32>(pk)?)?;
            assert_eq!(vk.to_hex(), pk);
            assert_eq!(
                SigningKey::from_bytes(&arr::<32>(sk_hex)?).verifying_key(),
                vk
            );
        }
        Ok(())
    }

    #[test]
    fn rfc_signature_is_not_valid_in_any_domain() -> Result<(), SignError> {
        // A raw RFC signature (no domain prefix) must not verify through our API.
        let (_, _, pk, msg, sig) = RFC8032_7_1[0];
        let vk = VerifyingKey::from_hex(pk)?;
        let sig = Signature::from_hex(sig)?;
        let msg = hex_decode(msg)?;
        for d in Domain::ALL {
            assert_eq!(vk.verify(d, &msg, &sig), Err(SignError::BadSignature));
        }
        Ok(())
    }

    // ---- signed bytes, domains, kid ----

    #[test]
    fn signed_message_layout() {
        assert_eq!(
            signed_message(Domain::Decision, b"ab"),
            b"decision-os/v1/decision\x00ab".to_vec()
        );
        assert_eq!(
            signed_message(Domain::AuditHead, b""),
            b"decision-os/v1/audit-head\x00".to_vec()
        );
    }

    #[test]
    fn domain_tags_are_closed_and_round_trip() {
        let tags = [
            "decision",
            "capability",
            "revocation",
            "consent",
            "audit-head",
        ];
        for (d, t) in Domain::ALL.iter().zip(tags.iter()) {
            assert_eq!(d.tag(), *t);
            assert_eq!(Domain::from_tag(t), Ok(*d));
            assert!(!d.tag().as_bytes().contains(&0));
        }
        for bad in [
            "",
            "Decision",
            "DECISION",
            "decision\0",
            " decision",
            "audit_head",
            "x",
        ] {
            assert_eq!(
                Domain::from_tag(bad),
                Err(SignError::UnknownDomain),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn signed_messages_are_injective_across_domains() {
        // Same payload, different domains: different messages; and no domain's
        // message is a prefix-shifted copy of another's.
        for a in Domain::ALL {
            for b in Domain::ALL {
                if a != b {
                    let ma = signed_message(a, b"p");
                    let mb = signed_message(b, b"p");
                    assert_ne!(ma, mb);
                    let pa = signed_message(a, b"");
                    let pb = signed_message(b, b"");
                    assert!(!pb.starts_with(&pa), "{a:?} prefix of {b:?}");
                }
            }
        }
    }

    #[test]
    fn domain_a_signature_rejected_under_every_other_domain() -> Result<(), SignError> {
        let sk = test_key()?;
        let vk = sk.verifying_key();
        for a in Domain::ALL {
            let sig = sk.sign(a, b"{\"v\":1}");
            assert_eq!(vk.verify(a, b"{\"v\":1}", &sig), Ok(()));
            for b in Domain::ALL {
                if a != b {
                    assert_eq!(
                        vk.verify(b, b"{\"v\":1}", &sig),
                        Err(SignError::BadSignature)
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_key_public_and_kid() -> Result<(), SignError> {
        let sk = test_key()?;
        assert_eq!(sk.verifying_key().to_hex(), TEST1_PUBLIC);
        assert_eq!(sk.kid().to_hex(), TEST1_KID);
        assert_eq!(sk.verifying_key().kid(), sk.kid());
        assert!(sk.verifying_key().is_conformance_test_key());
        let other = SigningKey::from_bytes(&arr::<32>(RFC8032_7_1[1].1)?);
        assert!(!other.verifying_key().is_conformance_test_key());
        assert_ne!(other.kid(), sk.kid());
        Ok(())
    }

    #[test]
    fn wrong_kid_is_refused_before_signature() -> Result<(), SignError> {
        let sk = test_key()?;
        let vk = sk.verifying_key();
        let sig = sk.sign(Domain::Decision, b"x");
        assert_eq!(
            vk.verify_with_kid(Domain::Decision, b"x", &sig, &sk.kid()),
            Ok(())
        );
        let mut kid = sk.kid().to_bytes();
        flip(&mut kid, 0);
        let wrong = Kid::from_bytes(&kid);
        assert_eq!(
            vk.verify_with_kid(Domain::Decision, b"x", &sig, &wrong),
            Err(SignError::KidMismatch)
        );
        // Kid of another key.
        let other = SigningKey::from_bytes(&arr::<32>(RFC8032_7_1[2].1)?).kid();
        assert_eq!(
            vk.verify_with_kid(Domain::Decision, b"x", &sig, &other),
            Err(SignError::KidMismatch)
        );
        // Mismatch wins even when the signature is also bad.
        let bad = Signature::from_bytes(&[0u8; 64])?;
        assert_eq!(
            vk.verify_with_kid(Domain::Decision, b"x", &bad, &wrong),
            Err(SignError::KidMismatch)
        );
        Ok(())
    }

    // ---- weak and non-canonical keys ----

    #[test]
    fn small_order_list_is_complete() {
        let mut from_lib: std::vec::Vec<String> = curve25519_dalek::constants::EIGHT_TORSION
            .iter()
            .map(|p| hex_encode(p.compress().as_bytes()))
            .collect();
        from_lib.sort();
        let mut ours: std::vec::Vec<String> =
            SMALL_ORDER.iter().map(|s| String::from(*s)).collect();
        ours.sort();
        assert_eq!(from_lib, ours);
    }

    #[test]
    fn all_eight_small_order_keys_refused() -> Result<(), SignError> {
        for s in SMALL_ORDER {
            assert_eq!(
                VerifyingKey::from_bytes(&arr::<32>(s)?),
                Err(SignError::WeakKey),
                "{s}"
            );
            assert_eq!(VerifyingKey::from_hex(s), Err(SignError::WeakKey), "{s}");
        }
        Ok(())
    }

    #[test]
    fn all_zero_key_refused() {
        assert_eq!(
            VerifyingKey::from_bytes(&[0u8; 32]),
            Err(SignError::WeakKey)
        );
    }

    #[test]
    fn non_canonical_key_encodings_refused() {
        // y = p + 1 (identity, non-canonical) and identity with the sign bit set.
        assert_eq!(
            VerifyingKey::from_bytes(&p_plus(1)),
            Err(SignError::NonCanonicalKey)
        );
        let mut neg_zero = [0u8; 32];
        if let Some(b) = neg_zero.first_mut() {
            *b = 1;
        }
        if let Some(b) = neg_zero.last_mut() {
            *b = 0x80;
        }
        assert_eq!(
            VerifyingKey::from_bytes(&neg_zero),
            Err(SignError::NonCanonicalKey)
        );
        // y = -1 + p would be 2p - 1 > 2^255: not encodable. y = 0 + p:
        assert_eq!(
            VerifyingKey::from_bytes(&p_plus(0)),
            Err(SignError::NonCanonicalKey)
        );
        // Every y in p..p+18 that decompresses must be refused as non-canonical.
        let mut on_curve = 0;
        for i in 0..=18u8 {
            let b = p_plus(i);
            if CompressedEdwardsY(b).decompress().is_some() {
                on_curve += 1;
                assert_eq!(
                    VerifyingKey::from_bytes(&b),
                    Err(SignError::NonCanonicalKey),
                    "p+{i}"
                );
            } else {
                assert_eq!(
                    VerifyingKey::from_bytes(&b),
                    Err(SignError::InvalidKey),
                    "p+{i}"
                );
            }
        }
        assert!(on_curve >= 3);
    }

    #[test]
    fn non_canonical_large_order_key_exists_and_is_refused() {
        // The dangerous case verify_strict alone misses: a non-canonical encoding
        // of a point that is NOT small order.
        let mut found = false;
        for i in 2..=18u8 {
            let b = p_plus(i);
            let large_order = CompressedEdwardsY(b)
                .decompress()
                .is_some_and(|p| !p.is_small_order());
            if large_order {
                found = true;
                // The library alone accepts it, and verify_strict would not
                // reject it (it only checks small order).
                assert!(
                    ed25519_dalek::VerifyingKey::from_bytes(&b).is_ok_and(|k| !k.is_weak()),
                    "dalek accepts p+{i}"
                );
                assert_eq!(
                    VerifyingKey::from_bytes(&b),
                    Err(SignError::NonCanonicalKey)
                );
            }
        }
        assert!(found);
    }

    #[test]
    fn not_on_curve_refused() {
        let mut found = false;
        for y in 2..=40u8 {
            let mut b = [0u8; 32];
            if let Some(f) = b.first_mut() {
                *f = y;
            }
            if CompressedEdwardsY(b).decompress().is_none() {
                found = true;
                assert_eq!(
                    VerifyingKey::from_bytes(&b),
                    Err(SignError::InvalidKey),
                    "y={y}"
                );
            }
        }
        assert!(found);
    }

    // ---- signature malleability ----

    #[test]
    fn s_plus_l_refused() -> Result<(), SignError> {
        let sk = test_key()?;
        let sig = sk.sign(Domain::Decision, b"m").to_bytes();
        let mall = add_l_to_s(sig);
        assert_ne!(mall, sig);
        assert_eq!(
            Signature::from_bytes(&mall),
            Err(SignError::NonCanonicalSignature)
        );
        assert_eq!(
            Signature::from_hex(&hex_encode(&mall)),
            Err(SignError::NonCanonicalSignature)
        );
        Ok(())
    }

    #[test]
    fn s_top_bits_refused() -> Result<(), SignError> {
        let sk = test_key()?;
        for bit in [253usize, 254, 255] {
            let mut sig = sk.sign(Domain::Decision, b"m").to_bytes();
            flip(&mut sig, 256 + bit);
            assert_eq!(
                Signature::from_bytes(&sig),
                Err(SignError::NonCanonicalSignature),
                "bit {bit}"
            );
        }
        Ok(())
    }

    #[test]
    fn s_equal_l_refused_and_l_minus_1_parses() -> Result<(), SignError> {
        let mut sig = [0u8; 64];
        for (o, l) in sig.iter_mut().skip(32).zip(L_LE.iter()) {
            *o = *l;
        }
        assert_eq!(
            Signature::from_bytes(&sig),
            Err(SignError::NonCanonicalSignature)
        );
        if let Some(b) = sig.get_mut(32) {
            *b = 0xec;
        }
        assert!(Signature::from_bytes(&sig).is_ok());
        Ok(())
    }

    #[test]
    fn small_order_r_refused() -> Result<(), SignError> {
        // R = identity, S = 0 under the real test key: rejected by verify_strict.
        let vk = test_key()?.verifying_key();
        for r in SMALL_ORDER {
            let mut sig = [0u8; 64];
            for (o, b) in sig.iter_mut().zip(arr::<32>(r)?.iter()) {
                *o = *b;
            }
            let sig = Signature::from_bytes(&sig)?;
            assert_eq!(
                vk.verify(Domain::Decision, b"", &sig),
                Err(SignError::BadSignature)
            );
        }
        Ok(())
    }

    #[test]
    fn non_canonical_r_refused() -> Result<(), SignError> {
        // Replace R by a non-canonical encoding of the same point (only possible
        // for y < 19, i.e. none of our real R values), so: take R = p+1 (identity).
        let vk = test_key()?.verifying_key();
        let mut sig = [0u8; 64];
        for (o, b) in sig.iter_mut().zip(p_plus(1).iter()) {
            *o = *b;
        }
        let sig = Signature::from_bytes(&sig)?;
        assert_eq!(
            vk.verify(Domain::Decision, b"", &sig),
            Err(SignError::BadSignature)
        );
        Ok(())
    }

    /// Step 3 of the task: the one deliberate use of non-strict `verify`. It shows
    /// that the weak-key test exercises a real difference between the two.
    #[test]
    fn demonstrates_plain_verify_is_weaker() -> Result<(), SignError> {
        // Scoped to this test only: nowhere else may plain `verify` be reachable.
        use ed25519_dalek::Verifier;
        let identity = arr::<32>(SMALL_ORDER[0])?;
        let dalek_vk = ed25519_dalek::VerifyingKey::from_bytes(&identity)
            .map_err(|_| SignError::InvalidKey)?;
        // R = identity, S = 0: [0]B == identity + [k]identity for every message.
        let mut forged = [0u8; 64];
        for (o, b) in forged.iter_mut().zip(identity.iter()) {
            *o = *b;
        }
        let forged = ed25519_dalek::Signature::from_bytes(&forged);
        let mut plain_accepts = 0;
        for msg in [
            &b""[..],
            b"pay 1000 to mallory",
            b"decision-os/v1/decision\x00{}",
        ] {
            if dalek_vk.verify(msg, &forged).is_ok() {
                plain_accepts += 1;
            }
            assert!(dalek_vk.verify_strict(msg, &forged).is_err());
        }
        std::println!(
            "plain verify accepted the forged signature for {plain_accepts}/3 messages; verify_strict rejected 3/3"
        );
        assert_eq!(plain_accepts, 3);
        // And our API refuses the key outright.
        assert_eq!(VerifyingKey::from_bytes(&identity), Err(SignError::WeakKey));
        Ok(())
    }

    // ---- hex ----

    #[test]
    fn hex_policy() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff, 0x10]), "00abff10");
        assert_eq!(hex_decode("00abff10"), Ok(vec![0x00, 0xab, 0xff, 0x10]));
        assert_eq!(hex_decode(""), Ok(vec![]));
        assert_eq!(hex_decode("AB"), Err(SignError::BadHex));
        assert_eq!(hex_decode("aB"), Err(SignError::BadHex));
        assert_eq!(hex_decode("abc"), Err(SignError::BadHex));
        assert_eq!(hex_decode("0g"), Err(SignError::BadHex));
        assert_eq!(hex_decode(" 00"), Err(SignError::BadHex));
        assert_eq!(hex_decode("0x00"), Err(SignError::BadHex));
        assert_eq!(hex_decode("\u{e9}\u{e9}"), Err(SignError::BadHex));
        assert_eq!(hex_decode_array::<2>("0011"), Ok([0x00, 0x11]));
        assert_eq!(hex_decode_array::<2>("00"), Err(SignError::BadLength));
        assert_eq!(hex_decode_array::<2>("001122"), Err(SignError::BadLength));
        assert_eq!(hex_decode_array::<2>("00112"), Err(SignError::BadHex));
    }

    #[test]
    fn truncated_and_extended_hex_refused() -> Result<(), SignError> {
        let sk = test_key()?;
        let sig = sk.sign(Domain::Decision, b"").to_hex();
        assert_eq!(sig.len(), 128);
        let pk = sk.verifying_key().to_hex();
        let kid = sk.kid().to_hex();
        let cut = |s: &str, n: usize| String::from(s.get(..s.len() - n).unwrap_or(""));
        assert_eq!(
            Signature::from_hex(&cut(&sig, 2)),
            Err(SignError::BadLength)
        );
        assert_eq!(Signature::from_hex(&cut(&sig, 1)), Err(SignError::BadHex));
        assert_eq!(
            Signature::from_hex(&format!("{sig}00")),
            Err(SignError::BadLength)
        );
        assert_eq!(Signature::from_hex(""), Err(SignError::BadLength));
        assert_eq!(
            Signature::from_hex(&sig.to_uppercase()),
            Err(SignError::BadHex)
        );
        assert_eq!(
            VerifyingKey::from_hex(&cut(&pk, 2)),
            Err(SignError::BadLength)
        );
        assert_eq!(
            VerifyingKey::from_hex(&format!("{pk}00")),
            Err(SignError::BadLength)
        );
        assert_eq!(
            VerifyingKey::from_hex(&pk.to_uppercase()),
            Err(SignError::BadHex)
        );
        assert_eq!(Kid::from_hex(&cut(&kid, 2)), Err(SignError::BadLength));
        assert_eq!(
            Kid::from_hex(&format!("{kid}00")),
            Err(SignError::BadLength)
        );
        assert_eq!(Kid::from_hex(&kid.to_uppercase()), Err(SignError::BadHex));
        assert_eq!(Kid::from_hex(&kid), Ok(sk.kid()));
        assert_eq!(Signature::from_hex(&sig).map(|s| s.to_hex()), Ok(sig));
        Ok(())
    }

    #[test]
    fn error_codes_are_stable() {
        let all = [
            (SignError::BadHex, "bad_hex"),
            (SignError::BadLength, "bad_length"),
            (SignError::InvalidKey, "invalid_key"),
            (SignError::NonCanonicalKey, "non_canonical_key"),
            (SignError::WeakKey, "weak_key"),
            (SignError::NonCanonicalSignature, "non_canonical_signature"),
            (SignError::BadSignature, "bad_signature"),
            (SignError::KidMismatch, "kid_mismatch"),
            (SignError::UnknownDomain, "unknown_domain"),
        ];
        for (e, c) in all {
            assert_eq!(e.code(), c);
            assert_eq!(format!("{e}"), c);
        }
    }

    // ---- secrets ----

    #[test]
    fn debug_never_prints_secret() -> Result<(), SignError> {
        let sk = test_key()?;
        let dbg = format!("{sk:?} {sk:#?}");
        assert!(!dbg.contains(TEST1_SECRET), "{dbg}");
        assert!(!dbg.contains("9d61b1"), "{dbg}");
        assert!(!dbg.contains("157"), "decimal secret byte leaked: {dbg}");
        assert!(dbg.contains(TEST1_KID), "{dbg}");
        Ok(())
    }

    #[test]
    fn signing_key_zeroizes_on_drop() {
        fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroize_on_drop::<SigningKey>();
        zeroize_on_drop::<ed25519_dalek::SigningKey>();
    }

    // ---- backend ----

    #[test]
    fn fiat_backend_selected() {
        // Checked at compile time: without the flag this test target does not
        // build, so the suite cannot pass on the default backend.
        const {
            assert!(
                cfg!(curve25519_dalek_backend = "fiat"),
                "curve25519-dalek must build with the Fiat-Crypto backend (.cargo/config.toml); RUSTFLAGS in the environment overrides it"
            )
        }
    }

    // ---- properties ----

    fn secret() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    fn domain() -> impl Strategy<Value = Domain> {
        proptest::sample::select(Domain::ALL.to_vec())
    }

    proptest! {
        #[test]
        fn round_trip(sk in secret(), d in domain(), payload in proptest::collection::vec(any::<u8>(), 0..300)) {
            let sk = SigningKey::from_bytes(&sk);
            let vk = VerifyingKey::from_bytes(&sk.verifying_key().to_bytes());
            prop_assert_eq!(vk, Ok(sk.verifying_key()));
            let sig = sk.sign(d, &payload);
            prop_assert_eq!(sk.verifying_key().verify(d, &payload, &sig), Ok(()));
            prop_assert_eq!(sk.verifying_key().verify_with_kid(d, &payload, &sig, &sk.kid()), Ok(()));
            let parsed = Signature::from_hex(&sig.to_hex());
            prop_assert_eq!(parsed, Ok(sig));
            prop_assert_eq!(Kid::from_hex(&sk.kid().to_hex()), Ok(sk.kid()));
            prop_assert_eq!(sk.sign(d, &payload), sig);
        }

        #[test]
        fn payload_bit_flip_fails(sk in secret(), d in domain(), payload in proptest::collection::vec(any::<u8>(), 1..200), bit in any::<usize>()) {
            let sk = SigningKey::from_bytes(&sk);
            let sig = sk.sign(d, &payload);
            let mut p = payload.clone();
            flip(&mut p, bit % (payload.len() * 8));
            prop_assert_eq!(sk.verifying_key().verify(d, &p, &sig), Err(SignError::BadSignature));
        }

        #[test]
        fn signature_bit_flip_fails(sk in secret(), d in domain(), payload in proptest::collection::vec(any::<u8>(), 0..200), bit in 0usize..512) {
            let sk = SigningKey::from_bytes(&sk);
            let mut sig = sk.sign(d, &payload).to_bytes();
            flip(&mut sig, bit);
            let res = Signature::from_bytes(&sig).and_then(|s| sk.verifying_key().verify(d, &payload, &s));
            prop_assert!(res.is_err());
        }

        #[test]
        fn key_bit_flip_fails(sk in secret(), d in domain(), payload in proptest::collection::vec(any::<u8>(), 0..200), bit in 0usize..256) {
            let sk = SigningKey::from_bytes(&sk);
            let sig = sk.sign(d, &payload);
            let mut pk = sk.verifying_key().to_bytes();
            flip(&mut pk, bit);
            let res = VerifyingKey::from_bytes(&pk).and_then(|vk| vk.verify(d, &payload, &sig));
            prop_assert!(res.is_err());
        }

        #[test]
        fn hex_decode_never_panics(s in ".{0,80}") {
            let _ = hex_decode(&s);
            let _ = Signature::from_hex(&s);
            let _ = VerifyingKey::from_hex(&s);
            let _ = Kid::from_hex(&s);
            let _ = Domain::from_tag(&s);
        }

        #[test]
        fn arbitrary_key_and_signature_bytes_never_verify(pk in proptest::array::uniform32(any::<u8>()), r in proptest::array::uniform32(any::<u8>()), s in proptest::array::uniform32(any::<u8>())) {
            let mut sig = [0u8; 64];
            for (o, b) in sig.iter_mut().zip(r.iter().chain(s.iter())) {
                *o = *b;
            }
            let res = VerifyingKey::from_bytes(&pk)
                .and_then(|vk| Signature::from_bytes(&sig).and_then(|sg| vk.verify(Domain::Decision, b"x", &sg)));
            prop_assert!(res.is_err());
        }
    }
}
