//! Shared fixtures: fixed keys, in-memory trust stores, chain builders.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;

use dos_authority::cap::{CapId, Capability, Link, Right, RightSet, SignedCapability};
use dos_authority::mint::{Grant, delegate, issue_root};
use dos_authority::{AuthorityError, ValidChain, verify_chain};
use dos_core::canon::{self, Value};
use dos_core::sign::SigningKey;
use dos_core::store::{KeyStore, RevocationSource, StoreError};

/// RFC 8032 TEST 1 secret: the repo's fixed conformance key, used as the trust anchor.
pub const ROOT_SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

pub const NOW: i64 = 1_000_000;
pub const FAR: i64 = 10_000_000;

pub fn root() -> SigningKey {
    SigningKey::from_bytes(&ROOT_SECRET)
}

/// Deterministic non-root key number `n` (n != 0).
pub fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

pub fn kid_of(k: &SigningKey) -> String {
    k.kid().to_hex()
}

/// A KeyStore holding the given public keys; `fail` makes every call an error.
pub struct Keys {
    pub keys: Vec<(String, [u8; 32])>,
    pub fail: bool,
    pub raw: Vec<(String, [u8; 32])>,
}

impl Keys {
    pub fn trusting(ks: &[&SigningKey]) -> Keys {
        Keys {
            keys: ks
                .iter()
                .map(|k| (kid_of(k), k.verifying_key().to_bytes()))
                .collect(),
            fail: false,
            raw: Vec::new(),
        }
    }
    pub fn none() -> Keys {
        Keys::trusting(&[])
    }
}

impl KeyStore for Keys {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        if self.fail {
            return Err(StoreError::Unavailable);
        }
        Ok(self
            .keys
            .iter()
            .chain(self.raw.iter())
            .find(|(k, _)| k == kid)
            .map(|(_, v)| *v))
    }
}

/// A RevocationSource. Records how many times each method was called.
pub struct Revs {
    pub revoked: Vec<String>,
    pub min_epoch: u64,
    pub fail_revoked: bool,
    pub fail_epoch: bool,
    pub revoked_calls: Cell<u32>,
    pub epoch_calls: Cell<u32>,
}

impl Revs {
    pub fn clean() -> Revs {
        Revs {
            revoked: Vec::new(),
            min_epoch: 0,
            fail_revoked: false,
            fail_epoch: false,
            revoked_calls: Cell::new(0),
            epoch_calls: Cell::new(0),
        }
    }
    pub fn revoking(ids: &[&CapId]) -> Revs {
        let mut r = Revs::clean();
        r.revoked = ids.iter().map(|i| i.to_hex()).collect();
        r
    }
    pub fn min_epoch(e: u64) -> Revs {
        let mut r = Revs::clean();
        r.min_epoch = e;
        r
    }
}

impl RevocationSource for Revs {
    fn any_revoked(&self, ids: &[String], _now: i64) -> Result<bool, StoreError> {
        self.revoked_calls.set(self.revoked_calls.get() + 1);
        if self.fail_revoked {
            return Err(StoreError::Unavailable);
        }
        Ok(ids.iter().any(|i| self.revoked.contains(i)))
    }
    fn min_epoch(&self, _root_kid: &str) -> Result<u64, StoreError> {
        self.epoch_calls.set(self.epoch_calls.get() + 1);
        if self.fail_epoch {
            return Err(StoreError::Unavailable);
        }
        Ok(self.min_epoch)
    }
}

pub fn rights(rs: &[Right]) -> RightSet {
    RightSet::of(rs)
}

pub fn grant(subject: &str, resources: &[&str], rs: &[Right], exp: i64, epoch: u64) -> Grant {
    Grant {
        subject: subject.to_string(),
        resources: resources.iter().map(|s| s.to_string()).collect(),
        rights: rights(rs),
        expires_at_ms: exp,
        epoch,
    }
}

pub const DX: [Right; 2] = [Right::Delegate, Right::Execute];
pub const X: [Right; 1] = [Right::Execute];

/// root -> key(1) -> key(2) -> "agent:x", every link on `tool:send_email`.
pub fn chain3() -> Vec<SignedCapability> {
    let a = key(1);
    let b = key(2);
    let c0 = issue_root(&root(), &grant(&kid_of(&a), &["tool:*"], &DX, FAR, 1)).unwrap();
    let c1 = delegate(
        &c0,
        &a,
        &grant(&kid_of(&b), &["tool:send_email"], &DX, FAR, 1),
        NOW,
    )
    .unwrap();
    let c2 = delegate(
        &c1,
        &b,
        &grant("agent:x", &["tool:send_email"], &X, FAR, 1),
        NOW,
    )
    .unwrap();
    vec![c0, c1, c2]
}

pub fn verify(chain: &[SignedCapability]) -> Result<ValidChain, AuthorityError> {
    verify_chain(chain, &Keys::trusting(&[&root()]), &Revs::clean(), NOW)
}

pub fn err(chain: &[SignedCapability]) -> AuthorityError {
    verify(chain).expect_err("chain must refuse")
}

/// Builds a raw link body and signs it with `signer`, bypassing every minting rule.
#[allow(clippy::too_many_arguments)]
pub fn forge(
    signer: &SigningKey,
    subject: &str,
    resources: &[&str],
    rs: &[Right],
    exp: i64,
    epoch: u64,
    parent: Option<&SignedCapability>,
) -> SignedCapability {
    let link = match parent {
        None => Link::Root,
        Some(p) => Link::Delegated {
            parent: *p.id(),
            issuer_key: Box::new(signer.verifying_key()),
        },
    };
    let mut res: Vec<String> = resources.iter().map(|s| s.to_string()).collect();
    res.sort();
    let cap = Capability::new(
        signer.kid(),
        subject.to_string(),
        res,
        rights(rs),
        exp,
        epoch,
        link,
    )
    .unwrap();
    SignedCapability::sign(cap, signer).unwrap()
}

/// The link's JSON value, for byte-level tampering.
pub fn link_value(l: &SignedCapability) -> Value {
    l.to_value().unwrap()
}

/// Replace (or insert) a member of the link's `cap` body.
pub fn set_body(v: &mut Value, name: &str, new: Value) {
    let Value::Object(top) = v else { panic!() };
    let (_, cap) = top.iter_mut().find(|(k, _)| k == "cap").unwrap();
    let Value::Object(m) = cap else { panic!() };
    match m.iter_mut().find(|(k, _)| k == name) {
        Some((_, slot)) => *slot = new,
        None => m.push((name.to_string(), new)),
    }
}

pub fn remove_body(v: &mut Value, name: &str) {
    let Value::Object(top) = v else { panic!() };
    let (_, cap) = top.iter_mut().find(|(k, _)| k == "cap").unwrap();
    let Value::Object(m) = cap else { panic!() };
    m.retain(|(k, _)| k != name);
}

pub fn s(x: &str) -> Value {
    Value::String(x.to_string())
}

pub fn n(x: f64) -> Value {
    Value::Number(canon::Number::new(x).unwrap())
}

pub fn arr(xs: &[&str]) -> Value {
    Value::Array(xs.iter().map(|x| s(x)).collect())
}

/// Parse a link from its tampered value through the strict byte decoder.
pub fn reparse(v: &Value) -> Result<SignedCapability, AuthorityError> {
    let bytes = canon::to_jcs(v).unwrap();
    SignedCapability::parse(&bytes)
}
