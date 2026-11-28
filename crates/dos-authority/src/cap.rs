//! Capability tokens: the v1 body, its JCS encoding, signing and the computed id.
//!
//! Wire format and rules: `design/authority.md`. Every decoder here is strict: an
//! unknown member, a missing member, a wrong type, an unsorted or duplicated set, an
//! out of range number or an oversized input refuses.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use dos_core::canon::{self, Number, Value};
use dos_core::sign::{self, Domain, Kid, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::AuthorityError;

/// Wire version of capability bodies and revocation notices.
pub const VERSION: u64 = 1;
/// Longest accepted chain, root included (sluicegate's 16, closes SG-7).
pub const MAX_CHAIN_LEN: usize = 16;
/// Most resources in one capability.
pub const MAX_RESOURCES: usize = 64;
/// Longest subject or resource string, in bytes.
pub const MAX_STR_BYTES: usize = 256;
/// Largest accepted encoding of one signed link.
pub const MAX_LINK_BYTES: usize = 32 * 1024;
/// Largest accepted encoding of a chain.
pub const MAX_CHAIN_BYTES: usize = MAX_CHAIN_LEN * MAX_LINK_BYTES;
/// Largest integer member (2^53 - 1, exact in JSON numbers and in JCS).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// A right. The set is closed; the names are sluicegate's rights bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Right {
    Delegate,
    Execute,
    ModelInvoke,
    Network,
    PolicyModify,
    Read,
    Spawn,
    Write,
}

impl Right {
    /// Every right, in ascending order of its wire name (the canonical set order).
    pub const ALL: [Right; 8] = [
        Right::Delegate,
        Right::Execute,
        Right::ModelInvoke,
        Right::Network,
        Right::PolicyModify,
        Right::Read,
        Right::Spawn,
        Right::Write,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Right::Delegate => "delegate",
            Right::Execute => "execute",
            Right::ModelInvoke => "model_invoke",
            Right::Network => "network",
            Right::PolicyModify => "policy_modify",
            Right::Read => "read",
            Right::Spawn => "spawn",
            Right::Write => "write",
        }
    }

    /// Exact, case-sensitive inverse of [`Right::as_str`].
    pub fn from_name(s: &str) -> Option<Right> {
        Right::ALL.into_iter().find(|r| r.as_str() == s)
    }

    fn bit(self) -> u8 {
        match self {
            Right::Delegate => 1,
            Right::Execute => 1 << 1,
            Right::ModelInvoke => 1 << 2,
            Right::Network => 1 << 3,
            Right::PolicyModify => 1 << 4,
            Right::Read => 1 << 5,
            Right::Spawn => 1 << 6,
            Right::Write => 1 << 7,
        }
    }
}

/// A set of rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct RightSet(u8);

impl RightSet {
    pub const EMPTY: RightSet = RightSet(0);

    pub fn of(rights: &[Right]) -> RightSet {
        rights.iter().fold(RightSet::EMPTY, |s, r| s.with(*r))
    }

    pub fn all() -> RightSet {
        RightSet::of(&Right::ALL)
    }

    #[must_use]
    pub fn with(self, r: Right) -> RightSet {
        RightSet(self.0 | r.bit())
    }

    #[must_use]
    pub fn without(self, r: Right) -> RightSet {
        RightSet(self.0 & !r.bit())
    }

    pub fn contains(self, r: Right) -> bool {
        self.0 & r.bit() != 0
    }

    pub fn is_subset(self, of: RightSet) -> bool {
        self.0 & !of.0 == 0
    }

    #[must_use]
    pub fn intersect(self, other: RightSet) -> RightSet {
        RightSet(self.0 & other.0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The rights in canonical (ascending name) order.
    pub fn iter(self) -> impl Iterator<Item = Right> {
        Right::ALL.into_iter().filter(move |r| self.contains(*r))
    }

    /// The raw bits (for property tests and debugging).
    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn from_bits(bits: u8) -> RightSet {
        RightSet(bits)
    }
}

/// True if `r` is a valid resource item: 1..=256 bytes, `*` only as the last character.
pub fn resource_is_valid(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= MAX_STR_BYTES
        && r.find('*').is_none_or(|i| i.saturating_add(1) == r.len())
}

/// Resource coverage. An exact item covers only itself; a pattern `p*` covers every
/// item (exact or pattern) that starts with `p`. Reflexive and transitive.
pub fn covers(parent: &str, child: &str) -> bool {
    match parent.strip_suffix('*') {
        Some(prefix) => child.starts_with(prefix),
        None => parent == child,
    }
}

/// A capability id: SHA-256 of the signed message of the body. Computed, never read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CapId(pub [u8; 32]);

impl CapId {
    pub fn to_hex(&self) -> String {
        sign::hex_encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Result<CapId, AuthorityError> {
        sign::hex_decode_array::<32>(s)
            .map(CapId)
            .map_err(|_| AuthorityError::BadValue)
    }

    /// The id of a body whose JCS bytes are `body_jcs`.
    pub fn of_body(body_jcs: &[u8]) -> CapId {
        let digest = Sha256::digest(sign::signed_message(Domain::Capability, body_jcs));
        let mut id = [0u8; 32];
        for (o, d) in id.iter_mut().zip(digest.iter()) {
            *o = *d;
        }
        CapId(id)
    }
}

/// Root link or delegated link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    /// Signed by a trust anchor found in the KeyStore by `kid`.
    Root,
    /// Signed by `issuer_key`, whose kid must be the parent's subject.
    Delegated {
        parent: CapId,
        issuer_key: Box<VerifyingKey>,
    },
}

/// A capability body (v1), validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    kid: Kid,
    subject: String,
    resources: Vec<String>,
    rights: RightSet,
    expires_at_ms: i64,
    epoch: u64,
    link: Link,
}

const MEMBERS: [&str; 9] = [
    "v",
    "kid",
    "subject",
    "resources",
    "rights",
    "expires_at_ms",
    "epoch",
    "parent",
    "issuer_key",
];

fn member<'a>(members: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    members.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

fn need<'a>(members: &'a [(String, Value)], name: &str) -> Result<&'a Value, AuthorityError> {
    member(members, name).ok_or(AuthorityError::BadShape)
}

pub(crate) fn as_str(v: &Value) -> Result<&str, AuthorityError> {
    match v {
        Value::String(s) => Ok(s),
        _ => Err(AuthorityError::BadShape),
    }
}

/// A non-negative integer up to 2^53 - 1.
pub(crate) fn as_uint(v: &Value) -> Result<u64, AuthorityError> {
    let Value::Number(n) = v else {
        return Err(AuthorityError::BadShape);
    };
    let f = n.get();
    if !(0.0..=MAX_SAFE_INTEGER as f64).contains(&f) {
        return Err(AuthorityError::BadValue);
    }
    let u = f as u64;
    if u as f64 != f {
        return Err(AuthorityError::BadValue);
    }
    Ok(u)
}

pub(crate) fn uint_value(u: u64) -> Result<Value, AuthorityError> {
    if u > MAX_SAFE_INTEGER {
        return Err(AuthorityError::BadValue);
    }
    Number::new(u as f64)
        .map(Value::Number)
        .map_err(|_| AuthorityError::BadValue)
}

fn strictly_ascending(items: &[&str]) -> bool {
    items.windows(2).all(|w| match w {
        [a, b] => a.as_bytes() < b.as_bytes(),
        _ => true,
    })
}

impl Capability {
    /// Builds and validates a body. `resources` must already be in canonical order
    /// (strictly ascending, no duplicates); see [`crate::mint`] for the normalizing
    /// constructors.
    pub fn new(
        kid: Kid,
        subject: String,
        resources: Vec<String>,
        rights: RightSet,
        expires_at_ms: i64,
        epoch: u64,
        link: Link,
    ) -> Result<Capability, AuthorityError> {
        if subject.is_empty() || subject.len() > MAX_STR_BYTES {
            return Err(AuthorityError::BadValue);
        }
        if resources.is_empty()
            || resources.len() > MAX_RESOURCES
            || !resources.iter().all(|r| resource_is_valid(r))
        {
            return Err(AuthorityError::BadValue);
        }
        let refs: Vec<&str> = resources.iter().map(String::as_str).collect();
        if !strictly_ascending(&refs) {
            return Err(AuthorityError::BadValue);
        }
        if rights.is_empty() {
            return Err(AuthorityError::BadValue);
        }
        let exp_ok = u64::try_from(expires_at_ms).is_ok_and(|e| e <= MAX_SAFE_INTEGER);
        if !exp_ok || epoch > MAX_SAFE_INTEGER {
            return Err(AuthorityError::BadValue);
        }
        Ok(Capability {
            kid,
            subject,
            resources,
            rights,
            expires_at_ms,
            epoch,
            link,
        })
    }

    pub fn kid(&self) -> &Kid {
        &self.kid
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn resources(&self) -> &[String] {
        &self.resources
    }
    pub fn rights(&self) -> RightSet {
        self.rights
    }
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// True if some resource of this capability covers `resource`.
    pub fn covers(&self, resource: &str) -> bool {
        self.resources.iter().any(|p| covers(p, resource))
    }

    /// The body as a JSON value.
    pub fn to_value(&self) -> Result<Value, AuthorityError> {
        let mut m: Vec<(String, Value)> = Vec::with_capacity(9);
        m.push(("v".to_string(), uint_value(VERSION)?));
        m.push(("kid".to_string(), Value::String(self.kid.to_hex())));
        m.push(("subject".to_string(), Value::String(self.subject.clone())));
        m.push((
            "resources".to_string(),
            Value::Array(
                self.resources
                    .iter()
                    .map(|r| Value::String(r.clone()))
                    .collect(),
            ),
        ));
        m.push((
            "rights".to_string(),
            Value::Array(
                self.rights
                    .iter()
                    .map(|r| Value::String(r.as_str().to_string()))
                    .collect(),
            ),
        ));
        let exp = u64::try_from(self.expires_at_ms).map_err(|_| AuthorityError::BadValue)?;
        m.push(("expires_at_ms".to_string(), uint_value(exp)?));
        m.push(("epoch".to_string(), uint_value(self.epoch)?));
        if let Link::Delegated { parent, issuer_key } = &self.link {
            m.push(("parent".to_string(), Value::String(parent.to_hex())));
            m.push(("issuer_key".to_string(), Value::String(issuer_key.to_hex())));
        }
        Ok(Value::Object(m))
    }

    /// The JCS bytes of the body: what is signed and hashed.
    pub fn to_jcs(&self) -> Result<Vec<u8>, AuthorityError> {
        canon::to_jcs(&self.to_value()?).map_err(|_| AuthorityError::BadValue)
    }

    /// Strict decode of a body value.
    pub fn from_value(v: &Value) -> Result<Capability, AuthorityError> {
        let Value::Object(members) = v else {
            return Err(AuthorityError::BadShape);
        };
        if members.iter().any(|(k, _)| !MEMBERS.contains(&k.as_str())) {
            return Err(AuthorityError::BadShape);
        }
        if as_uint(need(members, "v")?).map_err(|_| AuthorityError::BadVersion)? != VERSION {
            return Err(AuthorityError::BadVersion);
        }
        let kid =
            Kid::from_hex(as_str(need(members, "kid")?)?).map_err(|_| AuthorityError::BadValue)?;
        let subject = as_str(need(members, "subject")?)?.to_string();
        let Value::Array(res) = need(members, "resources")? else {
            return Err(AuthorityError::BadShape);
        };
        let resources = res
            .iter()
            .map(|r| as_str(r).map(ToString::to_string))
            .collect::<Result<Vec<String>, _>>()?;
        let Value::Array(rts) = need(members, "rights")? else {
            return Err(AuthorityError::BadShape);
        };
        let names = rts.iter().map(as_str).collect::<Result<Vec<&str>, _>>()?;
        if names.len() > Right::ALL.len() || !strictly_ascending(&names) {
            return Err(AuthorityError::BadValue);
        }
        let mut rights = RightSet::EMPTY;
        for n in names {
            rights = rights.with(Right::from_name(n).ok_or(AuthorityError::BadValue)?);
        }
        let expires = as_uint(need(members, "expires_at_ms")?)?;
        let expires_at_ms = i64::try_from(expires).map_err(|_| AuthorityError::BadValue)?;
        let epoch = as_uint(need(members, "epoch")?)?;
        let link = match (member(members, "parent"), member(members, "issuer_key")) {
            (None, None) => Link::Root,
            (Some(p), Some(k)) => Link::Delegated {
                parent: CapId::from_hex(as_str(p)?)?,
                issuer_key: Box::new(
                    VerifyingKey::from_hex(as_str(k)?).map_err(|_| AuthorityError::BadIssuerKey)?,
                ),
            },
            _ => return Err(AuthorityError::BadShape),
        };
        Capability::new(kid, subject, resources, rights, expires_at_ms, epoch, link)
    }
}

/// A capability with its signature and computed id. Holding one says nothing about
/// validity: only [`crate::chain::verify_chain`] does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCapability {
    cap: Capability,
    body_jcs: Vec<u8>,
    sig: Signature,
    id: CapId,
}

impl SignedCapability {
    /// Signs `cap` with `key` (domain `capability`). This checks nothing about
    /// authority: a forger can call it too. The verifier decides.
    pub fn sign(cap: Capability, key: &SigningKey) -> Result<SignedCapability, AuthorityError> {
        let body_jcs = cap.to_jcs()?;
        let sig = key.sign(Domain::Capability, &body_jcs);
        Ok(SignedCapability::assemble(cap, body_jcs, sig))
    }

    /// Pairs a body with any signature (for tests and adapters; verification decides).
    pub fn with_signature(
        cap: Capability,
        sig: Signature,
    ) -> Result<SignedCapability, AuthorityError> {
        let body_jcs = cap.to_jcs()?;
        Ok(SignedCapability::assemble(cap, body_jcs, sig))
    }

    fn assemble(cap: Capability, body_jcs: Vec<u8>, sig: Signature) -> SignedCapability {
        let id = CapId::of_body(&body_jcs);
        SignedCapability {
            cap,
            body_jcs,
            sig,
            id,
        }
    }

    pub fn capability(&self) -> &Capability {
        &self.cap
    }
    pub fn id(&self) -> &CapId {
        &self.id
    }
    pub fn signature(&self) -> &Signature {
        &self.sig
    }
    pub fn body_jcs(&self) -> &[u8] {
        &self.body_jcs
    }

    /// `{"cap": <body>, "sig": "<hex>"}`.
    pub fn to_value(&self) -> Result<Value, AuthorityError> {
        Ok(Value::Object(alloc::vec![
            ("cap".to_string(), self.cap.to_value()?),
            ("sig".to_string(), Value::String(self.sig.to_hex())),
        ]))
    }

    pub fn to_jcs(&self) -> Result<Vec<u8>, AuthorityError> {
        canon::to_jcs(&self.to_value()?).map_err(|_| AuthorityError::BadValue)
    }

    /// Strict decode of `{"cap": ..., "sig": ...}`.
    pub fn from_value(v: &Value) -> Result<SignedCapability, AuthorityError> {
        let Value::Object(members) = v else {
            return Err(AuthorityError::BadShape);
        };
        if members.len() != 2 || members.iter().any(|(k, _)| k != "cap" && k != "sig") {
            return Err(AuthorityError::BadShape);
        }
        let raw = need(members, "cap")?;
        let raw_jcs = canon::to_jcs(raw).map_err(|_| AuthorityError::BadEncoding)?;
        if raw_jcs.len() > MAX_LINK_BYTES {
            return Err(AuthorityError::TooLarge);
        }
        let cap = Capability::from_value(raw)?;
        let body_jcs = cap.to_jcs()?;
        // Defense in depth: what we sign-check is exactly what was sent.
        if body_jcs != raw_jcs {
            return Err(AuthorityError::BadValue);
        }
        let sig = Signature::from_hex(as_str(need(members, "sig")?)?).map_err(|e| match e {
            sign::SignError::NonCanonicalSignature => AuthorityError::BadSignature,
            _ => AuthorityError::BadValue,
        })?;
        Ok(SignedCapability::assemble(cap, body_jcs, sig))
    }

    /// Strict decode of one link from bytes.
    pub fn parse(bytes: &[u8]) -> Result<SignedCapability, AuthorityError> {
        if bytes.len() > MAX_LINK_BYTES {
            return Err(AuthorityError::TooLarge);
        }
        let v = canon::parse_strict(bytes).map_err(|_| AuthorityError::BadEncoding)?;
        SignedCapability::from_value(&v)
    }
}

/// Strict decode of a chain value: an array of 1..=16 links, root first.
pub fn chain_from_value(v: &Value) -> Result<Vec<SignedCapability>, AuthorityError> {
    let Value::Array(items) = v else {
        return Err(AuthorityError::BadShape);
    };
    if items.is_empty() {
        return Err(AuthorityError::EmptyChain);
    }
    if items.len() > MAX_CHAIN_LEN {
        return Err(AuthorityError::ChainTooLong);
    }
    items.iter().map(SignedCapability::from_value).collect()
}

/// Strict decode of a chain from bytes.
pub fn parse_chain(bytes: &[u8]) -> Result<Vec<SignedCapability>, AuthorityError> {
    if bytes.len() > MAX_CHAIN_BYTES {
        return Err(AuthorityError::TooLarge);
    }
    let v = canon::parse_strict(bytes).map_err(|_| AuthorityError::BadEncoding)?;
    chain_from_value(&v)
}

/// JCS bytes of a chain (array of links).
pub fn chain_to_jcs(chain: &[SignedCapability]) -> Result<Vec<u8>, AuthorityError> {
    let items = chain
        .iter()
        .map(SignedCapability::to_value)
        .collect::<Result<Vec<Value>, _>>()?;
    canon::to_jcs(&Value::Array(items)).map_err(|_| AuthorityError::BadValue)
}
