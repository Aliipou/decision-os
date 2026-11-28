//! Root-signed revocation notices (domain `revocation`).
//!
//! The PDP never reads revocations from a request (SG-1): it asks a trusted
//! `RevocationSource`. A notice is how such a source can accept a revocation over an
//! untrusted transport: it verifies the notice here, then records `target`.
//!
//! Body: `{"v":1,"kid":<root kid>,"target":<capability id>,"revoked_at_ms":<int>}`.
//! Signed: `{"notice": <body>, "sig": "<hex>"}`.

use alloc::string::ToString;
use alloc::vec::Vec;

use dos_core::canon::{self, Value};
use dos_core::sign::{Domain, Kid, Signature, SigningKey, VerifyingKey};
use dos_core::store::KeyStore;

use crate::cap::{CapId, MAX_SAFE_INTEGER, VERSION, as_str, as_uint, uint_value};
use crate::error::AuthorityError;

/// Largest accepted encoding of a signed notice.
pub const MAX_NOTICE_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationNotice {
    pub kid: Kid,
    pub target: CapId,
    pub revoked_at_ms: i64,
}

impl RevocationNotice {
    fn to_value(&self) -> Result<Value, AuthorityError> {
        let at = u64::try_from(self.revoked_at_ms).map_err(|_| AuthorityError::BadValue)?;
        Ok(Value::Object(alloc::vec![
            ("v".to_string(), uint_value(VERSION)?),
            ("kid".to_string(), Value::String(self.kid.to_hex())),
            ("target".to_string(), Value::String(self.target.to_hex())),
            ("revoked_at_ms".to_string(), uint_value(at)?),
        ]))
    }

    fn from_value(v: &Value) -> Result<RevocationNotice, AuthorityError> {
        let Value::Object(m) = v else {
            return Err(AuthorityError::BadShape);
        };
        let known = ["v", "kid", "target", "revoked_at_ms"];
        if m.len() != known.len() || m.iter().any(|(k, _)| !known.contains(&k.as_str())) {
            return Err(AuthorityError::BadShape);
        }
        let get = |name: &str| {
            m.iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v)
                .ok_or(AuthorityError::BadShape)
        };
        if as_uint(get("v")?).map_err(|_| AuthorityError::BadVersion)? != VERSION {
            return Err(AuthorityError::BadVersion);
        }
        let kid = Kid::from_hex(as_str(get("kid")?)?).map_err(|_| AuthorityError::BadValue)?;
        let target = CapId::from_hex(as_str(get("target")?)?)?;
        let at = as_uint(get("revoked_at_ms")?)?;
        if at > MAX_SAFE_INTEGER {
            return Err(AuthorityError::BadValue);
        }
        let revoked_at_ms = i64::try_from(at).map_err(|_| AuthorityError::BadValue)?;
        Ok(RevocationNotice {
            kid,
            target,
            revoked_at_ms,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRevocation {
    notice: RevocationNotice,
    body_jcs: Vec<u8>,
    sig: Signature,
}

impl SignedRevocation {
    /// A notice revoking `target`, signed by `root`.
    pub fn issue(
        root: &SigningKey,
        target: &CapId,
        revoked_at_ms: i64,
    ) -> Result<SignedRevocation, AuthorityError> {
        let notice = RevocationNotice {
            kid: root.kid(),
            target: *target,
            revoked_at_ms,
        };
        let body_jcs = canon::to_jcs(&notice.to_value()?).map_err(|_| AuthorityError::BadValue)?;
        let sig = root.sign(Domain::Revocation, &body_jcs);
        Ok(SignedRevocation {
            notice,
            body_jcs,
            sig,
        })
    }

    pub fn notice(&self) -> &RevocationNotice {
        &self.notice
    }

    pub fn to_jcs(&self) -> Result<Vec<u8>, AuthorityError> {
        let v = Value::Object(alloc::vec![
            ("notice".to_string(), self.notice.to_value()?),
            ("sig".to_string(), Value::String(self.sig.to_hex())),
        ]);
        canon::to_jcs(&v).map_err(|_| AuthorityError::BadValue)
    }

    /// Strict decode. Verification is a separate step ([`SignedRevocation::verify`]).
    pub fn parse(bytes: &[u8]) -> Result<SignedRevocation, AuthorityError> {
        if bytes.len() > MAX_NOTICE_BYTES {
            return Err(AuthorityError::TooLarge);
        }
        let v = canon::parse_strict(bytes).map_err(|_| AuthorityError::BadEncoding)?;
        let Value::Object(m) = &v else {
            return Err(AuthorityError::BadShape);
        };
        if m.len() != 2 || m.iter().any(|(k, _)| k != "notice" && k != "sig") {
            return Err(AuthorityError::BadShape);
        }
        let raw = m
            .iter()
            .find(|(k, _)| k == "notice")
            .map(|(_, v)| v)
            .ok_or(AuthorityError::BadShape)?;
        let sig_v = m
            .iter()
            .find(|(k, _)| k == "sig")
            .map(|(_, v)| v)
            .ok_or(AuthorityError::BadShape)?;
        let notice = RevocationNotice::from_value(raw)?;
        let body_jcs = canon::to_jcs(&notice.to_value()?).map_err(|_| AuthorityError::BadValue)?;
        let raw_jcs = canon::to_jcs(raw).map_err(|_| AuthorityError::BadEncoding)?;
        if body_jcs != raw_jcs {
            return Err(AuthorityError::BadValue);
        }
        let sig = Signature::from_hex(as_str(sig_v)?).map_err(|_| AuthorityError::BadSignature)?;
        Ok(SignedRevocation {
            notice,
            body_jcs,
            sig,
        })
    }

    /// Strict verification against a trusted root key (by `kid`) at `now_unix_ms`.
    /// Only a trust anchor may revoke. Every failure refuses.
    pub fn verify<K: KeyStore + ?Sized>(
        &self,
        keys: &K,
        now_unix_ms: i64,
    ) -> Result<&RevocationNotice, AuthorityError> {
        let kid = self.notice.kid.to_hex();
        let bytes = keys
            .verifying_key(&kid, now_unix_ms)
            .map_err(|_| AuthorityError::StoreUnavailable)?
            .ok_or(AuthorityError::UntrustedRoot)?;
        let vk = VerifyingKey::from_bytes(&bytes).map_err(|_| AuthorityError::UntrustedRoot)?;
        vk.verify_with_kid(
            Domain::Revocation,
            &self.body_jcs,
            &self.sig,
            &self.notice.kid,
        )
        .map_err(|e| match e {
            dos_core::sign::SignError::KidMismatch => AuthorityError::KidMismatch,
            _ => AuthorityError::BadSignature,
        })?;
        Ok(&self.notice)
    }
}
