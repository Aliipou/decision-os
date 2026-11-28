//! Delegation chain validation (U-CHAIN, U-ATTEN, U-EXPIRY, U-EPOCH, U-REVOKE).
//!
//! Adapted from sluicegate `tcb/dag.rs::validate_chain` and `tcb/engine.rs::verify`:
//! same signature, issuer binding (AT-5.1), resource and rights attenuation and
//! per-link epoch (AT-3.1) checks, plus the gaps closed in KNOWN_GAPS: every link's
//! expiry (SG-5), DELEGATE on every parent (SG-6), a real length bound (SG-7),
//! `verify_strict` only (SG-8), domain separation (SG-9), computed ids (SG-2) and
//! revocation and epoch from a trusted source (SG-1).
//!
//! Check order: `design/authority.md`. The first failure is returned; every failure
//! means DENY. No store is called before every signature has verified.
//!
//! Work is bounded: at most `MAX_CHAIN_LEN` links, each with at most `MAX_RESOURCES`
//! resources, so at most 16 signature checks and 15 * 64 * 64 coverage tests.

use alloc::string::String;
use alloc::vec::Vec;

use dos_core::sign::{Domain, Kid, SignError, VerifyingKey};
use dos_core::store::{KeyStore, RevocationSource};

use crate::cap::{CapId, Capability, Link, MAX_CHAIN_LEN, Right, SignedCapability, covers};
use crate::error::AuthorityError;

/// A chain that passed every check at the given time. Only [`verify_chain`] makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidChain {
    root_kid: Kid,
    ids: Vec<CapId>,
    leaf: Capability,
}

impl ValidChain {
    /// The trust anchor the chain is rooted at.
    pub fn root_kid(&self) -> &Kid {
        &self.root_kid
    }
    /// Computed ids, root first.
    pub fn ids(&self) -> &[CapId] {
        &self.ids
    }
    /// The last link: the authority the chain grants.
    pub fn leaf(&self) -> &Capability {
        &self.leaf
    }
}

fn sig_error(e: SignError) -> AuthorityError {
    match e {
        SignError::KidMismatch => AuthorityError::KidMismatch,
        _ => AuthorityError::BadSignature,
    }
}

/// `child` narrows `parent` in every dimension, and `parent` may delegate.
fn check_attenuation(parent: &Capability, child: &Capability) -> Result<(), AuthorityError> {
    if !parent.rights().contains(Right::Delegate) {
        return Err(AuthorityError::ParentLacksDelegate);
    }
    if !child.rights().is_subset(parent.rights()) {
        return Err(AuthorityError::RightsAmplified);
    }
    let covered = child
        .resources()
        .iter()
        .all(|c| parent.resources().iter().any(|p| covers(p, c)));
    if !covered {
        return Err(AuthorityError::ResourcesAmplified);
    }
    if child.expires_at_ms() > parent.expires_at_ms() {
        return Err(AuthorityError::ExpiryExtended);
    }
    if child.epoch() < parent.epoch() {
        return Err(AuthorityError::EpochLowered);
    }
    Ok(())
}

/// Validates `chain` (root first) at `now_unix_ms`.
pub fn verify_chain<K: KeyStore + ?Sized, R: RevocationSource + ?Sized>(
    chain: &[SignedCapability],
    keys: &K,
    revocations: &R,
    now_unix_ms: i64,
) -> Result<ValidChain, AuthorityError> {
    // 1. Structure.
    let Some((root, rest)) = chain.split_first() else {
        return Err(AuthorityError::EmptyChain);
    };
    if chain.len() > MAX_CHAIN_LEN {
        return Err(AuthorityError::ChainTooLong);
    }
    if !matches!(root.capability().link(), Link::Root) {
        return Err(AuthorityError::RootNotAnchored);
    }
    if rest
        .iter()
        .any(|l| matches!(l.capability().link(), Link::Root))
    {
        return Err(AuthorityError::UnexpectedRoot);
    }
    for (i, a) in chain.iter().enumerate() {
        if chain
            .iter()
            .skip(i.saturating_add(1))
            .any(|b| b.id() == a.id())
        {
            return Err(AuthorityError::Cycle);
        }
    }

    // 2. Root: trusted key by kid, strict verification.
    let root_kid = *root.capability().kid();
    let root_kid_hex = root_kid.to_hex();
    let root_bytes = keys
        .verifying_key(&root_kid_hex, now_unix_ms)
        .map_err(|_| AuthorityError::StoreUnavailable)?
        .ok_or(AuthorityError::UntrustedRoot)?;
    let root_key =
        VerifyingKey::from_bytes(&root_bytes).map_err(|_| AuthorityError::UntrustedRoot)?;
    root_key
        .verify_with_kid(
            Domain::Capability,
            root.body_jcs(),
            root.signature(),
            &root_kid,
        )
        .map_err(sig_error)?;

    // 3. Every delegated link against its parent.
    let mut prev = root;
    for link in rest {
        let cap = link.capability();
        let Link::Delegated { parent, issuer_key } = cap.link() else {
            return Err(AuthorityError::UnexpectedRoot);
        };
        if parent != prev.id() {
            return Err(AuthorityError::ParentMismatch);
        }
        if issuer_key.kid() != *cap.kid() {
            return Err(AuthorityError::KidMismatch);
        }
        if cap.kid().to_hex() != prev.capability().subject() {
            return Err(AuthorityError::IssuerNotParentSubject);
        }
        issuer_key
            .verify_with_kid(
                Domain::Capability,
                link.body_jcs(),
                link.signature(),
                cap.kid(),
            )
            .map_err(sig_error)?;
        check_attenuation(prev.capability(), cap)?;
        prev = link;
    }

    // 4. Every link is alive at `now` (refused at and after expiry).
    if chain
        .iter()
        .any(|l| now_unix_ms >= l.capability().expires_at_ms())
    {
        return Err(AuthorityError::Expired);
    }

    // 5. Every link meets the authoritative minimum epoch.
    let min_epoch = revocations
        .min_epoch(&root_kid_hex)
        .map_err(|_| AuthorityError::StoreUnavailable)?;
    if chain.iter().any(|l| l.capability().epoch() < min_epoch) {
        return Err(AuthorityError::StaleEpoch);
    }

    // 6. No link is revoked (computed ids, trusted source).
    let ids: Vec<CapId> = chain.iter().map(|l| *l.id()).collect();
    let id_hex: Vec<String> = ids.iter().map(CapId::to_hex).collect();
    if revocations
        .any_revoked(&id_hex, now_unix_ms)
        .map_err(|_| AuthorityError::StoreUnavailable)?
    {
        return Err(AuthorityError::Revoked);
    }

    Ok(ValidChain {
        root_kid,
        ids,
        leaf: prev.capability().clone(),
    })
}
