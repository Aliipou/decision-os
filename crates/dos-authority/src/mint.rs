//! Minting: root grants and attenuated delegation.
//!
//! `delegate` follows the oracle's clamping (`attenuation.py::AuthorityGraph.delegate`):
//! the result is the intersection of what was asked and what the parent holds, with
//! the expiry clamped to the parent's. It refuses where the oracle raises
//! `AttenuationError`. The verifier never trusts these functions: it re-checks every
//! rule in `chain::verify_chain`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use dos_core::sign::SigningKey;

use crate::cap::{Capability, Link, Right, RightSet, SignedCapability};
use crate::error::AuthorityError;

/// What a minting call asks for. Resources may be in any order; they are sorted and
/// deduplicated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub subject: String,
    pub resources: Vec<String>,
    pub rights: RightSet,
    pub expires_at_ms: i64,
    pub epoch: u64,
}

fn canonical_resources(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = items.to_vec();
    out.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    out.dedup();
    out
}

/// A root capability signed by the trust anchor `root`.
pub fn issue_root(root: &SigningKey, grant: &Grant) -> Result<SignedCapability, AuthorityError> {
    let cap = Capability::new(
        root.kid(),
        grant.subject.clone(),
        canonical_resources(&grant.resources),
        grant.rights,
        grant.expires_at_ms,
        grant.epoch,
        Link::Root,
    )?;
    SignedCapability::sign(cap, root)
}

/// Mints a child of `parent`, signed by `holder` (the parent's subject key), granting
/// what `grant` asks for narrowed to what `parent` holds. `grant.subject` is the child.
pub fn delegate(
    parent: &SignedCapability,
    holder: &SigningKey,
    grant: &Grant,
    now_unix_ms: i64,
) -> Result<SignedCapability, AuthorityError> {
    let p = parent.capability();
    if now_unix_ms >= p.expires_at_ms() {
        return Err(AuthorityError::Expired);
    }
    if !p.rights().contains(Right::Delegate) {
        return Err(AuthorityError::ParentLacksDelegate);
    }
    if holder.kid().to_hex() != p.subject() {
        return Err(AuthorityError::IssuerNotParentSubject);
    }
    let rights = grant.rights.intersect(p.rights());
    let covered: Vec<String> = grant
        .resources
        .iter()
        .filter(|c| p.covers(c))
        .cloned()
        .collect();
    let resources = canonical_resources(&covered);
    if rights.is_empty() || resources.is_empty() {
        return Err(AuthorityError::EmptyAfterAttenuation);
    }
    let expires_at_ms = grant.expires_at_ms.min(p.expires_at_ms());
    if now_unix_ms >= expires_at_ms {
        return Err(AuthorityError::WouldMintExpired);
    }
    let epoch = grant.epoch.max(p.epoch());
    let cap = Capability::new(
        holder.kid(),
        grant.subject.clone(),
        resources,
        rights,
        expires_at_ms,
        epoch,
        Link::Delegated {
            parent: *parent.id(),
            issuer_key: Box::new(holder.verifying_key()),
        },
    )?;
    SignedCapability::sign(cap, holder)
}
