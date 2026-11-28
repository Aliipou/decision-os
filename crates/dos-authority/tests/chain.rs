//! Chain validation. Ports of sluicegate `tcb/dag.rs` and `tcb/engine.rs` tests,
//! adapted to the v1 wire format, plus the SG gap closures (KNOWN_GAPS SG-1, 2, 5, 6, 7).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use dos_authority::cap::{MAX_CHAIN_LEN, Right};
use dos_authority::mint::{delegate, issue_root};
use dos_authority::{AuthorityError as E, verify_chain};

// ---- sluicegate dag.rs ----

#[test]
fn valid_root_proof_passes() {
    let c = issue_root(&root(), &grant("agent:x", &["tool:a"], &X, FAR, 1)).unwrap();
    let v = verify(std::slice::from_ref(&c)).unwrap();
    assert_eq!(v.leaf(), c.capability());
    assert_eq!(v.ids(), &[*c.id()]);
    assert_eq!(v.root_kid(), &root().kid());
}

#[test]
fn wrong_root_key_fails() {
    let c = issue_root(&root(), &grant("agent:x", &["tool:a"], &X, FAR, 1)).unwrap();
    let other = key(9);
    let r = verify_chain(&[c], &Keys::trusting(&[&other]), &Revs::clean(), NOW);
    assert_eq!(r.unwrap_err(), E::UntrustedRoot);
}

#[test]
fn root_signed_by_untrusted_key_claiming_root_kid_fails() {
    // Body names the trusted root kid, but the signature is by another key.
    let mut c = issue_root(&root(), &grant("agent:x", &["tool:a"], &X, FAR, 1)).unwrap();
    let forged_sig = key(9).sign(dos_core::sign::Domain::Capability, c.body_jcs());
    c = dos_authority::SignedCapability::with_signature(c.capability().clone(), forged_sig)
        .unwrap();
    assert_eq!(err(&[c]), E::BadSignature);
}

#[test]
fn attenuation_violation_rejected() {
    let child_key = key(1);
    let parent = issue_root(&root(), &grant(&kid_of(&child_key), &["r"], &DX, FAR, 1)).unwrap();
    let child = forge(
        &child_key,
        "agent:y",
        &["r"],
        &[Right::Execute, Right::Write],
        FAR,
        1,
        Some(&parent),
    );
    assert_eq!(err(&[parent, child]), E::RightsAmplified);
}

#[test]
fn at5_delegation_impersonation_rejected() {
    // Parent issued to key(5); attacker key(6) signs a child under it.
    let parent = issue_root(&root(), &grant(&kid_of(&key(5)), &["r"], &DX, FAR, 1)).unwrap();
    let fake = forge(&key(6), "agent:y", &["r"], &X, FAR, 1, Some(&parent));
    assert_eq!(err(&[parent, fake]), E::IssuerNotParentSubject);
}

#[test]
fn at3_1_intermediate_stale_epoch_rejected() {
    let d = key(1);
    let parent = issue_root(&root(), &grant(&kid_of(&d), &["r"], &DX, FAR, 0)).unwrap();
    let child = delegate(&parent, &d, &grant("agent:y", &["r"], &X, FAR, 5), NOW).unwrap();
    assert_eq!(child.capability().epoch(), 5);
    let r = verify_chain(
        &[parent, child],
        &Keys::trusting(&[&root()]),
        &Revs::min_epoch(5),
        NOW,
    );
    assert_eq!(r.unwrap_err(), E::StaleEpoch);
}

#[test]
fn resource_mismatch_in_delegation_rejected() {
    let d = key(1);
    let parent = issue_root(&root(), &grant(&kid_of(&d), &["R1"], &DX, FAR, 1)).unwrap();
    let child = forge(&d, "agent:y", &["R2"], &X, FAR, 1, Some(&parent));
    assert_eq!(err(&[parent, child]), E::ResourcesAmplified);
}

#[test]
fn valid_two_level_chain() {
    let d = key(1);
    let parent = issue_root(&root(), &grant(&kid_of(&d), &["r"], &DX, FAR, 1)).unwrap();
    let child = delegate(&parent, &d, &grant("agent:y", &["r"], &X, FAR, 1), NOW).unwrap();
    let v = verify(&[parent, child]).unwrap();
    assert_eq!(v.leaf().subject(), "agent:y");
}

#[test]
fn valid_three_level_chain() {
    let v = verify(&chain3()).unwrap();
    assert_eq!(v.ids().len(), 3);
    assert_eq!(v.leaf().subject(), "agent:x");
}

// ---- sluicegate engine.rs ----

#[test]
fn expired_capability_denied() {
    let c = issue_root(&root(), &grant("agent:x", &["r"], &X, 500, 1)).unwrap();
    assert_eq!(err(&[c]), E::Expired);
}

#[test]
fn stale_epoch_denied() {
    let c = issue_root(&root(), &grant("agent:x", &["r"], &X, FAR, 1)).unwrap();
    let r = verify_chain(&[c], &Keys::trusting(&[&root()]), &Revs::min_epoch(5), NOW);
    assert_eq!(r.unwrap_err(), E::StaleEpoch);
}

#[test]
fn epoch_equal_to_minimum_passes() {
    let c = issue_root(&root(), &grant("agent:x", &["r"], &X, FAR, 5)).unwrap();
    let r = verify_chain(&[c], &Keys::trusting(&[&root()]), &Revs::min_epoch(5), NOW);
    assert!(r.is_ok());
}

#[test]
fn tampered_body_denied() {
    // sluicegate tampered_ir_denied: change rights after signing.
    let c = issue_root(&root(), &grant("agent:x", &["r"], &X, FAR, 1)).unwrap();
    let mut v = link_value(&c);
    set_body(&mut v, "rights", arr(&["execute", "write"]));
    let t = reparse(&v).unwrap();
    assert_eq!(err(&[t]), E::BadSignature);
}

// ---- expiry boundaries (U-EXPIRY) ----

#[test]
fn expiry_boundary_instants() {
    let c = issue_root(&root(), &grant("agent:x", &["r"], &X, NOW, 1)).unwrap();
    let k = Keys::trusting(&[&root()]);
    assert!(verify_chain(std::slice::from_ref(&c), &k, &Revs::clean(), NOW - 1).is_ok());
    assert_eq!(
        verify_chain(std::slice::from_ref(&c), &k, &Revs::clean(), NOW).unwrap_err(),
        E::Expired
    );
    assert_eq!(
        verify_chain(&[c], &k, &Revs::clean(), NOW + 1).unwrap_err(),
        E::Expired
    );
}

#[test]
fn sg5_expired_middle_link_refused() {
    // The middle link is expired at verify time though the leaf claims no more than it.
    let a = key(1);
    let b = key(2);
    let c0 = issue_root(&root(), &grant(&kid_of(&a), &["r"], &DX, FAR, 1)).unwrap();
    let c1 = delegate(&c0, &a, &grant(&kid_of(&b), &["r"], &DX, NOW + 10, 1), NOW).unwrap();
    let c2 = delegate(&c1, &b, &grant("agent:x", &["r"], &X, NOW + 5, 1), NOW).unwrap();
    let k = Keys::trusting(&[&root()]);
    assert!(
        verify_chain(
            &[c0.clone(), c1.clone(), c2.clone()],
            &k,
            &Revs::clean(),
            NOW
        )
        .is_ok()
    );
    // The leaf dies first; the middle link's expiry also kills it later.
    assert_eq!(
        verify_chain(&[c0, c1, c2], &k, &Revs::clean(), NOW + 10).unwrap_err(),
        E::Expired
    );
}

#[test]
fn sg5_expired_root_refused() {
    let a = key(1);
    let c0 = issue_root(&root(), &grant(&kid_of(&a), &["r"], &DX, NOW + 1, 1)).unwrap();
    let c1 = delegate(&c0, &a, &grant("agent:x", &["r"], &X, NOW + 1, 1), NOW).unwrap();
    let k = Keys::trusting(&[&root()]);
    assert_eq!(
        verify_chain(&[c0, c1], &k, &Revs::clean(), NOW + 1).unwrap_err(),
        E::Expired
    );
}

#[test]
fn child_expiry_beyond_parent_refused() {
    let a = key(1);
    let c0 = issue_root(&root(), &grant(&kid_of(&a), &["r"], &DX, NOW + 100, 1)).unwrap();
    let c1 = forge(&a, "agent:x", &["r"], &X, NOW + 101, 1, Some(&c0));
    assert_eq!(err(&[c0, c1]), E::ExpiryExtended);
}

// ---- SG-6: DELEGATE required ----

#[test]
fn sg6_parent_without_delegate_right_refused() {
    let a = key(1);
    let c0 = issue_root(&root(), &grant(&kid_of(&a), &["r"], &X, FAR, 1)).unwrap();
    let c1 = forge(&a, "agent:x", &["r"], &X, FAR, 1, Some(&c0));
    assert_eq!(err(&[c0, c1]), E::ParentLacksDelegate);
}

// ---- SG-7: length bound ----

fn chain_of(len: usize) -> Vec<dos_authority::SignedCapability> {
    // root -> key(1) -> key(2) -> ... ; link i is issued to key(i+1).
    let mut out = vec![issue_root(&root(), &grant(&kid_of(&key(1)), &["r"], &DX, FAR, 1)).unwrap()];
    for i in 1..len {
        let holder = key(i as u8);
        let next = kid_of(&key(i as u8 + 1));
        let l = delegate(
            out.last().unwrap(),
            &holder,
            &grant(&next, &["r"], &DX, FAR, 1),
            NOW,
        )
        .unwrap();
        out.push(l);
    }
    out
}

#[test]
fn sg7_chain_at_bound_passes_and_bound_plus_one_refused() {
    assert_eq!(MAX_CHAIN_LEN, 16);
    assert!(verify(&chain_of(16)).is_ok());
    assert_eq!(err(&chain_of(17)), E::ChainTooLong);
}

#[test]
fn empty_chain_refused() {
    assert_eq!(err(&[]), E::EmptyChain);
}

// ---- structure ----

#[test]
fn chain_starting_with_delegated_link_refused() {
    let c = chain3();
    assert_eq!(err(&c[1..]), E::RootNotAnchored);
}

#[test]
fn second_root_in_chain_refused() {
    let c0 = issue_root(&root(), &grant("agent:x", &["r"], &DX, FAR, 1)).unwrap();
    let c1 = issue_root(&root(), &grant("agent:y", &["r"], &X, FAR, 1)).unwrap();
    assert_eq!(err(&[c0, c1]), E::UnexpectedRoot);
}

#[test]
fn reordered_chain_refused() {
    let c = chain3();
    assert_eq!(
        err(&[c[0].clone(), c[2].clone(), c[1].clone()]),
        E::ParentMismatch
    );
}

#[test]
fn skipped_middle_link_refused() {
    let c = chain3();
    assert_eq!(err(&[c[0].clone(), c[2].clone()]), E::ParentMismatch);
}

#[test]
fn duplicated_link_refused_as_cycle() {
    let c = chain3();
    assert_eq!(err(&[c[0].clone(), c[1].clone(), c[1].clone()]), E::Cycle);
}

// ---- SG-1, SG-2: revocation from the trusted source, ids computed ----

#[test]
fn sg1_revoked_leaf_middle_and_root_each_refuse() {
    let c = chain3();
    let k = Keys::trusting(&[&root()]);
    for l in &c {
        let r = verify_chain(&c, &k, &Revs::revoking(&[l.id()]), NOW);
        assert_eq!(r.unwrap_err(), E::Revoked, "revoking {}", l.id().to_hex());
    }
}

#[test]
fn sg2_ids_are_computed_from_the_body() {
    let c = chain3();
    for l in &c {
        assert_eq!(
            l.id(),
            &dos_authority::CapId::of_body(&l.capability().to_jcs().unwrap())
        );
    }
    // The wire format has no id field at all: an "id" member is refused.
    let mut v = link_value(&c[0]);
    set_body(&mut v, "id", s(&"0".repeat(64)));
    assert_eq!(reparse(&v).unwrap_err(), E::BadShape);
}

#[test]
fn revocation_source_is_asked_once_with_every_id() {
    struct Spy(std::cell::RefCell<Vec<String>>);
    impl dos_core::store::RevocationSource for Spy {
        fn any_revoked(&self, ids: &[String], _: i64) -> Result<bool, dos_core::store::StoreError> {
            self.0.borrow_mut().extend_from_slice(ids);
            Ok(false)
        }
        fn min_epoch(&self, _: &str) -> Result<u64, dos_core::store::StoreError> {
            Ok(0)
        }
    }
    let c = chain3();
    let spy = Spy(Default::default());
    verify_chain(&c, &Keys::trusting(&[&root()]), &spy, NOW).unwrap();
    let want: Vec<String> = c.iter().map(|l| l.id().to_hex()).collect();
    assert_eq!(*spy.0.borrow(), want);
}

// ---- store failures refuse (fail closed) ----

#[test]
fn keystore_error_refuses() {
    let mut k = Keys::trusting(&[&root()]);
    k.fail = true;
    let r = verify_chain(&chain3(), &k, &Revs::clean(), NOW);
    assert_eq!(r.unwrap_err(), E::StoreUnavailable);
}

#[test]
fn revocation_error_refuses() {
    let mut r = Revs::clean();
    r.fail_revoked = true;
    let out = verify_chain(&chain3(), &Keys::trusting(&[&root()]), &r, NOW);
    assert_eq!(out.unwrap_err(), E::StoreUnavailable);
}

#[test]
fn min_epoch_error_refuses() {
    let mut r = Revs::clean();
    r.fail_epoch = true;
    let out = verify_chain(&chain3(), &Keys::trusting(&[&root()]), &r, NOW);
    assert_eq!(out.unwrap_err(), E::StoreUnavailable);
}

#[test]
fn weak_key_in_keystore_refuses() {
    // A store that returns a small-order point for the root kid.
    let mut k = Keys::none();
    k.raw.push((kid_of(&root()), [0u8; 32]));
    let mut ident = [0u8; 32];
    ident[0] = 1; // identity point, small order
    k.raw.insert(0, (kid_of(&root()), ident));
    let out = verify_chain(&chain3(), &k, &Revs::clean(), NOW);
    assert_eq!(out.unwrap_err(), E::UntrustedRoot);
}

#[test]
fn keystore_returning_a_different_key_for_the_kid_refuses() {
    let mut k = Keys::none();
    k.raw
        .push((kid_of(&root()), key(7).verifying_key().to_bytes()));
    let out = verify_chain(&chain3(), &k, &Revs::clean(), NOW);
    assert_eq!(out.unwrap_err(), E::KidMismatch);
}

// ---- epoch narrowing ----

#[test]
fn child_epoch_below_parent_refused() {
    let a = key(1);
    let c0 = issue_root(&root(), &grant(&kid_of(&a), &["r"], &DX, FAR, 3)).unwrap();
    let c1 = forge(&a, "agent:x", &["r"], &X, FAR, 2, Some(&c0));
    assert_eq!(err(&[c0, c1]), E::EpochLowered);
}
