//! Property tests (proptest). U-ATTEN: no child ever widens rights, scope, expiry or
//! lowers epoch; the verifier accepts a link exactly when it narrows. U-CORE: decoding
//! and verifying arbitrary or mutated bytes never panics, and a mutated chain never
//! verifies as something other than the original.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use dos_authority::cap::{
    Right, RightSet, SignedCapability, chain_to_jcs, covers, parse_chain, resource_is_valid,
};
use dos_authority::mint::{delegate, issue_root};
use dos_authority::{AuthorityError as E, verify_chain};
use proptest::prelude::*;

/// Resource items from a small alphabet so that coverage relations actually occur.
fn resource() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_string()),
        Just("tool:*".to_string()),
        Just("tool:a".to_string()),
        Just("tool:a*".to_string()),
        Just("tool:ab".to_string()),
        Just("tool:b".to_string()),
        Just("file:*".to_string()),
        Just("file:x".to_string()),
        "[a-c:*]{1,5}",
    ]
}

fn resources() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(resource(), 1..6)
}

fn rightset() -> impl Strategy<Value = RightSet> {
    any::<u8>().prop_map(RightSet::from_bits)
}

fn canonical(mut v: Vec<String>) -> Vec<String> {
    v.retain(|r| resource_is_valid(r));
    v.sort();
    v.dedup();
    v
}

fn subset_of(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|c| parent.iter().any(|p| covers(p, c)))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, .. ProptestConfig::default() })]

    /// Minting never widens, and every minted chain verifies.
    #[test]
    fn delegate_never_widens_and_verifies(
        p_res in resources(), p_rights in rightset(), p_exp in (NOW + 1)..FAR, p_epoch in 0u64..5,
        c_res in resources(), c_rights in rightset(), c_exp in 0i64..(2 * FAR), c_epoch in 0u64..5,
    ) {
        let p_res = canonical(p_res);
        prop_assume!(!p_res.is_empty());
        let p_rights = p_rights.with(Right::Delegate);
        let a = key(1);
        let parent = issue_root(&root(), &dos_authority::Grant {
            subject: kid_of(&a), resources: p_res.clone(), rights: p_rights,
            expires_at_ms: p_exp, epoch: p_epoch,
        }).unwrap();
        let req = dos_authority::Grant {
            subject: "agent:c".into(), resources: c_res, rights: c_rights,
            expires_at_ms: c_exp, epoch: c_epoch,
        };
        match delegate(&parent, &a, &req, NOW) {
            Ok(child) => {
                let c = child.capability();
                prop_assert!(c.rights().is_subset(p_rights));
                prop_assert!(subset_of(c.resources(), &p_res));
                prop_assert!(c.expires_at_ms() <= p_exp);
                prop_assert!(c.epoch() >= p_epoch);
                prop_assert!(verify(&[parent, child]).is_ok());
            }
            Err(e) => prop_assert!(matches!(
                e,
                E::EmptyAfterAttenuation | E::WouldMintExpired | E::BadValue
            ), "{e:?}"),
        }
    }

    /// The verifier accepts a correctly signed child exactly when it narrows.
    #[test]
    fn verifier_accepts_iff_child_narrows(
        p_res in resources(), p_rights in rightset(), p_exp in (NOW + 1)..FAR, p_epoch in 0u64..5,
        c_res in resources(), c_rights in rightset(), c_exp in (NOW + 1)..(2 * FAR), c_epoch in 0u64..5,
    ) {
        let p_res = canonical(p_res);
        let c_res = canonical(c_res);
        prop_assume!(!p_res.is_empty() && !c_res.is_empty() && !c_rights.is_empty());
        let p_rights = p_rights.with(Right::Delegate);
        let a = key(1);
        let parent = issue_root(&root(), &dos_authority::Grant {
            subject: kid_of(&a), resources: p_res.clone(), rights: p_rights,
            expires_at_ms: p_exp, epoch: p_epoch,
        }).unwrap();
        let rights_list: Vec<Right> = c_rights.iter().collect();
        let res_ref: Vec<&str> = c_res.iter().map(String::as_str).collect();
        let child = forge(&a, "agent:c", &res_ref, &rights_list, c_exp, c_epoch, Some(&parent));
        let narrows = c_rights.is_subset(p_rights)
            && subset_of(&c_res, &p_res)
            && c_exp <= p_exp
            && c_epoch >= p_epoch;
        let got = verify(&[parent, child]);
        prop_assert_eq!(got.is_ok(), narrows, "{:?}", got);
    }

    /// Transitivity along a chain: whatever verifies, the leaf is within the root.
    #[test]
    fn verified_leaf_is_within_root(
        hops in prop::collection::vec((resources(), rightset(), 0i64..FAR, 0u64..4), 1..6),
    ) {
        let mut chain = vec![issue_root(&root(), &grant(&kid_of(&key(1)), &["tool:*", "file:*"], &Right::ALL, FAR, 0)).unwrap()];
        for (i, (res, rs, exp, ep)) in hops.into_iter().enumerate() {
            let holder = key(i as u8 + 1);
            let next = kid_of(&key(i as u8 + 2));
            let g = dos_authority::Grant { subject: next, resources: res, rights: rs.with(Right::Delegate), expires_at_ms: exp, epoch: ep };
            match delegate(chain.last().unwrap(), &holder, &g, NOW) {
                Ok(l) => chain.push(l),
                Err(_) => break,
            }
        }
        let v = verify(&chain).unwrap();
        let root_cap = chain[0].capability();
        prop_assert!(v.leaf().rights().is_subset(root_cap.rights()));
        prop_assert!(subset_of(v.leaf().resources(), root_cap.resources()));
        prop_assert!(v.leaf().expires_at_ms() <= root_cap.expires_at_ms());
        for w in chain.windows(2) {
            prop_assert!(w[1].capability().epoch() >= w[0].capability().epoch());
        }
    }

    /// Coverage is transitive (the property leaf-only checking relies on).
    #[test]
    fn covers_is_transitive(a in resource(), b in resource(), c in resource()) {
        prop_assume!(resource_is_valid(&a) && resource_is_valid(&b) && resource_is_valid(&c));
        if covers(&a, &b) && covers(&b, &c) {
            prop_assert!(covers(&a, &c));
        }
        prop_assert!(covers(&a, &a));
    }

    /// Arbitrary bytes never panic in any decoder.
    #[test]
    fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_chain(&bytes);
        let _ = SignedCapability::parse(&bytes);
        let _ = dos_authority::revocation::SignedRevocation::parse(&bytes);
    }

    /// A mutated encoding of a valid chain never panics and never verifies as anything
    /// but the original chain.
    #[test]
    fn mutated_chain_never_verifies_as_something_else(
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
    ) {
        let chain = chain3();
        let original = chain_to_jcs(&chain).unwrap();
        let mut bytes = original.clone();
        for (i, b) in edits {
            let at = i.index(bytes.len());
            bytes[at] = b;
        }
        if let Ok(parsed) = parse_chain(&bytes) {
            let k = Keys::trusting(&[&root()]);
            if verify_chain(&parsed, &k, &Revs::clean(), NOW).is_ok() {
                prop_assert_eq!(chain_to_jcs(&parsed).unwrap(), original);
            }
        }
    }
}
