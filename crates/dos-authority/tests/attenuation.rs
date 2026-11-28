//! AE-4 / AE-5 attenuation. Ports of oracle `tests/test_attenuation.py` and
//! `tests/test_redteam_attenuation.py` (decision-os-min), adapted from HMAC macaroons
//! held in a graph (oracle) to signed chains presented by the caller (design D1, D2).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use dos_authority::cap::Right;
use dos_authority::mint::{delegate, issue_root};
use dos_authority::{AuthorityError as E, verify_chain};

/// Root grant to `principal` (key 1) on send_email only.
fn principal_chain() -> dos_authority::SignedCapability {
    issue_root(
        &root(),
        &grant(&kid_of(&key(1)), &["tool:send_email"], &DX, FAR, 1),
    )
    .unwrap()
}

#[test]
fn ae4_delegation_cannot_amplify() {
    // test_ae4_delegation_cannot_amplify: asking for more drops the extra tool.
    let p = principal_chain();
    let m = delegate(
        &p,
        &key(1),
        &grant(
            "agent:sub",
            &["tool:send_email", "tool:wire_money"],
            &X,
            FAR,
            1,
        ),
        NOW,
    )
    .unwrap();
    assert_eq!(m.capability().resources(), &["tool:send_email".to_string()]);
    let v = verify(&[p, m]).unwrap();
    assert!(v.leaf().covers("tool:send_email"));
    assert!(!v.leaf().covers("tool:wire_money"));
}

#[test]
fn ae4_delegation_rights_are_intersected() {
    let p = principal_chain();
    let m = delegate(
        &p,
        &key(1),
        &grant(
            "agent:sub",
            &["tool:send_email"],
            &[Right::Execute, Right::Write],
            FAR,
            1,
        ),
        NOW,
    )
    .unwrap();
    assert_eq!(m.capability().rights(), rights(&X));
}

#[test]
fn ae4_empty_after_attenuation_refused() {
    let p = principal_chain();
    let r = delegate(
        &p,
        &key(1),
        &grant("agent:sub", &["tool:wire_money"], &X, FAR, 1),
        NOW,
    );
    assert_eq!(r.unwrap_err(), E::EmptyAfterAttenuation);
    // Rights disjoint from the parent's: also empty.
    let r = delegate(
        &p,
        &key(1),
        &grant("agent:sub", &["tool:send_email"], &[Right::Write], FAR, 1),
        NOW,
    );
    assert_eq!(r.unwrap_err(), E::EmptyAfterAttenuation);
}

#[test]
fn ae5_child_cannot_outlive_parent() {
    // test_ae5_child_cannot_outlive_parent: clamped to the parent ceiling.
    let parent_exp = NOW + 1000;
    let c0 = issue_root(
        &root(),
        &grant(&kid_of(&key(1)), &["tool:send_email"], &DX, FAR, 1),
    )
    .unwrap();
    let parent = delegate(
        &c0,
        &key(1),
        &grant(&kid_of(&key(2)), &["tool:send_email"], &DX, parent_exp, 1),
        NOW,
    )
    .unwrap();
    let child = delegate(
        &parent,
        &key(2),
        &grant("agent:child", &["tool:send_email"], &X, NOW + 3_600_000, 1),
        NOW,
    )
    .unwrap();
    assert_eq!(child.capability().expires_at_ms(), parent_exp);
    let chain = [c0, parent, child];
    let k = Keys::trusting(&[&root()]);
    assert!(verify_chain(&chain, &k, &Revs::clean(), parent_exp - 50).is_ok());
    assert_eq!(
        verify_chain(&chain, &k, &Revs::clean(), parent_exp + 50).unwrap_err(),
        E::Expired
    );
}

#[test]
fn ae5_expired_capability_refused_by_verifier() {
    // test_ae5_expired_macaroon_refused_by_kernel: an already expired link, injected
    // without the minting rules, must not authorize.
    let past = NOW - 1000;
    let c = forge(
        &root(),
        "agent:sub",
        &["tool:send_email"],
        &X,
        past,
        1,
        None,
    );
    assert_eq!(err(&[c]), E::Expired);
}

#[test]
fn dropping_or_changing_a_member_breaks_the_signature() {
    // test_dropping_a_caveat_breaks_the_hmac_chain: here the analog is any change to
    // the signed body with the old signature. Expiry raised (dropping the time caveat).
    let c = issue_root(
        &root(),
        &grant(
            "agent:sub",
            &["tool:send_email", "tool:wire_money"],
            &X,
            NOW + 10,
            1,
        ),
    )
    .unwrap();
    let mut v = link_value(&c);
    set_body(&mut v, "expires_at_ms", n(FAR as f64));
    assert_eq!(err(&[reparse(&v).unwrap()]), E::BadSignature);
    // Dropping a resource with the stale signature also fails.
    let mut v = link_value(&c);
    set_body(&mut v, "resources", arr(&["tool:send_email"]));
    assert_eq!(err(&[reparse(&v).unwrap()]), E::BadSignature);
    // Dropping a required member is a shape error.
    let mut v = link_value(&c);
    remove_body(&mut v, "expires_at_ms");
    assert_eq!(reparse(&v).unwrap_err(), E::BadShape);
}

#[test]
fn fixed_append_cannot_amplify_tools() {
    // test_fixed_hmac_append_cannot_amplify_tools. A holder without the root key widens
    // its own link's resources and re-signs with its own key: the root signature fails.
    let c = issue_root(
        &root(),
        &grant("agent:sub", &["tool:send_email"], &X, FAR, 1),
    )
    .unwrap();
    let mut v = link_value(&c);
    set_body(
        &mut v,
        "resources",
        arr(&["tool:send_email", "tool:wire_money"]),
    );
    assert_eq!(err(&[reparse(&v).unwrap()]), E::BadSignature);
    // Appending a child link that widens is refused by attenuation.
    let a = key(1);
    let p = issue_root(
        &root(),
        &grant(&kid_of(&a), &["tool:send_email"], &DX, FAR, 1),
    )
    .unwrap();
    let wide = forge(
        &a,
        "agent:sub",
        &["tool:send_email", "tool:wire_money"],
        &X,
        FAR,
        1,
        Some(&p),
    );
    assert_eq!(err(&[p, wide]), E::ResourcesAmplified);
}

#[test]
fn fixed_append_cannot_delegate_amplified_tool() {
    // test_fixed_hmac_append_cannot_delegate_amplified_tool: transitive AE-4.
    let a = key(1);
    let b = key(2);
    let p = issue_root(
        &root(),
        &grant(&kid_of(&a), &["tool:send_email"], &DX, FAR, 1),
    )
    .unwrap();
    let mid = forge(
        &a,
        &kid_of(&b),
        &["tool:send_email", "tool:wire_money"],
        &DX,
        FAR,
        1,
        Some(&p),
    );
    // Minting from the widened link only yields what the (forged) parent claims...
    let leaf = delegate(
        &mid,
        &b,
        &grant("agent:child", &["tool:wire_money"], &X, FAR, 1),
        NOW,
    )
    .unwrap();
    // ...and the verifier refuses the whole chain at the widened link.
    assert_eq!(err(&[p, mid, leaf]), E::ResourcesAmplified);
}

#[test]
fn fixed_capability_cannot_be_rebound_to_another_holder() {
    // test_fixed_macaroon_cannot_be_rebound_to_another_holder: subject is signed.
    let c = issue_root(
        &root(),
        &grant("agent:good", &["tool:send_email"], &X, FAR, 1),
    )
    .unwrap();
    let mut v = link_value(&c);
    set_body(&mut v, "subject", s("agent:evil"));
    assert_eq!(err(&[reparse(&v).unwrap()]), E::BadSignature);
}

#[test]
fn fixed_ae5_expired_parent_cannot_delegate() {
    let a = key(1);
    let p = forge(
        &root(),
        &kid_of(&a),
        &["tool:send_email"],
        &DX,
        NOW - 5000,
        1,
        None,
    );
    let r = delegate(
        &p,
        &a,
        &grant("agent:child", &["tool:send_email"], &X, FAR, 1),
        NOW,
    );
    assert_eq!(r.unwrap_err(), E::Expired);
    // A child forged under it anyway is refused by the verifier.
    let child = forge(
        &a,
        "agent:child",
        &["tool:send_email"],
        &X,
        NOW - 5000,
        1,
        Some(&p),
    );
    assert_eq!(err(&[p, child]), E::Expired);
}

#[test]
fn minting_already_expired_authority_refused() {
    let p = principal_chain();
    let r = delegate(
        &p,
        &key(1),
        &grant("agent:sub", &["tool:send_email"], &X, NOW, 1),
        NOW,
    );
    assert_eq!(r.unwrap_err(), E::WouldMintExpired);
}

#[test]
fn delegate_requires_parent_delegate_right() {
    let p = issue_root(&root(), &grant(&kid_of(&key(1)), &["r"], &X, FAR, 1)).unwrap();
    let r = delegate(&p, &key(1), &grant("agent:sub", &["r"], &X, FAR, 1), NOW);
    assert_eq!(r.unwrap_err(), E::ParentLacksDelegate);
}

#[test]
fn delegate_requires_holder_to_be_parent_subject() {
    let p = principal_chain();
    let r = delegate(
        &p,
        &key(2),
        &grant("agent:sub", &["tool:send_email"], &X, FAR, 1),
        NOW,
    );
    assert_eq!(r.unwrap_err(), E::IssuerNotParentSubject);
}

#[test]
fn delegate_raises_epoch_to_parent() {
    let p = issue_root(&root(), &grant(&kid_of(&key(1)), &["r"], &DX, FAR, 7)).unwrap();
    let c = delegate(&p, &key(1), &grant("agent:sub", &["r"], &X, FAR, 2), NOW).unwrap();
    assert_eq!(c.capability().epoch(), 7);
}

#[test]
fn pattern_resources_narrow_only() {
    // A wildcard parent may delegate a narrower pattern or an exact item, never wider.
    let a = key(1);
    let p = issue_root(&root(), &grant(&kid_of(&a), &["tool:send*"], &DX, FAR, 1)).unwrap();
    let narrow = delegate(
        &p,
        &a,
        &grant(
            "agent:sub",
            &["tool:send_email", "tool:send_sms*", "tool:*"],
            &X,
            FAR,
            1,
        ),
        NOW,
    )
    .unwrap();
    assert_eq!(
        narrow.capability().resources(),
        &["tool:send_email".to_string(), "tool:send_sms*".to_string()]
    );
    assert!(verify(&[p.clone(), narrow]).is_ok());
    let wide = forge(&a, "agent:sub", &["tool:*"], &X, FAR, 1, Some(&p));
    assert_eq!(err(&[p, wide]), E::ResourcesAmplified);
}

#[test]
fn separate_credentials_stay_separate() {
    // Oracle test_fixed_ae4_parent_union_of_credentials_not_intersection and
    // test_fixed_ae5_root_tools_not_clamped_by_unrelated_macaroon_expiry. In the chain
    // model a holder presents one chain per request, so two credentials never mix:
    // delegating from one is clamped only by that one.
    let p = key(1);
    let long = issue_root(
        &root(),
        &grant(&kid_of(&p), &["tool:send_email"], &DX, FAR, 1),
    )
    .unwrap();
    let short = issue_root(
        &root(),
        &grant(&kid_of(&p), &["tool:wire_money"], &DX, NOW + 300, 1),
    )
    .unwrap();
    let c1 = delegate(
        &long,
        &p,
        &grant("agent:c", &["tool:send_email"], &X, FAR, 1),
        NOW,
    )
    .unwrap();
    assert_eq!(c1.capability().expires_at_ms(), FAR);
    let c2 = delegate(
        &short,
        &p,
        &grant("agent:c", &["tool:wire_money"], &X, FAR, 1),
        NOW,
    )
    .unwrap();
    assert_eq!(c2.capability().expires_at_ms(), NOW + 300);
    assert!(verify(&[long.clone(), c1]).is_ok());
    assert!(verify(&[short.clone(), c2.clone()]).is_ok());
    // Splicing the short credential's child under the long one is refused.
    assert_eq!(err(&[long, c2]), E::ParentMismatch);
}
