//! Attacks on dos-authority. Each one is a permanent test. Findings: `findings/authority.md`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use dos_authority::cap::{
    CapId, Capability, Link, MAX_CHAIN_BYTES, MAX_CHAIN_LEN, MAX_RESOURCES, Right, RightSet,
    SignedCapability, chain_to_jcs, parse_chain,
};
use dos_authority::mint::{delegate, issue_root};
use dos_authority::revocation::SignedRevocation;
use dos_authority::{AuthorityError as E, BuiltinPdp, Request, verify_chain};
use dos_core::canon::Value;
use dos_core::sign::{Domain, Signature};
use dos_core::verdict::Verdict;

fn root_link() -> SignedCapability {
    issue_root(&root(), &grant(&kid_of(&key(1)), &["tool:*"], &DX, FAR, 1)).unwrap()
}

// ---- forged and re-signed links ----

#[test]
fn signature_from_another_domain_refused() {
    // The root really signed these bytes, but as a decision, not a capability.
    let c = root_link();
    for d in [
        Domain::Decision,
        Domain::Revocation,
        Domain::Consent,
        Domain::AuditHead,
    ] {
        let sig = root().sign(d, c.body_jcs());
        let t = SignedCapability::with_signature(c.capability().clone(), sig).unwrap();
        assert_eq!(err(&[t]), E::BadSignature, "{d:?}");
    }
}

#[test]
fn raw_body_signature_without_domain_refused() {
    // A signature over the bare JCS bytes (oracle style, no domain prefix).
    let c = root_link();
    // Sign the payload so that signed_message(capability, x) != body: use the decision
    // domain message as the "payload" to get a signature on a different message.
    let msg = dos_core::sign::signed_message(Domain::Capability, c.body_jcs());
    let sig = root().sign(Domain::Capability, &msg);
    let t = SignedCapability::with_signature(c.capability().clone(), sig).unwrap();
    assert_eq!(err(&[t]), E::BadSignature);
}

#[test]
fn attacker_self_signed_root_refused() {
    // Attacker signs a root link with its own key and its own kid.
    let c = forge(&key(66), "agent:x", &["*"], &Right::ALL, FAR, 1, None);
    assert_eq!(err(&[c]), E::UntrustedRoot);
}

#[test]
fn swapped_issuer_key_without_its_secret_refused() {
    // Delegated link names the real parent subject's key, but is signed by the attacker.
    let p = root_link();
    let cap = Capability::new(
        key(1).kid(),
        "agent:x".into(),
        vec!["tool:send_email".into()],
        RightSet::of(&X),
        FAR,
        1,
        Link::Delegated {
            parent: *p.id(),
            issuer_key: Box::new(key(1).verifying_key()),
        },
    )
    .unwrap();
    let forged = SignedCapability::sign(cap, &key(66)).unwrap();
    assert_eq!(err(&[p, forged]), E::BadSignature);
}

#[test]
fn kid_field_not_matching_issuer_key_refused() {
    // kid names the parent's subject, issuer_key is the attacker's own key.
    let p = root_link();
    let cap = Capability::new(
        key(1).kid(),
        "agent:x".into(),
        vec!["tool:send_email".into()],
        RightSet::of(&X),
        FAR,
        1,
        Link::Delegated {
            parent: *p.id(),
            issuer_key: Box::new(key(66).verifying_key()),
        },
    )
    .unwrap();
    let forged = SignedCapability::sign(cap, &key(66)).unwrap();
    assert_eq!(err(&[p, forged]), E::KidMismatch);
}

#[test]
fn spliced_link_from_another_chain_refused() {
    // A valid child of chain A placed under the root of chain B (same holder key).
    let a = issue_root(&root(), &grant(&kid_of(&key(1)), &["tool:a"], &DX, FAR, 1)).unwrap();
    let b = issue_root(&root(), &grant(&kid_of(&key(1)), &["tool:*"], &DX, FAR, 1)).unwrap();
    let child_of_a =
        delegate(&a, &key(1), &grant("agent:x", &["tool:a"], &X, FAR, 1), NOW).unwrap();
    assert!(verify(&[a, child_of_a.clone()]).is_ok());
    assert_eq!(err(&[b, child_of_a]), E::ParentMismatch);
}

#[test]
fn truncated_chain_leaf_alone_refused() {
    let c = chain3();
    assert_eq!(err(&c[2..]), E::RootNotAnchored);
    assert_eq!(err(&c[1..2]), E::RootNotAnchored);
}

#[test]
fn compromised_delegate_cannot_amplify_itself() {
    // key(2) holds a valid execute-only, send_email-only link with delegate. It mints a
    // child to itself with every right and every resource and a later expiry.
    let c = chain3();
    let b = key(2);
    for (rs, res, exp, epoch, want) in [
        (
            Right::ALL.to_vec(),
            vec!["tool:send_email"],
            FAR,
            1,
            E::RightsAmplified,
        ),
        (DX.to_vec(), vec!["*"], FAR, 1, E::ResourcesAmplified),
        (
            DX.to_vec(),
            vec!["tool:send_email*"],
            FAR,
            1,
            E::ResourcesAmplified,
        ),
        (
            DX.to_vec(),
            vec!["tool:send_email"],
            FAR + 1,
            1,
            E::ExpiryExtended,
        ),
        (
            DX.to_vec(),
            vec!["tool:send_email"],
            FAR,
            0,
            E::EpochLowered,
        ),
    ] {
        let me = forge(&b, &kid_of(&b), &res, &rs, exp, epoch, Some(&c[1]));
        assert_eq!(err(&[c[0].clone(), c[1].clone(), me]), want);
    }
}

#[test]
fn exact_parent_does_not_cover_pattern_child() {
    let a = key(1);
    let p = issue_root(
        &root(),
        &grant(&kid_of(&a), &["tool:send_email"], &DX, FAR, 1),
    )
    .unwrap();
    let c = forge(&a, "agent:x", &["tool:send_email*"], &X, FAR, 1, Some(&p));
    assert_eq!(err(&[p.clone(), c]), E::ResourcesAmplified);
    let star = forge(&a, "agent:x", &["*"], &X, FAR, 1, Some(&p));
    assert_eq!(err(&[p, star]), E::ResourcesAmplified);
}

#[test]
fn leaf_without_delegate_cannot_extend_chain() {
    let c = chain3(); // leaf is execute only, subject "agent:x" (not a key)
    let x = key(3);
    let ext = forge(&x, "agent:z", &["tool:send_email"], &X, FAR, 1, Some(&c[2]));
    let mut chain = c.clone();
    chain.push(ext);
    // agent:x is not key(3)'s kid, and agent:x has no delegate right.
    assert_eq!(err(&chain), E::IssuerNotParentSubject);
}

#[test]
fn revocation_id_ignores_the_signature() {
    // Re-signing the same body (any second signature) keeps the id, so a revocation of
    // that id still applies. The signature is not part of the identity.
    let c = root_link();
    let other_sig = key(9).sign(Domain::Capability, c.body_jcs());
    let resigned = SignedCapability::with_signature(c.capability().clone(), other_sig).unwrap();
    assert_eq!(resigned.id(), c.id());
    // Changing anything in the body changes the id.
    let d = issue_root(&root(), &grant(&kid_of(&key(1)), &["tool:*"], &DX, FAR, 2)).unwrap();
    assert_ne!(d.id(), c.id());
}

#[test]
fn revocation_of_any_link_kills_the_chain_even_if_others_reissued() {
    // Re-issuing the leaf does not resurrect authority under a revoked middle link.
    let c = chain3();
    let fresh_leaf = delegate(
        &c[1],
        &key(2),
        &grant("agent:x", &["tool:send_email"], &X, FAR, 2),
        NOW,
    )
    .unwrap();
    let chain = [c[0].clone(), c[1].clone(), fresh_leaf];
    let r = verify_chain(
        &chain,
        &Keys::trusting(&[&root()]),
        &Revs::revoking(&[c[1].id()]),
        NOW,
    );
    assert_eq!(r.unwrap_err(), E::Revoked);
}

#[test]
fn stale_epoch_on_any_link_refuses() {
    let a = key(1);
    let b = key(2);
    let c0 = issue_root(&root(), &grant(&kid_of(&a), &["r"], &DX, FAR, 1)).unwrap();
    let c1 = delegate(&c0, &a, &grant(&kid_of(&b), &["r"], &DX, FAR, 3), NOW).unwrap();
    let c2 = delegate(&c1, &b, &grant("agent:x", &["r"], &X, FAR, 3), NOW).unwrap();
    let k = Keys::trusting(&[&root()]);
    let chain = [c0, c1, c2];
    assert!(verify_chain(&chain, &k, &Revs::min_epoch(1), NOW).is_ok());
    // Root at epoch 1 is stale at min 2, though both later links are at 3.
    assert_eq!(
        verify_chain(&chain, &k, &Revs::min_epoch(2), NOW).unwrap_err(),
        E::StaleEpoch
    );
}

#[test]
fn now_at_exact_expiry_of_a_middle_link_refuses() {
    let a = key(1);
    let b = key(2);
    let c0 = issue_root(&root(), &grant(&kid_of(&a), &["r"], &DX, FAR, 1)).unwrap();
    let c1 = delegate(&c0, &a, &grant(&kid_of(&b), &["r"], &DX, NOW + 7, 1), NOW).unwrap();
    // Leaf forged with the same expiry as the middle link (allowed: equal is not wider).
    let c2 = delegate(&c1, &b, &grant("agent:x", &["r"], &X, NOW + 7, 1), NOW).unwrap();
    let k = Keys::trusting(&[&root()]);
    let chain = [c0, c1, c2];
    assert!(verify_chain(&chain, &k, &Revs::clean(), NOW + 6).is_ok());
    assert_eq!(
        verify_chain(&chain, &k, &Revs::clean(), NOW + 7).unwrap_err(),
        E::Expired
    );
}

#[test]
fn store_is_not_consulted_before_signatures_check() {
    // A forged chain never reaches the revocation source (no oracle for probing it).
    let forged = forge(&key(66), "agent:x", &["*"], &Right::ALL, FAR, 1, None);
    let revs = Revs::clean();
    let _ = verify_chain(&[forged], &Keys::trusting(&[&root()]), &revs, NOW);
    assert_eq!(revs.revoked_calls.get(), 0);
    assert_eq!(revs.epoch_calls.get(), 0);
}

// ---- huge chains and inputs (bounded work) ----

#[test]
fn chain_with_more_than_bound_links_refused_before_link_decoding() {
    // 1000 junk elements: refused on the count, links are not decoded.
    let mut s = String::from("[");
    for i in 0..1000 {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{}");
    }
    s.push(']');
    assert_eq!(parse_chain(s.as_bytes()).unwrap_err(), E::ChainTooLong);
}

#[test]
fn oversized_chain_bytes_refused_before_parsing() {
    let big = vec![b' '; MAX_CHAIN_BYTES + 1];
    assert_eq!(parse_chain(&big).unwrap_err(), E::TooLarge);
    let big_link = vec![b' '; 32 * 1024 + 1];
    assert_eq!(SignedCapability::parse(&big_link).unwrap_err(), E::TooLarge);
}

#[test]
fn maximal_chain_verifies_within_bounds() {
    // 16 links, 64 resources of 256 bytes each: the largest valid input.
    let res: Vec<String> = (0..MAX_RESOURCES)
        .map(|i| format!("{:0>3}{}", i, "r".repeat(253)))
        .collect();
    let res_ref: Vec<&str> = res.iter().map(String::as_str).collect();
    let mut chain =
        vec![issue_root(&root(), &grant(&kid_of(&key(1)), &res_ref, &DX, FAR, 1)).unwrap()];
    for i in 1..MAX_CHAIN_LEN {
        let next = kid_of(&key(i as u8 + 1));
        let l = delegate(
            chain.last().unwrap(),
            &key(i as u8),
            &grant(&next, &res_ref, &DX, FAR, 1),
            NOW,
        )
        .unwrap();
        chain.push(l);
    }
    let bytes = chain_to_jcs(&chain).unwrap();
    assert!(bytes.len() <= MAX_CHAIN_BYTES, "{}", bytes.len());
    let parsed = parse_chain(&bytes).unwrap();
    assert_eq!(parsed, chain);
    assert!(verify(&parsed).is_ok());
}

#[test]
fn too_many_or_too_long_resources_refused() {
    let c = root_link();
    let many: Vec<String> = (0..=MAX_RESOURCES).map(|i| format!("r{i:03}")).collect();
    let mut v = link_value(&c);
    set_body(
        &mut v,
        "resources",
        Value::Array(many.iter().map(|x| s(x)).collect()),
    );
    assert_eq!(reparse(&v).unwrap_err(), E::BadValue);
    let mut v = link_value(&c);
    set_body(&mut v, "resources", arr(&[&"r".repeat(257)]));
    assert_eq!(reparse(&v).unwrap_err(), E::BadValue);
    let mut v = link_value(&c);
    set_body(&mut v, "subject", s(&"a".repeat(257)));
    assert_eq!(reparse(&v).unwrap_err(), E::BadValue);
}

// ---- malformed encodings ----

fn tamper(f: impl FnOnce(&mut Value)) -> Result<SignedCapability, E> {
    let mut v = link_value(&root_link());
    f(&mut v);
    reparse(&v)
}

type Mutation = Box<dyn FnOnce(&mut Value)>;

#[test]
fn malformed_bodies_refuse_with_stable_codes() {
    let cases: Vec<(&str, Mutation, E)> = vec![
        (
            "unknown member",
            Box::new(|v| set_body(v, "admin", Value::Bool(true))),
            E::BadShape,
        ),
        (
            "missing kid",
            Box::new(|v| remove_body(v, "kid")),
            E::BadShape,
        ),
        ("missing v", Box::new(|v| remove_body(v, "v")), E::BadShape),
        (
            "v = 2",
            Box::new(|v| set_body(v, "v", n(2.0))),
            E::BadVersion,
        ),
        (
            "v = \"1\"",
            Box::new(|v| set_body(v, "v", s("1"))),
            E::BadVersion,
        ),
        (
            "v = 0.5",
            Box::new(|v| set_body(v, "v", n(0.5))),
            E::BadVersion,
        ),
        (
            "kid uppercase",
            Box::new(|v| set_body(v, "kid", s(&kid_of(&root()).to_uppercase()))),
            E::BadValue,
        ),
        (
            "kid short",
            Box::new(|v| set_body(v, "kid", s("abcd"))),
            E::BadValue,
        ),
        (
            "subject empty",
            Box::new(|v| set_body(v, "subject", s(""))),
            E::BadValue,
        ),
        (
            "subject number",
            Box::new(|v| set_body(v, "subject", n(1.0))),
            E::BadShape,
        ),
        (
            "resources empty",
            Box::new(|v| set_body(v, "resources", arr(&[]))),
            E::BadValue,
        ),
        (
            "resources unsorted",
            Box::new(|v| set_body(v, "resources", arr(&["b", "a"]))),
            E::BadValue,
        ),
        (
            "resources duplicate",
            Box::new(|v| set_body(v, "resources", arr(&["a", "a"]))),
            E::BadValue,
        ),
        (
            "star in the middle",
            Box::new(|v| set_body(v, "resources", arr(&["tool:*x"]))),
            E::BadValue,
        ),
        (
            "two stars",
            Box::new(|v| set_body(v, "resources", arr(&["**"]))),
            E::BadValue,
        ),
        (
            "resource empty string",
            Box::new(|v| set_body(v, "resources", arr(&[""]))),
            E::BadValue,
        ),
        (
            "resources not array",
            Box::new(|v| set_body(v, "resources", s("tool:*"))),
            E::BadShape,
        ),
        (
            "rights empty",
            Box::new(|v| set_body(v, "rights", arr(&[]))),
            E::BadValue,
        ),
        (
            "rights unknown",
            Box::new(|v| set_body(v, "rights", arr(&["admin"]))),
            E::BadValue,
        ),
        (
            "rights case",
            Box::new(|v| set_body(v, "rights", arr(&["Execute"]))),
            E::BadValue,
        ),
        (
            "rights unsorted",
            Box::new(|v| set_body(v, "rights", arr(&["execute", "delegate"]))),
            E::BadValue,
        ),
        (
            "rights duplicate",
            Box::new(|v| set_body(v, "rights", arr(&["execute", "execute"]))),
            E::BadValue,
        ),
        (
            "rights 9 items",
            Box::new(|v| set_body(v, "rights", arr(&["delegate"; 9]))),
            E::BadValue,
        ),
        (
            "expiry negative",
            Box::new(|v| set_body(v, "expires_at_ms", n(-1.0))),
            E::BadValue,
        ),
        (
            "expiry fraction",
            Box::new(|v| set_body(v, "expires_at_ms", n(1.5))),
            E::BadValue,
        ),
        (
            "expiry 2^53",
            Box::new(|v| set_body(v, "expires_at_ms", n(9_007_199_254_740_992.0))),
            E::BadValue,
        ),
        (
            "expiry 1e300",
            Box::new(|v| set_body(v, "expires_at_ms", n(1e300))),
            E::BadValue,
        ),
        (
            "expiry string",
            Box::new(|v| set_body(v, "expires_at_ms", s("1"))),
            E::BadShape,
        ),
        (
            "epoch null",
            Box::new(|v| set_body(v, "epoch", Value::Null)),
            E::BadShape,
        ),
        (
            "parent without issuer_key",
            Box::new(|v| set_body(v, "parent", s(&"0".repeat(64)))),
            E::BadShape,
        ),
        (
            "issuer_key without parent",
            Box::new(|v| set_body(v, "issuer_key", s(&key(1).verifying_key().to_hex()))),
            E::BadShape,
        ),
    ];
    for (name, f, want) in cases {
        assert_eq!(tamper(f).unwrap_err(), want, "{name}");
    }
}

#[test]
fn malformed_delegated_members_refuse() {
    let c = chain3();
    let set = |name: &str, val: Value| {
        let mut v = link_value(&c[1]);
        set_body(&mut v, name, val);
        reparse(&v)
    };
    // Small-order issuer key (identity point).
    let mut ident = "01".to_string();
    ident.push_str(&"00".repeat(31));
    assert_eq!(set("issuer_key", s(&ident)).unwrap_err(), E::BadIssuerKey);
    assert_eq!(set("issuer_key", s("zz")).unwrap_err(), E::BadIssuerKey);
    assert_eq!(set("parent", s(&"A".repeat(64))).unwrap_err(), E::BadValue);
    assert_eq!(set("parent", s("00")).unwrap_err(), E::BadValue);
    assert_eq!(set("parent", Value::Null).unwrap_err(), E::BadShape);
}

#[test]
fn malformed_signatures_refuse() {
    let c = root_link();
    let with_sig = |sig: Value| {
        let mut v = link_value(&c);
        let Value::Object(top) = &mut v else { panic!() };
        for (k, slot) in top.iter_mut() {
            if k == "sig" {
                *slot = sig.clone();
            }
        }
        reparse(&v)
    };
    assert_eq!(
        with_sig(s(&c.signature().to_hex().to_uppercase())).unwrap_err(),
        E::BadValue
    );
    assert_eq!(with_sig(s("00")).unwrap_err(), E::BadValue);
    assert_eq!(with_sig(n(1.0)).unwrap_err(), E::BadShape);
    // S >= L (S = 2^256 - 1): non-canonical, refused at decode.
    let mut bad = c.signature().to_hex()[..64].to_string();
    bad.push_str(&"f".repeat(64));
    assert_eq!(with_sig(s(&bad)).unwrap_err(), E::BadSignature);
    // Valid S = R-of-something-else: decodes, then fails strict verification.
    let mut zero_r = "00".repeat(32);
    zero_r.push_str(&c.signature().to_hex()[64..]);
    let t = with_sig(s(&zero_r)).unwrap();
    assert_eq!(err(&[t]), E::BadSignature);
}

#[test]
fn malformed_wrappers_refuse() {
    let c = root_link();
    let body = String::from_utf8(c.capability().to_jcs().unwrap()).unwrap();
    let sig = c.signature().to_hex();
    let good = format!("{{\"cap\":{body},\"sig\":\"{sig}\"}}");
    assert!(SignedCapability::parse(good.as_bytes()).is_ok());
    // Whitespace and member order do not matter: the signature is over the JCS value.
    let spaced = format!("{{ \"sig\" : \"{sig}\" ,\n \"cap\" : {body} }}");
    assert_eq!(SignedCapability::parse(spaced.as_bytes()).unwrap(), c);
    for bad in [
        format!("{{\"cap\":{body},\"sig\":\"{sig}\",\"id\":\"x\"}}"),
        format!("{{\"cap\":{body}}}"),
        format!("[{{\"cap\":{body},\"sig\":\"{sig}\"}}]"),
        "\"cap\"".to_string(),
    ] {
        assert_eq!(
            SignedCapability::parse(bad.as_bytes()).unwrap_err(),
            E::BadShape,
            "{bad}"
        );
    }
    for bad in [
        format!("\u{feff}{good}"),
        format!("{good} x"),
        format!("{{\"cap\":{body},\"sig\":\"{sig}\",\"sig\":\"{sig}\"}}"),
        good.replace("\"subject\":\"", "\"subject\":\"\\ud800"),
        "[".repeat(200),
        "{\"cap\":".to_string(),
    ] {
        assert_eq!(
            SignedCapability::parse(bad.as_bytes()).unwrap_err(),
            E::BadEncoding,
            "{bad}"
        );
    }
    // Invalid UTF-8.
    let mut raw = good.clone().into_bytes();
    raw.insert(10, 0xff);
    assert_eq!(SignedCapability::parse(&raw).unwrap_err(), E::BadEncoding);
    // Duplicate member inside the body.
    let dup = good.replacen("\"epoch\":1", "\"epoch\":1,\"epoch\":1", 1);
    assert_eq!(
        SignedCapability::parse(dup.as_bytes()).unwrap_err(),
        E::BadEncoding
    );
}

#[test]
fn chain_parse_rejects_non_array_and_bad_links() {
    assert_eq!(parse_chain(b"{}").unwrap_err(), E::BadShape);
    assert_eq!(parse_chain(b"[]").unwrap_err(), E::EmptyChain);
    assert_eq!(parse_chain(b"[1]").unwrap_err(), E::BadShape);
    let ok = chain_to_jcs(&chain3()).unwrap();
    assert_eq!(parse_chain(&ok).unwrap(), chain3());
}

// ---- revocation notices ----

#[test]
fn revocation_notice_roundtrip_and_verify() {
    let target = *root_link().id();
    let n = SignedRevocation::issue(&root(), &target, NOW).unwrap();
    let bytes = n.to_jcs().unwrap();
    let parsed = SignedRevocation::parse(&bytes).unwrap();
    let got = parsed.verify(&Keys::trusting(&[&root()]), NOW).unwrap();
    assert_eq!(got.target, target);
    assert_eq!(got.revoked_at_ms, NOW);
}

#[test]
fn revocation_notice_from_non_root_refused() {
    let target = *root_link().id();
    let n = SignedRevocation::issue(&key(1), &target, NOW).unwrap();
    assert_eq!(
        n.verify(&Keys::trusting(&[&root()]), NOW).unwrap_err(),
        E::UntrustedRoot
    );
}

#[test]
fn revocation_notice_tampered_or_cross_domain_refused() {
    let target = *root_link().id();
    let n = SignedRevocation::issue(&root(), &target, NOW).unwrap();
    let json = String::from_utf8(n.to_jcs().unwrap()).unwrap();
    let other = CapId([7u8; 32]).to_hex();
    let tampered = json.replace(&target.to_hex(), &other);
    let t = SignedRevocation::parse(tampered.as_bytes()).unwrap();
    assert_eq!(
        t.verify(&Keys::trusting(&[&root()]), NOW).unwrap_err(),
        E::BadSignature
    );
    // A capability-domain signature by the root over the notice body is refused.
    // JCS order is {"notice":<body>,"sig":...}: the body sits between the first ':' and ',"sig"'.
    let body = &json[json.find(':').unwrap() + 1..json.rfind(",\"sig\"").unwrap()];
    let cap_sig: Signature = root().sign(Domain::Capability, body.as_bytes());
    let cross = format!("{{\"notice\":{body},\"sig\":\"{}\"}}", cap_sig.to_hex());
    let t = SignedRevocation::parse(cross.as_bytes()).unwrap();
    assert_eq!(
        t.verify(&Keys::trusting(&[&root()]), NOW).unwrap_err(),
        E::BadSignature
    );
    // And a revocation signature never verifies as a capability.
    let c = root_link();
    let rsig = root().sign(Domain::Revocation, c.body_jcs());
    let t = SignedCapability::with_signature(c.capability().clone(), rsig).unwrap();
    assert_eq!(err(&[t]), E::BadSignature);
}

#[test]
fn revocation_notice_malformed_refused() {
    for bad in [
        "{}".to_string(),
        "{\"notice\":{},\"sig\":\"00\"}".to_string(),
        format!(
            "{{\"notice\":{{\"v\":1,\"kid\":\"{}\",\"target\":\"{}\",\"revoked_at_ms\":-1}},\"sig\":\"00\"}}",
            kid_of(&root()),
            "0".repeat(64)
        ),
        format!(
            "{{\"notice\":{{\"v\":2,\"kid\":\"{}\",\"target\":\"{}\",\"revoked_at_ms\":1}},\"sig\":\"00\"}}",
            kid_of(&root()),
            "0".repeat(64)
        ),
        " ".repeat(5000),
    ] {
        assert!(SignedRevocation::parse(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn keystore_error_on_notice_refuses() {
    let n = SignedRevocation::issue(&root(), &CapId([1; 32]), NOW).unwrap();
    let mut k = Keys::trusting(&[&root()]);
    k.fail = true;
    assert_eq!(n.verify(&k, NOW).unwrap_err(), E::StoreUnavailable);
}

// ---- PDP-level attacks ----

#[test]
fn pdp_actor_must_be_leaf_subject_not_an_intermediate() {
    // An intermediate delegator presenting a chain whose leaf is someone else.
    let pdp = BuiltinPdp::default();
    let c = chain3();
    let r = Request {
        actor: &kid_of(&key(2)),
        resource: "tool:send_email",
        rights: RightSet::of(&X),
        tool: None,
        purpose: None,
        data_labels: &[],
    };
    let d = pdp.decide(&c, &r, &Keys::trusting(&[&root()]), &Revs::clean(), NOW);
    assert_eq!((d.verdict, d.reason), (Verdict::Deny, "actor_mismatch"));
}

#[test]
fn pdp_deny_reason_is_the_chain_code() {
    let pdp = BuiltinPdp::default();
    let forged = forge(&key(66), "agent:x", &["*"], &Right::ALL, FAR, 1, None);
    let r = Request {
        actor: "agent:x",
        resource: "tool:wire_money",
        rights: RightSet::of(&X),
        tool: None,
        purpose: None,
        data_labels: &[],
    };
    let d = pdp.decide(
        &[forged],
        &r,
        &Keys::trusting(&[&root()]),
        &Revs::clean(),
        NOW,
    );
    assert_eq!(
        (d.verdict, d.reason, d.leaf),
        (Verdict::Deny, "untrusted_root", None)
    );
}
