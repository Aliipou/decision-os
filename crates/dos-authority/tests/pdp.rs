//! Builtin PDP. AE-1, AE-4, AE-5, AE-6 cases of `oracle/contracts-spec/conformance/suite.py`
//! reached through the authority layer, and oracle `authority_pdp.py` behavior
//! (`BuiltinAuthorityPDP.evaluate`, `canonicalize_authority_output`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use dos_authority::cap::{Right, RightSet};
use dos_authority::mint::{delegate, issue_root};
use dos_authority::pdp::{MAX_REASON_CHARS, canonicalize_external};
use dos_authority::{BuiltinPdp, Request, SignedCapability};
use dos_core::canon::{self, Value};
use dos_core::verdict::Verdict;

fn req<'a>(actor: &'a str, resource: &'a str) -> Request<'a> {
    Request {
        actor,
        resource,
        rights: RightSet::of(&X),
        tool: None,
        purpose: None,
        data_labels: &[],
    }
}

fn decide(
    pdp: &BuiltinPdp,
    chain: &[SignedCapability],
    r: &Request<'_>,
) -> (Verdict, &'static str) {
    let d = pdp.decide(chain, r, &Keys::trusting(&[&root()]), &Revs::clean(), NOW);
    (d.verdict, d.reason)
}

fn grant_x(actor: &str, tool: &str) -> Vec<SignedCapability> {
    vec![issue_root(&root(), &grant(actor, &[tool], &X, FAR, 1)).unwrap()]
}

#[test]
fn allow_with_valid_chain() {
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:x", "tool:send_email");
    let d = pdp.decide(
        &c,
        &req("agent:x", "tool:send_email"),
        &Keys::trusting(&[&root()]),
        &Revs::clean(),
        NOW,
    );
    assert_eq!(d.verdict, Verdict::Allow);
    assert_eq!(d.reason, "granted");
    assert_eq!(d.leaf, Some(*c[0].id()));
}

#[test]
fn ae1_default_deny_without_any_grant() {
    let pdp = BuiltinPdp::default();
    assert_eq!(
        decide(&pdp, &[], &req("agent:x", "tool:send_email")),
        (Verdict::Deny, "empty_chain")
    );
}

#[test]
fn ae1_grant_for_someone_else_denies() {
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:y", "tool:send_email");
    assert_eq!(
        decide(&pdp, &c, &req("agent:x", "tool:send_email")),
        (Verdict::Deny, "actor_mismatch")
    );
}

#[test]
fn ae1_ungranted_tool_denies() {
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:x", "tool:send_email");
    assert_eq!(
        decide(&pdp, &c, &req("agent:x", "tool:wire_money")),
        (Verdict::Deny, "resource_not_covered")
    );
}

#[test]
fn missing_right_denies() {
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:x", "tool:send_email");
    let mut r = req("agent:x", "tool:send_email");
    r.rights = RightSet::of(&[Right::Execute, Right::Write]);
    assert_eq!(decide(&pdp, &c, &r), (Verdict::Deny, "rights_not_covered"));
}

#[test]
fn request_without_rights_denies() {
    // An empty rights set is a vacuous subset of anything: refuse it explicitly.
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:x", "tool:send_email");
    let mut r = req("agent:x", "tool:send_email");
    r.rights = RightSet::EMPTY;
    assert_eq!(decide(&pdp, &c, &r), (Verdict::Deny, "bad_request"));
}

#[test]
fn malformed_requests_deny() {
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:x", "tool:*");
    for (actor, resource) in [
        ("", "tool:a"),
        ("agent:x", ""),
        ("agent:x", "tool:*"),
        ("agent:x", "tool:*a"),
    ] {
        assert_eq!(
            decide(&pdp, &c, &req(actor, resource)),
            (Verdict::Deny, "bad_request"),
            "{actor:?} {resource:?}"
        );
    }
    let long = "a".repeat(257);
    assert_eq!(
        decide(&pdp, &c, &req(&long, "tool:a")),
        (Verdict::Deny, "bad_request")
    );
}

#[test]
fn wildcard_grant_covers_matching_resource() {
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:x", "tool:*");
    assert_eq!(
        decide(&pdp, &c, &req("agent:x", "tool:anything")).0,
        Verdict::Allow
    );
    assert_eq!(
        decide(&pdp, &c, &req("agent:x", "file:/etc/passwd")).0,
        Verdict::Deny
    );
}

#[test]
fn ambiguous_capability_denies() {
    // Oracle: capability 'tool:a' != tool 'b' is DENY even when 'tool:a' is granted.
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:x", "tool:send_email");
    let mut r = req("agent:x", "tool:send_email");
    r.tool = Some("wire_money");
    assert_eq!(
        decide(&pdp, &c, &r),
        (Verdict::Deny, "ambiguous_capability")
    );
    r.tool = Some("send_email");
    assert_eq!(decide(&pdp, &c, &r).0, Verdict::Allow);
}

#[test]
fn ae4_delegated_authority_bounded_by_parent() {
    // suite.ae4_attenuation: grant send_email, delegate [send_email, wire_money].
    let pdp = BuiltinPdp::default();
    let p = issue_root(
        &root(),
        &grant(&kid_of(&key(1)), &["tool:send_email"], &DX, FAR, 1),
    )
    .unwrap();
    let sub = delegate(
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
    let chain = [p, sub];
    assert_eq!(
        decide(&pdp, &chain, &req("agent:sub", "tool:wire_money")).0,
        Verdict::Deny
    );
    assert_eq!(
        decide(&pdp, &chain, &req("agent:sub", "tool:send_email")).0,
        Verdict::Allow
    );
}

#[test]
fn ae5_child_refused_after_parent_expiry() {
    // suite.ae5_temporal_attenuation with a parameter clock instead of sleep.
    let pdp = BuiltinPdp::default();
    let c0 = issue_root(
        &root(),
        &grant(&kid_of(&key(1)), &["tool:send_email"], &DX, FAR, 1),
    )
    .unwrap();
    let parent_exp = NOW + 2000;
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
        &grant("agent:child", &["tool:send_email"], &X, NOW + 86_400_000, 1),
        NOW,
    )
    .unwrap();
    let chain = [c0, parent, child];
    let k = Keys::trusting(&[&root()]);
    let r = req("agent:child", "tool:send_email");
    assert_eq!(
        pdp.decide(&chain, &r, &k, &Revs::clean(), NOW).verdict,
        Verdict::Allow
    );
    let late = pdp.decide(&chain, &r, &k, &Revs::clean(), parent_exp + 100);
    assert_eq!((late.verdict, late.reason), (Verdict::Deny, "expired"));
}

#[test]
fn ae6_revoked_authority_refused() {
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:x", "tool:send_email");
    let k = Keys::trusting(&[&root()]);
    let r = req("agent:x", "tool:send_email");
    assert_eq!(
        pdp.decide(&c, &r, &k, &Revs::clean(), NOW).verdict,
        Verdict::Allow
    );
    let d = pdp.decide(&c, &r, &k, &Revs::revoking(&[c[0].id()]), NOW);
    assert_eq!((d.verdict, d.reason), (Verdict::Deny, "revoked"));
}

#[test]
fn ae6_revoking_an_ancestor_reaches_every_descendant() {
    // Divergence D5: the oracle's revoke() leaves delegated macaroons alive.
    let pdp = BuiltinPdp::default();
    let chain = chain3();
    let k = Keys::trusting(&[&root()]);
    let d = pdp.decide(
        &chain,
        &req("agent:x", "tool:send_email"),
        &k,
        &Revs::revoking(&[chain[0].id()]),
        NOW,
    );
    assert_eq!((d.verdict, d.reason), (Verdict::Deny, "revoked"));
}

#[test]
fn store_failure_denies() {
    let pdp = BuiltinPdp::default();
    let c = grant_x("agent:x", "tool:send_email");
    let mut revs = Revs::clean();
    revs.fail_revoked = true;
    let d = pdp.decide(
        &c,
        &req("agent:x", "tool:send_email"),
        &Keys::trusting(&[&root()]),
        &revs,
        NOW,
    );
    assert_eq!((d.verdict, d.reason), (Verdict::Deny, "store_unavailable"));
}

// ---- purpose bindings (oracle BuiltinAuthorityPDP) ----

fn purposes(default_deny: bool) -> BuiltinPdp {
    BuiltinPdp::new(
        vec![(
            "customer_support".to_string(),
            vec!["support_reply".to_string()],
        )],
        default_deny,
    )
}

#[test]
fn purpose_matching_binding_allows() {
    let c = grant_x("agent:x", "tool:send_email");
    let mut r = req("agent:x", "tool:send_email");
    let labels = ["customer_support"];
    r.data_labels = &labels;
    r.purpose = Some("support_reply");
    assert_eq!(decide(&purposes(true), &c, &r).0, Verdict::Allow);
}

#[test]
fn purpose_mismatch_denies() {
    let c = grant_x("agent:x", "tool:send_email");
    let mut r = req("agent:x", "tool:send_email");
    let labels = ["customer_support"];
    r.data_labels = &labels;
    r.purpose = Some("marketing");
    assert_eq!(
        decide(&purposes(false), &c, &r),
        (Verdict::Deny, "purpose_mismatch")
    );
    r.purpose = None;
    assert_eq!(
        decide(&purposes(false), &c, &r),
        (Verdict::Deny, "purpose_mismatch")
    );
}

#[test]
fn unknown_label_under_default_deny_denies() {
    let c = grant_x("agent:x", "tool:send_email");
    let mut r = req("agent:x", "tool:send_email");
    let labels = ["medical"];
    r.data_labels = &labels;
    assert_eq!(
        decide(&purposes(true), &c, &r),
        (Verdict::Deny, "unknown_purpose_label")
    );
    assert_eq!(decide(&purposes(false), &c, &r).0, Verdict::Allow);
}

#[test]
fn chain_failure_is_checked_before_purposes() {
    // Authority first: an invalid chain is never rescued or masked by purposes.
    let mut r = req("agent:x", "tool:send_email");
    let labels = ["medical"];
    r.data_labels = &labels;
    assert_eq!(
        decide(&purposes(true), &[], &r),
        (Verdict::Deny, "empty_chain")
    );
}

#[test]
fn builtin_never_returns_anything_but_allow_or_deny() {
    let pdp = BuiltinPdp::default();
    let c = chain3();
    for actor in ["agent:x", "agent:y", ""] {
        for res in ["tool:send_email", "tool:x", "*"] {
            let v = decide(&pdp, &c, &req(actor, res)).0;
            assert!(matches!(v, Verdict::Allow | Verdict::Deny));
        }
    }
}

// ---- external PDP output (oracle canonicalize_authority_output) ----

fn parse(json: &str) -> Value {
    canon::parse_strict(json.as_bytes()).unwrap()
}

#[test]
fn external_lattice_strings_map_exactly() {
    for v in Verdict::ALL {
        let out = canonicalize_external("opa", &parse(&format!("\"{}\"", v.as_str())));
        assert_eq!(out.verdict, v);
        let obj = parse(&format!(
            "{{\"verdict\":\"{}\",\"reason\":\"r\"}}",
            v.as_str()
        ));
        let out = canonicalize_external("opa", &obj);
        assert_eq!((out.verdict, out.reason.as_str()), (v, "r"));
    }
}

#[test]
fn external_malformed_or_off_lattice_fails_closed() {
    // test_malformed_or_off_lattice_provider_output_fails_closed: None, 42, {}, "ROOT",
    // {"verdict": object()}.
    for json in [
        "null",
        "42",
        "{}",
        "\"ROOT\"",
        "{\"verdict\":{}}",
        "{\"verdict\":1}",
        "\"allow\"",
        "\"ALLOW \"",
        "[\"ALLOW\"]",
        "true",
    ] {
        let out = canonicalize_external("opa", &parse(json));
        assert_eq!(out.verdict, Verdict::Deny, "{json}");
    }
    let out = canonicalize_external("opa", &parse("\"ROOT\""));
    assert!(
        out.reason
            .starts_with("unknown/malformed authority verdict (fail-closed)")
    );
}

#[test]
fn external_extra_fields_are_dropped() {
    // test_provider_field_injection_is_stripped_before_kernel_signs.
    let out = canonicalize_external(
        "opa",
        &parse(
            "{\"verdict\":\"ALLOW\",\"reason\":\"ok\",\"token_id\":\"x\",\"capability\":\"tool:wire_money\"}",
        ),
    );
    assert_eq!(out.verdict, Verdict::Allow);
    assert_eq!(out.reason, "ok");
}

#[test]
fn external_reason_is_bounded() {
    let huge = "x".repeat(10_000);
    let out = canonicalize_external(
        "opa",
        &parse(&format!("{{\"verdict\":\"DENY\",\"reason\":\"{huge}\"}}")),
    );
    assert_eq!(out.reason.chars().count(), MAX_REASON_CHARS);
    let multibyte = "\u{00e9}".repeat(5000);
    let out = canonicalize_external(
        "opa",
        &parse(&format!(
            "{{\"verdict\":\"FOO\",\"reason\":\"{multibyte}\"}}"
        )),
    );
    assert_eq!(out.verdict, Verdict::Deny);
    assert_eq!(out.reason.chars().count(), MAX_REASON_CHARS);
}

#[test]
fn external_missing_reason_gets_fallback() {
    let out = canonicalize_external("opa", &parse("\"LIMIT\""));
    assert_eq!(out.reason, "opa: limit");
}
