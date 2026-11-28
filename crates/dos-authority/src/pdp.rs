//! The builtin authority PDP and the canonicalization of a foreign PDP's answer.
//!
//! Oracle: `decision_os_min/authority_pdp.py` (`BuiltinAuthorityPDP.evaluate`,
//! `canonicalize_authority_output`). The builtin PDP answers only `ALLOW` or `DENY`;
//! every path except the last one is `DENY` (U-DENY, AE-1). Its reason is a stable
//! code for the audit log: an [`AuthorityError::code`] or `"granted"`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use dos_core::canon::Value;
use dos_core::store::{KeyStore, RevocationSource};
use dos_core::verdict::{self, Verdict};

use crate::cap::{CapId, MAX_STR_BYTES, RightSet, SignedCapability};
use crate::chain::verify_chain;
use crate::error::AuthorityError;

/// Bound on a foreign PDP's reason, in characters (oracle `MAX_REASON_CHARS`).
pub const MAX_REASON_CHARS: usize = 1024;
/// Most data labels in one request.
pub const MAX_LABELS: usize = 64;

/// What the caller wants to do.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// Must equal the leaf's subject.
    pub actor: &'a str,
    /// The exact resource acted on (no `*`), e.g. `tool:send_email`.
    pub resource: &'a str,
    /// Rights needed; must be non-empty (`execute` for a tool call).
    pub rights: RightSet,
    /// Oracle `tool`: if given, `resource` must be `tool:<tool>`.
    pub tool: Option<&'a str>,
    /// Oracle `action_purpose`.
    pub purpose: Option<&'a str>,
    /// Oracle `data_labels`.
    pub data_labels: &'a [&'a str],
}

/// The builtin PDP's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityDecision {
    /// `Allow` or `Deny`, nothing else.
    pub verdict: Verdict,
    /// Stable code: `"granted"` or the refusal's [`AuthorityError::code`].
    pub reason: &'static str,
    /// The leaf id of the chain that granted, for the audit log.
    pub leaf: Option<CapId>,
}

impl AuthorityDecision {
    fn deny(e: AuthorityError) -> AuthorityDecision {
        AuthorityDecision {
            verdict: Verdict::Deny,
            reason: e.code(),
            leaf: None,
        }
    }
}

/// Capability chain plus oracle purpose bindings.
#[derive(Clone, Debug, Default)]
pub struct BuiltinPdp {
    purpose_bindings: Vec<(String, Vec<String>)>,
    default_deny: bool,
}

fn request_ok(r: &Request<'_>) -> bool {
    !r.actor.is_empty()
        && r.actor.len() <= MAX_STR_BYTES
        && !r.resource.is_empty()
        && r.resource.len() <= MAX_STR_BYTES
        && !r.resource.contains('*')
        && !r.rights.is_empty()
        && r.data_labels.len() <= MAX_LABELS
}

impl BuiltinPdp {
    /// `purpose_bindings`: data label -> allowed purposes. `default_deny`: an unbound
    /// label refuses (oracle `default_deny`).
    pub fn new(purpose_bindings: Vec<(String, Vec<String>)>, default_deny: bool) -> BuiltinPdp {
        BuiltinPdp {
            purpose_bindings,
            default_deny,
        }
    }

    fn check(&self, r: &Request<'_>, leaf: &crate::cap::Capability) -> Result<(), AuthorityError> {
        if leaf.subject() != r.actor {
            return Err(AuthorityError::ActorMismatch);
        }
        if !leaf.covers(r.resource) {
            return Err(AuthorityError::ResourceNotCovered);
        }
        if !r.rights.is_subset(leaf.rights()) {
            return Err(AuthorityError::RightsNotCovered);
        }
        for label in r.data_labels {
            match self.purpose_bindings.iter().find(|(l, _)| l == label) {
                None if self.default_deny => return Err(AuthorityError::UnknownPurposeLabel),
                None => {}
                Some((_, allowed)) => {
                    let ok = r.purpose.is_some_and(|p| allowed.iter().any(|a| a == p));
                    if !ok {
                        return Err(AuthorityError::PurposeMismatch);
                    }
                }
            }
        }
        Ok(())
    }

    /// The authority verdict for `request` under `chain` at `now_unix_ms`.
    pub fn decide<K: KeyStore + ?Sized, R: RevocationSource + ?Sized>(
        &self,
        chain: &[SignedCapability],
        request: &Request<'_>,
        keys: &K,
        revocations: &R,
        now_unix_ms: i64,
    ) -> AuthorityDecision {
        if !request_ok(request) {
            return AuthorityDecision::deny(AuthorityError::BadRequest);
        }
        if let Some(t) = request.tool
            && request.resource.strip_prefix("tool:") != Some(t)
        {
            return AuthorityDecision::deny(AuthorityError::AmbiguousCapability);
        }
        let valid = match verify_chain(chain, keys, revocations, now_unix_ms) {
            Ok(v) => v,
            Err(e) => return AuthorityDecision::deny(e),
        };
        if let Err(e) = self.check(request, valid.leaf()) {
            return AuthorityDecision::deny(e);
        }
        AuthorityDecision {
            verdict: Verdict::Allow,
            reason: "granted",
            leaf: valid.ids().last().copied(),
        }
    }
}

/// A foreign PDP's answer, reduced to a verdict and a bounded reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalAuthority {
    pub verdict: Verdict,
    pub reason: String,
}

fn bounded(s: &str) -> String {
    s.chars().take(MAX_REASON_CHARS).collect()
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Port of oracle `canonicalize_authority_output`. Only `verdict` and `reason` survive;
/// a string or `{"verdict": <string>}` goes through `verdict::parse` (fail closed);
/// any other shape is `DENY`. A missing `verdict` member is `"DENY"`, as in the
/// oracle's `output.get("verdict", DENY)`.
pub fn canonicalize_external(provider: &str, output: &Value) -> ExternalAuthority {
    let deny = Verdict::Deny.as_str();
    let (raw_verdict, raw_reason): (Option<&str>, Option<String>) = match output {
        Value::String(s) => (Some(s.as_str()), None),
        Value::Object(m) => {
            let get = |k: &str| m.iter().find(|(n, _)| n == k).map(|(_, v)| v);
            let v = match get("verdict") {
                None => Some(deny),
                Some(Value::String(s)) => Some(s.as_str()),
                Some(_) => None,
            };
            let r = match get("reason") {
                Some(Value::String(s)) => Some(s.clone()),
                _ => None,
            };
            (v, r)
        }
        other => (
            None,
            Some(alloc::format!(
                "malformed authority output: {}",
                type_name(other)
            )),
        ),
    };
    let verdict = raw_verdict.map_or(Verdict::Deny, verdict::parse);
    let fallback = || {
        let mut f = provider.to_string();
        f.push_str(": ");
        f.push_str(&verdict.as_str().to_ascii_lowercase());
        f
    };
    let mut reason = match raw_reason {
        Some(r) if !r.is_empty() => bounded(&r),
        _ => bounded(&fallback()),
    };
    if verdict == Verdict::Deny && raw_verdict != Some(deny) {
        let mut marked = String::from("unknown/malformed authority verdict (fail-closed): ");
        marked.push_str(&reason);
        reason = bounded(&marked);
    }
    ExternalAuthority { verdict, reason }
}
