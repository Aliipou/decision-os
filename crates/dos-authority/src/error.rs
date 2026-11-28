//! Every refusal of this crate. `code()` strings are stable (conformance vectors,
//! audit reasons). Every variant means DENY.

use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    // ---- encoding ----
    /// Input bytes exceed the size bound for this object.
    TooLarge,
    /// Not strict I-JSON (`dos_core::canon::parse_strict` refused it).
    BadEncoding,
    /// Wrong JSON shape: not an object, a missing, unknown or mistyped member.
    BadShape,
    /// A member has the right type but a value outside its rule.
    BadValue,
    /// `v` is not 1.
    BadVersion,
    /// A delegated link's issuer key fails the strict key checks.
    BadIssuerKey,
    // ---- chain structure ----
    EmptyChain,
    ChainTooLong,
    /// Link 0 is not a root link.
    RootNotAnchored,
    /// A root link after link 0.
    UnexpectedRoot,
    /// The same capability id twice in one chain.
    Cycle,
    // ---- trust ----
    /// A KeyStore or RevocationSource call failed.
    StoreUnavailable,
    /// The root kid is not trusted at `now`, or its stored key is not a valid key.
    UntrustedRoot,
    BadSignature,
    KidMismatch,
    /// A link's `parent` is not the id of the link before it.
    ParentMismatch,
    /// A link is not issued by the parent's subject.
    IssuerNotParentSubject,
    // ---- attenuation ----
    ParentLacksDelegate,
    RightsAmplified,
    ResourcesAmplified,
    ExpiryExtended,
    EpochLowered,
    // ---- liveness ----
    Expired,
    StaleEpoch,
    Revoked,
    // ---- minting ----
    EmptyAfterAttenuation,
    WouldMintExpired,
    // ---- PDP ----
    BadRequest,
    AmbiguousCapability,
    ActorMismatch,
    ResourceNotCovered,
    RightsNotCovered,
    UnknownPurposeLabel,
    PurposeMismatch,
}

impl AuthorityError {
    pub fn code(self) -> &'static str {
        match self {
            AuthorityError::TooLarge => "too_large",
            AuthorityError::BadEncoding => "bad_encoding",
            AuthorityError::BadShape => "bad_shape",
            AuthorityError::BadValue => "bad_value",
            AuthorityError::BadVersion => "bad_version",
            AuthorityError::BadIssuerKey => "bad_issuer_key",
            AuthorityError::EmptyChain => "empty_chain",
            AuthorityError::ChainTooLong => "chain_too_long",
            AuthorityError::RootNotAnchored => "root_not_anchored",
            AuthorityError::UnexpectedRoot => "unexpected_root",
            AuthorityError::Cycle => "cycle",
            AuthorityError::StoreUnavailable => "store_unavailable",
            AuthorityError::UntrustedRoot => "untrusted_root",
            AuthorityError::BadSignature => "bad_signature",
            AuthorityError::KidMismatch => "kid_mismatch",
            AuthorityError::ParentMismatch => "parent_mismatch",
            AuthorityError::IssuerNotParentSubject => "issuer_not_parent_subject",
            AuthorityError::ParentLacksDelegate => "parent_lacks_delegate",
            AuthorityError::RightsAmplified => "rights_amplified",
            AuthorityError::ResourcesAmplified => "resources_amplified",
            AuthorityError::ExpiryExtended => "expiry_extended",
            AuthorityError::EpochLowered => "epoch_lowered",
            AuthorityError::Expired => "expired",
            AuthorityError::StaleEpoch => "stale_epoch",
            AuthorityError::Revoked => "revoked",
            AuthorityError::EmptyAfterAttenuation => "empty_after_attenuation",
            AuthorityError::WouldMintExpired => "would_mint_expired",
            AuthorityError::BadRequest => "bad_request",
            AuthorityError::AmbiguousCapability => "ambiguous_capability",
            AuthorityError::ActorMismatch => "actor_mismatch",
            AuthorityError::ResourceNotCovered => "resource_not_covered",
            AuthorityError::RightsNotCovered => "rights_not_covered",
            AuthorityError::UnknownPurposeLabel => "unknown_purpose_label",
            AuthorityError::PurposeMismatch => "purpose_mismatch",
        }
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl core::error::Error for AuthorityError {}
