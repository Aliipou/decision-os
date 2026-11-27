//! Chain verifier.

use std::fmt;
use std::path::Path;

use dos_core::canon::{self, Value};
use dos_core::sign::{Domain, Kid, Signature, VerifyingKey};
use dos_core::store::KeyStore;

use crate::anchor::{Head, read_anchor_file};
use crate::entry::{GENESIS, hash_of, legacy_hash_of, seq_field, signing_bytes, str_field};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyErrorKind {
    Io,
    /// Not a strict-JSON object, or a required field is missing or mistyped.
    Malformed,
    /// Line is valid JSON but not the JCS bytes of itself.
    NonCanonical,
    /// Final line has no newline (torn write) or a blank line is present.
    PartialLine,
    /// `seq` is not the line index: reorder, insert, delete or head deletion.
    SeqMismatch,
    PrevHashMismatch,
    HashMismatch,
    MissingSignature,
    BadSignature,
    UnknownKey,
    /// The log ends before the anchored head: entries were dropped.
    Truncated,
    /// The entry at the anchored seq has a different hash: the chain was rewritten.
    AnchorMismatch,
    /// The log has entries but the anchor file does not exist.
    AnchorMissing,
    AnchorInvalid,
}

impl VerifyErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Malformed => "malformed",
            Self::NonCanonical => "non_canonical",
            Self::PartialLine => "partial_line",
            Self::SeqMismatch => "seq_mismatch",
            Self::PrevHashMismatch => "prev_hash_mismatch",
            Self::HashMismatch => "hash_mismatch",
            Self::MissingSignature => "missing_signature",
            Self::BadSignature => "bad_signature",
            Self::UnknownKey => "unknown_key",
            Self::Truncated => "truncated",
            Self::AnchorMismatch => "anchor_mismatch",
            Self::AnchorMissing => "anchor_missing",
            Self::AnchorInvalid => "anchor_invalid",
        }
    }
}

/// Why verification failed, and at which line (0-based) if it is about one line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError {
    pub line: Option<usize>,
    pub kind: VerifyErrorKind,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(l) => write!(f, "{} at line {l}", self.kind.code()),
            None => f.write_str(self.kind.code()),
        }
    }
}

impl std::error::Error for VerifyError {}

pub struct VerifyOptions<'a> {
    pub keys: &'a dyn KeyStore,
    pub now_unix_ms: i64,
    /// Accept an oracle (Python) log: unsigned entries, non-canonical lines, blank
    /// lines, Python's ASCII-escaped hash. Signatures present are still verified.
    pub python_compat: bool,
    /// Expected head retained out of band.
    pub anchor: Option<Head>,
}

/// A verified chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub entries: u64,
    /// `None` for an empty log.
    pub head: Option<Head>,
}

fn err(line: usize, kind: VerifyErrorKind) -> VerifyError {
    VerifyError {
        line: Some(line),
        kind,
    }
}

/// Verifies the chain in `path`, then the anchor if `opts.anchor` is set.
pub fn verify_file(path: &Path, opts: &VerifyOptions<'_>) -> Result<Verified, VerifyError> {
    let bytes = std::fs::read(path).map_err(|_| VerifyError {
        line: None,
        kind: VerifyErrorKind::Io,
    })?;
    verify_bytes(&bytes, opts)
}

/// Verifies the log and checks it against the signed head file at `anchor_path`
/// (`<log>.anchor` for `FileSink`). A missing anchor file on a non-empty log is an error.
pub fn verify_file_with_anchor_file(
    path: &Path,
    anchor_path: &Path,
    mut opts: VerifyOptions<'_>,
) -> Result<Verified, VerifyError> {
    let anchor = read_anchor_file(anchor_path, opts.keys, opts.now_unix_ms)?;
    opts.anchor = anchor;
    let v = verify_file(path, &opts)?;
    if opts.anchor.is_none() && v.entries > 0 {
        return Err(VerifyError {
            line: None,
            kind: VerifyErrorKind::AnchorMissing,
        });
    }
    Ok(v)
}

/// Verifies log bytes (the file contents); `verify_file` reads the file and calls this.
pub fn verify_bytes(bytes: &[u8], opts: &VerifyOptions<'_>) -> Result<Verified, VerifyError> {
    let mut prev = GENESIS.to_string();
    let mut count: usize = 0;
    let mut anchor_hit = false;
    let mut rest = bytes;
    let mut line_no = 0usize;
    while !rest.is_empty() {
        let Some(nl) = rest.iter().position(|b| *b == b'\n') else {
            return Err(err(line_no, VerifyErrorKind::PartialLine));
        };
        let line = rest.get(..nl).unwrap_or_default();
        rest = rest.get(nl + 1..).unwrap_or_default();
        let this = line_no;
        line_no += 1;
        if line.iter().all(u8::is_ascii_whitespace) {
            if opts.python_compat {
                continue;
            }
            return Err(err(this, VerifyErrorKind::PartialLine));
        }
        let hash = verify_line(line, count, &prev, opts, this)?;
        if let Some(a) = opts.anchor.as_ref().filter(|a| a.seq == count as u64) {
            if a.entry_hash != hash {
                return Err(err(this, VerifyErrorKind::AnchorMismatch));
            }
            anchor_hit = true;
        }
        prev = hash;
        count += 1;
    }
    if opts.anchor.is_some() && !anchor_hit {
        return Err(VerifyError {
            line: None,
            kind: VerifyErrorKind::Truncated,
        });
    }
    Ok(Verified {
        entries: count as u64,
        head: count.checked_sub(1).map(|s| Head {
            seq: s as u64,
            entry_hash: prev,
        }),
    })
}

fn verify_line(
    line: &[u8],
    index: usize,
    prev: &str,
    opts: &VerifyOptions<'_>,
    n: usize,
) -> Result<String, VerifyError> {
    let Ok(Value::Object(m)) = canon::parse_strict(line) else {
        return Err(err(n, VerifyErrorKind::Malformed));
    };
    if !opts.python_compat && canon::to_jcs(&Value::Object(m.clone())).as_deref() != Ok(line) {
        return Err(err(n, VerifyErrorKind::NonCanonical));
    }
    if seq_field(&m) != Some(index as u64) {
        return Err(err(n, VerifyErrorKind::SeqMismatch));
    }
    if str_field(&m, "prev_hash") != Some(prev) {
        return Err(err(n, VerifyErrorKind::PrevHashMismatch));
    }
    let stored = str_field(&m, "entry_hash").ok_or_else(|| err(n, VerifyErrorKind::Malformed))?;
    let jcs_ok = hash_of(&m).map_err(|_| err(n, VerifyErrorKind::Malformed))? == stored;
    let legacy_ok = opts.python_compat && legacy_hash_of(&m).as_deref() == Some(stored);
    if !jcs_ok && !legacy_ok {
        return Err(err(n, VerifyErrorKind::HashMismatch));
    }
    match str_field(&m, "sig") {
        None if opts.python_compat && str_field(&m, "kid").is_none() => {}
        None => return Err(err(n, VerifyErrorKind::MissingSignature)),
        Some(sig_hex) => {
            let bad = || err(n, VerifyErrorKind::BadSignature);
            let kid_hex = str_field(&m, "kid").ok_or_else(|| err(n, VerifyErrorKind::Malformed))?;
            let key = opts
                .keys
                .verifying_key(kid_hex, opts.now_unix_ms)
                .map_err(|_| err(n, VerifyErrorKind::Io))?
                .ok_or_else(|| err(n, VerifyErrorKind::UnknownKey))?;
            let key = VerifyingKey::from_bytes(&key).map_err(|_| bad())?;
            let kid = Kid::from_hex(kid_hex).map_err(|_| bad())?;
            let sig = Signature::from_hex(sig_hex).map_err(|_| bad())?;
            let payload = signing_bytes(&m).map_err(|_| bad())?;
            key.verify_with_kid(Domain::AuditHead, &payload, &sig, &kid)
                .map_err(|_| bad())?;
        }
    }
    Ok(stored.to_string())
}
