//! The `verify` command line shared by `dos-audit` and `decision-os audit`.
//! `dos-audit verify <log> [--anchor-file <path>] --key <pubkey-hex>... [--python-compat]`
//!
//! Exit 0: the log verifies. Exit 1: it does not (reason on stderr). Exit 2: usage.

use std::path::PathBuf;
use std::process::ExitCode;

use crate::{VerifyOptions, verify_file, verify_file_with_anchor_file};
use dos_core::sign::VerifyingKey;
use dos_core::store::{KeyStore, StoreError};

struct Keys(Vec<(String, [u8; 32])>);

impl KeyStore for Keys {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok(self.0.iter().find(|(k, _)| k == kid).map(|(_, v)| *v))
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: dos-audit verify <log> --key <ed25519-public-key-hex>... [--anchor-file <path>] [--python-compat] [--no-anchor]"
    );
    ExitCode::from(2)
}

/// Runs the `verify` command on `args` (the program name already removed).
pub fn run(mut args: impl Iterator<Item = String>) -> ExitCode {
    if args.next().as_deref() != Some("verify") {
        return usage();
    }
    let mut log: Option<PathBuf> = None;
    let mut anchor: Option<PathBuf> = None;
    let mut keys = Keys(Vec::new());
    let mut compat = false;
    let mut no_anchor = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--anchor-file" => match args.next() {
                Some(p) => anchor = Some(PathBuf::from(p)),
                None => return usage(),
            },
            "--key" => {
                let Some(hex) = args.next() else {
                    return usage();
                };
                match VerifyingKey::from_hex(&hex) {
                    Ok(k) => keys.0.push((k.kid().to_hex(), k.to_bytes())),
                    Err(e) => {
                        eprintln!("bad key: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--python-compat" => compat = true,
            "--no-anchor" => no_anchor = true,
            _ if log.is_none() && !a.starts_with("--") => log = Some(PathBuf::from(a)),
            _ => return usage(),
        }
    }
    let Some(log) = log else { return usage() };
    // `<log>.anchor` next to the log is used automatically; `--no-anchor` opts out.
    if anchor.is_none() && !no_anchor {
        let mut s = log.clone().into_os_string();
        s.push(".anchor");
        let candidate = PathBuf::from(s);
        if candidate.exists() {
            anchor = Some(candidate);
        }
    }
    let opts = VerifyOptions {
        keys: &keys,
        now_unix_ms: 0,
        python_compat: compat,
        anchor: None,
    };
    let result = match &anchor {
        Some(p) => verify_file_with_anchor_file(&log, p, opts),
        None => verify_file(&log, &opts),
    };
    if anchor.is_none() {
        eprintln!("warning: no --anchor-file: tail truncation is not checked");
    }
    match result {
        Ok(v) => {
            match v.head {
                Some(h) => println!("ok entries={} head={}:{}", v.entries, h.seq, h.entry_hash),
                None => println!("ok entries=0"),
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL {e}");
            ExitCode::from(1)
        }
    }
}
