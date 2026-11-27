//! kill -9 in the middle of appends: the log is either intact or has one torn last line;
//! `repair_torn_tail` removes only that line, and the chain continues and verifies.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::time::Duration;

use dos_audit::*;
use dos_core::sign::SigningKey;
use dos_core::store::{AuditSink, KeyStore, StoreError};

const SECRET: [u8; 32] = [7u8; 32];

struct Keys(String, [u8; 32]);
impl KeyStore for Keys {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok((kid == self.0).then_some(self.1))
    }
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dos-audit-kill-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("audit.log")
}

#[test]
fn kill_child_appender() {
    // Runs only as a child of `kill_nine_mid_append_is_recoverable`: appends until killed.
    let Ok(path) = std::env::var("DOS_AUDIT_KILL_LOG") else {
        return;
    };
    let s = FileSink::open(&path, &SECRET).unwrap();
    let blob = "x".repeat(200_000);
    loop {
        if s.append(format!(r#"{{"blob":"{blob}"}}"#).as_bytes())
            .is_err()
        {
            return;
        }
    }
}

#[test]
fn kill_nine_mid_append_is_recoverable() {
    let p = tmp("kill");
    let sk = SigningKey::from_bytes(&SECRET);
    let keys = Keys(sk.kid().to_hex(), sk.verifying_key().to_bytes());
    let mut anchor = p.as_os_str().to_os_string();
    anchor.push(".anchor");
    let anchor = PathBuf::from(anchor);
    let exe = std::env::current_exe().unwrap();
    let mut torn_seen = 0;
    for round in 0..6u64 {
        let mut child = std::process::Command::new(&exe)
            .args(["kill_child_appender", "--exact", "--test-threads=1"])
            .env("DOS_AUDIT_KILL_LOG", &p)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(150 + round * 37));
        // A child that already exited (an append error) cannot be killed; recovery is checked either way.
        let _ = child.kill();
        let status = child.wait().unwrap();
        eprintln!("round {round}: child status {status:?}");

        let opts = |a| VerifyOptions {
            keys: &keys,
            now_unix_ms: 0,
            python_compat: false,
            anchor: a,
        };
        let s = FileSink::open(&p, &SECRET).unwrap();
        match verify_file(&p, &opts(None)) {
            Ok(_) => {}
            Err(e) => {
                // The only damage a kill may cause is one torn last line.
                assert_eq!(e.kind, VerifyErrorKind::PartialLine, "round {round}: {e}");
                torn_seen += 1;
                assert_eq!(s.append(b"{}"), Err(StoreError::Unavailable), "fail closed");
                assert!(s.repair_torn_tail().unwrap() > 0);
            }
        }
        // Repaired or intact: the chain verifies, and the sink continues it (the anchor may
        // be one entry behind if the kill came between the write and the anchor update).
        verify_file(&p, &opts(None)).unwrap();
        let r = s.append(br#"{"after":"kill"}"#).unwrap();
        let v = verify_file_with_anchor_file(&p, &anchor, opts(None)).unwrap();
        assert_eq!(v.head.unwrap().seq, r.seq);
    }
    eprintln!("torn tails seen: {torn_seen}");
}

#[test]
fn repair_only_touches_a_torn_last_line() {
    let p = tmp("repair");
    let s = FileSink::open(&p, &SECRET).unwrap();
    s.append(b"{}").unwrap();
    s.append(b"{}").unwrap();
    let whole = std::fs::read(&p).unwrap();
    assert_eq!(s.repair_torn_tail().unwrap(), 0, "intact log untouched");
    assert_eq!(std::fs::read(&p).unwrap(), whole);

    let mut torn = whole.clone();
    torn.extend_from_slice(b"{\"half\":");
    std::fs::write(&p, &torn).unwrap();
    assert_eq!(s.repair_torn_tail().unwrap(), 8);
    assert_eq!(std::fs::read(&p).unwrap(), whole);

    // Other damage (a complete but bad line) is not repaired: appends keep refusing.
    let mut bad = whole.clone();
    bad.extend_from_slice(b"garbage\n");
    std::fs::write(&p, &bad).unwrap();
    assert_eq!(s.repair_torn_tail().unwrap(), 0);
    assert_eq!(s.append(b"{}"), Err(StoreError::Unavailable));
}
