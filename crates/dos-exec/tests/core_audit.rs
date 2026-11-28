//! The executor's audit events land in the signed, hash-chained log, fail closed, and the
//! log verifies. (The proxy's own tests cover when it records; this covers the bridge.)
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use dos_audit::{FileSink, VerifyOptions, verify_file_with_anchor_file};
use dos_core::sign::SigningKey;
use dos_core::store::{KeyStore, StoreError};
use dos_exec::{AuditEvent, AuditSink, CoreAudit};

const SECRET: [u8; 32] = [7u8; 32];

struct Keys(String, [u8; 32]);
impl KeyStore for Keys {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok((kid == self.0).then_some(self.1))
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("dos-exec-audit-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("audit.jsonl")
}

fn ev(tool: &str, verdict: &'static str, reason: &str, executed: bool) -> AuditEvent {
    AuditEvent {
        tool: tool.into(),
        verdict,
        reason: reason.into(),
        executed,
    }
}

#[test]
fn events_are_chained_signed_and_verify_with_the_anchor() {
    let p = tmp("chain");
    let audit = CoreAudit::new(FileSink::open(&p, &SECRET).unwrap());
    audit
        .record(&ev("fs/read", "ALLOW", "policy", true))
        .unwrap();
    audit
        .record(&ev("fs/write", "DENY", "outside root", false))
        .unwrap();

    let sk = SigningKey::from_bytes(&SECRET);
    let keys = Keys(sk.kid().to_hex(), sk.verifying_key().to_bytes());
    let mut anchor = p.as_os_str().to_os_string();
    anchor.push(".anchor");
    let opts = VerifyOptions {
        keys: &keys,
        now_unix_ms: 0,
        python_compat: false,
        anchor: None,
    };
    let v = verify_file_with_anchor_file(&p, std::path::Path::new(&anchor), opts).unwrap();
    assert_eq!(v.entries, 2);

    let text = std::fs::read_to_string(&p).unwrap();
    let first = text.lines().next().unwrap();
    for needle in [
        r#""actor":"dos-exec""#,
        r#""executed":true"#,
        r#""tool":"fs/read""#,
        r#""verdict":"ALLOW""#,
        r#""payload_digest":null"#,
    ] {
        assert!(first.contains(needle), "{needle} missing in {first}");
    }
    assert!(text.lines().nth(1).unwrap().contains(r#""executed":false"#));
}

#[test]
fn a_failed_write_is_an_error_so_the_proxy_refuses() {
    let p = tmp("fail");
    let sink = FileSink::open(&p, &SECRET).unwrap();
    let audit = CoreAudit::new(sink);
    audit.record(&ev("a/b", "ALLOW", "ok", true)).unwrap();
    // Damage the log: every later append must fail, and with it the call.
    std::fs::write(&p, b"garbage without newline").unwrap();
    let r = audit.record(&ev("a/b", "ALLOW", "ok", true));
    assert!(r.is_err(), "{r:?}");
}

#[test]
fn text_the_log_refuses_does_not_stop_the_record() {
    let p = tmp("clean");
    let audit = CoreAudit::new(FileSink::open(&p, &SECRET).unwrap());
    // U+2028 would break Python's splitlines; it is replaced, not refused.
    audit
        .record(&ev(
            "srv/t\u{2028}x",
            "DENY",
            "bad\u{2029}reason\u{85}",
            false,
        ))
        .unwrap();
    let text = std::fs::read_to_string(&p).unwrap();
    assert_eq!(text.lines().count(), 1);
}
