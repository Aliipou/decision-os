//! Red team 2 (findings/audit-redteam2.md). A failing test here is a finding; keep it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dos_audit::*;
use dos_core::canon::{self, Number, Value};
use dos_core::sign::{Domain, SigningKey, hex_encode};
use dos_core::store::{AuditSink, KeyStore, StoreError};
use sha2::{Digest, Sha256};

const SECRET: [u8; 32] = [0x5au8; 32];

struct Keys(Vec<(String, [u8; 32])>);
impl KeyStore for Keys {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok(self.0.iter().find(|(k, _)| k == kid).map(|(_, v)| *v))
    }
}

fn keys() -> Keys {
    let sk = SigningKey::from_bytes(&SECRET);
    Keys(vec![(sk.kid().to_hex(), sk.verifying_key().to_bytes())])
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dos-audit-rt2-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("audit.jsonl")
}

fn suffixed(p: &Path, s: &str) -> PathBuf {
    let mut o = p.as_os_str().to_os_string();
    o.push(s);
    PathBuf::from(o)
}

fn anchor_of(p: &Path) -> PathBuf {
    suffixed(p, ".anchor")
}

fn opts(k: &Keys, compat: bool, anchor: Option<Head>) -> VerifyOptions<'_> {
    VerifyOptions {
        keys: k,
        now_unix_ms: 0,
        python_compat: compat,
        anchor,
    }
}

fn fill(path: &Path, n: usize) -> FileSink {
    let sink = FileSink::open(path, &SECRET).unwrap();
    for i in 0..n {
        let e = format!(r#"{{"actor":"a","tool":"t{i}","verdict":"ALLOW"}}"#);
        sink.append(e.as_bytes()).unwrap();
    }
    sink
}

fn anchored_verify(p: &Path, compat: bool) -> Result<Verified, VerifyError> {
    let k = keys();
    verify_file_with_anchor_file(p, &anchor_of(p), opts(&k, compat, None))
}

/// Keeps the first `n` lines of the log (byte-exact).
fn keep_lines(p: &Path, n: usize) {
    let b = std::fs::read(p).unwrap();
    let mut out = Vec::new();
    for l in b.split_inclusive(|c| *c == b'\n').take(n) {
        out.extend_from_slice(l);
    }
    std::fs::write(p, out).unwrap();
}

fn last_hash(p: &Path) -> String {
    let b = std::fs::read(p).unwrap();
    let s = String::from_utf8(b).unwrap();
    let last = s.lines().last().unwrap();
    let v: serde_json::Value = serde_json::from_str(last).unwrap();
    v["entry_hash"].as_str().unwrap().to_string()
}

fn num(n: f64) -> Value {
    Value::Number(Number::new(n).unwrap())
}

fn s(v: &str) -> Value {
    Value::String(v.into())
}

/// Builds a log line by the documented rule; `sk = None` leaves it unsigned.
fn make_line(sk: Option<&SigningKey>, seq: f64, prev: &str, content: &[(&str, Value)]) -> Vec<u8> {
    let mut m: Vec<(String, Value)> = content
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    m.push(("seq".into(), num(seq)));
    m.push(("prev_hash".into(), s(prev)));
    if let Some(sk) = sk {
        m.push(("kid".into(), s(&sk.kid().to_hex())));
        let payload = canon::to_jcs(&Value::Object(m.clone())).unwrap();
        let sig = sk.sign(Domain::AuditHead, &payload);
        m.push(("sig".into(), s(&hex_encode(&sig.to_bytes()))));
    }
    let h = hex_encode(&Sha256::digest(
        canon::to_jcs(&Value::Object(m.clone())).unwrap(),
    ));
    m.push(("entry_hash".into(), s(&h)));
    let mut line = canon::to_jcs(&Value::Object(m)).unwrap();
    line.push(b'\n');
    line
}

fn append_raw(p: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
    f.write_all(bytes).unwrap();
}

// ---------------------------------------------------------------- truncation / rollback

#[test]
fn h01_truncate_tail_then_one_append_verifies_with_anchor() {
    let p = tmp("h01");
    let s = fill(&p, 5);
    assert!(anchored_verify(&p, false).is_ok());
    keep_lines(&p, 2); // attacker drops entries 2..4
    assert_eq!(
        anchored_verify(&p, false).unwrap_err().kind,
        VerifyErrorKind::Truncated
    );
    // The next legitimate append must refuse (on-disk head older than the anchor),
    // or at least the result must not verify.
    let r = s.append(br#"{"tool":"next"}"#);
    let v = anchored_verify(&p, false);
    assert!(
        r.is_err() || v.is_err(),
        "dropped 3 entries; after one append the log verifies with its anchor: {r:?} {v:?}"
    );
}

#[test]
fn h01b_truncate_tail_then_reopen_and_append_verifies_with_anchor() {
    // Same, across a restart (new FileSink): nothing remembers the old head.
    let p = tmp("h01b");
    drop(fill(&p, 4));
    keep_lines(&p, 1);
    let s = FileSink::open(&p, &SECRET).unwrap();
    let r = s.append(b"{}");
    let v = anchored_verify(&p, false);
    assert!(
        r.is_err() || v.is_err(),
        "truncation hidden by a restart + append: {r:?} {v:?}"
    );
}

#[test]
fn h02_wipe_log_then_append_verifies_with_anchor() {
    let p = tmp("h02");
    let s = fill(&p, 5);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&p)
        .unwrap()
        .set_len(0)
        .unwrap();
    let r = s.append(br#"{"tool":"fresh"}"#);
    let v = anchored_verify(&p, false);
    assert!(
        r.is_err() || v.is_err(),
        "whole history replaced by a fresh chain that verifies: {r:?} {v:?}"
    );
}

#[test]
fn h03_wipe_log_and_delete_anchor_verifies() {
    let p = tmp("h03");
    drop(fill(&p, 3));
    std::fs::write(&p, b"").unwrap();
    std::fs::remove_file(anchor_of(&p)).unwrap();
    let v = anchored_verify(&p, false);
    assert!(
        v.is_err(),
        "empty log + deleted anchor verifies as a valid empty log: {v:?}"
    );
}

#[test]
#[ignore = "accepted limit, needs an external anchor, see ESCALATION.md E-A1"]
fn h04_anchor_rollback_with_matching_truncation_verifies() {
    // Documented limitation of FileAnchor (anchor.rs doc comment); recorded as residual.
    let p = tmp("h04");
    let s = fill(&p, 2);
    let old_anchor = std::fs::read(anchor_of(&p)).unwrap();
    for _ in 0..3 {
        s.append(b"{}").unwrap();
    }
    keep_lines(&p, 2);
    std::fs::write(anchor_of(&p), old_anchor).unwrap();
    let v = anchored_verify(&p, false);
    assert!(
        v.is_err(),
        "rolled-back anchor + truncated log verifies: {v:?}"
    );
}

// ---------------------------------------------------------------- sink trusts the tail

#[test]
fn h05a_sink_refuses_to_extend_a_forged_unsigned_tail() {
    let p = tmp("h05a");
    let s = fill(&p, 2);
    let prev = last_hash(&p);
    let forged = make_line(None, 2.0, &prev, &[("tool", self::s("forged"))]);
    append_raw(&p, &forged);
    let r = s.append(br#"{"tool":"legit"}"#);
    assert!(
        r.is_err(),
        "sink signed an entry chained onto an unsigned forged line: {r:?}"
    );
}

#[test]
fn h05b_sink_refuses_to_extend_a_duplicated_tail() {
    let p = tmp("h05b");
    let s = fill(&p, 2);
    let b = std::fs::read(&p).unwrap();
    let last: Vec<u8> = b
        .split_inclusive(|c| *c == b'\n')
        .next_back()
        .unwrap()
        .to_vec();
    append_raw(&p, &last);
    let r = s.append(b"{}");
    assert!(
        r.is_err(),
        "sink extended a log whose last two lines have the same seq: {r:?}"
    );
}

#[test]
fn h05c_sink_refuses_tail_signed_by_another_key() {
    let p = tmp("h05c");
    let s = fill(&p, 1);
    let other = SigningKey::from_bytes(&[9u8; 32]);
    let prev = last_hash(&p);
    append_raw(&p, &make_line(Some(&other), 1.0, &prev, &[("x", num(1.0))]));
    let r = s.append(b"{}");
    assert!(
        r.is_err(),
        "sink extended a tail signed by an unknown key: {r:?}"
    );
}

// ---------------------------------------------------------------- anchor failure semantics

struct FailingAnchor;
impl Anchor for FailingAnchor {
    fn publish(&self, _h: &Head) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
}

#[test]
fn h06a_failed_append_leaves_no_entry() {
    let p = tmp("h06a");
    let s = FileSink::open_with_anchor(&p, &SECRET, Some(Box::new(FailingAnchor))).unwrap();
    let r = s.append(br#"{"tool":"rm","verdict":"ALLOW"}"#);
    assert_eq!(r, Err(StoreError::Unavailable));
    let len = std::fs::read(&p).unwrap().len();
    assert_eq!(
        len, 0,
        "append returned Err (caller skips the effect) but a signed ALLOW entry is durable"
    );
}

#[test]
fn h06b_blocked_anchor_tmp_fails_append_and_leaves_entry() {
    let p = tmp("h06b");
    let s = fill(&p, 1);
    std::fs::create_dir(suffixed(&p, ".anchor.tmp")).unwrap();
    let before = std::fs::read(&p).unwrap().len();
    let r = s.append(b"{}");
    assert!(r.is_err());
    assert_eq!(
        std::fs::read(&p).unwrap().len(),
        before,
        "append refused but the entry was written"
    );
}

#[cfg(windows)]
#[test]
fn h06c_windows_reader_without_share_delete_on_anchor() {
    use std::os::windows::fs::OpenOptionsExt;
    let p = tmp("h06c");
    let s = fill(&p, 1);
    // A backup tool / editor holding the anchor with FILE_SHARE_READ only.
    let _hold = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(anchor_of(&p))
        .unwrap();
    let before = std::fs::read(&p).unwrap().len();
    let r = s.append(b"{}");
    let after = std::fs::read(&p).unwrap().len();
    assert!(
        r.is_ok() || after == before,
        "reader on .anchor: append Err={r:?} yet log grew {before}->{after}"
    );
}

// ---------------------------------------------------------------- locking / paths

#[test]
#[ignore = "accepted limit: lock identity is the lock path; hard links need file ids (unsafe), see ESCALATION.md E-A2"]
fn h07_hard_linked_log_path_forks_the_chain() {
    let p = tmp("h07");
    drop(FileSink::open(&p, &SECRET).unwrap());
    let alias = p.with_file_name("alias.jsonl");
    std::fs::hard_link(&p, &alias).unwrap();
    let a = Arc::new(FileSink::open_with_anchor(&p, &SECRET, None).unwrap());
    let b = Arc::new(FileSink::open_with_anchor(&alias, &SECRET, None).unwrap());
    let mut hs = Vec::new();
    for t in 0..4 {
        let sink = if t % 2 == 0 { a.clone() } else { b.clone() };
        hs.push(std::thread::spawn(move || {
            for i in 0..40 {
                let _ = sink.append(format!(r#"{{"t":{t},"i":{i}}}"#).as_bytes());
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    let k = keys();
    let v = verify_file(&p, &opts(&k, false, None));
    assert!(v.is_ok(), "two lock files for one log: chain forked: {v:?}");
}

#[test]
fn h08_default_lock_matches_python_locked_hashlog_default() {
    // Python LockedHashLog default: Path("audit.jsonl").with_suffix(".lock") == "audit.lock".
    let p = tmp("h08");
    let py_lock = p.with_extension("lock");
    let s = Arc::new(FileSink::open(&p, &SECRET).unwrap());
    let lock = std::fs::File::create(&py_lock).unwrap();
    lock.lock().unwrap(); // a Python writer holds its default lock
    let (tx, rx) = std::sync::mpsc::channel();
    let s2 = s.clone();
    let h = std::thread::spawn(move || {
        tx.send(s2.append(b"{}")).unwrap();
    });
    let got = rx.recv_timeout(Duration::from_millis(700));
    lock.unlock().unwrap();
    h.join().unwrap();
    assert!(
        got.is_err(),
        "Rust append ran while the Python default lock was held: {got:?}"
    );
}

#[test]
fn h17_path_spellings_threads_share_one_lock() {
    let p = tmp("h17");
    drop(FileSink::open(&p, &SECRET).unwrap());
    let dir = p.parent().unwrap().to_path_buf();
    let mut spellings: Vec<PathBuf> = vec![
        p.clone(),
        dir.join(".").join("audit.jsonl"),
        dir.join("sub").join("..").join("audit.jsonl"),
    ];
    if cfg!(windows) {
        spellings.push(dir.join("AUDIT.JSONL"));
    }
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    let mut hs = Vec::new();
    for (t, sp) in spellings.into_iter().enumerate() {
        hs.push(std::thread::spawn(move || {
            let sink = FileSink::open(&sp, &SECRET).unwrap();
            for i in 0..30 {
                sink.append(format!(r#"{{"t":{t},"i":{i}}}"#).as_bytes())
                    .unwrap();
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    let k = keys();
    let v = verify_file(&p, &opts(&k, false, None)).unwrap();
    assert!(v.entries >= 90);
}

#[test]
fn rt2_child_appender() {
    let Ok(path) = std::env::var("DOS_AUDIT_RT2_CHILD") else {
        return;
    };
    let s = FileSink::open(&path, &SECRET).unwrap();
    for i in 0..20 {
        s.append(format!(r#"{{"child":{i}}}"#).as_bytes()).unwrap();
    }
}

#[test]
fn h17b_processes_with_different_path_spellings() {
    let p = tmp("h17b");
    drop(FileSink::open(&p, &SECRET).unwrap());
    let dir = p.parent().unwrap();
    let exe = std::env::current_exe().unwrap();
    let variants = [
        p.clone(),
        dir.join(".").join("audit.jsonl"),
        if cfg!(windows) {
            dir.join("Audit.Jsonl")
        } else {
            p.clone()
        },
    ];
    let kids: Vec<_> = variants
        .iter()
        .map(|v| {
            std::process::Command::new(&exe)
                .args(["rt2_child_appender", "--exact", "--test-threads=1"])
                .env("DOS_AUDIT_RT2_CHILD", v)
                .spawn()
                .unwrap()
        })
        .collect();
    for mut k in kids {
        assert!(k.wait().unwrap().success());
    }
    let v = anchored_verify(&p, false).unwrap();
    assert_eq!(v.entries, 60);
}

// ---------------------------------------------------------------- Python interop

#[test]
fn h09_rust_lines_survive_python_splitlines() {
    // Python HashLog.__init__/verify use str.splitlines(), which also splits on
    // \x0b \x0c \x1c \x1d \x1e \x85    . JCS escapes the C0 ones, not the rest.
    let p = tmp("h09");
    let s = FileSink::open(&p, &SECRET).unwrap();
    // Fixed by refusing those characters (finding R2-6); a clean entry then yields one line.
    assert_eq!(
        s.append("{\"reason\":\"a\u{2028}b\u{2029}c\u{85}d\"}".as_bytes()),
        Err(StoreError::InvalidInput)
    );
    s.append(br#"{"reason":"abcd"}"#).unwrap();
    let text = String::from_utf8(std::fs::read(&p).unwrap()).unwrap();
    let seps = [
        '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}', '\u{2029}',
    ];
    let pieces = text
        .split(|c: char| c == '\n' || c == '\r' || seps.contains(&c))
        .filter(|x| !x.is_empty())
        .count();
    assert_eq!(
        pieces, 1,
        "Python splitlines() sees {pieces} lines in a 1-entry Rust log; json.loads raises"
    );
}

// ---------------------------------------------------------------- CLI

#[test]
fn h10_cli_without_anchor_flag_accepts_truncated_log() {
    let p = tmp("h10");
    drop(fill(&p, 3));
    keep_lines(&p, 1);
    let pk = hex_encode(&SigningKey::from_bytes(&SECRET).verifying_key().to_bytes());
    let exe = env!("CARGO_BIN_EXE_dos-audit");
    let with = std::process::Command::new(exe)
        .args(["verify", p.to_str().unwrap(), "--key", &pk, "--anchor-file"])
        .arg(anchor_of(&p))
        .output()
        .unwrap();
    assert_eq!(
        with.status.code(),
        Some(1),
        "with --anchor-file it must fail"
    );
    let without = std::process::Command::new(exe)
        .args(["verify", p.to_str().unwrap(), "--key", &pk])
        .output()
        .unwrap();
    assert_ne!(
        without.status.code(),
        Some(0),
        "CLI default (no --anchor-file) accepts a truncated log although <log>.anchor exists: {}",
        String::from_utf8_lossy(&without.stdout)
    );
}

#[test]
fn h10b_cli_hostile_args_do_not_panic() {
    let exe = env!("CARGO_BIN_EXE_dos-audit");
    let p = tmp("h10b");
    std::fs::write(&p, b"\xff\xfe{\n").unwrap();
    for args in [
        vec![],
        vec!["verify"],
        vec!["verify", "--key"],
        vec!["verify", "x", "--key", "zz"],
        vec!["verify", "x", "--key", &"0".repeat(64)],
        vec!["verify", p.to_str().unwrap(), "--python-compat"],
        vec!["verify", p.to_str().unwrap(), "--anchor-file"],
        vec!["verify", "a", "b"],
    ] {
        let o = std::process::Command::new(exe)
            .args(&args)
            .output()
            .unwrap();
        let code = o.status.code();
        assert!(matches!(code, Some(1) | Some(2)), "{args:?} -> {code:?}");
        assert!(!String::from_utf8_lossy(&o.stderr).contains("panicked"));
    }
}

// ---------------------------------------------------------------- resource use

#[test]
fn h11_huge_unterminated_tail_refuses_quickly() {
    let p = tmp("h11");
    let s = fill(&p, 1);
    append_raw(&p, &vec![b'x'; 24 << 20]);
    let t = Instant::now();
    let r = s.append(b"{}");
    let took = t.elapsed();
    assert!(r.is_err());
    assert!(
        took < Duration::from_secs(3),
        "append on a 24 MiB unterminated tail held the lock for {took:?} (quadratic read_tail)"
    );
}

#[test]
fn h12_verifier_during_concurrent_appends_never_false_alarms() {
    let p = tmp("h12");
    let s = Arc::new(fill(&p, 1));
    let s2 = s.clone();
    let big = format!(r#"{{"blob":"{}"}}"#, "y".repeat(200_000));
    let writer = std::thread::spawn(move || {
        for _ in 0..60 {
            s2.append(big.as_bytes()).unwrap();
        }
    });
    let mut failures = Vec::new();
    let mut runs = 0;
    while !writer.is_finished() {
        runs += 1;
        if let Err(e) = anchored_verify(&p, false) {
            failures.push(e);
        }
    }
    writer.join().unwrap();
    assert!(anchored_verify(&p, false).is_ok());
    assert!(
        failures.is_empty(),
        "{} of {runs} verifications of a healthy log failed during appends: {:?}",
        failures.len(),
        failures.first()
    );
}

// ---------------------------------------------------------------- mutation sweep

#[test]
fn h13_byte_edits_never_verify_strict_and_never_change_meaning_in_compat() {
    let p = tmp("h13");
    let s = fill(&p, 2);
    s.append("{\"r\":\"\u{e9}\\u0000\",\"n\":-1.5e-7}".as_bytes())
        .unwrap();
    let orig = std::fs::read(&p).unwrap();
    let anchor = read_anchor_file(&anchor_of(&p), &keys(), 0)
        .unwrap()
        .unwrap();
    let k = keys();
    let canon_lines = |b: &[u8]| -> Vec<Vec<u8>> {
        b.split(|c| *c == b'\n')
            .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
            .map(|l| canon::canonicalize(l).unwrap_or_default())
            .collect()
    };
    let want = canon_lines(&orig);
    let mut bad = Vec::new();
    for i in 0..=orig.len() {
        let mut cands: Vec<Vec<u8>> = Vec::new();
        for ins in *b" \n\r0\"" {
            let mut m = orig.clone();
            m.insert(i, ins);
            cands.push(m);
        }
        if i < orig.len() {
            let mut d = orig.clone();
            d.remove(i);
            cands.push(d);
            for rep in [b' ', b'\n', b'0', b'f', orig[i] ^ 0x20, orig[i] ^ 0x01] {
                if rep != orig[i] {
                    let mut m = orig.clone();
                    m[i] = rep;
                    cands.push(m);
                }
            }
        }
        for m in cands {
            if verify_bytes(&m, &opts(&k, false, Some(anchor.clone()))).is_ok() {
                bad.push(format!("strict ok at {i}"));
            }
            if verify_bytes(&m, &opts(&k, true, Some(anchor.clone()))).is_ok()
                && canon_lines(&m) != want
            {
                bad.push(format!("compat ok with changed meaning at {i}"));
            }
        }
    }
    assert!(bad.is_empty(), "{:?}", &bad[..bad.len().min(10)]);
}

// ---------------------------------------------------------------- hostile anchor files

#[test]
fn h14_hostile_anchor_files_never_panic_or_pass_a_tampered_log() {
    let p = tmp("h14");
    drop(fill(&p, 3));
    let good = std::fs::read(anchor_of(&p)).unwrap();
    let good_s = String::from_utf8(good.clone()).unwrap();
    let mut variants: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\n".to_vec(),
        b"\xef\xbb\xbf".iter().chain(good.iter()).copied().collect(),
        good_s.replace('\n', "\r\n").into_bytes(),
        good_s.replace("\"seq\":2", "\"seq\":\"2\"").into_bytes(),
        good_s
            .replace("\"seq\":2", "\"seq\":2,\"seq\":2")
            .into_bytes(),
        good_s.replace("\"seq\":2", "\"seq\":1").into_bytes(),
        good_s
            .replace("\"seq\":2", "\"seq\":9007199254740993")
            .into_bytes(),
        good_s.replace("\"seq\":2", "\"seq\":1e400").into_bytes(),
        good_s.to_uppercase().into_bytes(),
        format!("{}{}", "[".repeat(100_000), "]".repeat(100_000)).into_bytes(),
        vec![0xff; 1000],
    ];
    variants.push(good.repeat(2));
    let k = keys();
    // Tamper the log so that only a broken anchor check would let it pass.
    keep_lines(&p, 2);
    for (i, v) in variants.iter().enumerate() {
        std::fs::write(anchor_of(&p), v).unwrap();
        let r = std::panic::catch_unwind(|| {
            verify_file_with_anchor_file(&p, &anchor_of(&p), opts(&k, false, None))
        });
        let r = r.unwrap_or_else(|_| panic!("variant {i} panicked"));
        assert!(r.is_err(), "anchor variant {i} let a truncated log verify");
    }
}

// ---------------------------------------------------------------- secrets

#[test]
fn h15_secret_never_leaks_to_debug_errors_or_files() {
    let secret = [0xc3u8; 32];
    let sk = SigningKey::from_bytes(&secret);
    let hex = hex_encode(&secret);
    let dbg = format!("{sk:?} {sk:#?}");
    assert!(
        !dbg.contains(&hex) && !dbg.to_lowercase().contains("c3, c3"),
        "{dbg}"
    );
    let p = tmp("h15");
    let s = FileSink::open(&p, &secret).unwrap();
    s.append(b"{}").unwrap();
    let _ = s.append(br#"{"sig":"x"}"#).map_err(|e| {
        let t = format!("{e:?}");
        assert!(!t.contains(&hex));
    });
    for f in std::fs::read_dir(p.parent().unwrap()).unwrap() {
        let b = std::fs::read(f.unwrap().path()).unwrap_or_default();
        assert!(!b.windows(32).any(|w| w == secret), "raw secret in a file");
        let t = String::from_utf8_lossy(&b).to_lowercase();
        assert!(!t.contains(&hex), "hex secret in a file");
    }
}

// ---------------------------------------------------------------- seq limits

#[test]
fn h16_tail_at_max_safe_seq_refuses_without_writing() {
    let sk = SigningKey::from_bytes(&SECRET);
    for seq in [9_007_199_254_740_991.0, 9_007_199_254_740_992.0, 1e300] {
        let p = tmp("h16");
        let line = make_line(Some(&sk), seq, GENESIS, &[("x", num(0.0))]);
        std::fs::write(&p, &line).unwrap();
        let s = FileSink::open(&p, &SECRET).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.append(b"{}")));
        let r = r.unwrap_or_else(|_| panic!("panic at seq {seq}"));
        assert!(r.is_err(), "seq {seq}: {r:?}");
        assert_eq!(std::fs::read(&p).unwrap(), line, "seq {seq}: file changed");
        let _ = s.head();
    }
}

// ---------------------------------------------------------------- compat mode

#[test]
fn h18_compat_with_anchor_accepts_unsigned_entries_after_the_head() {
    let p = tmp("h18");
    drop(fill(&p, 2));
    let prev = last_hash(&p);
    append_raw(&p, &make_line(None, 2.0, &prev, &[("tool", s("evil"))]));
    let v = anchored_verify(&p, true);
    assert!(
        v.is_err(),
        "compat + anchor accepted an unsigned entry appended by someone without the key: {v:?}"
    );
}

#[test]
fn h19_compat_strip_signature_on_anchored_last_entry_refused() {
    let p = tmp("h19");
    drop(fill(&p, 2));
    let text = String::from_utf8(std::fs::read(&p).unwrap()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let mut v: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let o = v.as_object_mut().unwrap();
    o.remove("sig");
    o.remove("kid");
    o.remove("entry_hash");
    let content: Vec<(String, Value)> = o
        .iter()
        .filter(|(k, _)| *k != "seq" && *k != "prev_hash")
        .map(|(k, v)| (k.clone(), s(v.as_str().unwrap())))
        .collect();
    let refs: Vec<(&str, Value)> = content
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    let prev = o["prev_hash"].as_str().unwrap().to_string();
    let mut out = format!("{}\n", lines[0]).into_bytes();
    out.extend(make_line(None, 1.0, &prev, &refs));
    std::fs::write(&p, out).unwrap();
    assert!(anchored_verify(&p, true).is_err());
}

#[test]
fn h20_compat_kid_without_sig_refused() {
    let sk = SigningKey::from_bytes(&SECRET);
    let mut m = vec![
        ("kid".to_string(), s(&sk.kid().to_hex())),
        ("prev_hash".to_string(), s(GENESIS)),
        ("seq".to_string(), num(0.0)),
    ];
    let h = hex_encode(&Sha256::digest(
        canon::to_jcs(&Value::Object(m.clone())).unwrap(),
    ));
    m.push(("entry_hash".into(), s(&h)));
    let mut line = canon::to_jcs(&Value::Object(m)).unwrap();
    line.push(b'\n');
    let k = keys();
    assert_eq!(
        verify_bytes(&line, &opts(&k, true, None)).unwrap_err().kind,
        VerifyErrorKind::MissingSignature
    );
}

// ---------------------------------------------------------------- artifact-only attacker
// Has: a log, its anchor, the dos-audit binary, the public key, the oracle source. No secret.

fn pubhex() -> String {
    hex_encode(&SigningKey::from_bytes(&SECRET).verifying_key().to_bytes())
}

fn cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_dos-audit"))
        .args(args)
        .output()
        .unwrap()
}

fn lines_vec(p: &Path) -> Vec<Vec<u8>> {
    std::fs::read(p)
        .unwrap()
        .split_inclusive(|c| *c == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

fn victim_kid_line(prev: &str, sig: &str) -> Vec<u8> {
    let victim_kid = SigningKey::from_bytes(&SECRET).kid().to_hex();
    let mut m = vec![
        ("tool".to_string(), s("forged")),
        ("seq".to_string(), num(2.0)),
        ("prev_hash".to_string(), s(prev)),
        ("kid".to_string(), s(&victim_kid)),
        ("sig".to_string(), s(sig)),
    ];
    let h = hex_encode(&Sha256::digest(
        canon::to_jcs(&Value::Object(m.clone())).unwrap(),
    ));
    m.push(("entry_hash".into(), s(&h)));
    let mut l = canon::to_jcs(&Value::Object(m)).unwrap();
    l.push(b'\n');
    l
}

#[test]
fn a01_format_recovered_from_artifacts_but_new_entry_cannot_be_forged() {
    // Format recovered from the artifacts alone: JCS lines with seq, prev_hash, kid, sig,
    // entry_hash = sha256(JCS of all fields but entry_hash).
    let p = tmp("a01");
    drop(fill(&p, 2));
    let text = String::from_utf8(std::fs::read(&p).unwrap()).unwrap();
    let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    let o = first.as_object().unwrap();
    for f in ["seq", "prev_hash", "kid", "sig", "entry_hash"] {
        assert!(o.contains_key(f), "format recovery: {f} missing");
    }
    let prev = last_hash(&p);
    let attacker = SigningKey::from_bytes(&[0x11; 32]);
    let victim_kid = SigningKey::from_bytes(&SECRET).kid().to_hex();
    let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    let reused_sig = last["sig"].as_str().unwrap().to_string();
    let attacker_sig = {
        let m = vec![
            ("tool".to_string(), s("forged")),
            ("seq".to_string(), num(2.0)),
            ("prev_hash".to_string(), s(&prev)),
            ("kid".to_string(), s(&victim_kid)),
        ];
        let payload = canon::to_jcs(&Value::Object(m)).unwrap();
        hex_encode(&attacker.sign(Domain::AuditHead, &payload).to_bytes())
    };
    let tries: Vec<Vec<u8>> = vec![
        make_line(None, 2.0, &prev, &[("tool", s("forged"))]),
        make_line(Some(&attacker), 2.0, &prev, &[("tool", s("forged"))]),
        victim_kid_line(&prev, &attacker_sig),
        victim_kid_line(&prev, &reused_sig),
        victim_kid_line(&prev, &"0".repeat(128)),
    ];
    let base = std::fs::read(&p).unwrap();
    let k = keys();
    for (i, t) in tries.iter().enumerate() {
        let mut b = base.clone();
        b.extend_from_slice(t);
        assert!(
            verify_bytes(&b, &opts(&k, false, None)).is_err(),
            "forgery {i} verified"
        );
        std::fs::write(&p, &b).unwrap();
        let o = cli(&["verify", p.to_str().unwrap(), "--key", &pubhex()]);
        assert_eq!(o.status.code(), Some(1), "CLI accepted forgery {i}");
    }
}

#[test]
fn a02_splice_two_logs_signed_with_the_same_key_is_detected() {
    let a = tmp("a02a");
    let b = tmp("a02b");
    drop(fill(&a, 4));
    let sb = FileSink::open(&b, &SECRET).unwrap();
    for i in 0..4 {
        sb.append(format!(r#"{{"other":{i}}}"#).as_bytes()).unwrap();
    }
    let la = lines_vec(&a);
    let lb = lines_vec(&b);
    let k = keys();
    let anchor_a = read_anchor_file(&anchor_of(&a), &k, 0).unwrap();
    let anchor_b = read_anchor_file(&anchor_of(&b), &k, 0).unwrap();
    for cut in 1..4 {
        let spliced: Vec<u8> = la[..cut]
            .iter()
            .chain(lb[cut..].iter())
            .flatten()
            .copied()
            .collect();
        for anc in [None, anchor_a.clone(), anchor_b.clone()] {
            assert!(
                verify_bytes(&spliced, &opts(&k, false, anc.clone())).is_err(),
                "splice at {cut} with anchor {anc:?} verified"
            );
            assert!(verify_bytes(&spliced, &opts(&k, true, anc)).is_err());
        }
    }
}

#[test]
#[ignore = "accepted limit, needs an external anchor, see ESCALATION.md E-A1"]
fn a02b_whole_log_and_anchor_substituted_from_another_log_with_the_same_key() {
    // Entries and anchor bind no log identity (path, log id), so a log+anchor pair from
    // another log sharing the key (staging, a rotated file) replaces this one undetected.
    let a = tmp("a02c");
    let b = tmp("a02d");
    drop(fill(&a, 6));
    let sb = FileSink::open(&b, &SECRET).unwrap();
    sb.append(br#"{"tool":"harmless"}"#).unwrap();
    std::fs::copy(&b, &a).unwrap();
    std::fs::copy(anchor_of(&b), anchor_of(&a)).unwrap();
    let v = anchored_verify(&a, false);
    assert!(
        v.is_err(),
        "log+anchor of another log with the same key verified: {v:?}"
    );
}

#[test]
fn a03_old_anchor_replay() {
    let p = tmp("a03");
    let s = fill(&p, 2);
    let old = std::fs::read(anchor_of(&p)).unwrap();
    s.append(b"{}").unwrap();
    // Old anchor + full log: the log extends the anchored head (accepted, by design).
    std::fs::write(anchor_of(&p), &old).unwrap();
    assert!(anchored_verify(&p, false).is_ok());
    // Anchor of a different log with the same key and length: caught.
    let q = tmp("a03b");
    drop(fill(&q, 3));
    std::fs::copy(anchor_of(&q), anchor_of(&p)).unwrap();
    assert_eq!(
        anchored_verify(&p, false).unwrap_err().kind,
        VerifyErrorKind::AnchorMismatch
    );
}

#[test]
#[ignore = "accepted limit, needs an external anchor, see ESCALATION.md E-A1"]
fn a03b_old_anchor_with_matching_truncation_through_the_cli() {
    let p = tmp("a03c");
    let s = fill(&p, 2);
    let old = std::fs::read(anchor_of(&p)).unwrap();
    s.append(b"{}").unwrap();
    // Old anchor + log truncated to it, through the CLI.
    keep_lines(&p, 2);
    std::fs::write(anchor_of(&p), &old).unwrap();
    let ap = anchor_of(&p);
    let o = cli(&[
        "verify",
        p.to_str().unwrap(),
        "--key",
        &pubhex(),
        "--anchor-file",
        ap.to_str().unwrap(),
    ]);
    assert_ne!(
        o.status.code(),
        Some(0),
        "CLI accepted a replayed old anchor + truncated log"
    );
}

/// The oracle's `json.dumps(entry)` line and `_hash` (sorted, compact, ASCII).
fn python_minted_line(seq: u64, prev: &str, tool: &str) -> String {
    let body = format!(
        r#""actor":"evil","executed":true,"payload_digest":null,"prev_hash":"{prev}","reason":"minted","seq":{seq},"tool":"{tool}","ts":"2026-01-01T00:00:00+00:00","verdict":"ALLOW""#
    );
    let h = hex_encode(&Sha256::digest(format!("{{{body}}}").as_bytes()));
    format!(
        r#"{{"seq": {seq}, "ts": "2026-01-01T00:00:00+00:00", "actor": "evil", "tool": "{tool}", "verdict": "ALLOW", "reason": "minted", "executed": true, "payload_digest": null, "prev_hash": "{prev}", "entry_hash": "{h}"}}"#
    )
}

#[test]
fn a04_log_minted_from_the_python_recipe() {
    let p = tmp("a04");
    let l0 = python_minted_line(0, GENESIS, "rm");
    let v0: serde_json::Value = serde_json::from_str(&l0).unwrap();
    let l1 = python_minted_line(1, v0["entry_hash"].as_str().unwrap(), "exfil");
    std::fs::write(&p, format!("{l0}\n{l1}\n")).unwrap();
    let k = keys();
    assert!(
        verify_file(&p, &opts(&k, false, None)).is_err(),
        "strict accepted"
    );
    assert_eq!(
        anchored_verify(&p, true).unwrap_err().kind,
        VerifyErrorKind::AnchorMissing
    );
    // The sink continues the minted log and the real key signs on top of it.
    let s = FileSink::open(&p, &SECRET).unwrap();
    let r = s.append(br#"{"tool":"legit"}"#);
    let v = anchored_verify(&p, true);
    let o = cli(&[
        "verify",
        p.to_str().unwrap(),
        "--key",
        &pubhex(),
        "--python-compat",
    ]);
    // `--python-compat` without an anchor exists to read unsigned oracle logs; it accepts
    // this log by design (ESCALATION.md E-A3). The sink and the anchored check refuse it.
    let _ = o;
    assert!(
        r.is_err() && v.is_err(),
        "keyless minted log: sink signed onto it ({r:?}); compat+anchor {v:?}"
    );
}

#[test]
fn a05_secret_not_extractable_from_binary_artifacts_or_outputs() {
    let p = tmp("a05");
    let s = fill(&p, 3);
    std::fs::create_dir(suffixed(&p, ".anchor.tmp")).unwrap();
    let _ = s.append(b"{}");
    std::fs::remove_dir(suffixed(&p, ".anchor.tmp")).unwrap();
    s.append(b"{}").unwrap();
    let hex = hex_encode(&SECRET);
    let mut blobs: Vec<(String, Vec<u8>)> = vec![(
        "binary".into(),
        std::fs::read(env!("CARGO_BIN_EXE_dos-audit")).unwrap(),
    )];
    for f in std::fs::read_dir(p.parent().unwrap()).unwrap() {
        let f = f.unwrap().path();
        if f.is_file() {
            blobs.push((f.display().to_string(), std::fs::read(&f).unwrap()));
        }
    }
    // Includes an operator mistakenly passing the SECRET as --key: it must not be echoed.
    for key in [hex.clone(), pubhex(), "zz".to_string()] {
        let o = cli(&["verify", p.to_str().unwrap(), "--key", &key]);
        let mut out = o.stdout.clone();
        out.extend(o.stderr);
        blobs.push((format!("cli --key {}..", &key[..2]), out));
    }
    blobs.push((
        "debug".into(),
        format!(
            "{:?} {:#?}",
            SigningKey::from_bytes(&SECRET),
            SigningKey::from_bytes(&SECRET)
        )
        .into_bytes(),
    ));
    for (name, b) in blobs {
        assert!(!b.windows(32).any(|w| w == SECRET), "raw secret in {name}");
        let t = String::from_utf8_lossy(&b).to_lowercase();
        assert!(!t.contains(&hex), "hex secret in {name}");
    }
}
