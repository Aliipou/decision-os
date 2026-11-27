//! End to end: the `decision-os` binary in front of the fake MCP server. The policy gates
//! the calls, only allowed calls reach the server, every outcome is in the signed log, and
//! `audit verify` accepts the log.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_decision-os");

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dos-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The fake MCP server of dos-exec, built on demand next to this test's binaries.
fn fake_server() -> PathBuf {
    let exe = PathBuf::from(BIN);
    let dir = exe.parent().unwrap();
    let name = format!("dos-exec-fake-mcp{}", std::env::consts::EXE_SUFFIX);
    let p = dir.join(&name);
    if !p.exists() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let st = Command::new(cargo)
            .args([
                "build",
                "-p",
                "dos-exec",
                "--bin",
                "dos-exec-fake-mcp",
                "--offline",
                "-j",
                "2",
            ])
            .status()
            .unwrap();
        assert!(st.success(), "could not build the fake MCP server");
    }
    assert!(p.exists(), "{} missing", p.display());
    p
}

fn keygen(d: &std::path::Path) -> (PathBuf, String) {
    let key = d.join("key.hex");
    let o = Command::new(BIN).arg("keygen").arg(&key).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8(o.stdout).unwrap();
    let pk = out.trim().strip_prefix("public key: ").unwrap().to_owned();
    assert_eq!(pk.len(), 64);
    (key, pk)
}

#[test]
fn keygen_refuses_to_overwrite_and_hides_the_secret() {
    let d = tmpdir("keygen");
    let (key, pk) = keygen(&d);
    let secret = std::fs::read_to_string(&key).unwrap();
    assert_eq!(secret.trim().len(), 64);
    assert!(!pk.contains(secret.trim()));
    let again = Command::new(BIN).arg("keygen").arg(&key).output().unwrap();
    assert_eq!(again.status.code(), Some(1));
    assert_eq!(
        std::fs::read_to_string(&key).unwrap(),
        secret,
        "key overwritten"
    );
    // the secret is never printed
    assert!(!String::from_utf8_lossy(&again.stdout).contains(secret.trim()));
    assert!(!String::from_utf8_lossy(&again.stderr).contains(secret.trim()));
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &[][..],
        &["nope"],
        &["proxy"],
        &["proxy", "--key-file", "k"],
        &["keygen"],
    ] {
        let o = Command::new(BIN).args(args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn proxy_gates_calls_audits_every_outcome_and_the_log_verifies() {
    let d = tmpdir("e2e");
    let (key, pk) = keygen(&d);
    let policy = d.join("policy.toml");
    std::fs::write(
        &policy,
        "profile = \"balanced\"\n\n[[rule]]\ntool = \"delete_everything\"\ndecision = \"deny\"\nreason = \"never\"\n",
    )
    .unwrap();
    let audit = d.join("audit.jsonl");
    let server_log = d.join("server.log");
    let mut child = Command::new(BIN)
        .arg("proxy")
        .args(["--key-file"])
        .arg(&key)
        .arg("--policy")
        .arg(&policy)
        .arg("--audit")
        .arg(&audit)
        .arg("--")
        .arg(fake_server())
        .arg(&server_log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let call = |id: u32, tool: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{"path":"/tmp/x"}}}}}}"#
        )
    };
    {
        let mut si = child.stdin.take().unwrap();
        for l in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#.to_owned(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_owned(),
            call(2, "read_file"),
            call(3, "delete_everything"),
            call(4, "write_file"),
        ] {
            writeln!(si, "{l}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let reply = |id: u32| -> serde_json::Value {
        stdout
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|v| v["id"] == id)
            .unwrap_or_else(|| {
                panic!(
                    "no reply for id {id}: {stdout}\n{}",
                    String::from_utf8_lossy(&out.stderr)
                )
            })
    };
    assert!(
        reply(2).get("result").is_some(),
        "read_file should pass: {}",
        reply(2)
    );
    assert!(blocked(&reply(3)), "deny rule must block: {}", reply(3));
    assert!(
        blocked(&reply(4)),
        "Ask is refused without approvals: {}",
        reply(4)
    );

    // only the allowed call reached the server
    let served = std::fs::read_to_string(&server_log).unwrap_or_default();
    assert!(served.contains("read_file"), "{served}");
    assert!(
        !served.contains("delete_everything") && !served.contains("write_file"),
        "{served}"
    );

    // every outcome is in the log, in order, with the right verdicts
    let text = std::fs::read_to_string(&audit).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let find = |t: &str| {
        lines
            .iter()
            .find(|v| v["tool"].as_str().is_some_and(|x| x.ends_with(t)))
            .unwrap_or_else(|| panic!("{t} not audited: {text}"))
    };
    assert_eq!(find("read_file")["verdict"], "ALLOW");
    assert_eq!(find("read_file")["executed"], true);
    assert_eq!(find("delete_everything")["verdict"], "DENY");
    assert_eq!(find("delete_everything")["executed"], false);
    assert_eq!(find("write_file")["verdict"], "DENY");

    // the log verifies against the public key and its anchor
    let v = Command::new(BIN)
        .args(["audit", "verify"])
        .arg(&audit)
        .args(["--key", &pk])
        .output()
        .unwrap();
    assert_eq!(
        v.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&v.stderr)
    );
    assert!(String::from_utf8_lossy(&v.stdout).starts_with("ok entries="));

    // and a tampered log does not
    let tampered = text.replacen("ALLOW", "DENY_", 1);
    std::fs::write(&audit, tampered).unwrap();
    let bad = Command::new(BIN)
        .args(["audit", "verify"])
        .arg(&audit)
        .args(["--key", &pk])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
}

#[test]
fn proxy_fails_closed_when_the_audit_log_is_unusable() {
    let d = tmpdir("failclosed");
    let (key, _pk) = keygen(&d);
    let audit = d.join("audit.jsonl");
    std::fs::write(&audit, b"corrupt tail without newline").unwrap();
    let server_log = d.join("server.log");
    let mut child = Command::new(BIN)
        .arg("proxy")
        .arg("--key-file")
        .arg(&key)
        .arg("--audit")
        .arg(&audit)
        .arg("--")
        .arg(fake_server())
        .arg(&server_log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut si = child.stdin.take().unwrap();
        writeln!(si, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"read_file","arguments":{{}}}}}}"#).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"isError\":true") || stdout.contains("\"error\""),
        "{stdout}"
    );
    assert!(
        !std::fs::read_to_string(&server_log)
            .unwrap_or_default()
            .contains("read_file"),
        "effect ran without an audit entry"
    );
}

/// A refused call: a JSON-RPC error, or an MCP tool result with `isError`.
fn blocked(v: &serde_json::Value) -> bool {
    v.get("error").is_some() || v["result"]["isError"] == true
}
