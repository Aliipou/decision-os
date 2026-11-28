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

/// Clears every variable the installer reads so a test can never touch a real config.
fn throwaway(cmd: &mut Command, root: &std::path::Path) {
    for k in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "CODEX_HOME",
        "COPILOT_HOME",
        "HOMEDRIVE",
        "HOMEPATH",
    ] {
        cmd.env(k, root);
    }
}

#[test]
fn install_wraps_a_project_server_the_wrapped_entry_runs_and_uninstall_restores_it() {
    let d = tmpdir("install");
    let home = d.join("home");
    let project = d.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let server_log = d.join("server.log");
    let fake = fake_server();
    let original = format!(
        "{{\n  \"mcpServers\": {{\n    \"fake\": {{\n      \"command\": {},\n      \"args\": [{}]\n    }}\n  }}\n}}\n",
        serde_json::to_string(&fake.to_string_lossy()).unwrap(),
        serde_json::to_string(&server_log.to_string_lossy()).unwrap()
    );
    let cfg = project.join(".mcp.json");
    std::fs::write(&cfg, &original).unwrap();

    let run = |action: &str| {
        let mut c = Command::new(BIN);
        throwaway(&mut c, &d);
        c.arg(action)
            .args(["--client", "claude-code", "--project"])
            .arg(&project)
            .arg("--home")
            .arg(&home);
        c.output().unwrap()
    };
    let o = run("install");
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let wrapped: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    let entry = &wrapped["mcpServers"]["fake"];
    assert_eq!(entry["command"], BIN);
    assert_eq!(entry["args"][0], "mcp-proxy");
    assert_ne!(std::fs::read_to_string(&cfg).unwrap(), original);

    // the status command reports it as wrapped, and changes nothing
    let st = run("status");
    assert_eq!(st.status.code(), Some(0));

    // Run the wrapped entry exactly as a client would.
    let args: Vec<String> = entry["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let mut child = Command::new(entry["command"].as_str().unwrap())
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut si = child.stdin.take().unwrap();
        writeln!(si, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"/tmp/x"}}}}}}"#).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"result\"") && !stdout.contains("isError"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        std::fs::read_to_string(&server_log)
            .unwrap()
            .contains("read_file")
    );
    // the key and the signed log were created in the home, and the log verifies
    let key = home.join("keys").join("audit.key");
    assert!(key.exists() && home.join("audit.jsonl").exists());
    let secret = std::fs::read_to_string(&key).unwrap();
    let shown = Command::new(BIN)
        .arg("keygen")
        .arg(d.join("scratch.key"))
        .output()
        .unwrap();
    assert!(shown.status.success());
    let sk = {
        // derive the public key through the library the binary uses
        let bytes = dos_core::sign::hex_decode_array::<32>(secret.trim()).unwrap();
        dos_core::sign::SigningKey::from_bytes(&bytes)
            .verifying_key()
            .to_hex()
    };
    let v = Command::new(BIN)
        .args(["audit", "verify"])
        .arg(home.join("audit.jsonl"))
        .args(["--key", &sk])
        .output()
        .unwrap();
    assert_eq!(
        v.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&v.stderr)
    );

    // uninstall restores the file byte for byte
    let un = run("uninstall");
    assert_eq!(
        un.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&un.stderr)
    );
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), original);
}

/// Runs `mcp-proxy` on the home, sends one `write_file` call (policy: Ask) and resolves the
/// approval from the outside (`resolve`: Some(true) approve, Some(false) deny, None leave it).
fn ask_round(
    name: &str,
    resolve: Option<bool>,
    ask_timeout: u32,
) -> (serde_json::Value, String, Vec<serde_json::Value>) {
    let d = tmpdir(name);
    let home = d.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("policy.toml"),
        format!("ask_timeout_seconds = {ask_timeout}\n"),
    )
    .unwrap();
    let server_log = d.join("server.log");
    let mut child = Command::new(BIN)
        .args(["mcp-proxy", "--home"])
        .arg(&home)
        .args(["--client", "t", "--server", "fake", "--"])
        .arg(fake_server())
        .arg(&server_log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut si = child.stdin.take().unwrap();
    writeln!(si, r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"write_file","arguments":{{"path":"/tmp/x","content":"hi"}}}}}}"#).unwrap();
    si.flush().unwrap();
    // wait for the pending approval to show up, then resolve it like a user would
    let mut id = None;
    for _ in 0..100 {
        let o = Command::new(BIN)
            .arg("approvals")
            .arg("--home")
            .arg(&home)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        if let Some(first) = text.lines().next() {
            id = first.split_whitespace().next().map(str::to_owned);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // With nobody answering the window is the policy timeout (1 s): seeing the request is
    // optional there, so a loaded machine cannot make the test flaky.
    if resolve.is_some() {
        assert!(id.is_some(), "the proxy never asked for approval");
    }
    if let Some(id) = &id {
        assert!(id.starts_with("ask-"));
    }
    if let (Some(approve), Some(id)) = (resolve, id) {
        let verb = if approve { "approve" } else { "deny" };
        let o = Command::new(BIN)
            .args([verb, &id, "--home"])
            .arg(&home)
            .output()
            .unwrap();
        assert_eq!(
            o.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&o.stderr)
        );
        // a second resolution of the same approval is refused
        let again = Command::new(BIN)
            .args(["approve", &id, "--home"])
            .arg(&home)
            .output()
            .unwrap();
        assert_eq!(again.status.code(), Some(1));
    }
    drop(si);
    let out = child.wait_with_output().unwrap();
    let reply: serde_json::Value = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["id"] == 7)
        .unwrap_or_else(|| panic!("no reply: {}", String::from_utf8_lossy(&out.stderr)));
    let served = std::fs::read_to_string(&server_log).unwrap_or_default();
    let audit: Vec<serde_json::Value> = std::fs::read_to_string(home.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // the approval record is gone afterwards: it is single use
    assert!(
        Command::new(BIN)
            .arg("approvals")
            .arg("--home")
            .arg(&home)
            .output()
            .unwrap()
            .stdout
            .is_empty(),
        "approval record left behind"
    );
    (reply, served, audit)
}

#[test]
fn ask_approved_from_outside_runs_once_and_is_audited() {
    let (reply, served, audit) = ask_round("ask-yes", Some(true), 20);
    assert!(!blocked(&reply), "{reply}");
    assert!(served.contains("write_file"), "{served}");
    let last = audit.last().unwrap();
    assert_eq!(last["verdict"], "ALLOW");
    assert_eq!(last["executed"], true);
    assert!(
        last["reason"].as_str().unwrap().contains("approved"),
        "{last}"
    );
}

#[test]
fn ask_denied_from_outside_is_refused_and_never_runs() {
    let (reply, served, audit) = ask_round("ask-no", Some(false), 20);
    assert!(blocked(&reply), "{reply}");
    assert!(!served.contains("write_file"), "{served}");
    assert_eq!(audit.last().unwrap()["verdict"], "DENY");
    assert_eq!(audit.last().unwrap()["executed"], false);
}

#[test]
fn ask_nobody_answers_expires_and_is_refused() {
    let (reply, served, audit) = ask_round("ask-timeout", None, 1);
    assert!(blocked(&reply), "{reply}");
    assert!(!served.contains("write_file"), "{served}");
    assert_eq!(audit.last().unwrap()["verdict"], "DENY");
}

#[test]
fn approval_ids_cannot_name_other_files() {
    let d = tmpdir("approve-id");
    for bad in ["../x", "a/b", r"a\b", "", "x.json"] {
        let o = Command::new(BIN)
            .args(["approve", bad, "--home"])
            .arg(&d)
            .output()
            .unwrap();
        assert_ne!(o.status.code(), Some(0), "{bad:?}");
    }
}

#[test]
fn a_planted_approval_does_not_pre_approve_a_call() {
    // Someone who can write the approvals directory plants an approved record for the exact
    // id before the proxy asks. The proxy replaces it with a pending one and waits for a real
    // decision (here: none, so the call expires and is refused).
    let d = tmpdir("planted");
    let home = d.join("home");
    std::fs::create_dir_all(home.join("approvals")).unwrap();
    // long while the first run learns the id (answered at once), short for the planted run
    std::fs::write(home.join("policy.toml"), "ask_timeout_seconds = 30\n").unwrap();
    let server_log = d.join("server.log");
    let start = |planted: Option<&str>| {
        if let Some(id) = planted {
            std::fs::write(
                home.join("approvals").join(format!("{id}.json")),
                format!(r#"{{"id":"{id}","server":"fake","tool":"write_file","reason":"x","state":"approved","created_unix":1}}"#),
            )
            .unwrap();
        }
        let mut child = Command::new(BIN)
            .args(["mcp-proxy", "--home"])
            .arg(&home)
            .args(["--client", "t", "--server", "fake", "--"])
            .arg(fake_server())
            .arg(&server_log)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut si = child.stdin.take().unwrap();
        writeln!(si, r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"write_file","arguments":{{"path":"/tmp/x","content":"hi"}}}}}}"#).unwrap();
        si.flush().unwrap();
        let mut id = None;
        for _ in 0..100 {
            let o = Command::new(BIN)
                .arg("approvals")
                .arg("--home")
                .arg(&home)
                .output()
                .unwrap();
            if let Some(first) = String::from_utf8_lossy(&o.stdout).lines().next() {
                id = first.split_whitespace().next().map(str::to_owned);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
        // Learning run: answer it at once so the proxy ends; the planted run must expire alone.
        if let (true, Some(id)) = (planted.is_none(), &id) {
            let _ = Command::new(BIN)
                .args(["deny", id, "--home"])
                .arg(&home)
                .output();
        }
        drop(si);
        let out = child.wait_with_output().unwrap();
        (id, String::from_utf8_lossy(&out.stdout).into_owned())
    };
    // first run only to learn the deterministic id of this exact call
    let (id, _) = start(None);
    let id = id.expect("no approval requested");
    // second run with a planted approved record for that id, and a short timeout
    std::fs::write(home.join("policy.toml"), "ask_timeout_seconds = 1\n").unwrap();
    let (_, stdout) = start(Some(&id));
    assert!(
        stdout.contains("isError"),
        "planted approval let the call through: {stdout}"
    );
    assert!(
        !std::fs::read_to_string(&server_log)
            .unwrap_or_default()
            .contains("write_file")
    );
}

#[test]
fn garbage_approval_records_never_approve() {
    let d = tmpdir("garbage");
    let dir = d.join("approvals");
    std::fs::create_dir_all(&dir).unwrap();
    for (i, body) in ["", "not json", "{}", r#"{"state":"approved"}"#, "[1]"]
        .iter()
        .enumerate()
    {
        std::fs::write(dir.join(format!("ask-{i}.json")), body).unwrap();
        // none of these is a pending approval to resolve, and listing never panics
        let o = Command::new(BIN)
            .args(["approve", &format!("ask-{i}"), "--home"])
            .arg(&d)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(1), "{body:?}");
    }
    let o = Command::new(BIN)
        .arg("approvals")
        .arg("--home")
        .arg(&d)
        .output()
        .unwrap();
    assert!(o.stdout.is_empty());
}

/// One `write_file` call through `mcp-proxy` on `home`. If `answer` is `Some((approve, always))`
/// the pending approval is resolved from outside. Returns the reply and the audit entries.
fn one_write(
    home: &std::path::Path,
    server_log: &std::path::Path,
    content: &str,
    answer: Option<(bool, bool)>,
) -> (serde_json::Value, Vec<serde_json::Value>) {
    let mut child = Command::new(BIN)
        .args(["mcp-proxy", "--home"])
        .arg(home)
        .args(["--client", "t", "--server", "fake", "--"])
        .arg(fake_server())
        .arg(server_log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut si = child.stdin.take().unwrap();
    writeln!(si, r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"write_file","arguments":{{"path":"/tmp/x","content":"{content}"}}}}}}"#).unwrap();
    si.flush().unwrap();
    if let Some((approve, always)) = answer {
        let mut id = None;
        for _ in 0..200 {
            let o = Command::new(BIN)
                .arg("approvals")
                .arg("--home")
                .arg(home)
                .output()
                .unwrap();
            if let Some(first) = String::from_utf8_lossy(&o.stdout).lines().next() {
                id = first.split_whitespace().next().map(str::to_owned);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let id = id.expect("the proxy never asked");
        let mut c = Command::new(BIN);
        c.args([if approve { "approve" } else { "deny" }, &id]);
        if always {
            c.arg("--always");
        }
        let o = c.arg("--home").arg(home).output().unwrap();
        assert_eq!(
            o.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    drop(si);
    let out = child.wait_with_output().unwrap();
    let reply = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["id"] == 7)
        .unwrap_or_else(|| panic!("no reply: {}", String::from_utf8_lossy(&out.stderr)));
    let audit = std::fs::read_to_string(home.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (reply, audit)
}

#[test]
fn always_allow_is_remembered_and_a_deny_rule_still_wins() {
    let d = tmpdir("always");
    let home = d.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("policy.toml"), "ask_timeout_seconds = 30\n").unwrap();
    let log = d.join("server.log");
    // First call asks; the user answers "always allow".
    let (r1, _) = one_write(&home, &log, "one", Some((true, true)));
    assert!(!blocked(&r1), "{r1}");
    assert!(
        std::fs::read_to_string(home.join("learned.json"))
            .unwrap()
            .contains("allow")
    );
    // A later call, other arguments, new process: no question, allowed, audited as chosen.
    let (r2, audit) = one_write(&home, &log, "two", None);
    assert!(!blocked(&r2), "{r2}");
    let last = audit.last().unwrap();
    assert_eq!(last["verdict"], "ALLOW");
    assert!(
        last["reason"].as_str().unwrap().contains("always allow"),
        "{last}"
    );
    let served = std::fs::read_to_string(&log).unwrap();
    assert!(served.contains("one") && served.contains("two"), "{served}");
    // A deny rule in the policy beats the remembered choice.
    std::fs::write(
        home.join("policy.toml"),
        "[[rule]]\ntool = \"write_file\"\ndecision = \"deny\"\nreason = \"frozen\"\n",
    )
    .unwrap();
    let (r3, audit) = one_write(&home, &log, "three", None);
    assert!(blocked(&r3), "{r3}");
    assert_eq!(audit.last().unwrap()["verdict"], "DENY");
    assert!(!std::fs::read_to_string(&log).unwrap().contains("three"));
}

#[test]
fn always_deny_is_remembered_and_a_broken_learned_file_grants_nothing() {
    let d = tmpdir("alwaysdeny");
    let home = d.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("policy.toml"), "ask_timeout_seconds = 30\n").unwrap();
    let log = d.join("server.log");
    let (r1, _) = one_write(&home, &log, "one", Some((false, true)));
    assert!(blocked(&r1), "{r1}");
    let (r2, audit) = one_write(&home, &log, "two", None);
    assert!(blocked(&r2), "{r2}");
    assert_eq!(audit.last().unwrap()["verdict"], "DENY");
    assert!(
        !std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("write_file")
    );
    // A corrupt learned file means no remembered choices: the call asks again (and here is
    // answered "no" once).
    std::fs::write(home.join("learned.json"), "{ not json").unwrap();
    let (r3, _) = one_write(&home, &log, "three", Some((false, false)));
    assert!(blocked(&r3), "{r3}");
}
