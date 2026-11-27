//! End to end: an MCP client conversation through `Proxy` to the fake server
//! (`src/bin/dos-exec-fake-mcp.rs`). Mirrors `tests/gateway/test_mcp_proxy.py`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use dos_exec::{
    AuditEvent, AuditSink, CallRequest, DecisionEngine, EngineError, MemoryApprovals, Proxy,
    StaticVerdict, Verdict,
};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const FAKE: &str = env!("CARGO_BIN_EXE_dos-exec-fake-mcp");

/// A stand-in for the policy: the same answers the oracle's default policy gives
/// the fake server's tools.
struct Engine {
    calls: Mutex<Vec<(String, Option<String>)>>,
}

impl DecisionEngine for Engine {
    fn decide(&self, req: &CallRequest, approval: Option<&str>) -> Result<Verdict, EngineError> {
        self.calls
            .lock()
            .unwrap()
            .push((req.tool.clone(), approval.map(str::to_owned)));
        let args = Value::Object(req.arguments.clone()).to_string();
        let protected = args.contains(".ssh") || args.contains("/etc/shadow");
        if protected {
            return Ok(Verdict::Deny {
                reason: "protected path".into(),
            });
        }
        if approval.is_some() {
            return Ok(Verdict::Allow {
                reason: "approved by you".into(),
            });
        }
        let ask = || Verdict::Ask {
            reason: "unclassified tool".into(),
            approval_id: format!("{}:{}", req.tool, args),
        };
        Ok(match req.tool.as_str() {
            "read_file" | "resources/read" | "die" | "slow" => Verdict::Allow {
                reason: "read".into(),
            },
            "delete_everything" => Verdict::Deny {
                reason: "destructive tool".into(),
            },
            "boom" => return Err(EngineError("engine is broken".into())),
            "frobnicate" if req.hints.iter().any(|h| h == "hint:readonly") => Verdict::Allow {
                reason: "read-only hint".into(),
            },
            _ => ask(),
        })
    }

    fn static_decision(
        &self,
        _server: &str,
        tool: &str,
        _hints: &[String],
    ) -> Result<StaticVerdict, EngineError> {
        Ok(if tool == "delete_everything" {
            StaticVerdict::Deny
        } else {
            StaticVerdict::Allow
        })
    }

    fn hide_denied_tools(&self) -> bool {
        true
    }
}

#[derive(Default)]
struct Audit {
    entries: Mutex<Vec<AuditEvent>>,
    fail: bool,
}

impl AuditSink for Audit {
    fn record(&self, ev: &AuditEvent) -> Result<(), String> {
        if self.fail {
            return Err("disk full".into());
        }
        self.entries.lock().unwrap().push(ev.clone());
        Ok(())
    }
}

struct Client {
    w: Option<std::io::PipeWriter>,
    q: Receiver<Value>,
    stash: Vec<Value>,
    proxy: Option<JoinHandle<i32>>,
    log: PathBuf,
    n: i64,
    engine: Arc<Engine>,
    audit: Arc<Audit>,
    _dir: TempDir,
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> TempDir {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("dos-exec-test-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    TempDir(p)
}

#[derive(Default)]
struct Opts {
    approvals: Option<Arc<MemoryApprovals>>,
    audit_fails: bool,
    argv: Option<Vec<String>>,
}

impl Client {
    fn start(o: Opts) -> Self {
        let dir = tempdir();
        let log = dir.0.join("upstream.log");
        let engine = Arc::new(Engine {
            calls: Mutex::new(Vec::new()),
        });
        let audit = Arc::new(Audit {
            fail: o.audit_fails,
            ..Default::default()
        });
        let mut proxy = Proxy::new(engine.clone(), "fs").with_audit(audit.clone());
        if let Some(a) = o.approvals {
            proxy = proxy.with_approvals(a);
        }
        let argv = o
            .argv
            .unwrap_or_else(|| vec![FAKE.to_owned(), log.to_string_lossy().into_owned()]);
        let (in_r, in_w) = std::io::pipe().unwrap();
        let (out_r, out_w) = std::io::pipe().unwrap();
        let h = std::thread::spawn(move || proxy.run(&argv, in_r, out_w));
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out_r).lines() {
                let Ok(line) = line else { break };
                tx.send(serde_json::from_str::<Value>(&line).unwrap())
                    .unwrap();
            }
        });
        Client {
            w: Some(in_w),
            q: rx,
            stash: Vec::new(),
            proxy: Some(h),
            log,
            n: 0,
            engine,
            audit,
            _dir: dir,
        }
    }

    fn initialized(o: Opts) -> Self {
        let mut c = Self::start(o);
        let init = c.request("initialize", json!({"protocolVersion": "2025-06-18"}));
        assert_eq!(init["result"]["serverInfo"]["name"], "fake");
        c.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        c
    }

    fn send_raw(&mut self, b: &[u8]) {
        let w = self.w.as_mut().unwrap();
        w.write_all(b).unwrap();
        w.write_all(b"\n").unwrap();
        w.flush().unwrap();
    }

    fn send(&mut self, m: &Value) {
        self.send_raw(m.to_string().as_bytes());
    }

    fn next_id(&mut self) -> i64 {
        self.n += 1;
        self.n
    }

    fn send_call(&mut self, name: &str, args: Value) -> i64 {
        let id = self.next_id();
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": name, "arguments": args}}));
        id
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id();
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        self.reply(id)
    }

    fn reply(&mut self, id: i64) -> Value {
        self.wait_for(|m| m["id"] == json!(id) && m.get("method").is_none(), 15)
    }

    fn call(&mut self, name: &str, args: Value) -> Value {
        let id = self.send_call(name, args);
        self.reply(id)
    }

    fn wait_for(&mut self, pred: impl Fn(&Value) -> bool, secs: u64) -> Value {
        if let Some(i) = self.stash.iter().position(&pred) {
            return self.stash.remove(i);
        }
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if let Ok(m) = self.q.recv_timeout(Duration::from_millis(50)) {
                if pred(&m) {
                    return m;
                }
                self.stash.push(m);
            }
        }
        panic!("timed out; saw {:?}", self.stash);
    }

    /// Every message that arrives within `ms`.
    fn drain(&mut self, ms: u64) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < deadline {
            if let Ok(m) = self.q.recv_timeout(Duration::from_millis(20)) {
                self.stash.push(m);
            }
        }
        self.stash.clone()
    }

    fn upstream_calls(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn upstream_names(&self) -> Vec<String> {
        self.upstream_calls()
            .iter()
            .map(|c| c["name"].as_str().unwrap_or("").to_owned())
            .collect()
    }

    fn close(&mut self) -> i32 {
        self.w.take();
        self.proxy.take().unwrap().join().unwrap()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.w.take();
        if let Some(h) = self.proxy.take() {
            let _ = h.join();
        }
    }
}

fn text(r: &Value) -> String {
    r["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

fn is_error(r: &Value) -> bool {
    r["result"]["isError"] == json!(true)
}

fn approve_when_pending(
    a: Arc<MemoryApprovals>,
    tool: &'static str,
    yes: bool,
) -> JoinHandle<bool> {
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(p) = a.pending().into_iter().find(|p| p.tool == tool) {
                return a.resolve(&p.id, yes);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    })
}

// ------------------------------------------------------------------ oracle parity

#[test]
fn notifications_and_tools_list_hide_denied() {
    let mut c = Client::initialized(Opts::default());
    let note = c.wait_for(|m| m["method"] == "notifications/message", 15);
    assert_eq!(note["params"]["data"], "hello");
    let r = c.request("tools/list", json!({}));
    let tools: Vec<&str> = r["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(!tools.contains(&"delete_everything"));
    for t in ["read_file", "write_file", "ask_roots"] {
        assert!(tools.contains(&t), "{tools:?}");
    }
}

#[test]
fn allowed_call_is_forwarded() {
    let mut c = Client::initialized(Opts::default());
    let r = c.call("read_file", json!({"path": "/tmp/a"}));
    assert_eq!(
        serde_json::from_str::<Value>(&text(&r)).unwrap(),
        json!({"path": "/tmp/a"})
    );
    assert!(!is_error(&r));
    assert_eq!(c.upstream_names(), vec!["read_file"]);
}

#[test]
fn denied_call_never_reaches_the_server() {
    let mut c = Client::initialized(Opts::default());
    let r = c.call("delete_everything", json!({}));
    assert!(is_error(&r) && text(&r).contains("Decision OS blocked `fs/delete_everything`"));
    let r = c.call("read_file", json!({"path": "~/.ssh/id_rsa"}));
    assert!(is_error(&r) && text(&r).contains("protected"));
    assert!(c.upstream_calls().is_empty());
}

#[test]
fn annotation_hint_lets_unclassified_read_tool_run() {
    let mut c = Client::initialized(Opts::default());
    // Before tools/list there is no hint: the tool is unclassified -> ask -> refused.
    let r = c.call("frobnicate", json!({}));
    assert!(is_error(&r));
    c.request("tools/list", json!({}));
    let r = c.call("frobnicate", json!({}));
    assert!(!is_error(&r), "{r}");
}

#[test]
fn ask_approve_and_deny() {
    let a = Arc::new(MemoryApprovals::new(Duration::from_secs(10)));
    let mut c = Client::initialized(Opts {
        approvals: Some(a.clone()),
        ..Default::default()
    });
    let ap = approve_when_pending(a.clone(), "write_file", true);
    let r = c.call("write_file", json!({"path": "/tmp/x.txt", "content": "hi"}));
    assert!(ap.join().unwrap());
    assert!(!is_error(&r), "{r}");
    let ap = approve_when_pending(a.clone(), "write_file", false);
    let r = c.call("write_file", json!({"path": "/tmp/y.txt", "content": "hi"}));
    assert!(ap.join().unwrap());
    assert!(is_error(&r) && text(&r).contains("denied by you"), "{r}");
    let paths: Vec<Value> = c
        .upstream_calls()
        .iter()
        .map(|x| x["arguments"]["path"].clone())
        .collect();
    assert_eq!(paths, vec![json!("/tmp/x.txt")]);
    // The approved call was decided twice, the second time with the approval id.
    let calls = c.engine.calls.lock().unwrap().clone();
    assert!(calls.iter().any(|(t, a)| t == "write_file" && a.is_some()));
}

#[test]
fn parallel_calls_and_server_initiated_requests() {
    let a = Arc::new(MemoryApprovals::new(Duration::from_secs(30)));
    let mut c = Client::initialized(Opts {
        approvals: Some(a.clone()),
        ..Default::default()
    });
    // a call waiting for approval must not block other traffic
    let slow_id = c.send_call("write_file", json!({"path": "/tmp/slow"}));
    let fast = c.call("read_file", json!({"path": "/tmp/fast"}));
    assert_eq!(
        serde_json::from_str::<Value>(&text(&fast)).unwrap(),
        json!({"path": "/tmp/fast"})
    );
    // server -> client request passes through, and the client's answer goes back
    let ap = approve_when_pending(a.clone(), "ask_roots", true);
    let rid = c.send_call("ask_roots", json!({}));
    assert!(ap.join().unwrap());
    let srv = c.wait_for(|m| m["method"] == "roots/list", 15);
    c.send(
        &json!({"jsonrpc": "2.0", "id": srv["id"], "result": {"roots": [{"uri": "file:///w"}]}}),
    );
    let done = c.reply(rid);
    assert_eq!(
        serde_json::from_str::<Value>(&text(&done)).unwrap(),
        json!({"roots": [{"uri": "file:///w"}]})
    );
    // cancel the slow one: no response is sent, and it never reaches the server
    c.send(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": slow_id, "reason": "user"}}),
    );
    let seen = c.drain(600);
    assert!(seen.iter().all(|m| m["id"] != json!(slow_id)), "{seen:?}");
    assert!(
        !serde_json::to_string(&c.upstream_calls())
            .unwrap()
            .contains("/tmp/slow")
    );
}

#[test]
fn audit_records_every_outcome() {
    let mut c = Client::initialized(Opts::default());
    c.call("read_file", json!({"path": "/tmp/a"}));
    c.call("delete_everything", json!({}));
    let e: Vec<(String, &str, bool)> = c
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|e| (e.tool.clone(), e.verdict, e.executed))
        .collect();
    assert_eq!(
        e,
        vec![
            ("fs/read_file".to_owned(), "ALLOW", true),
            ("fs/delete_everything".to_owned(), "DENY", false)
        ]
    );
}

#[test]
fn bad_upstream_command_exits_cleanly() {
    let mut c = Client::start(Opts {
        argv: Some(vec!["definitely-not-a-command-xyz".into()]),
        ..Default::default()
    });
    assert_eq!(c.close(), 127);
    let mut c = Client::start(Opts {
        argv: Some(vec![]),
        ..Default::default()
    });
    assert_eq!(c.close(), 2);
}

#[test]
fn replies_still_arrive_after_the_client_half_closes() {
    let a = Arc::new(MemoryApprovals::new(Duration::from_secs(30)));
    let mut c = Client::start(Opts {
        approvals: Some(a),
        ..Default::default()
    });
    let mut batch = Vec::new();
    for m in [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "slow", "arguments": {"path": "/tmp/a"}}}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}}}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "write_file", "arguments": {}}}),
    ] {
        batch.extend_from_slice(m.to_string().as_bytes());
        batch.push(b'\n');
    }
    c.w.as_mut().unwrap().write_all(&batch).unwrap();
    let started = Instant::now();
    c.close();
    // The approval wait was aborted, not left to its 30 s timeout.
    assert!(started.elapsed() < Duration::from_secs(10));
    let seen = c.drain(300);
    let ids: std::collections::BTreeSet<i64> =
        seen.iter().filter_map(|m| m["id"].as_i64()).collect();
    assert_eq!(ids, [1, 2, 3, 4].into_iter().collect(), "{seen:?}");
    let r2 = seen.iter().find(|m| m["id"] == 2).unwrap();
    assert!(!is_error(r2));
    let r3 = seen.iter().find(|m| m["id"] == 3).unwrap();
    assert!(is_error(r3));
    let r4 = seen.iter().find(|m| m["id"] == 4).unwrap();
    assert!(is_error(r4) && text(r4).contains("cancelled"), "{r4}");
}

#[test]
fn id_less_tools_call_is_never_forwarded() {
    let mut c = Client::initialized(Opts::default());
    c.send(&json!({"jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "delete_everything", "arguments": {}}}));
    c.send(&json!([{"jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "/x"}}}]));
    c.send(&json!({"jsonrpc": "2.0", "method": "resources/read", "params": {"uri": "file:///x"}}));
    let r = c.call("read_file", json!({"path": "/tmp/after"}));
    assert!(!is_error(&r));
    assert_eq!(c.upstream_names(), vec!["read_file"]);
}

#[test]
fn resources_read_is_governed() {
    let mut c = Client::initialized(Opts::default());
    let ok = c.request("resources/read", json!({"uri": "file:///tmp/notes.txt"}));
    assert_eq!(ok["result"]["contents"][0]["text"], "resource body");
    let bad = c.request("resources/read", json!({"uri": "file:///etc/shadow"}));
    assert_eq!(bad["error"]["code"], -32001);
    assert!(
        bad["error"]["message"]
            .as_str()
            .unwrap()
            .contains("protected")
    );
    let uris: Vec<Value> = c
        .upstream_calls()
        .iter()
        .map(|x| x["arguments"]["uri"].clone())
        .collect();
    assert_eq!(uris, vec![json!("file:///tmp/notes.txt")]);
}

// ------------------------------------------------------------------ fail closed

#[test]
fn batch_mixes_gated_calls_and_plain_requests() {
    let mut c = Client::initialized(Opts::default());
    c.send(&json!([
        {"jsonrpc": "2.0", "id": 50, "method": "tools/call", "params": {"name": "read_file", "arguments": {"p": 1}}},
        {"jsonrpc": "2.0", "id": 51, "method": "tools/call", "params": {"name": "delete_everything", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 52, "method": "ping"},
    ]));
    let r = c.reply(50);
    assert!(!is_error(&r));
    let r = c.reply(51);
    assert!(is_error(&r));
    // The non-gated remainder went upstream as a batch, without the calls.
    std::thread::sleep(Duration::from_millis(200));
    let calls = c.upstream_calls();
    let batch = calls.iter().find(|x| x["name"] == "batch").unwrap();
    assert_eq!(
        batch["arguments"],
        json!([{"jsonrpc": "2.0", "id": 52, "method": "ping"}])
    );
    assert!(!calls.iter().any(|x| x["name"] == "delete_everything"));
}

#[test]
fn bad_requests_get_errors() {
    let mut c = Client::initialized(Opts::default());
    let r = c.request("tools/call", json!({"arguments": {}}));
    assert_eq!(r["error"]["code"], -32602);
    let r = c.request("tools/call", json!({"name": "", "arguments": {}}));
    assert_eq!(r["error"]["code"], -32602);
    let r = c.request("tools/call", json!({"name": "read_file", "arguments": [1]}));
    assert!(is_error(&r) && text(&r).contains("must be a JSON object"));
    let r = c.request("tools/call", json!({"name": "read_file"}));
    assert!(!is_error(&r), "missing arguments means {{}}: {r}");
    assert_eq!(c.upstream_calls().len(), 1);
}

#[test]
fn engine_error_refuses() {
    let mut c = Client::initialized(Opts::default());
    let r = c.call("boom", json!({}));
    assert_eq!(r["error"]["code"], -32603);
    assert!(c.upstream_calls().is_empty());
    let a = c.audit.entries.lock().unwrap().clone();
    assert!(a.iter().any(|e| e.tool == "fs/boom" && !e.executed));
}

#[test]
fn audit_failure_refuses_before_the_effect() {
    let mut c = Client::initialized(Opts {
        audit_fails: true,
        ..Default::default()
    });
    let r = c.call("read_file", json!({"path": "/tmp/a"}));
    assert!(is_error(&r) && text(&r).contains("audit"), "{r}");
    assert!(c.upstream_calls().is_empty());
}

#[test]
fn ask_without_a_human_is_refused() {
    let mut c = Client::initialized(Opts::default());
    let r = c.call("write_file", json!({"path": "/tmp/x"}));
    assert!(
        is_error(&r) && text(&r).contains("unclassified tool"),
        "{r}"
    );
    assert!(c.upstream_calls().is_empty());
}

#[test]
fn ask_times_out() {
    let a = Arc::new(MemoryApprovals::new(Duration::from_millis(200)));
    let mut c = Client::initialized(Opts {
        approvals: Some(a),
        ..Default::default()
    });
    let r = c.call("write_file", json!({"path": "/tmp/x"}));
    assert!(is_error(&r) && text(&r).contains("no answer before the approval timeout"));
    assert!(c.upstream_calls().is_empty());
}

#[test]
fn upstream_death_mid_call_is_an_error() {
    let mut c = Client::initialized(Opts::default());
    let r = c.call("die", json!({}));
    assert_eq!(r["error"]["code"], -32603, "{r}");
    assert!(r["error"]["message"].as_str().unwrap().contains("exited"));
    assert_eq!(c.close(), 3);
}

#[test]
fn upstream_death_aborts_an_approval_wait() {
    let a = Arc::new(MemoryApprovals::new(Duration::from_secs(30)));
    let mut c = Client::initialized(Opts {
        approvals: Some(a.clone()),
        ..Default::default()
    });
    let waiting = c.send_call("write_file", json!({"path": "/tmp/w"}));
    let deadline = Instant::now() + Duration::from_secs(10);
    while a.pending().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let started = Instant::now();
    c.send_call("die", json!({}));
    let r = c.reply(waiting);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(is_error(&r) && text(&r).contains("exited"), "{r}");
    assert!(
        !a.resolve(
            &a.pending()
                .first()
                .map(|p| p.id.clone())
                .unwrap_or_default(),
            true
        )
    );
    assert_eq!(c.upstream_names(), vec!["die"]);
}

#[test]
fn ambiguous_client_json_is_dropped() {
    let mut c = Client::initialized(Opts::default());
    // Duplicate keys: a first-wins server parser would see tools/call.
    c.send_raw(br#"{"jsonrpc":"2.0","id":90,"method":"tools/call","method":"ping","params":{"name":"delete_everything","arguments":{}}}"#);
    c.send_raw(br#"{"jsonrpc":"2.0","id":91,"method":"ping","method":"tools/call","params":{"name":"delete_everything","arguments":{}}}"#);
    // Python's json accepts NaN; a Python server would run this.
    c.send_raw(br#"{"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"delete_everything","arguments":{"n":NaN}}}"#);
    c.send_raw(b"not json at all");
    let r = c.call("read_file", json!({"path": "/tmp/after"}));
    assert!(!is_error(&r));
    assert_eq!(c.upstream_names(), vec!["read_file"]);
    let seen = c.drain(200);
    assert!(
        seen.iter()
            .all(|m| ![90, 91, 92].contains(&m["id"].as_i64().unwrap_or(0)))
    );
}

#[test]
fn many_parallel_calls_all_answered() {
    let mut c = Client::initialized(Opts::default());
    let ids: Vec<i64> = (0..30)
        .map(|i| c.send_call("read_file", json!({"i": i})))
        .collect();
    for id in ids {
        let r = c.reply(id);
        assert!(!is_error(&r));
    }
    assert_eq!(c.upstream_calls().len(), 30);
}

#[test]
fn tool_hints_match_oracle() {
    use dos_exec::tool_hints;
    assert_eq!(
        tool_hints(&json!({"annotations": {"readOnlyHint": true, "destructiveHint": true}})),
        vec!["hint:readonly"]
    );
    assert_eq!(
        tool_hints(&json!({"annotations": {"destructiveHint": true, "openWorldHint": true}})),
        vec!["hint:destructive", "hint:openworld"]
    );
    assert!(tool_hints(&json!({"annotations": {"readOnlyHint": "true"}})).is_empty());
    assert!(tool_hints(&json!({"annotations": []})).is_empty());
}
