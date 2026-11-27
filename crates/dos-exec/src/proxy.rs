//! The stdio MCP proxy. Port of `gateway/mcp_proxy.py` plus the govern flow of
//! `gateway/engine.py`. See `design/executor.md`.
//!
//! ```text
//! MCP client  <-- stdio -->  dos-exec  <-- stdio -->  governed server
//! ```
//!
//! Everything is relayed unchanged except `tools/call` and `resources/read`
//! requests, which run only after the decision engine allows them, and
//! `tools/list` replies, whose hints are remembered and whose hard-denied tools
//! are removed.

use crate::approvals::NonInteractive;
use crate::decision::{
    ApprovalOutcome, Approvals, AuditEvent, AuditSink, CallRequest, CancelToken, DecisionEngine,
    NoAudit, StaticVerdict, Verdict,
};
use crate::launch::{resolve_argv, slug};
use crate::strict;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

pub const BLOCK_HINT: &str = "The user can review this in the Decision OS dashboard (`decision-os ui`) \
or change ~/.decision-os/policy.toml.";

const GATED: [&str; 2] = ["tools/call", "resources/read"];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

fn method(m: &Value) -> Option<&str> {
    m.get("method").and_then(Value::as_str)
}

fn is_gated(m: &Value) -> bool {
    method(m).is_some_and(|x| GATED.contains(&x))
}

fn has_id(m: &Value) -> bool {
    m.as_object().is_some_and(|o| o.contains_key("id"))
}

/// Oracle `tool_hints`.
pub fn tool_hints(tool: &Value) -> Vec<String> {
    let Some(ann) = tool.get("annotations").and_then(Value::as_object) else {
        return Vec::new();
    };
    let yes = |k: &str| ann.get(k) == Some(&Value::Bool(true));
    let mut out = Vec::new();
    if yes("readOnlyHint") {
        out.push("hint:readonly".to_owned());
    }
    if yes("destructiveHint") && !yes("readOnlyHint") {
        out.push("hint:destructive".to_owned());
    }
    if yes("openWorldHint") {
        out.push("hint:openworld".to_owned());
    }
    out
}

/// The executor: a decision engine, a way to ask a human, and an audit sink.
pub struct Proxy {
    engine: Arc<dyn DecisionEngine>,
    approvals: Arc<dyn Approvals>,
    audit: Arc<dyn AuditSink>,
    server: String,
    max_parallel_calls: usize,
}

impl Proxy {
    /// Non-interactive (every `Ask` refused) and no audit until wired.
    pub fn new(engine: Arc<dyn DecisionEngine>, server: &str) -> Self {
        Self {
            engine,
            approvals: Arc::new(NonInteractive),
            audit: Arc::new(NoAudit),
            server: slug(server),
            max_parallel_calls: 8,
        }
    }

    pub fn with_approvals(mut self, a: Arc<dyn Approvals>) -> Self {
        self.approvals = a;
        self
    }

    pub fn with_audit(mut self, a: Arc<dyn AuditSink>) -> Self {
        self.audit = a;
        self
    }

    pub fn with_max_parallel_calls(mut self, n: usize) -> Self {
        self.max_parallel_calls = n.max(1);
        self
    }

    /// Proxy the process's own stdin/stdout.
    pub fn run_stdio(&self, argv: &[String]) -> i32 {
        self.run(argv, std::io::stdin(), std::io::stdout())
    }

    /// Launch `argv` and proxy `client_in`/`client_out` to it until either side
    /// closes. Returns the server's exit code, 127 if it cannot start, 2 on a bad command.
    pub fn run<R, W>(&self, argv: &[String], client_in: R, client_out: W) -> i32
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let argv = match resolve_argv(argv) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("decision-os: {e}");
                return 2;
            }
        };
        let Some((prog, args)) = argv.split_first() else {
            return 2;
        };
        let mut child = match Command::new(prog)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("decision-os: cannot start MCP server {argv:?}: {e}");
                return 127;
            }
        };
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            eprintln!("decision-os: cannot start MCP server {argv:?}: no pipes");
            let _ = child.kill();
            let _ = child.wait();
            return 127;
        };

        let (job_tx, job_rx) = channel::<Value>();
        let inner = Arc::new(Inner {
            engine: Arc::clone(&self.engine),
            approvals: Arc::clone(&self.approvals),
            audit: Arc::clone(&self.audit),
            server: self.server.clone(),
            out: Mutex::new(Box::new(client_out)),
            up: Mutex::new(Some(stdin)),
            st: Mutex::new(State::default()),
            jobs: Mutex::new(Some(job_tx)),
            workers: (Mutex::new(0), Condvar::new()),
            done: (Mutex::new(false), Condvar::new()),
        });

        let job_rx = Arc::new(Mutex::new(job_rx));
        for _ in 0..self.max_parallel_calls {
            *lock(&inner.workers.0) += 1;
            let (i, rx) = (Arc::clone(&inner), Arc::clone(&job_rx));
            if thread::Builder::new()
                .name("dos-call".into())
                .spawn(move || worker(&i, &rx))
                .is_err()
            {
                *lock(&inner.workers.0) -= 1;
            }
        }
        if *lock(&inner.workers.0) == 0 {
            eprintln!("decision-os: cannot start worker threads");
            return finish(&inner, child);
        }
        let i = Arc::clone(&inner);
        let up = thread::Builder::new()
            .name("dos-upstream".into())
            .spawn(move || pump_upstream(&i, stdout));
        let i = Arc::clone(&inner);
        let cl = thread::Builder::new()
            .name("dos-client".into())
            .spawn(move || pump_client(&i, client_in));
        if up.is_err() || cl.is_err() {
            eprintln!("decision-os: cannot start proxy threads");
            inner.set_done();
        }
        // The client reader may stay blocked in read() after the server exits;
        // it is detached, as in the oracle.
        inner.wait_done();
        finish(&inner, child)
    }
}

fn finish(inner: &Inner, mut child: Child) -> i32 {
    inner.close_jobs();
    inner.wait_workers();
    let _ = lock(&inner.out).flush();
    inner.close_upstream();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s.code().unwrap_or(1),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => break,
        }
    }
    let _ = child.kill();
    child.wait().ok().and_then(|s| s.code()).unwrap_or(1)
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Sender<Result<Value, String>>>,
    upstream_closed: bool,
    waiting: HashMap<String, CancelToken>,
    cancelled: HashSet<String>,
    list_ids: HashSet<String>,
    hints: HashMap<String, Vec<String>>,
}

struct Inner {
    engine: Arc<dyn DecisionEngine>,
    approvals: Arc<dyn Approvals>,
    audit: Arc<dyn AuditSink>,
    server: String,
    out: Mutex<Box<dyn Write + Send>>,
    up: Mutex<Option<ChildStdin>>,
    st: Mutex<State>,
    jobs: Mutex<Option<Sender<Value>>>,
    workers: (Mutex<usize>, Condvar),
    done: (Mutex<bool>, Condvar),
}

struct WorkerGuard<'a>(&'a Inner);

impl Drop for WorkerGuard<'_> {
    fn drop(&mut self) {
        let (m, c) = &self.0.workers;
        let mut n = lock(m);
        *n = n.saturating_sub(1);
        c.notify_all();
    }
}

fn worker(inner: &Inner, rx: &Mutex<Receiver<Value>>) {
    let _guard = WorkerGuard(inner);
    loop {
        let job = lock(rx).recv();
        match job {
            Ok(msg) => inner.gate_call(&msg),
            Err(_) => return,
        }
    }
}

fn pump_client<R: Read>(inner: &Inner, r: R) {
    let mut r = BufReader::new(r);
    let mut line = Vec::new();
    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if !line.trim_ascii().is_empty() {
                    inner.on_client(&line);
                }
            }
        }
    }
    // Client closed its side: abort approval waits (nobody can answer in time),
    // let in-flight calls finish and still write their replies, since a
    // half-closed client may still be reading, then stop the server.
    inner.cancel_all_waits();
    inner.close_jobs();
    inner.wait_workers();
    inner.close_upstream();
    inner.set_done();
}

fn pump_upstream<R: Read>(inner: &Inner, r: R) {
    let mut r = BufReader::new(r);
    let mut line = Vec::new();
    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if !line.trim_ascii().is_empty() {
                    inner.on_upstream(&line);
                }
            }
        }
    }
    let (pending, waits) = {
        let mut st = lock(&inner.st);
        st.upstream_closed = true;
        let p: Vec<_> = st.pending.drain().map(|(_, tx)| tx).collect();
        let w: Vec<_> = st.waiting.values().cloned().collect();
        (p, w)
    };
    for tx in pending {
        let _ = tx.send(Err("the MCP server exited".into()));
    }
    for w in waits {
        w.cancel();
    }
    inner.set_done();
}

enum Refusal {
    /// Tool result `isError` (or `-32001` for resources) with this reason.
    Blocked(String),
    /// JSON-RPC `-32603`.
    Internal(String),
}

impl Inner {
    // ---------------------------------------------------------------- io
    fn set_done(&self) {
        *lock(&self.done.0) = true;
        self.done.1.notify_all();
    }

    fn wait_done(&self) {
        let mut d = lock(&self.done.0);
        while !*d {
            d = self.done.1.wait(d).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn close_jobs(&self) {
        lock(&self.jobs).take();
    }

    fn wait_workers(&self) {
        let mut n = lock(&self.workers.0);
        while *n > 0 {
            n = self.workers.1.wait(n).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn close_upstream(&self) {
        lock(&self.up).take();
    }

    fn cancel_all_waits(&self) {
        let waits: Vec<_> = lock(&self.st).waiting.values().cloned().collect();
        for w in waits {
            w.cancel();
        }
    }

    fn to_client(&self, data: &[u8]) {
        let mut out = lock(&self.out);
        let body = data.trim_ascii_end();
        let ok = out
            .write_all(body)
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush());
        if ok.is_err() {
            drop(out);
            self.set_done();
        }
    }

    fn send_json(&self, msg: &Value) {
        match serde_json::to_vec(msg) {
            Ok(b) => self.to_client(&b),
            Err(e) => eprintln!("decision-os: cannot encode a reply: {e}"),
        }
    }

    fn to_upstream(&self, data: &[u8]) -> Result<(), String> {
        let mut up = lock(&self.up);
        let Some(w) = up.as_mut() else {
            return Err("the MCP server input is closed".into());
        };
        w.write_all(data.trim_ascii_end())
            .and_then(|()| w.write_all(b"\n"))
            .and_then(|()| w.flush())
            .map_err(|e| format!("cannot write to the MCP server: {e}"))
    }

    // ---------------------------------------------------------------- client -> server
    fn on_client(&self, raw: &[u8]) {
        let msg = match strict::parse(raw) {
            Ok(v) => v,
            Err(e) => {
                // Deviation from the oracle (which forwards it): fail closed.
                eprintln!("decision-os: dropped a client message that is not strict JSON: {e}");
                return;
            }
        };
        match msg {
            Value::Array(items) => {
                let mut rest = Vec::new();
                let mut calls = Vec::new();
                for m in items {
                    if is_gated(&m) && has_id(&m) {
                        calls.push(m);
                    } else if !self.ungated_effect(&m) {
                        self.track(&m);
                        rest.push(m);
                    }
                }
                if !rest.is_empty() {
                    match serde_json::to_vec(&Value::Array(rest)) {
                        Ok(b) => {
                            let _ = self.to_upstream(&b);
                        }
                        Err(e) => eprintln!("decision-os: dropped a batch: {e}"),
                    }
                }
                for m in calls {
                    self.submit(m);
                }
            }
            Value::Object(_) => {
                if is_gated(&msg) && has_id(&msg) {
                    self.submit(msg);
                } else if !self.ungated_effect(&msg) {
                    self.track(&msg);
                    let _ = self.to_upstream(raw);
                }
            }
            _ => {
                let _ = self.to_upstream(raw);
            }
        }
    }

    /// A gated method without an id would reach the server unchecked; dropped.
    fn ungated_effect(&self, m: &Value) -> bool {
        if m.is_object() && is_gated(m) && !has_id(m) {
            eprintln!(
                "decision-os: dropped {} sent without an id",
                method(m).unwrap_or_default()
            );
            return true;
        }
        false
    }

    fn track(&self, m: &Value) {
        let Some(o) = m.as_object() else { return };
        match method(m) {
            Some("tools/list") => {
                if let Some(id) = o.get("id") {
                    lock(&self.st).list_ids.insert(key(id));
                }
            }
            Some("notifications/cancelled") => {
                let rid = o
                    .get("params")
                    .and_then(|p| p.get("requestId"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let k = key(&rid);
                let tok = {
                    let mut st = lock(&self.st);
                    st.cancelled.insert(k.clone());
                    st.waiting.get(&k).cloned()
                };
                if let Some(t) = tok {
                    t.cancel();
                }
            }
            _ => {}
        }
    }

    fn submit(&self, msg: Value) {
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let k = key(&id);
        lock(&self.st).waiting.insert(k.clone(), CancelToken::new());
        let sent = match lock(&self.jobs).as_ref() {
            Some(tx) => tx.send(msg).is_ok(),
            None => false,
        };
        if !sent {
            lock(&self.st).waiting.remove(&k);
            self.send_error(&id, -32603, "Decision OS: the gateway is shutting down");
        }
    }

    fn send_error(&self, id: &Value, code: i64, message: &str) {
        self.send_json(
            &json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
        );
    }

    // ---------------------------------------------------------------- one call
    fn gate_call(&self, msg: &Value) {
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let k = key(&id);
        let cancel = lock(&self.st).waiting.get(&k).cloned().unwrap_or_default();
        let res = self.govern(msg, &id, &k, &cancel);
        lock(&self.st).waiting.remove(&k);
        let Some(res) = res else { return };
        let is_resource = method(msg) == Some("resources/read");
        match res {
            Ok(mut out) => {
                if let Some(o) = out.as_object_mut() {
                    o.insert("id".into(), id);
                }
                self.send_json(&out);
            }
            Err(Refusal::Internal(e)) => {
                self.send_error(&id, -32603, &format!("Decision OS: {e}"));
            }
            Err(Refusal::Blocked(reason)) => {
                if lock(&self.st).cancelled.remove(&k) {
                    return; // the client cancelled; MCP says no response is sent
                }
                let name = if is_resource {
                    "resources/read".to_owned()
                } else {
                    msg.get("params")
                        .and_then(|p| p.get("name"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                let text = format!(
                    "Decision OS blocked `{}/{}`: {}. {}",
                    self.server, name, reason, BLOCK_HINT
                );
                if is_resource {
                    self.send_error(&id, -32001, &text);
                } else {
                    self.send_json(&json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"content": [{"type": "text", "text": text}], "isError": true},
                    }));
                }
            }
        }
    }

    /// `None`: a reply was already sent (bad request).
    fn govern(
        &self,
        msg: &Value,
        id: &Value,
        k: &str,
        cancel: &CancelToken,
    ) -> Option<Result<Value, Refusal>> {
        let params: Map<String, Value> = msg
            .get("params")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let is_resource = method(msg) == Some("resources/read");
        let (name, arguments) = if is_resource {
            let mut a = Map::new();
            a.insert(
                "uri".into(),
                params.get("uri").cloned().unwrap_or(Value::Null),
            );
            (Some("resources/read".to_owned()), Value::Object(a))
        } else {
            (
                params
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                params.get("arguments").cloned().unwrap_or(Value::Null),
            )
        };
        let Some(name) = name.filter(|n| !n.is_empty()) else {
            self.send_error(id, -32602, "tools/call needs a tool name");
            return None;
        };
        let cap = format!("{}/{}", self.server, name);
        let arguments = match arguments {
            Value::Null => Map::new(),
            Value::Object(m) => m,
            _ => {
                return Some(Err(
                    self.refuse(&cap, "tool arguments must be a JSON object")
                ));
            }
        };
        let hints = lock(&self.st).hints.get(&name).cloned().unwrap_or_default();
        let req = CallRequest {
            server: self.server.clone(),
            tool: name,
            arguments,
            hints,
        };

        let reason = match self.engine.decide(&req, None) {
            Err(e) => {
                return Some(Err(
                    self.internal(&cap, &format!("decision engine error: {e}"))
                ));
            }
            Ok(Verdict::Deny { reason }) => return Some(Err(self.refuse(&cap, &reason))),
            Ok(Verdict::Allow { reason }) => {
                return Some(self.release(msg, &params, is_resource, &req, &cap, &reason, k));
            }
            Ok(Verdict::Ask {
                reason,
                approval_id,
            }) => match self.approvals.wait(&req, &approval_id, &reason, cancel) {
                ApprovalOutcome::Approved => {
                    return Some(match self.engine.decide(&req, Some(&approval_id)) {
                        Ok(Verdict::Allow { reason }) => {
                            self.release(msg, &params, is_resource, &req, &cap, &reason, k)
                        }
                        Ok(Verdict::Deny { reason }) => Err(self.refuse(&cap, &reason)),
                        Ok(Verdict::Ask { reason, .. }) => Err(self.refuse(
                            &cap,
                            &format!("the approval did not unlock this call ({reason})"),
                        )),
                        Err(e) => Err(self.internal(&cap, &format!("decision engine error: {e}"))),
                    });
                }
                ApprovalOutcome::Unavailable => reason,
                ApprovalOutcome::Denied => format!("denied by you ({reason})"),
                ApprovalOutcome::Expired => {
                    format!("no answer before the approval timeout ({reason})")
                }
                ApprovalOutcome::Cancelled => {
                    if lock(&self.st).upstream_closed {
                        format!("the MCP server exited ({reason})")
                    } else {
                        format!("the client cancelled the request ({reason})")
                    }
                }
            },
        };
        Some(Err(self.refuse(&cap, &reason)))
    }

    fn audit(
        &self,
        cap: &str,
        verdict: &'static str,
        reason: &str,
        executed: bool,
    ) -> Result<(), String> {
        self.audit.record(&AuditEvent {
            tool: cap.to_owned(),
            verdict,
            reason: reason.to_owned(),
            executed,
        })
    }

    fn refuse(&self, cap: &str, reason: &str) -> Refusal {
        if let Err(e) = self.audit(cap, "DENY", reason, false) {
            eprintln!("decision-os: audit write failed for a refusal: {e}");
        }
        Refusal::Blocked(reason.to_owned())
    }

    fn internal(&self, cap: &str, reason: &str) -> Refusal {
        if let Err(e) = self.audit(cap, "DENY", reason, false) {
            eprintln!("decision-os: audit write failed for a refusal: {e}");
        }
        Refusal::Internal(reason.to_owned())
    }

    /// The effect: forward the decided call and wait for the server's reply.
    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        msg: &Value,
        params: &Map<String, Value>,
        is_resource: bool,
        req: &CallRequest,
        cap: &str,
        reason: &str,
        k: &str,
    ) -> Result<Value, Refusal> {
        // Audit first: no record, no effect.
        if let Err(e) = self.audit(cap, "ALLOW", reason, true) {
            return Err(Refusal::Blocked(format!(
                "audit write failed (fail-closed): {e}"
            )));
        }
        let mut p = params.clone();
        if is_resource {
            p.insert(
                "uri".into(),
                req.arguments.get("uri").cloned().unwrap_or(Value::Null),
            );
        } else {
            p.insert("arguments".into(), Value::Object(req.arguments.clone()));
        }
        let mut fwd = msg.clone();
        if let Some(o) = fwd.as_object_mut() {
            o.insert("params".into(), Value::Object(p));
        }
        let bytes = serde_json::to_vec(&fwd).map_err(|e| Refusal::Internal(e.to_string()))?;
        let (tx, rx) = channel();
        {
            let mut st = lock(&self.st);
            if st.upstream_closed {
                return Err(Refusal::Internal("the MCP server exited".into()));
            }
            st.pending.insert(k.to_owned(), tx);
        }
        if let Err(e) = self.to_upstream(&bytes) {
            lock(&self.st).pending.remove(k);
            return Err(Refusal::Internal(e));
        }
        match rx.recv() {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(Refusal::Internal(e)),
            Err(_) => Err(Refusal::Internal("the MCP server exited".into())),
        }
    }

    // ---------------------------------------------------------------- server -> client
    fn on_upstream(&self, raw: &[u8]) {
        let Ok(msg) = serde_json::from_slice::<Value>(raw) else {
            self.to_client(raw);
            return;
        };
        if let Some(o) = msg.as_object()
            && !o.contains_key("method")
            && let Some(id) = o.get("id")
        {
            let k = key(id);
            let (tx, is_list) = {
                let mut st = lock(&self.st);
                (st.pending.remove(&k), st.list_ids.remove(&k))
            };
            if let Some(tx) = tx {
                let _ = tx.send(Ok(msg));
                return;
            }
            if is_list {
                let filtered = self.filter_tools(msg);
                self.send_json(&filtered);
                return;
            }
        }
        self.to_client(raw);
    }

    fn filter_tools(&self, mut msg: Value) -> Value {
        let Some(tools) = msg
            .get_mut("result")
            .and_then(|r| r.get_mut("tools"))
            .and_then(Value::as_array_mut)
        else {
            return msg;
        };
        let hide = self.engine.hide_denied_tools();
        tools.retain(|t| {
            let Some(name) = t.get("name").and_then(Value::as_str) else {
                return true;
            };
            let hints = tool_hints(t);
            lock(&self.st).hints.insert(name.to_owned(), hints.clone());
            if !hide {
                return true;
            }
            !matches!(
                self.engine.static_decision(&self.server, name, &hints),
                Ok(StaticVerdict::Deny) | Err(_)
            )
        });
        msg
    }
}
