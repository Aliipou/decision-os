//! Test fixture: a minimal stdio MCP server, the Rust twin of
//! `oracle/decision-os-min/tests/gateway/fake_mcp_server.py`. Logs every
//! `tools/call` and `resources/read` it receives to argv[1] (or `FAKE_MCP_LOG`).
//! Extra tools for executor tests: `die` exits mid-call, `slow` answers after 300 ms.

use serde_json::{Value, json};
use std::io::{BufRead, Write};

fn send(out: &mut impl Write, msg: &Value) {
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}

fn log(entry: &Value) {
    if let Some(path) = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("FAKE_MCP_LOG").ok())
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let _ = writeln!(f, "{entry}");
    }
}

fn main() {
    let tools = json!([
        {"name": "read_file", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": true}},
        {"name": "write_file", "inputSchema": {"type": "object"}},
        {"name": "delete_everything", "inputSchema": {"type": "object"}},
        {"name": "frobnicate", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": true}},
        {"name": "ask_roots", "inputSchema": {"type": "object"}},
        {"name": "die", "inputSchema": {"type": "object"}},
        {"name": "slow", "inputSchema": {"type": "object"}},
    ]);
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut waiting_roots = Value::Null;
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if msg.is_array() {
            log(&json!({"name": "batch", "arguments": msg}));
            continue;
        }
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        match method {
            "initialize" => send(
                &mut out,
                &json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "1"}}}),
            ),
            "tools/list" => send(
                &mut out,
                &json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}}),
            ),
            "tools/call" => {
                let p = msg.get("params").cloned().unwrap_or(Value::Null);
                log(&p);
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                match name {
                    "ask_roots" => {
                        waiting_roots = id;
                        send(
                            &mut out,
                            &json!({"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"}),
                        );
                        continue;
                    }
                    "die" => std::process::exit(3),
                    "slow" => std::thread::sleep(std::time::Duration::from_millis(300)),
                    _ => {}
                }
                let text = p
                    .get("arguments")
                    .cloned()
                    .unwrap_or(Value::Null)
                    .to_string();
                send(
                    &mut out,
                    &json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": text}]}}),
                );
            }
            "resources/read" => {
                let params = msg.get("params").cloned().unwrap_or(Value::Null);
                log(&json!({"name": "resources/read", "arguments": params}));
                let uri = params.get("uri").cloned().unwrap_or(Value::Null);
                send(
                    &mut out,
                    &json!({"jsonrpc": "2.0", "id": id, "result": {"contents": [{"uri": uri, "text": "resource body"}]}}),
                );
            }
            "ping" => send(&mut out, &json!({"jsonrpc": "2.0", "id": id, "result": {}})),
            "notifications/initialized" => send(
                &mut out,
                &json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "hello"}}),
            ),
            "" if id == json!("srv-1") && msg.get("result").is_some() => {
                let text = msg
                    .get("result")
                    .cloned()
                    .unwrap_or(Value::Null)
                    .to_string();
                send(
                    &mut out,
                    &json!({"jsonrpc": "2.0", "id": waiting_roots, "result": {"content": [{"type": "text", "text": text}]}}),
                );
            }
            _ => {}
        }
    }
}
