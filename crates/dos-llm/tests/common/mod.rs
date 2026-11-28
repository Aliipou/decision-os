#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dos_llm::{Gate, Outcome};
use serde_json::{Map, Value, json};

/// A gate with fixed decisions per tool name, recording every call.
pub struct Scripted {
    pub decisions: Map<String, Value>,
    pub calls: Vec<Value>,
    pub refused: Vec<(Option<String>, String)>,
    pub n: u64,
}

impl Scripted {
    pub fn new(decisions: Value) -> Self {
        Scripted {
            decisions: decisions.as_object().cloned().unwrap_or_default(),
            calls: Vec::new(),
            refused: Vec::new(),
            n: 0,
        }
    }

    /// The oracle test policy (`conftest.BASE_POLICY` plus the Bash guardrail).
    pub fn policy() -> Self {
        Scripted::new(json!({
            "get_weather": {"allow": true},
            "delete_repo": {"deny": "repos are not deleted by agents"},
            "send_email": {"output": {"to": "a@b.c", "password": "[REDACTED]"}},
            "Bash": {"deny": "guardrail: recursive delete of / or home"},
            "shell": {"deny": "guardrail: recursive delete of / or home"},
        }))
    }

    pub fn allow_all() -> Self {
        Scripted::new(json!({"*": {"allow": true}}))
    }
}

impl Gate for Scripted {
    fn govern(&mut self, tool: &str, args: &Map<String, Value>) -> Outcome {
        self.calls.push(json!([tool, args]));
        let d = self
            .decisions
            .get(tool)
            .or_else(|| self.decisions.get("*"))
            .cloned()
            .unwrap_or(json!({"deny": "no decision in vector"}));
        if let Some(r) = d.get("deny") {
            return Outcome::Deny(r.as_str().unwrap().to_owned());
        }
        if let Some(o) = d.get("output") {
            return Outcome::Allow(o.as_object().unwrap().clone());
        }
        Outcome::Allow(args.clone())
    }

    fn refused(&mut self, tool: Option<&str>, reason: &str) {
        self.refused
            .push((tool.map(str::to_owned), reason.to_owned()));
    }

    fn note_id(&mut self) -> String {
        self.n += 1;
        format!("msg_dos_{:020x}", self.n)
    }
}

/// `(event name, data)` per SSE event, data parsed when it is JSON.
pub fn events(raw: &[u8]) -> Vec<Value> {
    let text = std::str::from_utf8(raw).unwrap();
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        if block.trim().is_empty() {
            continue;
        }
        let mut data = Vec::new();
        for line in block.lines() {
            if let Some(d) = line.strip_prefix("data:") {
                data.push(d.strip_prefix(' ').unwrap_or(d));
            }
        }
        let d = data.join("\n");
        if d == "[DONE]" {
            out.push(json!("[DONE]"));
        } else if !d.is_empty() {
            out.push(serde_json::from_str(&d).unwrap());
        }
    }
    out
}
