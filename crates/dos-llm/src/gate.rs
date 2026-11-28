//! The decision seam and the oracle's `ToolCallJudge`.

use crate::json::{dumps_py, parse_args_text};
use serde_json::{Map, Value};

/// What the decision layer says about one tool call.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// Release the call with these arguments (the input unchanged, or a LIMIT rewrite).
    Allow(Map<String, Value>),
    /// Remove the call; the reason goes into the note the client sees.
    Deny(String),
}

/// The decision layer as the gateway sees it. One `Gate` serves one response.
pub trait Gate {
    /// Decide one tool call (server `llm`). Must audit its own decision.
    fn govern(&mut self, tool: &str, args: &Map<String, Value>) -> Outcome;

    /// A call removed without a decision (unreadable format, no name, ambiguous
    /// arguments). Implementations audit it.
    fn refused(&mut self, tool: Option<&str>, reason: &str);

    /// A fresh id for a note message (`msg_dos_` + 20 hex digits in the oracle).
    fn note_id(&mut self) -> String;
}

pub(crate) const UNRECOGNIZED: &str =
    "[Decision OS] Blocked a tool call in an unrecognized format.";
pub(crate) const NO_NAME: &str = "[Decision OS] Blocked a tool call with no name.";

/// The verdict for one call: `(keep, new raw arguments, note)` in the oracle.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Verdict {
    Keep,
    Rewrite(Value),
    Block(String),
}

impl Verdict {
    pub(crate) fn ok(&self) -> bool {
        !matches!(self, Verdict::Block(_))
    }
    pub(crate) fn new_args(&self) -> Option<&Value> {
        match self {
            Verdict::Rewrite(v) => Some(v),
            _ => None,
        }
    }
    pub(crate) fn note(&self) -> Option<&str> {
        match self {
            Verdict::Block(n) => Some(n),
            _ => None,
        }
    }
}

/// A call removed without asking the decision layer.
pub(crate) fn refuse(gate: &mut dyn Gate, tool: Option<&str>, note: &str) -> Verdict {
    gate.refused(tool, note);
    Verdict::Block(note.to_owned())
}

fn ambiguous(gate: &mut dyn Gate, name: &str) -> Verdict {
    let note = format!(
        "[Decision OS] Blocked the `{name}` tool call: its arguments are ambiguous (duplicate keys)"
    );
    refuse(gate, Some(name), &note)
}

/// `ToolCallJudge.judge(name, raw_args)`.
pub(crate) fn judge(gate: &mut dyn Gate, name: &str, raw: Option<&Value>) -> Verdict {
    let was_string = matches!(raw, Some(Value::String(_)));
    let args: Value = match raw {
        Some(Value::String(s)) => {
            if s.trim().is_empty() {
                Value::Object(Map::new())
            } else {
                match parse_args_text(s) {
                    Err(_) => return ambiguous(gate, name),
                    Ok(Some(v)) => v,
                    Ok(None) => raw_object("_raw", Value::String(s.clone())),
                }
            }
        }
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(v) => v.clone(),
    };
    let args = match args {
        Value::Object(m) => m,
        other => match raw_object("_value", other) {
            Value::Object(m) => m,
            _ => Map::new(),
        },
    };
    judge_map(gate, name, args, was_string)
}

/// The judge for arguments already parsed from a stream (Anthropic `partial_json`).
pub(crate) fn judge_text_or(
    gate: &mut dyn Gate,
    name: &str,
    joined: &str,
    fallback: Option<&Value>,
) -> Verdict {
    if joined.trim().is_empty() {
        let fb = fallback.filter(|v| crate::json::truthy(v)).cloned();
        return judge(gate, name, Some(&fb.unwrap_or(Value::Object(Map::new()))));
    }
    match parse_args_text(joined) {
        Err(_) => ambiguous(gate, name),
        Ok(Some(v)) => judge(gate, name, Some(&v)),
        Ok(None) => judge(
            gate,
            name,
            Some(&raw_object("_raw", Value::String(joined.to_owned()))),
        ),
    }
}

fn raw_object(key: &str, v: Value) -> Value {
    let mut m = Map::new();
    m.insert(key.to_owned(), v);
    Value::Object(m)
}

fn judge_map(
    gate: &mut dyn Gate,
    name: &str,
    args: Map<String, Value>,
    was_string: bool,
) -> Verdict {
    match gate.govern(name, &args) {
        Outcome::Deny(reason) => Verdict::Block(format!(
            "[Decision OS] Blocked the `{name}` tool call: {reason}"
        )),
        Outcome::Allow(out) => {
            if out == args {
                return Verdict::Keep;
            }
            let only = |k: &str| out.len() == 1 && out.contains_key(k);
            let new = if only("_raw") {
                out.get("_raw").cloned().unwrap_or(Value::Null)
            } else if only("_value") {
                out.get("_value").cloned().unwrap_or(Value::Null)
            } else {
                Value::Object(out)
            };
            if was_string && !new.is_string() {
                Verdict::Rewrite(Value::String(dumps_py(&new)))
            } else {
                Verdict::Rewrite(new)
            }
        }
    }
}

/// `"\n".join(notes)` with the existing content in front, as the oracle's `_join_notes`.
pub(crate) fn join_notes(existing: Option<&Value>, notes: &[String]) -> Value {
    let text = notes.join("\n");
    match existing {
        Some(Value::String(s)) if !s.is_empty() => Value::String(format!("{s}\n\n{text}")),
        Some(Value::Array(a)) if !a.is_empty() => {
            let mut parts = a.clone();
            let mut part = Map::new();
            part.insert("type".into(), Value::String("text".into()));
            part.insert("text".into(), Value::String(text));
            parts.push(Value::Object(part));
            Value::Array(parts)
        }
        Some(v) if crate::json::truthy(v) => Value::String(format!("{}\n\n{text}", dumps_py(v))),
        _ => Value::String(text),
    }
}
