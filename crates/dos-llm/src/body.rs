//! Non-streaming bodies: the oracle's `gate_chat_completion`, `gate_anthropic_message`
//! and `gate_responses_body`, with the wrong-type cases refused instead of crashing.

use crate::Refusal;
use crate::gate::{Gate, UNRECOGNIZED, Verdict, join_notes, judge, refuse};
use crate::json::{dumps_py, get, name_of};
use serde_json::{Map, Value};

fn bad(why: &str) -> Refusal {
    Refusal::UnparseableBody(why.to_owned())
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

/// A list field: `Ok(None)` when absent or null, `Err` when present with another type.
fn list_field<'a>(
    m: &'a mut Map<String, Value>,
    key: &str,
) -> Result<Option<&'a mut Vec<Value>>, Refusal> {
    match m.get_mut(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) => Ok(Some(a)),
        Some(_) => Err(bad(&format!("{key} is not a list"))),
    }
}

// ------------------------------------------------------------------ chat

/// Which part of a chat tool call carries it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChatKind {
    Function,
    Custom,
}

/// `(name, raw arguments, kind)` of a chat tool call, or `None` when the client could
/// read it in more than one way or not at all.
fn chat_call(tc: &Value) -> Option<(String, Value, ChatKind)> {
    let m = tc.as_object()?;
    let present = |k: &str| m.get(k).is_some_and(|v| !v.is_null());
    if present("function") && present("custom") {
        return None;
    }
    let declared = m.get("type").and_then(Value::as_str);
    if let Some(f) = m.get("function").filter(|v| v.is_object()) {
        let name = name_of(get(f, "name"))?;
        if declared.is_some_and(|t| t != "function") {
            return None;
        }
        let args = get(f, "arguments").cloned().unwrap_or(Value::Null);
        return Some((name.to_owned(), args, ChatKind::Function));
    }
    if let Some(c) = m.get("custom").filter(|v| v.is_object()) {
        let name = name_of(get(c, "name"))?;
        if declared.is_some_and(|t| t != "custom") {
            return None;
        }
        let mut a = Map::new();
        a.insert(
            "input".into(),
            get(c, "input").cloned().unwrap_or_else(|| s("")),
        );
        return Some((name.to_owned(), Value::Object(a), ChatKind::Custom));
    }
    None
}

/// The custom tool `input` for rewritten arguments.
pub(crate) fn custom_input(new: &Value) -> Value {
    match new {
        Value::Object(m) => m.get("input").cloned().unwrap_or_else(|| s("")),
        Value::String(_) => new.clone(),
        other => Value::String(dumps_py(other)),
    }
}

fn chat_call_with(tc: &mut Value, kind: ChatKind, new: &Value) {
    let (part, field, value) = match kind {
        ChatKind::Custom => ("custom", "input", custom_input(new)),
        ChatKind::Function => ("function", "arguments", new.clone()),
    };
    if let Some(p) = tc.get_mut(part).and_then(Value::as_object_mut) {
        p.insert(field.to_owned(), value);
    }
}

pub(crate) fn gate_chat_completion(body: &mut Value, gate: &mut dyn Gate) -> Result<(), Refusal> {
    let obj = body
        .as_object_mut()
        .ok_or_else(|| bad("not a JSON object"))?;
    let Some(choices) = list_field(obj, "choices")? else {
        return Ok(());
    };
    for choice in choices.iter_mut() {
        let choice = choice
            .as_object_mut()
            .ok_or_else(|| bad("a choice is not an object"))?;
        let mut finish_to_stop = false;
        let Some(Value::Object(msg)) = choice.get_mut("message") else {
            continue;
        };
        let mut notes: Vec<String> = Vec::new();
        let mut changed = false;
        if let Some(tcs) = list_field(msg, "tool_calls")?
            && !tcs.is_empty()
        {
            let mut kept = Vec::new();
            for tc in tcs.iter() {
                let Some((name, args, kind)) = chat_call(tc) else {
                    let tool = get(tc, "function")
                        .or_else(|| get(tc, "custom"))
                        .and_then(|p| name_of(get(p, "name")));
                    notes.push(UNRECOGNIZED.to_owned());
                    refuse(gate, tool, UNRECOGNIZED);
                    continue;
                };
                match judge(gate, &name, Some(&args)) {
                    Verdict::Keep => kept.push(tc.clone()),
                    Verdict::Rewrite(new) => {
                        let mut tc = tc.clone();
                        chat_call_with(&mut tc, kind, &new);
                        changed = true;
                        kept.push(tc);
                    }
                    Verdict::Block(note) => notes.push(note),
                }
            }
            if !notes.is_empty() || changed {
                if kept.is_empty() {
                    msg.shift_remove("tool_calls");
                    finish_to_stop = true;
                } else {
                    msg.insert("tool_calls".into(), Value::Array(kept));
                }
            }
        }
        let mut fc_to_stop = false;
        match msg.get("function_call") {
            None | Some(Value::Null) => {}
            Some(fc) => {
                let fc = fc.clone();
                match name_of(get(&fc, "name")) {
                    None => {
                        msg.shift_remove("function_call");
                        notes.push(UNRECOGNIZED.to_owned());
                        refuse(gate, None, UNRECOGNIZED);
                        fc_to_stop = true;
                    }
                    Some(name) => match judge(gate, name, get(&fc, "arguments")) {
                        Verdict::Keep => {}
                        Verdict::Block(note) => {
                            msg.shift_remove("function_call");
                            notes.push(note);
                            fc_to_stop = true;
                        }
                        Verdict::Rewrite(new) => {
                            let mut fc = fc.clone();
                            if let Some(m) = fc.as_object_mut() {
                                m.insert("arguments".into(), new);
                            }
                            msg.insert("function_call".into(), fc);
                        }
                    },
                }
            }
        }
        if !notes.is_empty() {
            let content = join_notes(msg.get("content"), &notes);
            msg.insert("content".into(), content);
        }
        let fin = choice.get("finish_reason").and_then(Value::as_str);
        if (finish_to_stop && fin == Some("tool_calls"))
            || (fc_to_stop && fin == Some("function_call"))
        {
            choice.insert("finish_reason".into(), s("stop"));
        }
    }
    Ok(())
}

// ------------------------------------------------------------- anthropic

pub(crate) fn gate_anthropic_message(body: &mut Value, gate: &mut dyn Gate) -> Result<(), Refusal> {
    let obj = body
        .as_object_mut()
        .ok_or_else(|| bad("not a JSON object"))?;
    let Some(content) = list_field(obj, "content")? else {
        return Ok(());
    };
    let mut kept = Vec::new();
    let mut notes = Vec::new();
    for block in content.iter() {
        if get(block, "type").and_then(Value::as_str) != Some("tool_use") {
            kept.push(block.clone());
            continue;
        }
        let Some(name) = name_of(get(block, "name")) else {
            notes.push(UNRECOGNIZED.to_owned());
            refuse(gate, None, UNRECOGNIZED);
            continue;
        };
        match judge(gate, name, get(block, "input")) {
            Verdict::Keep => kept.push(block.clone()),
            Verdict::Rewrite(new) => {
                let mut b = block.clone();
                if let Some(m) = b.as_object_mut() {
                    m.insert("input".into(), new);
                }
                kept.push(b);
            }
            Verdict::Block(note) => notes.push(note),
        }
    }
    let mut stop_to_end = false;
    if !notes.is_empty() {
        let mut t = Map::new();
        t.insert("type".into(), s("text"));
        t.insert("text".into(), Value::String(notes.join("\n")));
        kept.push(Value::Object(t));
        stop_to_end = !kept
            .iter()
            .any(|b| get(b, "type").and_then(Value::as_str) == Some("tool_use"));
    }
    *content = kept;
    if stop_to_end && obj.get("stop_reason").and_then(Value::as_str) == Some("tool_use") {
        obj.insert("stop_reason".into(), s("end_turn"));
    }
    Ok(())
}

// ------------------------------------------------------------- responses

/// Responses API items the provider executes itself; every other `*_call` item is run
/// by the client and gated.
pub(crate) const SERVER_EXECUTED_ITEMS: [&str; 6] = [
    "web_search_call",
    "file_search_call",
    "code_interpreter_call",
    "image_generation_call",
    "mcp_call",
    "tool_search_call",
];

const ITEM_META: [&str; 5] = ["type", "id", "call_id", "status", "name"];

/// Is this a Responses item the client executes?
pub(crate) fn is_gated_item(item: &Value) -> bool {
    get(item, "type")
        .and_then(Value::as_str)
        .is_some_and(|t| t.ends_with("_call") && !SERVER_EXECUTED_ITEMS.contains(&t))
}

/// `(name, raw arguments)` of a gated item, `None` when its name is not a string.
pub(crate) fn response_item_args(item: &Value) -> Option<(String, Value)> {
    let t = get(item, "type").and_then(Value::as_str).unwrap_or("");
    let name = match get(item, "name") {
        None | Some(Value::Null) => None,
        Some(Value::String(n)) if n.is_empty() => None,
        Some(Value::String(n)) => Some(n.clone()),
        Some(_) => return None,
    };
    if t == "function_call" {
        let args = get(item, "arguments").cloned().unwrap_or(Value::Null);
        return Some((name.unwrap_or_else(|| "function".into()), args));
    }
    if t == "custom_tool_call" {
        let mut a = Map::new();
        a.insert(
            "input".into(),
            get(item, "input").cloned().unwrap_or_else(|| s("")),
        );
        return Some((
            name.unwrap_or_else(|| "custom_tool".into()),
            Value::Object(a),
        ));
    }
    // local_shell_call, shell_call, apply_patch_call, computer_call, future kinds: the
    // tool is named after the item type, its arguments are the item's other fields.
    let name = name.unwrap_or_else(|| t.strip_suffix("_call").unwrap_or(t).to_owned());
    let args: Map<String, Value> = item
        .as_object()
        .map(|m| {
            m.iter()
                .filter(|(k, _)| !ITEM_META.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    Some((name, Value::Object(args)))
}

/// Judges one gated item; an unreadable name is refused.
pub(crate) fn judge_item(gate: &mut dyn Gate, item: &Value) -> Verdict {
    match response_item_args(item) {
        Some((name, args)) => judge(gate, &name, Some(&args)),
        None => refuse(gate, None, UNRECOGNIZED),
    }
}

/// `_apply_response_item(item, new)`.
pub(crate) fn apply_response_item(item: &Value, new: &Value) -> Value {
    let t = get(item, "type").and_then(Value::as_str);
    let Some(m) = item.as_object() else {
        return item.clone();
    };
    match t {
        Some("function_call") => {
            let mut m = m.clone();
            m.insert("arguments".into(), new.clone());
            Value::Object(m)
        }
        Some("custom_tool_call") => {
            let mut m = m.clone();
            m.insert("input".into(), custom_input(new));
            Value::Object(m)
        }
        _ => match new {
            Value::Object(n) => {
                let mut out: Map<String, Value> = m
                    .iter()
                    .filter(|(k, _)| ITEM_META.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                for (k, v) in n {
                    out.insert(k.clone(), v.clone());
                }
                Value::Object(out)
            }
            _ => item.clone(),
        },
    }
}

/// `_note_item(notes)`.
pub(crate) fn note_item(notes: &[String], id: String) -> Value {
    let mut part = Map::new();
    part.insert("type".into(), s("output_text"));
    part.insert("text".into(), Value::String(notes.join("\n")));
    part.insert("annotations".into(), Value::Array(Vec::new()));
    let mut m = Map::new();
    m.insert("type".into(), s("message"));
    m.insert("id".into(), Value::String(id));
    m.insert("status".into(), s("completed"));
    m.insert("role".into(), s("assistant"));
    m.insert("content".into(), Value::Array(vec![Value::Object(part)]));
    Value::Object(m)
}

pub(crate) fn gate_response_output(output: &[Value], gate: &mut dyn Gate) -> Vec<Value> {
    let mut kept = Vec::new();
    let mut notes = Vec::new();
    for item in output {
        if !is_gated_item(item) {
            kept.push(item.clone());
            continue;
        }
        match judge_item(gate, item) {
            Verdict::Keep => kept.push(item.clone()),
            Verdict::Rewrite(new) => kept.push(apply_response_item(item, &new)),
            Verdict::Block(note) => notes.push(note),
        }
    }
    if !notes.is_empty() {
        let id = gate.note_id();
        kept.push(note_item(&notes, id));
    }
    kept
}

pub(crate) fn gate_responses_body(body: &mut Value, gate: &mut dyn Gate) -> Result<(), Refusal> {
    let obj = body
        .as_object_mut()
        .ok_or_else(|| bad("not a JSON object"))?;
    if let Some(out) = list_field(obj, "output")? {
        let kept = gate_response_output(out, gate);
        *out = kept;
    }
    Ok(())
}
