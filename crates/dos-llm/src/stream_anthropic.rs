//! Anthropic Messages stream: the oracle's `stream_anthropic`.

use crate::Refusal;
use crate::gate::{Gate, UNRECOGNIZED, Verdict, judge_text_or, refuse};
use crate::json::{dumps_py, get, index_of, name_of, truthy};
use crate::sse::{Event, sse};
use crate::stream::Shaper;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

fn bad(why: &str) -> Refusal {
    Refusal::MalformedStream(why.to_owned())
}

#[derive(Default)]
pub(crate) struct AnthropicStream {
    buffering: bool,
    buffered: Vec<(Vec<u8>, Option<Value>)>,
    held: usize,
    first_idx: i64,
}

fn type_of(p: &Value) -> Option<&str> {
    get(p, "type").and_then(Value::as_str)
}

fn is_tool_use(b: &Value) -> bool {
    type_of(b) == Some("tool_use")
}

fn with(p: &Value, key: &str, v: Value) -> Value {
    let mut m = p.as_object().cloned().unwrap_or_default();
    m.insert(key.to_owned(), v);
    Value::Object(m)
}

fn event_name(p: &Value) -> Option<&str> {
    type_of(p).filter(|t| !t.is_empty())
}

impl Shaper for AnthropicStream {
    fn held(&self) -> usize {
        self.held
    }

    fn event(
        &mut self,
        ev: Event,
        _gate: &mut dyn Gate,
        out: &mut Vec<u8>,
    ) -> Result<bool, Refusal> {
        let parsed = ev.json()?;
        let t = parsed.as_ref().and_then(type_of).map(str::to_owned);
        if t.as_deref() == Some("message_start")
            && let Some(p) = &parsed
            && let Some(content) = get(p, "message").and_then(|m| get(m, "content"))
            && content
                .as_array()
                .is_some_and(|a| a.iter().any(is_tool_use))
        {
            return Err(bad("tool_use inside message_start"));
        }
        if !self.buffering
            && t.as_deref() == Some("content_block_start")
            && let Some(p) = &parsed
            && get(p, "content_block").is_some_and(is_tool_use)
        {
            self.buffering = true;
            self.first_idx = index_of(p, "index").map_err(|e| bad(&e))?;
        }
        if !self.buffering {
            out.extend_from_slice(&ev.raw);
            return Ok(false);
        }
        self.held += ev.raw.len();
        self.buffered.push((ev.raw, parsed));
        Ok(t.as_deref() == Some("message_stop"))
    }

    fn finish(&mut self, gate: &mut dyn Gate, out: &mut Vec<u8>) -> Result<(), Refusal> {
        if !self.buffering {
            return Ok(());
        }
        // index -> (content block, partial json pieces), in start order
        let mut blocks: Vec<(i64, Value, Vec<String>)> = Vec::new();
        for (_, p) in &self.buffered {
            let Some(p) = p else { continue };
            match type_of(p) {
                Some("content_block_start") => {
                    let idx = index_of(p, "index").map_err(|e| bad(&e))?;
                    if blocks.iter().any(|(i, _, _)| *i == idx) {
                        return Err(bad("two content blocks with one index"));
                    }
                    let block = match get(p, "content_block") {
                        None | Some(Value::Null) => Value::Object(Map::new()),
                        Some(b @ Value::Object(_)) => b.clone(),
                        Some(_) => return Err(bad("content_block is not an object")),
                    };
                    blocks.push((idx, block, Vec::new()));
                }
                Some("content_block_delta") => {
                    let idx = index_of(p, "index").map_err(|e| bad(&e))?;
                    let d = get(p, "delta").cloned().unwrap_or(Value::Null);
                    if type_of(&d) == Some("input_json_delta")
                        && let Some((_, _, json)) = blocks.iter_mut().find(|(i, _, _)| *i == idx)
                    {
                        match get(&d, "partial_json") {
                            None | Some(Value::Null) => {}
                            Some(Value::String(s)) => json.push(s.clone()),
                            Some(_) => return Err(bad("partial_json is not a string")),
                        }
                    }
                }
                _ => {}
            }
        }
        let mut verdicts: BTreeMap<i64, Verdict> = BTreeMap::new();
        let mut order: Vec<i64> = Vec::new();
        for (idx, block, json) in &blocks {
            if !is_tool_use(block) {
                continue;
            }
            let v = match name_of(get(block, "name")) {
                None => refuse(gate, None, UNRECOGNIZED),
                Some(name) => judge_text_or(gate, name, &json.concat(), get(block, "input")),
            };
            verdicts.insert(*idx, v);
            order.push(*idx);
        }
        if verdicts.values().all(|v| *v == Verdict::Keep) {
            for (raw, _) in &self.buffered {
                out.extend_from_slice(raw);
            }
            return Ok(());
        }
        let notes: Vec<String> = order
            .iter()
            .filter_map(|i| verdicts.get(i).and_then(Verdict::note))
            .map(str::to_owned)
            .collect();
        let any_tool_kept = verdicts.values().any(Verdict::ok);
        let mut remap: BTreeMap<i64, i64> = BTreeMap::new();
        let mut nxt = self.first_idx;
        let mut note_written = false;

        let mut emit_note = |out: &mut Vec<u8>, nxt: &mut i64| {
            if notes.is_empty() || note_written {
                return;
            }
            let mut start = Map::new();
            start.insert("type".into(), "content_block_start".into());
            start.insert("index".into(), Value::from(*nxt));
            let mut cb = Map::new();
            cb.insert("type".into(), "text".into());
            cb.insert("text".into(), "".into());
            start.insert("content_block".into(), Value::Object(cb));
            out.extend(sse(&Value::Object(start), Some("content_block_start")));
            let mut delta = Map::new();
            delta.insert("type".into(), "content_block_delta".into());
            delta.insert("index".into(), Value::from(*nxt));
            let mut td = Map::new();
            td.insert("type".into(), "text_delta".into());
            td.insert("text".into(), Value::String(notes.join("\n")));
            delta.insert("delta".into(), Value::Object(td));
            out.extend(sse(&Value::Object(delta), Some("content_block_delta")));
            let mut stop = Map::new();
            stop.insert("type".into(), "content_block_stop".into());
            stop.insert("index".into(), Value::from(*nxt));
            out.extend(sse(&Value::Object(stop), Some("content_block_stop")));
            *nxt += 1;
            note_written = true;
        };

        for (raw, p) in &self.buffered {
            let Some(p) = p else {
                out.extend_from_slice(raw);
                continue;
            };
            let t = type_of(p);
            match t {
                Some("content_block_start") => {
                    let idx = index_of(p, "index").map_err(|e| bad(&e))?;
                    let v = verdicts.get(&idx);
                    if v.is_some_and(|v| !v.ok()) {
                        continue;
                    }
                    remap.insert(idx, nxt);
                    let new_idx = Value::from(nxt);
                    nxt += 1;
                    if let Some(new) = v.and_then(Verdict::new_args) {
                        let blk = with(
                            get(p, "content_block").unwrap_or(&Value::Null),
                            "input",
                            Value::Object(Map::new()),
                        );
                        let ev = with(&with(p, "index", new_idx.clone()), "content_block", blk);
                        out.extend(sse(&ev, t));
                        let mut d = Map::new();
                        d.insert("type".into(), "content_block_delta".into());
                        d.insert("index".into(), new_idx);
                        let mut ij = Map::new();
                        ij.insert("type".into(), "input_json_delta".into());
                        ij.insert("partial_json".into(), Value::String(dumps_py(new)));
                        d.insert("delta".into(), Value::Object(ij));
                        out.extend(sse(&Value::Object(d), Some("content_block_delta")));
                    } else {
                        out.extend(sse(&with(p, "index", new_idx), t));
                    }
                }
                Some("content_block_delta") | Some("content_block_stop") => {
                    let idx = index_of(p, "index").map_err(|e| bad(&e))?;
                    let Some(new_idx) = remap.get(&idx) else {
                        continue;
                    };
                    let v = verdicts.get(&idx);
                    if t == Some("content_block_delta") && v.and_then(Verdict::new_args).is_some() {
                        continue;
                    }
                    out.extend(sse(&with(p, "index", Value::from(*new_idx)), t));
                }
                Some("message_delta") => {
                    emit_note(out, &mut nxt);
                    let mut delta = match get(p, "delta") {
                        Some(Value::Object(m)) => m.clone(),
                        Some(v) if truthy(v) => return Err(bad("delta is not an object")),
                        _ => Map::new(),
                    };
                    if !any_tool_kept
                        && delta.get("stop_reason").and_then(Value::as_str) == Some("tool_use")
                    {
                        delta.insert("stop_reason".into(), "end_turn".into());
                    }
                    out.extend(sse(&with(p, "delta", Value::Object(delta)), t));
                }
                _ => {
                    if t == Some("message_stop") {
                        emit_note(out, &mut nxt);
                    }
                    match event_name(p) {
                        Some(name) => out.extend(sse(p, Some(name))),
                        None => out.extend_from_slice(raw),
                    }
                }
            }
        }
        emit_note(out, &mut nxt);
        Ok(())
    }
}
