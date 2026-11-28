//! OpenAI Responses stream: the oracle's `stream_responses`, plus the final
//! `response.output` gated on its own (a client may execute from it).

use crate::Refusal;
use crate::body::{apply_response_item, is_gated_item, judge_item, note_item};
use crate::gate::{Gate, Verdict};
use crate::json::{get, index_of};
use crate::sse::{Event, sse};
use crate::stream::Shaper;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

fn bad(why: &str) -> Refusal {
    Refusal::MalformedStream(why.to_owned())
}

const TERMINAL: [&str; 3] = [
    "response.completed",
    "response.incomplete",
    "response.failed",
];

fn is_terminal(t: Option<&str>) -> bool {
    t.is_some_and(|t| TERMINAL.contains(&t))
}

#[derive(Default)]
pub(crate) struct ResponsesStream {
    buffering: bool,
    buffered: Vec<(Vec<u8>, Option<String>, Option<Value>)>,
    held: usize,
}

fn output_of(p: &Value) -> Option<&Vec<Value>> {
    get(p, "response")
        .and_then(|r| get(r, "output"))
        .and_then(Value::as_array)
}

fn with(p: &Value, key: &str, v: Value) -> Value {
    let mut m = p.as_object().cloned().unwrap_or_default();
    m.insert(key.to_owned(), v);
    Value::Object(m)
}

fn in_progress(item: &Value) -> Value {
    with(item, "status", Value::String("in_progress".into()))
}

fn item_event(t: &str, oi: i64, item: Value) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), Value::String(t.into()));
    m.insert("output_index".into(), Value::from(oi));
    m.insert("item".into(), item);
    Value::Object(m)
}

impl Shaper for ResponsesStream {
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
        let t: Option<String> = match &parsed {
            Some(p) => get(p, "type").and_then(Value::as_str).map(str::to_owned),
            None => ev.name.clone(),
        };
        let gated_output = parsed
            .as_ref()
            .and_then(output_of)
            .is_some_and(|o| o.iter().any(is_gated_item));
        if gated_output && !is_terminal(t.as_deref()) {
            return Err(bad("a client-executed item in a non-final response"));
        }
        let gated_item = parsed
            .as_ref()
            .and_then(|p| get(p, "item"))
            .is_some_and(is_gated_item);
        let item_event = matches!(
            t.as_deref(),
            Some("response.output_item.added") | Some("response.output_item.done")
        );
        if !self.buffering && ((item_event && gated_item) || gated_output) {
            self.buffering = true;
        }
        if !self.buffering {
            out.extend_from_slice(&ev.raw);
            return Ok(false);
        }
        let stop = is_terminal(t.as_deref());
        self.held += ev.raw.len();
        self.buffered.push((ev.raw, t, parsed));
        Ok(stop)
    }

    fn finish(&mut self, gate: &mut dyn Gate, out: &mut Vec<u8>) -> Result<(), Refusal> {
        if !self.buffering {
            return Ok(());
        }
        // output_index -> final item, in the order the oracle builds its dict
        let mut final_items: Vec<(i64, Value)> = Vec::new();
        let mut added_only: Vec<(i64, Value)> = Vec::new();
        for (_, t, p) in &self.buffered {
            let Some(p) = p else { continue };
            let kind = t.as_deref();
            if kind != Some("response.output_item.done")
                && kind != Some("response.output_item.added")
            {
                continue;
            }
            let oi = index_of(p, "output_index").map_err(|e| bad(&e))?;
            let item = match get(p, "item") {
                None | Some(Value::Null) => Value::Object(Map::new()),
                Some(i @ Value::Object(_)) => i.clone(),
                Some(_) => return Err(bad("item is not an object")),
            };
            if kind == Some("response.output_item.done") {
                match final_items.iter_mut().find(|(i, _)| *i == oi) {
                    Some(slot) => slot.1 = item,
                    None => final_items.push((oi, item)),
                }
            } else if is_gated_item(&item) {
                match added_only.iter_mut().find(|(i, _)| *i == oi) {
                    Some(slot) => slot.1 = item,
                    None => added_only.push((oi, item)),
                }
            }
        }
        // A gated item that was added but never finished is judged as added.
        for (oi, item) in added_only {
            if !final_items.iter().any(|(i, _)| *i == oi) {
                final_items.push((oi, item));
            }
        }
        let mut verdicts: BTreeMap<i64, Verdict> = BTreeMap::new();
        let mut order: Vec<i64> = Vec::new();
        for (oi, item) in &final_items {
            if is_gated_item(item) {
                verdicts.insert(*oi, judge_item(gate, item));
                order.push(*oi);
            }
        }
        // The final response's own items: judged again when they differ.
        let mut final_verdicts: BTreeMap<i64, Verdict> = BTreeMap::new();
        let mut final_order: Vec<i64> = Vec::new();
        if let Some((_, _, Some(p))) = self
            .buffered
            .iter()
            .find(|(_, t, _)| is_terminal(t.as_deref()))
            && let Some(output) = output_of(p)
        {
            for (i, item) in output.iter().enumerate() {
                let oi = i64::try_from(i).map_err(|_| bad("output too long"))?;
                if !is_gated_item(item) {
                    continue;
                }
                let same = final_items.iter().any(|(k, v)| *k == oi && v == item);
                if same && verdicts.contains_key(&oi) {
                    continue;
                }
                final_verdicts.insert(oi, judge_item(gate, item));
                final_order.push(oi);
            }
        }
        if verdicts
            .values()
            .chain(final_verdicts.values())
            .all(|v| *v == Verdict::Keep)
        {
            for (raw, _, _) in &self.buffered {
                out.extend_from_slice(raw);
            }
            return Ok(());
        }
        let blocked = |oi: i64| {
            verdicts.get(&oi).is_some_and(|v| !v.ok())
                || final_verdicts.get(&oi).is_some_and(|v| !v.ok())
        };
        let mut notes: Vec<String> = Vec::new();
        for oi in &order {
            if let Some(n) = verdicts.get(oi).and_then(Verdict::note) {
                notes.push(n.to_owned());
            }
        }
        for oi in &final_order {
            if let Some(n) = final_verdicts.get(oi).and_then(Verdict::note) {
                notes.push(n.to_owned());
            }
        }
        let mut seq: Option<i64> = self.buffered.iter().find_map(|(_, _, p)| {
            p.as_ref()
                .and_then(|p| get(p, "sequence_number"))
                .and_then(Value::as_i64)
        });
        let floor = verdicts
            .keys()
            .chain(final_verdicts.keys())
            .min()
            .copied()
            .unwrap_or(0);
        let mut nxt = floor;
        let mut remap: BTreeMap<i64, i64> = BTreeMap::new();
        let note = if notes.is_empty() {
            None
        } else {
            Some(note_item(&notes, gate.note_id()))
        };
        let mut emit = |p: Value, t: &str, out: &mut Vec<u8>| {
            let p = match seq {
                Some(n) => {
                    seq = Some(n.saturating_add(1));
                    with(&p, "sequence_number", Value::from(n))
                }
                None => p,
            };
            out.extend(sse(&p, Some(t)));
        };
        for (raw, t, p) in &self.buffered {
            let (Some(p), Some(t)) = (p, t.as_deref()) else {
                out.extend_from_slice(raw);
                continue;
            };
            if is_terminal(Some(t)) {
                if let Some(n) = &note {
                    let added = "response.output_item.added";
                    emit(item_event(added, nxt, in_progress(n)), added, out);
                    let done = "response.output_item.done";
                    emit(item_event(done, nxt, n.clone()), done, out);
                }
                let mut resp = match get(p, "response") {
                    Some(Value::Object(m)) => m.clone(),
                    None | Some(Value::Null) => Map::new(),
                    Some(_) => return Err(bad("response is not an object")),
                };
                if let Some(Value::Array(output)) = resp.get("output") {
                    let mut kept = Vec::new();
                    for (i, item) in output.iter().enumerate() {
                        let oi = i64::try_from(i).map_err(|_| bad("output too long"))?;
                        if blocked(oi) {
                            continue;
                        }
                        let new = final_verdicts
                            .get(&oi)
                            .or_else(|| verdicts.get(&oi))
                            .and_then(Verdict::new_args);
                        kept.push(match new {
                            Some(n) => apply_response_item(item, n),
                            None => item.clone(),
                        });
                    }
                    if let Some(n) = &note {
                        kept.push(n.clone());
                    }
                    resp.insert("output".into(), Value::Array(kept));
                }
                emit(with(p, "response", Value::Object(resp)), t, out);
                continue;
            }
            let Some(oi) = get(p, "output_index").and_then(Value::as_i64) else {
                emit(p.clone(), t, out);
                continue;
            };
            if blocked(oi) {
                continue; // blocked item: drop all of its events
            }
            if oi < floor {
                emit(p.clone(), t, out);
                continue;
            }
            let new_oi = *remap.entry(oi).or_insert_with(|| {
                let n = nxt;
                nxt += 1;
                n
            });
            if let Some(new) = verdicts.get(&oi).and_then(Verdict::new_args) {
                // transformed: only full added/done items
                if t == "response.output_item.done" {
                    let item = apply_response_item(get(p, "item").unwrap_or(&Value::Null), new);
                    let added = "response.output_item.added";
                    emit(item_event(added, new_oi, in_progress(&item)), added, out);
                    let ev = with(&with(p, "output_index", Value::from(new_oi)), "item", item);
                    emit(ev, t, out);
                }
                continue;
            }
            emit(with(p, "output_index", Value::from(new_oi)), t, out);
        }
        Ok(())
    }
}
