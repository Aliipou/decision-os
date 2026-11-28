//! OpenAI chat completions stream: the oracle's `stream_chat`.

use crate::Refusal;
use crate::gate::{Gate, NO_NAME, UNRECOGNIZED, Verdict, judge, refuse};
use crate::json::{get, index_of, truthy};
use crate::sse::{Event, sse};
use crate::stream::Shaper;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn bad(why: &str) -> Refusal {
    Refusal::MalformedStream(why.to_owned())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Function,
    Custom,
    Legacy,
}

struct Call {
    id: Value,
    name: String,
    args: Vec<String>,
    kind: Kind,
    /// The deltas could be read as more than one call.
    ambiguous: bool,
}

pub(crate) struct ChatStream {
    buffering: bool,
    buffered: Vec<(Vec<u8>, Option<Value>)>,
    held: usize,
    calls: Vec<((i64, i64), Call)>,
    finish: BTreeMap<i64, Value>,
    late_text: BTreeMap<i64, Vec<String>>,
    role_sent: BTreeSet<i64>,
    template: Option<Value>,
    done_raw: Vec<u8>,
}

impl Default for ChatStream {
    fn default() -> Self {
        ChatStream {
            buffering: false,
            buffered: Vec::new(),
            held: 0,
            calls: Vec::new(),
            finish: BTreeMap::new(),
            late_text: BTreeMap::new(),
            role_sent: BTreeSet::new(),
            template: None,
            done_raw: b"data: [DONE]\n\n".to_vec(),
        }
    }
}

fn choices_of(chunk: &Value) -> Result<&[Value], Refusal> {
    match get(chunk, "choices") {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        Some(_) => Err(bad("choices is not a list")),
    }
}

fn delta_of(c: &Value) -> Result<Option<&Map<String, Value>>, Refusal> {
    match get(c, "delta") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(v) if !truthy(v) => Ok(None),
        Some(_) => Err(bad("delta is not an object")),
    }
}

fn str_piece(v: Option<&Value>, what: &str) -> Result<Option<String>, Refusal> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
        Some(v) if truthy(v) => Err(bad(&format!("{what} is not a string"))),
        _ => Ok(None),
    }
}

impl ChatStream {
    fn call(&mut self, key: (i64, i64), kind: Kind) -> Option<&mut Call> {
        if !self.calls.iter().any(|(k, _)| *k == key) {
            self.calls.push((
                key,
                Call {
                    id: Value::Null,
                    name: String::new(),
                    args: Vec::new(),
                    kind,
                    ambiguous: false,
                },
            ));
        }
        self.calls
            .iter_mut()
            .find(|(k, _)| *k == key)
            .map(|(_, c)| c)
    }

    fn absorb(&mut self, chunk: &Value) -> Result<(), Refusal> {
        for c in choices_of(chunk)? {
            if !c.is_object() {
                continue;
            }
            let ci = index_of(c, "index").map_err(|e| bad(&e))?;
            let delta = delta_of(c)?;
            if let Some(f) = get(c, "finish_reason").filter(|v| truthy(v)) {
                self.finish.insert(ci, f.clone());
            }
            let Some(delta) = delta else { continue };
            if let Some(text) = str_piece(delta.get("content"), "content")? {
                self.late_text.entry(ci).or_default().push(text);
            }
            let tcs: &[Value] = match delta.get("tool_calls") {
                None | Some(Value::Null) => &[],
                Some(Value::Array(a)) => a,
                Some(v) if !truthy(v) => &[],
                Some(_) => return Err(bad("tool_calls is not a list")),
            };
            for tc in tcs {
                let m = tc
                    .as_object()
                    .ok_or_else(|| bad("a tool call delta is not an object"))?;
                let key = (ci, index_of(tc, "index").map_err(|e| bad(&e))?);
                let custom = m.get("custom").filter(|v| v.is_object());
                let function = m.get("function").filter(|v| v.is_object());
                let declared = match m.get("type") {
                    Some(Value::String(t)) if !t.is_empty() => Some(t.clone()),
                    Some(v) if truthy(v) => return Err(bad("tool call type is not a string")),
                    _ => None,
                };
                let part_kind = if custom.is_some() {
                    Kind::Custom
                } else {
                    Kind::Function
                };
                let part = custom.or(function);
                let both = custom.is_some() && m.get("function").is_some_and(|v| !v.is_null());
                let Some(st) = self.call(key, Kind::Function) else {
                    return Err(bad("tool call state"));
                };
                if let Some(id) = m.get("id").filter(|v| truthy(v)) {
                    st.id = id.clone();
                }
                if let Some(t) = &declared {
                    st.kind = if t == "custom" {
                        Kind::Custom
                    } else {
                        Kind::Function
                    };
                    let names_part = (t == "custom") == (part_kind == Kind::Custom);
                    if part.is_some() && !names_part {
                        st.ambiguous = true;
                    }
                }
                if custom.is_some() {
                    st.kind = Kind::Custom;
                }
                if both || (st.kind == Kind::Custom && function.is_some()) {
                    st.ambiguous = true;
                }
                if let Some(p) = part {
                    if let Some(n) = str_piece(get(p, "name"), "tool call name")? {
                        st.name.push_str(&n);
                    }
                    let field = if st.kind == Kind::Custom {
                        "input"
                    } else {
                        "arguments"
                    };
                    if let Some(a) = str_piece(get(p, field), "tool call arguments")? {
                        st.args.push(a);
                    }
                }
            }
            match delta.get("function_call") {
                None | Some(Value::Null) => {}
                Some(v) if !truthy(v) => {}
                Some(Value::Object(fc)) => {
                    let name = str_piece(fc.get("name"), "function_call name")?;
                    let args = str_piece(fc.get("arguments"), "function_call arguments")?;
                    let Some(st) = self.call((ci, -1), Kind::Legacy) else {
                        return Err(bad("tool call state"));
                    };
                    if let Some(n) = name {
                        st.name.push_str(&n);
                    }
                    if let Some(a) = args {
                        st.args.push(a);
                    }
                }
                Some(_) => return Err(bad("function_call is not an object")),
            }
        }
        Ok(())
    }
}

fn starts_tool_call(chunk: &Value) -> Result<bool, Refusal> {
    for c in choices_of(chunk)? {
        if let Some(d) = get(c, "delta").and_then(Value::as_object)
            && (d.get("tool_calls").is_some_and(truthy)
                || d.get("function_call").is_some_and(truthy))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Shaper for ChatStream {
    fn held(&self) -> usize {
        self.held
    }

    fn event(
        &mut self,
        ev: Event,
        _gate: &mut dyn Gate,
        out: &mut Vec<u8>,
    ) -> Result<bool, Refusal> {
        if ev.data.is_none() {
            if self.buffering {
                self.held += ev.raw.len();
                self.buffered.push((ev.raw, None));
            } else {
                out.extend_from_slice(&ev.raw);
            }
            return Ok(false);
        }
        if ev.is_done() {
            self.done_raw = ev.raw;
            return Ok(true);
        }
        let Some(chunk) = ev.json()? else {
            return Ok(false);
        };
        let choices = choices_of(&chunk)?;
        if starts_tool_call(&chunk)? {
            self.buffering = true;
        }
        if self.template.is_none() && !choices.is_empty() {
            self.template = Some(chunk.clone());
        }
        if !self.buffering {
            for c in choices {
                if c.is_object()
                    && get(c, "delta")
                        .and_then(|d| get(d, "role"))
                        .is_some_and(truthy)
                {
                    let ci = index_of(c, "index").map_err(|e| bad(&e))?;
                    self.role_sent.insert(ci);
                }
            }
            out.extend_from_slice(&ev.raw);
            return Ok(false);
        }
        self.absorb(&chunk)?;
        self.held += ev.raw.len();
        self.buffered.push((ev.raw, Some(chunk)));
        Ok(false)
    }

    fn finish(&mut self, gate: &mut dyn Gate, out: &mut Vec<u8>) -> Result<(), Refusal> {
        if !self.buffering {
            out.extend_from_slice(&self.done_raw);
            return Ok(());
        }
        let mut verdicts: Vec<Verdict> = Vec::new();
        for (_, st) in &self.calls {
            let v = if st.ambiguous {
                refuse(
                    gate,
                    Some(&st.name).filter(|n| !n.is_empty()).map(|n| n.as_str()),
                    UNRECOGNIZED,
                )
            } else if st.name.is_empty() {
                refuse(gate, None, NO_NAME)
            } else if st.kind == Kind::Custom {
                let mut a = Map::new();
                a.insert("input".into(), Value::String(st.args.concat()));
                judge(gate, &st.name, Some(&Value::Object(a)))
            } else {
                judge(gate, &st.name, Some(&Value::String(st.args.concat())))
            };
            verdicts.push(v);
        }
        if verdicts.iter().all(|v| *v == Verdict::Keep) {
            for (raw, _) in &self.buffered {
                out.extend_from_slice(raw);
            }
            out.extend_from_slice(&self.done_raw);
            return Ok(());
        }
        let empty = Value::Object(Map::new());
        let tpl = self
            .template
            .as_ref()
            .or_else(|| self.buffered.first().and_then(|(_, p)| p.as_ref()))
            .unwrap_or(&empty);
        let mut base = Map::new();
        for k in ["id", "object", "created", "model", "system_fingerprint"] {
            if let Some(v) = get(tpl, k) {
                base.insert(k.to_owned(), v.clone());
            }
        }
        if !base.contains_key("object") {
            base.insert(
                "object".into(),
                Value::String("chat.completion.chunk".into()),
            );
        }
        let make = |ci: i64, delta: Map<String, Value>, fin: Value| -> Vec<u8> {
            let mut choice = Map::new();
            choice.insert("index".into(), Value::from(ci));
            choice.insert("delta".into(), Value::Object(delta));
            choice.insert("finish_reason".into(), fin);
            let mut chunk = base.clone();
            chunk.insert("choices".into(), Value::Array(vec![Value::Object(choice)]));
            sse(&Value::Object(chunk), None)
        };
        let mut cis: BTreeSet<i64> = self.calls.iter().map(|((ci, _), _)| *ci).collect();
        cis.extend(self.late_text.keys().copied());
        cis.extend(self.finish.keys().copied());
        for ci in cis {
            let mut role = Map::new();
            if !self.role_sent.contains(&ci) {
                role.insert("role".into(), Value::String("assistant".into()));
            }
            if let Some(text) = self.late_text.get(&ci).filter(|t| !t.is_empty()) {
                let mut d = std::mem::take(&mut role);
                d.insert("content".into(), Value::String(text.concat()));
                out.extend(make(ci, d, Value::Null));
            }
            let mut kept_n: i64 = 0;
            let mut notes: Vec<String> = Vec::new();
            for (((cci, _), st), v) in self.calls.iter().zip(&verdicts) {
                if *cci != ci {
                    continue;
                }
                if let Some(n) = v.note() {
                    notes.push(n.to_owned());
                    continue;
                }
                let mut args = v
                    .new_args()
                    .cloned()
                    .unwrap_or_else(|| Value::String(st.args.concat()));
                if st.kind == Kind::Custom && args.is_object() {
                    args = get(&args, "input")
                        .cloned()
                        .unwrap_or_else(|| Value::String(String::new()));
                }
                let mut d = std::mem::take(&mut role);
                let name = Value::String(st.name.clone());
                if st.kind == Kind::Legacy {
                    let mut fc = Map::new();
                    fc.insert("name".into(), name);
                    fc.insert("arguments".into(), args);
                    d.insert("function_call".into(), Value::Object(fc));
                } else {
                    let (ty, part, field) = if st.kind == Kind::Custom {
                        ("custom", "custom", "input")
                    } else {
                        ("function", "function", "arguments")
                    };
                    let mut p = Map::new();
                    p.insert("name".into(), name);
                    p.insert(field.into(), args);
                    let mut tc = Map::new();
                    tc.insert("index".into(), Value::from(kept_n));
                    tc.insert("id".into(), st.id.clone());
                    tc.insert("type".into(), Value::String(ty.into()));
                    tc.insert(part.into(), Value::Object(p));
                    d.insert("tool_calls".into(), Value::Array(vec![Value::Object(tc)]));
                }
                out.extend(make(ci, d, Value::Null));
                kept_n += 1;
            }
            if !notes.is_empty() {
                let mut d = role.clone();
                let lead = if self.role_sent.contains(&ci) {
                    "\n\n"
                } else {
                    ""
                };
                d.insert(
                    "content".into(),
                    Value::String(format!("{lead}{}", notes.join("\n"))),
                );
                out.extend(make(ci, d, Value::Null));
            }
            let mut fin = self.finish.get(&ci).cloned();
            if kept_n == 0
                && fin
                    .as_ref()
                    .and_then(Value::as_str)
                    .is_some_and(|f| f == "tool_calls" || f == "function_call")
            {
                fin = Some(Value::String("stop".into()));
            }
            let fin = fin.unwrap_or_else(|| {
                Value::String(if kept_n > 0 { "tool_calls" } else { "stop" }.into())
            });
            out.extend(make(ci, Map::new(), fin));
        }
        for (raw, parsed) in &self.buffered {
            if let Some(p) = parsed
                && !get(p, "choices").is_some_and(truthy)
            {
                out.extend_from_slice(raw);
            }
        }
        out.extend_from_slice(&self.done_raw);
        Ok(())
    }
}
