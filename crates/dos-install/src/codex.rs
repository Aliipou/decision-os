//! Codex `config.toml`: parse with toml_edit (spans kept), then replace exactly the
//! lines of the `command` / `args` statements the oracle replaces, with the text it
//! writes. Every other byte is untouched; the result is re-parsed and verified.

use std::ops::Range;
use std::path::Path;

use serde_json::{Map, Value, json};
use toml_edit::{Document, Item, TableLike};

use crate::clients::Format;
use crate::entry::{self, Shape};
use crate::pyjson::json_string;
use crate::{Action, Code, Ctx, FileReport, StateOp, Status, read_config};

/// A TOML value as JSON, for comparisons and the state file. Floats and datetimes
/// become tagged strings (only compared, never written as TOML).
fn item_json(item: &Item) -> Value {
    match item {
        Item::None => Value::Null,
        Item::Value(v) => value_json(v),
        Item::Table(t) => table_json(t),
        Item::ArrayOfTables(a) => Value::Array(a.iter().map(|t| table_json(t)).collect()),
    }
}

fn table_json(t: &dyn TableLike) -> Value {
    let mut m = Map::new();
    for (k, v) in t.iter() {
        m.insert(k.to_string(), item_json(v));
    }
    Value::Object(m)
}

fn value_json(v: &toml_edit::Value) -> Value {
    use toml_edit::Value as V;
    match v {
        V::String(s) => Value::String(s.value().clone()),
        V::Integer(i) => json!(*i.value()),
        V::Float(f) => json!({"$float": format!("{:?}", f.value())}),
        V::Boolean(b) => json!(*b.value()),
        V::Datetime(d) => json!({"$datetime": d.value().to_string()}),
        V::Array(a) => Value::Array(a.iter().map(value_json).collect()),
        V::InlineTable(t) => table_json(t),
    }
}

fn toml_array(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| json_string(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// The byte range of the whole lines from the line holding `start` through the line
/// holding `end` (its newline included).
fn whole_lines(text: &str, start: usize, end: usize) -> Range<usize> {
    let ls = text.get(..start).and_then(|t| t.rfind('\n')).map_or(0, |i| i + 1);
    let le = text
        .get(end..)
        .and_then(|t| t.find('\n'))
        .map_or(text.len(), |i| end + i + 1);
    ls..le
}

/// The lines of one statement `key = value` inside `table`, with the indent and the
/// newline of its first line.
struct Stmt {
    lines: Range<usize>,
    indent: String,
    nl: &'static str,
}

fn stmt(text: &str, table: &toml_edit::Table, key: &str) -> Option<Stmt> {
    let (k, item) = table.get_key_value(key)?;
    let ks = k.span()?;
    let vs = item.as_value()?.span()?;
    let lines = whole_lines(text, ks.start, vs.end);
    let indent: String = text
        .get(lines.start..ks.start)?
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    let first_end = text.get(ks.start..)?.find('\n').map(|i| ks.start + i);
    let nl = match first_end {
        Some(i) if i > 0 && text.as_bytes().get(i - 1) == Some(&b'\r') => "\r\n",
        _ => "\n",
    };
    Some(Stmt {
        lines,
        indent,
        nl,
    })
}

/// The splices that set `command` (and `args`, or remove it when `None`) of the
/// plain `[mcp_servers.<name>]` table; `None` when there is no such table.
fn edit_server(
    text: &str,
    doc: &Document<&str>,
    name: &str,
    command: &str,
    args: Option<&[String]>,
) -> Option<Vec<(Range<usize>, String)>> {
    let servers = doc.as_table().get("mcp_servers")?.as_table()?;
    let t = servers.get(name)?.as_table()?;
    if t.is_dotted() || t.is_implicit() {
        return None;
    }
    let cmd = stmt(text, t, "command")?;
    let line = |key: &str, val: String| format!("{}{key} = {val}{}", cmd.indent, cmd.nl);
    let new_cmd = line("command", json_string(command));
    let new_args = args.map(|a| line("args", toml_array(a)));
    let mut out = Vec::new();
    if t.contains_key("args") {
        let a = stmt(text, t, "args")?;
        out.push((cmd.lines, new_cmd));
        out.push((a.lines, new_args.unwrap_or_default()));
    } else {
        out.push((cmd.lines, new_cmd + &new_args.unwrap_or_default()));
    }
    Some(out)
}

pub(crate) fn process(
    cx: &mut Ctx<'_>,
    client: &'static str,
    path: &Path,
    path_str: &str,
    action: Action,
) -> FileReport {
    let fmt = Format::Codex;
    let (bytes, text) = match read_config(client, path, fmt) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut rep = FileReport::new(client, path, fmt);
    if text.starts_with('\u{feff}') {
        // tomllib refuses a BOM; so do we
        return rep.fail(Status::Error, Code::InvalidToml, "not valid TOML: byte order mark");
    }
    let doc = match Document::parse(text.as_str()) {
        Ok(d) => d,
        Err(e) => return rep.fail(Status::Error, Code::InvalidToml, format!("not valid TOML: {e}")),
    };
    let unchanged = |mut rep: FileReport| {
        rep.status = if action == Action::Status {
            Status::Ok
        } else {
            Status::Unchanged
        };
        rep
    };
    let Some(servers) = doc.as_table().get("mcp_servers").and_then(Item::as_table_like) else {
        return unchanged(rep);
    };
    let pointer = vec!["mcp_servers".to_string()];
    let mut splices: Vec<(Range<usize>, String)> = Vec::new();
    let mut expected: Vec<(String, String, Option<Vec<String>>)> = Vec::new();
    let mut ops = Vec::new();
    for (name, item) in servers.iter() {
        let Some(e) = item.as_table_like() else {
            continue;
        };
        let cmd = e.get("command").map(item_json);
        let args = e.get("args").map(item_json);
        let shape = entry::wrapped_shape(args.as_ref());
        if e.contains_key("url") {
            rep.remote.push(name.to_string());
            continue;
        }
        match action {
            Action::Status => {
                if cmd.as_ref().is_some_and(Value::is_string) {
                    if shape.is_some() {
                        rep.already.push(name.to_string());
                    } else {
                        rep.plain.push(name.to_string());
                    }
                }
            }
            Action::Install => {
                if let Some(sh) = shape {
                    if sh != Shape::Rust {
                        rep.legacy.push(name.to_string());
                    }
                    rep.already.push(name.to_string());
                    continue;
                }
                let Some(cmd_s) = cmd.as_ref().and_then(Value::as_str) else {
                    rep.note(
                        Code::InlineTransport,
                        format!("{name}: uses an inline transport table; wrap by hand"),
                    );
                    continue;
                };
                let arg_strs: Vec<String> = match args.as_ref() {
                    None => Vec::new(),
                    Some(Value::Array(a)) if a.iter().all(Value::is_string) => {
                        a.iter().filter_map(Value::as_str).map(str::to_string).collect()
                    }
                    Some(_) => {
                        rep.note(
                            Code::ArgsNotStrings,
                            format!("{name}: args is not a list of strings; skipped"),
                        );
                        continue;
                    }
                };
                let new_args = entry::wrap_args(&cx.home_str, client, name, cmd_s, &arg_strs);
                let Some(sp) = edit_server(&text, &doc, name, &cx.binary, Some(&new_args)) else {
                    rep.status = Status::Manual;
                    rep.note(
                        Code::NotPlainTable,
                        format!("{name}: not a plain [mcp_servers.{name}] table; wrap by hand"),
                    );
                    return rep;
                };
                splices.extend(sp);
                let mut orig = Map::new();
                orig.insert("command".into(), json!(cmd_s));
                if let Some(a) = &args {
                    orig.insert("args".into(), a.clone());
                }
                ops.push(StateOp::Remember {
                    pointer: pointer.clone(),
                    name: name.to_string(),
                    original: Value::Object(orig),
                });
                expected.push((name.to_string(), cx.binary.clone(), Some(new_args)));
                rep.wrapped.push(name.to_string());
            }
            Action::Uninstall => {
                if shape.is_none() {
                    continue;
                }
                let a = args.as_ref().and_then(Value::as_array).cloned().unwrap_or_default();
                let Ok((o_cmd, o_args)) = entry::unwrap_args(&a) else {
                    rep.note(
                        Code::NoOriginalCommand,
                        format!("{name}: wrapped entry has no original command"),
                    );
                    continue;
                };
                let (Some(o_cmd), true) = (o_cmd.as_str(), o_args.iter().all(Value::is_string)) else {
                    rep.note(
                        Code::ArgsNotStrings,
                        format!("{name}: args is not a list of strings; skipped"),
                    );
                    continue;
                };
                let o_args: Vec<String> = o_args.iter().filter_map(Value::as_str).map(str::to_string).collect();
                let orig = cx.state.original(path_str, &pointer, name);
                let keep_args = match orig {
                    Some(o)
                        if !o.is_empty()
                            && o.get("command").and_then(Value::as_str) == Some(o_cmd)
                            && !o.contains_key("args")
                            && o_args.is_empty() =>
                    {
                        None
                    }
                    _ => Some(o_args),
                };
                let Some(sp) = edit_server(&text, &doc, name, o_cmd, keep_args.as_deref()) else {
                    rep.status = Status::Manual;
                    rep.note(Code::TableNotFound, format!("{name}: could not locate its table"));
                    return rep;
                };
                splices.extend(sp);
                ops.push(StateOp::Forget {
                    pointer: pointer.clone(),
                    name: name.to_string(),
                });
                expected.push((name.to_string(), o_cmd.to_string(), keep_args));
                rep.unwrapped.push(name.to_string());
            }
        }
    }
    if action == Action::Status || expected.is_empty() {
        return unchanged(rep);
    }
    splices.sort_by_key(|(r, _)| std::cmp::Reverse(r.start));
    let mut new_text = text.clone();
    for (r, s) in &splices {
        if new_text.get(r.clone()).is_none() {
            rep.status = Status::Error;
            rep.note(Code::VerifyFailed, "verification failed: overlapping edits; not written");
            return rep;
        }
        new_text.replace_range(r.clone(), s);
    }
    let new_doc = match Document::parse(new_text.as_str()) {
        Ok(d) => d,
        Err(e) => {
            rep.status = Status::Error;
            rep.note(
                Code::EditInvalidToml,
                format!("edit produced invalid TOML ({e}); not written"),
            );
            return rep;
        }
    };
    let mut old_data = item_json(doc.as_item());
    let mut new_data = item_json(new_doc.as_item());
    for (name, cmd, args) in &expected {
        let got = new_data.pointer(&format!("/mcp_servers/{}", ptr_escape(name)));
        let want_args = args.as_ref().map(|a| json!(a));
        if got.and_then(|g| g.get("command")) != Some(&json!(cmd))
            || got.and_then(|g| g.get("args")) != want_args.as_ref()
        {
            rep.status = Status::Error;
            rep.note(Code::VerifyFailed, format!("verification failed for {name}; not written"));
            return rep;
        }
        for d in [&mut old_data, &mut new_data] {
            if let Some(m) = d
                .get_mut("mcp_servers")
                .and_then(|s| s.get_mut(name.as_str()))
                .and_then(Value::as_object_mut)
            {
                m.shift_remove("command");
                m.shift_remove("args");
            }
        }
    }
    if old_data != new_data {
        rep.status = Status::Error;
        rep.note(
            Code::VerifyFailed,
            "verification failed: other settings changed; not written",
        );
        return rep;
    }
    if !cx.dry_run {
        let install = action == Action::Install;
        if let Err(m) = cx.commit(client, path, path_str, &bytes, new_text.as_bytes(), install, ops) {
            rep.status = Status::Error;
            rep.message = Some(m);
        }
    }
    rep
}

fn ptr_escape(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}
