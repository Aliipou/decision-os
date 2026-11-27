//! JSON client configs (`mcpServers`, VS Code `servers`, `~/.claude.json`): the
//! oracle's `_process_json`, with the printer of [`crate::pyjson`].

use std::path::Path;

use serde_json::{Map, Value};

use crate::clients::Format;
use crate::entry::{self, Shape};
use crate::pyjson::{self, Indent};
use crate::{Action, Code, Ctx, FileReport, StateOp, Status, read_config};

/// The pointers of every server table (oracle `_server_tables`).
fn server_tables(fmt: Format, data: &Map<String, Value>) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let key = if fmt == Format::Servers {
        "servers"
    } else {
        "mcpServers"
    };
    if data.get(key).is_some_and(Value::is_object) {
        out.push(vec![key.to_string()]);
    }
    if fmt == Format::ClaudeCode {
        if let Some(projects) = data.get("projects").and_then(Value::as_object) {
            for (proj, cfg) in projects {
                let non_empty = cfg
                    .get("mcpServers")
                    .and_then(Value::as_object)
                    .is_some_and(|m| !m.is_empty());
                if non_empty {
                    out.push(vec![
                        "projects".to_string(),
                        proj.clone(),
                        "mcpServers".to_string(),
                    ]);
                }
            }
        }
    }
    out
}

fn table_mut<'a>(data: &'a mut Map<String, Value>, pointer: &[String]) -> Option<&'a mut Map<String, Value>> {
    let (first, rest) = pointer.split_first()?;
    let mut node = data.get_mut(first)?;
    for k in rest {
        node = node.as_object_mut()?.get_mut(k)?;
    }
    node.as_object_mut()
}

/// The data with `command` and `args` removed from every server entry (oracle
/// `_strip_servers`).
fn strip_servers(data: &Map<String, Value>, fmt: Format) -> Map<String, Value> {
    let mut d = data.clone();
    for pointer in server_tables(fmt, data) {
        if let Some(t) = table_mut(&mut d, &pointer) {
            for (_, e) in t.iter_mut() {
                if let Some(m) = e.as_object_mut() {
                    m.shift_remove("command");
                    m.shift_remove("args");
                }
            }
        }
    }
    d
}

fn all_strings(a: &[Value]) -> bool {
    a.iter().all(Value::is_string)
}

/// `list(v or [])` for an `args` value that is null, missing or a list.
fn args_list(v: Option<&Value>) -> Option<Vec<Value>> {
    match v {
        None => Some(Vec::new()),
        Some(Value::Array(a)) => Some(a.clone()),
        Some(v) if !entry::truthy(v) => Some(Vec::new()),
        Some(_) => None,
    }
}

pub(crate) fn process(
    cx: &mut Ctx<'_>,
    client: &'static str,
    path: &Path,
    path_str: &str,
    fmt: Format,
    action: Action,
    force_jsonc: bool,
) -> FileReport {
    let (bytes, text) = match read_config(client, path, fmt) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut rep = FileReport::new(client, path, fmt);
    if pyjson::is_blank(&text) {
        rep.status = Status::Unchanged;
        return rep;
    }
    let (parsed, has_comments) = match serde_json::from_str::<Value>(&text) {
        Ok(v) => (v, false),
        Err(_) => match serde_json::from_str::<Value>(&pyjson::strip_jsonc(&text)) {
            Ok(v) => (v, true),
            Err(e) => {
                return rep.fail(Status::Error, Code::InvalidJson, format!("not valid JSON: {e}"));
            }
        },
    };
    let Value::Object(mut data) = parsed else {
        return rep.fail(Status::Error, Code::NotObject, "top level is not an object");
    };
    let original = data.clone();
    let mut changed = false;
    let mut ops: Vec<StateOp> = Vec::new();
    for pointer in server_tables(fmt, &original) {
        let label = match pointer.get(1) {
            Some(p) if pointer.len() > 1 => format!("[{p}] "),
            _ => String::new(),
        };
        let names: Vec<String> = match table_mut(&mut data, &pointer) {
            Some(t) => t.keys().cloned().collect(),
            None => continue,
        };
        for name in names {
            let Some(servers) = table_mut(&mut data, &pointer) else {
                continue;
            };
            let Some(Value::Object(entry)) = servers.get_mut(&name) else {
                continue;
            };
            let tag = format!("{label}{name}");
            let cmd = entry.get("command").cloned();
            let args = entry.get("args").cloned();
            let shape = entry::wrapped_shape(args.as_ref());
            match action {
                Action::Status => {
                    if entry::is_remote(entry) {
                        rep.remote.push(tag);
                    } else if shape.is_some() {
                        rep.already.push(tag);
                    } else if cmd.as_ref().is_some_and(Value::is_string) {
                        rep.plain.push(tag);
                    }
                }
                Action::Install => {
                    if entry::is_remote(entry) {
                        rep.remote.push(tag);
                        continue;
                    }
                    if let Some(sh) = shape {
                        if sh != Shape::Rust {
                            rep.legacy.push(tag.clone());
                        }
                        rep.already.push(tag);
                        continue;
                    }
                    let Some(cmd_s) = cmd.as_ref().and_then(Value::as_str).filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    let arg_strs: Vec<String> = match args.as_ref() {
                        None | Some(Value::Null) => Vec::new(),
                        Some(Value::Array(a)) if all_strings(a) => {
                            a.iter().filter_map(Value::as_str).map(str::to_string).collect()
                        }
                        Some(_) => {
                            rep.note(
                                Code::ArgsNotStrings,
                                format!("{tag}: args is not a list of strings; skipped"),
                            );
                            continue;
                        }
                    };
                    let new_args = entry::wrap_args(&cx.home_str, client, &name, cmd_s, &arg_strs);
                    ops.push(StateOp::Remember {
                        pointer: pointer.clone(),
                        name: name.clone(),
                        original: Value::Object(entry.clone()),
                    });
                    entry.insert("command".into(), Value::String(cx.binary.clone()));
                    entry.insert(
                        "args".into(),
                        Value::Array(new_args.into_iter().map(Value::String).collect()),
                    );
                    rep.wrapped.push(tag);
                    changed = true;
                }
                Action::Uninstall => {
                    if shape.is_none() {
                        continue;
                    }
                    let a = args.as_ref().and_then(Value::as_array).cloned().unwrap_or_default();
                    let (o_cmd, o_args) = match entry::unwrap_args(&a) {
                        Ok(x) => x,
                        Err(_) => {
                            rep.note(
                                Code::NoOriginalCommand,
                                format!("{tag}: wrapped entry has no original command"),
                            );
                            continue;
                        }
                    };
                    let orig = cx
                        .state
                        .original(path_str, &pointer, &name)
                        .filter(|m| !m.is_empty())
                        .cloned();
                    let mut restored = entry.clone();
                    let exact = orig.as_ref().is_some_and(|o| {
                        o.get("command") == Some(&o_cmd)
                            && args_list(o.get("args")).as_ref() == Some(&o_args)
                    });
                    match orig {
                        Some(o) if exact => {
                            for k in ["command", "args"] {
                                if let Some(v) = o.get(k) {
                                    restored.insert(k.into(), v.clone());
                                }
                            }
                            if !o.contains_key("args") {
                                restored.shift_remove("args");
                            }
                        }
                        _ => {
                            restored.insert("command".into(), o_cmd);
                            restored.insert("args".into(), Value::Array(o_args));
                        }
                    }
                    *entry = restored;
                    ops.push(StateOp::Forget {
                        pointer: pointer.clone(),
                        name: name.clone(),
                    });
                    rep.unwrapped.push(tag);
                    changed = true;
                }
            }
        }
    }
    if action == Action::Status {
        rep.status = Status::Ok;
        return rep;
    }
    if !changed {
        rep.status = Status::Unchanged;
        return rep;
    }
    if has_comments && !force_jsonc {
        rep.status = Status::Manual;
        rep.note(
            Code::Jsonc,
            "file contains comments, which a rewrite would drop; re-run with --force-jsonc \
             (a backup is kept) or wrap by hand",
        );
        if action == Action::Install {
            rep.plain = std::mem::take(&mut rep.wrapped);
        }
        rep.unwrapped.clear();
        return rep;
    }
    let mut new_text = match pyjson::dumps(&Value::Object(data), &pyjson::detect_indent(&text), false) {
        Ok(t) => t,
        Err(pyjson::NonFinite(n)) => {
            rep.status = Status::Error;
            rep.note(
                Code::NonFiniteNumber,
                format!("number {n} would be written as Infinity; not written"),
            );
            return rep;
        }
    };
    if text.ends_with('\n') {
        new_text.push('\n');
    }
    if !verify(&new_text, &original, fmt) {
        rep.status = Status::Error;
        rep.note(
            Code::VerifyFailed,
            "verification failed: non-server content changed; not written",
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

/// Re-parse what we are about to write; everything but `command` and `args` of the
/// server entries must be what we read (numbers compared as printed).
fn verify(new_text: &str, original: &Map<String, Value>, fmt: Format) -> bool {
    let Ok(Value::Object(reparsed)) = serde_json::from_str::<Value>(new_text) else {
        return false;
    };
    let ind = Indent::Spaces(0);
    let a = pyjson::dumps(&Value::Object(strip_servers(&reparsed, fmt)), &ind, false);
    let b = pyjson::dumps(&Value::Object(strip_servers(original, fmt)), &ind, false);
    matches!((a, b), (Ok(a), Ok(b)) if a == b)
}
