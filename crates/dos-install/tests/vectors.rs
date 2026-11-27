//! Replays every vector in `conformance/vectors/install/` (generated from the oracle by
//! `conformance/gen/install_from_oracle.py`) against the Rust installer, byte for byte.
//! Every case runs in its own throwaway HOME built through the explicit `Env`.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::Engine;
use dos_install::clients::{CLIENTS, Env, Os};
use dos_install::pyjson::json_string;
use dos_install::{Action, FileReport, Options, run};
use serde_json::Value;

type R<T> = Result<T, Box<dyn Error>>;

const HOME_PLACEHOLDER: &str = "@DOS_HOME@";

fn vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/install")
}

fn load_vectors() -> R<Vec<Value>> {
    let mut out = Vec::new();
    let mut names: Vec<PathBuf> = fs::read_dir(vector_dir())?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    names.sort();
    for p in names {
        if p.extension().is_some_and(|e| e == "json") {
            out.push(serde_json::from_slice(&fs::read(&p)?)?);
        }
    }
    Ok(out)
}

fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {k}").into())
}

fn blob(v: &Value) -> R<Option<Vec<u8>>> {
    if v.is_null() {
        return Ok(None);
    }
    if let Some(t) = v.get("text").and_then(Value::as_str) {
        return Ok(Some(t.as_bytes().to_vec()));
    }
    let b = s(v, "b64")?;
    Ok(Some(base64::engine::general_purpose::STANDARD.decode(b)?))
}

/// The same environment the generator gives the oracle: everything inside `user`.
pub fn linux_env(user: &Path) -> Env {
    let mut env = Env::new(Os::Linux);
    env.home = Some(user.into());
    env.userprofile = Some(user.into());
    env.appdata = Some(user.join("AppData").join("Roaming").into());
    env.localappdata = Some(user.join("AppData").join("Local").into());
    env.xdg_config_home = Some(user.join(".config").into());
    env
}

fn replace_bytes(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if !from.is_empty() && hay.get(i..i + from.len()) == Some(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else if let Some(b) = hay.get(i) {
            out.push(*b);
            i += 1;
        }
    }
    out
}

fn report_json(r: &FileReport) -> Value {
    serde_json::json!({
        "status": r.status.as_str(),
        "wrapped": r.wrapped,
        "already": r.already,
        "plain": r.plain,
        "remote": r.remote,
        "unwrapped": r.unwrapped,
        "message": r.message.as_ref().map(|m| m.code.as_str()),
    })
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> R<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(p: &Path, mode: u32) -> R<()> {
    let mut perm = fs::metadata(p)?.permissions();
    perm.set_readonly(mode & 0o200 == 0);
    fs::set_permissions(p, perm)?;
    Ok(())
}

#[cfg(unix)]
fn make_symlink(target: &Path, link: &Path) -> R<()> {
    std::os::unix::fs::symlink(target, link)?;
    Ok(())
}

#[cfg(windows)]
fn make_symlink(target: &Path, link: &Path) -> R<()> {
    std::os::windows::fs::symlink_file(target, link)?;
    Ok(())
}

fn replay_run(v: &Value) -> R<Vec<String>> {
    let name = s(v, "name")?;
    let input = v.get("input").ok_or("no input")?;
    let steps = v
        .pointer("/expected/ok/steps")
        .and_then(Value::as_array)
        .ok_or("no expected steps")?;
    let in_steps = input
        .get("steps")
        .and_then(Value::as_array)
        .ok_or("no input steps")?;
    let tmp = tempfile::tempdir()?;
    let user = tmp.path().join("user");
    fs::create_dir_all(&user)?;
    let env = linux_env(&user);
    let home = user.join(".decision-os");
    let home_lit = json_string(home.to_str().ok_or("non-utf8 temp dir")?);
    let placeholder_lit = json_string(HOME_PLACEHOLDER);
    let project = input
        .get("project")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let proj = tmp.path().join("proj");
    let target = if project { &proj } else { &user }.join(s(input, "path")?);
    let client = s(input, "client")?.to_string();
    let mode = input
        .get("mode")
        .and_then(Value::as_u64)
        .map(u32::try_from)
        .transpose()?;
    let link = input.get("symlink_to").and_then(Value::as_str);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(before) = blob(input.get("before").unwrap_or(&Value::Null))? {
        if let Some(l) = link {
            let real = user.join(l);
            if let Some(parent) = real.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&real, &before)?;
            make_symlink(&real, &target)?;
        } else {
            fs::write(&target, &before)?;
        }
        if let Some(m) = mode {
            set_mode(&target, m)?;
        }
    }
    let mut fails = Vec::new();
    for (i, (st, exp)) in in_steps.iter().zip(steps).enumerate() {
        if let Some(aw) = st.get("app_write") {
            let bytes = blob(aw)?.ok_or("app_write without bytes")?;
            let bytes = replace_bytes(&bytes, placeholder_lit.as_bytes(), home_lit.as_bytes());
            if mode.is_some() {
                set_mode(&target, 0o644)?;
            }
            fs::write(&target, bytes)?;
            if let Some(m) = mode {
                set_mode(&target, m)?;
            }
            continue;
        }
        let action = match s(st, "action")? {
            "install" => Action::Install,
            "uninstall" => Action::Uninstall,
            "status" => Action::Status,
            other => return Err(format!("unknown action {other}").into()),
        };
        let flag = |k: &str| st.get(k).and_then(Value::as_bool).unwrap_or(false);
        let opts = Options {
            action,
            clients: vec![client.clone()],
            project: project.then(|| proj.clone()),
            dry_run: flag("dry_run"),
            force_jsonc: flag("force_jsonc"),
            binary: s(input, "binary")?.to_string(),
            now: SystemTime::UNIX_EPOCH,
        };
        let reports = run(&home, &env, &opts)?;
        let mine: Vec<&FileReport> = reports.iter().filter(|r| r.path == target).collect();
        let [rep] = mine.as_slice() else {
            fails.push(format!("{name} step {i}: {} reports for the target", mine.len()));
            continue;
        };
        let got = report_json(rep);
        let want = exp.get("report").cloned().unwrap_or(Value::Null);
        if got != want {
            fails.push(format!("{name} step {i}: report\n  got  {got}\n  want {want}"));
        }
        let data = if target.exists() {
            Some(replace_bytes(
                &fs::read(&target)?,
                home_lit.as_bytes(),
                placeholder_lit.as_bytes(),
            ))
        } else {
            None
        };
        let want_file = blob(exp.get("file").unwrap_or(&Value::Null))?;
        if data != want_file {
            fails.push(format!(
                "{name} step {i}: file bytes differ\n  got  {:?}\n  want {:?}",
                data.as_deref().map(String::from_utf8_lossy),
                want_file.as_deref().map(String::from_utf8_lossy)
            ));
        }
        if let Some(want_link) = exp.get("symlink").and_then(Value::as_bool) {
            let is_link = fs::symlink_metadata(&target)?.file_type().is_symlink();
            if is_link != want_link {
                fails.push(format!("{name} step {i}: symlink {is_link}, want {want_link}"));
            }
        }
    }
    if let Some(m) = mode {
        if target.exists() {
            set_mode(&target, m | 0o600)?;
        }
    }
    Ok(fails)
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.components().eq(b.components())
}

fn replay_registry(v: &Value) -> R<Vec<String>> {
    let name = s(v, "name")?;
    let input = v.get("input").ok_or("no input")?;
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().to_str().ok_or("non-utf8 temp dir")?.to_string();
    let os = match s(input, "os")? {
        "linux" => Os::Linux,
        "macos" => Os::MacOs,
        "windows" => Os::Windows,
        other => return Err(format!("unknown os {other}").into()),
    };
    let mut env = Env::new(os);
    let vars = input
        .get("env")
        .and_then(Value::as_object)
        .ok_or("no env")?;
    for (k, val) in vars {
        let val = val.as_str().ok_or("env value")?.replace("<root>", &root);
        let slot = match k.as_str() {
            "HOME" => &mut env.home,
            "USERPROFILE" => &mut env.userprofile,
            "APPDATA" => &mut env.appdata,
            "LOCALAPPDATA" => &mut env.localappdata,
            "XDG_CONFIG_HOME" => &mut env.xdg_config_home,
            "CODEX_HOME" => &mut env.codex_home,
            "COPILOT_HOME" => &mut env.copilot_home,
            other => return Err(format!("unknown env var {other}").into()),
        };
        *slot = Some(val.into());
    }
    for f in input
        .get("files")
        .and_then(Value::as_array)
        .ok_or("no files")?
    {
        let p = PathBuf::from(f.as_str().ok_or("file")?.replace("<root>", &root));
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&p, "{}")?;
    }
    let want = v
        .pointer("/expected/ok/clients")
        .and_then(Value::as_object)
        .ok_or("no expected clients")?;
    let mut fails = Vec::new();
    let ids: Vec<&str> = CLIENTS.iter().map(|c| c.id).collect();
    let want_ids: Vec<&str> = want.keys().map(String::as_str).collect();
    if ids != want_ids {
        fails.push(format!("{name}: client ids {ids:?}, want {want_ids:?}"));
    }
    for c in CLIENTS.iter() {
        let Some(w) = want.get(c.id) else { continue };
        let got_meta = serde_json::json!({
            "name": c.name,
            "fmt": c.fmt.as_str(),
            "project": c.project.iter().map(|(p, f)| vec![p.to_string(), f.as_str().to_string()]).collect::<Vec<_>>(),
            "restart_hint": c.restart_hint,
        });
        let want_meta = serde_json::json!({
            "name": w.get("name"), "fmt": w.get("fmt"), "project": w.get("project"),
            "restart_hint": w.get("restart_hint"),
        });
        if got_meta != want_meta {
            fails.push(format!("{name}/{}: {got_meta} want {want_meta}", c.id));
        }
        let got = c.config_paths(&env)?;
        let want_paths: Vec<PathBuf> = w
            .get("paths")
            .and_then(Value::as_array)
            .ok_or("paths")?
            .iter()
            .filter_map(Value::as_str)
            .map(|p| PathBuf::from(p.replace("<root>", &root)))
            .collect();
        let ok = got.len() == want_paths.len()
            && got.iter().zip(&want_paths).all(|(a, b)| same_path(a, b));
        if !ok {
            fails.push(format!("{name}/{}: paths {got:?}, want {want_paths:?}", c.id));
        }
    }
    Ok(fails)
}

#[test]
fn every_install_vector_matches_byte_for_byte() -> R<()> {
    let vectors = load_vectors()?;
    assert!(vectors.len() >= 40, "only {} vectors", vectors.len());
    let mut fails = Vec::new();
    let mut runs = 0;
    let mut regs = 0;
    for v in &vectors {
        assert_eq!(v.get("area").and_then(Value::as_str), Some("install"));
        assert!(
            v.get("source").is_some(),
            "{:?} has no source",
            v.get("name")
        );
        match v.pointer("/input/kind").and_then(Value::as_str) {
            // Windows without Developer Mode or admin cannot create symlinks (error 1314);
            // the symlink vector runs wherever symlinks can be made (Linux, macOS, CI).
            Some("run") if v.pointer("/input/symlink_to").is_some() && !symlinks_available() => {
                eprintln!("skipped {:?}: this host cannot create symlinks", v.get("name"));
            }
            Some("run") => {
                runs += 1;
                fails.extend(replay_run(v)?);
            }
            Some("registry") => {
                regs += 1;
                fails.extend(replay_registry(v)?);
            }
            other => fails.push(format!("{:?}: unknown kind {other:?}", v.get("name"))),
        }
    }
    eprintln!(
        "{} vectors: {runs} run, {regs} registry, {} failure(s)",
        vectors.len(),
        fails.len()
    );
    assert!(fails.is_empty(), "\n{}", fails.join("\n"));
    Ok(())
}

#[cfg(unix)]
fn symlinks_available() -> bool {
    true
}

#[cfg(windows)]
fn symlinks_available() -> bool {
    let Ok(tmp) = tempfile::tempdir() else {
        return false;
    };
    let target = tmp.path().join("t");
    fs::write(&target, b"").is_ok() && make_symlink(&target, &tmp.path().join("l")).is_ok()
}
