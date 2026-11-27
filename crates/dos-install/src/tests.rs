//! Red-team and unit tests that need crate internals (the before-replace hook).
//! Every test runs in its own temp directory through an explicit `Env`; nothing reads
//! or writes the real user configuration.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::*;
use crate::clients::{Env, Os};

const BIN: &str = "/opt/decision-os/bin/decision-os";
const DESK: &str = "{\n  \"mcpServers\": {\n    \"a\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"a\"]\n    }\n  }\n}\n";

struct Fx {
    _tmp: tempfile::TempDir,
    user: PathBuf,
    home: PathBuf,
    env: Env,
}

fn fx() -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let user = tmp.path().join("user");
    fs::create_dir_all(&user).unwrap();
    let mut env = Env::new(Os::Linux);
    env.home = Some(user.clone().into());
    env.xdg_config_home = Some(user.join(".config").into());
    let home = user.join(".decision-os");
    Fx {
        _tmp: tmp,
        user,
        home,
        env,
    }
}

impl Fx {
    fn desktop(&self) -> PathBuf {
        self.user.join(".config/Claude/claude_desktop_config.json")
    }
    fn put(&self, p: &Path, data: &str) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }
}

fn opts(action: Action, secs: u64) -> Options {
    Options {
        action,
        clients: vec!["claude-desktop".into()],
        project: None,
        dry_run: false,
        force_jsonc: false,
        binary: BIN.into(),
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
    }
}

fn one(reps: Vec<FileReport>, p: &Path) -> FileReport {
    reps.into_iter().find(|r| r.path == p).unwrap()
}

#[test]
fn install_then_uninstall_restores_bytes() {
    let f = fx();
    let p = f.desktop();
    f.put(&p, DESK);
    let r = one(run(&f.home, &f.env, &opts(Action::Install, 0)).unwrap(), &p);
    assert_eq!(r.status, Status::Ok);
    assert_eq!(r.wrapped, vec!["a"]);
    assert_ne!(fs::read_to_string(&p).unwrap(), DESK);
    let r = one(run(&f.home, &f.env, &opts(Action::Uninstall, 1)).unwrap(), &p);
    assert_eq!(r.message.unwrap().code, Code::RestoredExact);
    assert_eq!(fs::read_to_string(&p).unwrap(), DESK);
}

#[test]
fn app_write_between_read_and_rename_is_detected() {
    let f = fx();
    let p = f.desktop();
    f.put(&p, DESK);
    let app = "{\"mcpServers\": {}, \"app\": 1}";
    let mut hook = |path: &Path| fs::write(path, app).unwrap();
    let reps = run_with_hook(&f.home, &f.env, &opts(Action::Install, 0), Some(&mut hook)).unwrap();
    let r = one(reps, &p);
    assert_eq!(r.status, Status::Error);
    assert_eq!(r.message.unwrap().code, Code::ChangedDuringWrite);
    assert_eq!(fs::read_to_string(&p).unwrap(), app, "the app's bytes stay");
    // the state does not claim the entry was wrapped
    let st = fs::read_to_string(f.home.join("state.json")).unwrap();
    assert!(!st.contains("npx"), "{st}");
}

#[test]
fn corrupt_state_refuses_the_run() {
    let f = fx();
    let p = f.desktop();
    f.put(&p, DESK);
    fs::create_dir_all(&f.home).unwrap();
    fs::write(f.home.join("state.json"), "{not json").unwrap();
    let e = run(&f.home, &f.env, &opts(Action::Install, 0)).unwrap_err();
    assert!(matches!(e, InstallError::StateCorrupt(_)));
    assert_eq!(fs::read_to_string(&p).unwrap(), DESK);
    assert_eq!(fs::read_to_string(f.home.join("state.json")).unwrap(), "{not json");
}

#[test]
fn unknown_client_and_no_home_refuse() {
    let f = fx();
    let mut o = opts(Action::Install, 0);
    o.clients = vec!["nope".into()];
    assert!(matches!(
        run(&f.home, &f.env, &o),
        Err(InstallError::UnknownClient(_))
    ));
    let env = Env::new(Os::Linux);
    assert!(matches!(
        run(&f.home, &env, &opts(Action::Install, 0)),
        Err(InstallError::NoHome)
    ));
}

#[test]
fn dry_run_creates_nothing() {
    let f = fx();
    let p = f.desktop();
    f.put(&p, DESK);
    let mut o = opts(Action::Install, 0);
    o.dry_run = true;
    let r = one(run(&f.home, &f.env, &o).unwrap(), &p);
    assert_eq!(r.wrapped, vec!["a"]);
    assert_eq!(fs::read_to_string(&p).unwrap(), DESK);
    assert!(!f.home.exists(), "dry run created the home directory");
}

#[test]
fn backups_are_never_overwritten() {
    let f = fx();
    let p = f.desktop();
    f.put(&p, DESK);
    // the same clock twice: the second backup must not replace the first
    run(&f.home, &f.env, &opts(Action::Install, 0)).unwrap();
    f.put(&p, DESK);
    run(&f.home, &f.env, &opts(Action::Install, 0)).unwrap();
    let dir = f.home.join("backups/19700101T000000Z/claude-desktop");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "{names:?}");
    for n in names {
        assert_eq!(fs::read_to_string(dir.join(n)).unwrap(), DESK);
    }
}

#[test]
fn concurrent_installs_do_not_lose_state() {
    let f = fx();
    let p = f.desktop();
    f.put(&p, DESK);
    let cursor = f.user.join(".cursor/mcp.json");
    f.put(&cursor, DESK);
    std::thread::scope(|s| {
        for c in ["claude-desktop", "cursor"] {
            let (home, env) = (&f.home, &f.env);
            s.spawn(move || {
                let mut o = opts(Action::Install, 0);
                o.clients = vec![c.into()];
                run(home, env, &o).unwrap();
            });
        }
    });
    let mut o = opts(Action::Uninstall, 5);
    o.clients = vec![];
    run(&f.home, &f.env, &o).unwrap();
    assert_eq!(fs::read_to_string(&p).unwrap(), DESK);
    assert_eq!(fs::read_to_string(&cursor).unwrap(), DESK);
}

#[test]
fn codex_command_inside_multiline_string_is_not_matched() {
    let f = fx();
    let p = f.user.join(".codex/config.toml");
    let src = "[mcp_servers.a]\nnote = \"\"\"\ncommand = \"fake\"\n[x]\n\"\"\"\ncommand = \"real\"\n";
    f.put(&p, src);
    let mut o = opts(Action::Install, 0);
    o.clients = vec!["codex".into()];
    let r = one(run(&f.home, &f.env, &o).unwrap(), &p);
    assert_eq!(r.status, Status::Ok, "{:?}", r.message);
    let got = fs::read_to_string(&p).unwrap();
    assert!(got.contains("command = \"fake\"\n[x]\n"), "{got}");
    assert!(got.contains("\"--\", \"real\"]"), "{got}");
    o.action = Action::Uninstall;
    run(&f.home, &f.env, &o).unwrap();
    assert_eq!(fs::read_to_string(&p).unwrap(), src);
}

#[test]
fn every_global_target_is_inside_the_given_home() {
    let f = fx();
    for p in clients::all_config_paths(&f.env) {
        assert!(p.starts_with(&f.user), "{}", p.display());
    }
}
