//! Property tests (design/install.md, test plan 3). Each case runs in a throwaway HOME
//! built through an explicit `Env`; the real user configuration is never read.

use std::fs;
use std::time::{Duration, SystemTime};

use dos_install::clients::{Env, Os};
use dos_install::entry::{unwrap_args, wrap_args, wrapped_shape};
use dos_install::pyjson::{json_string, py_float_repr};
use dos_install::{Action, Options, Status, run};
use proptest::prelude::*;
use serde_json::Value;

fn arg() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("--".to_string()),
        Just("-P".to_string()),
        Just("mcp-proxy".to_string()),
        Just("decision_os_min.gateway".to_string()),
        "[ -~]{0,12}",
        "\\PC{0,6}",
    ]
}

fn opts(action: Action, clients: &[&str], secs: u64) -> Options {
    Options {
        action,
        clients: clients.iter().map(|c| c.to_string()).collect(),
        project: None,
        dry_run: false,
        force_jsonc: false,
        binary: "/opt/decision-os/bin/decision-os".into(),
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
    }
}

fn env_for(user: &std::path::Path) -> Env {
    let mut env = Env::new(Os::Linux);
    env.home = Some(user.into());
    env.xdg_config_home = Some(user.join(".config").into());
    env
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn unwrap_inverts_wrap(name in arg(), cmd in arg(), args in prop::collection::vec(arg(), 0..6)) {
        let w: Vec<Value> = wrap_args("/h", "c", &name, &cmd, &args).into_iter().map(Value::String).collect();
        prop_assert!(wrapped_shape(Some(&Value::Array(w.clone()))).is_some());
        let (c, a) = unwrap_args(&w).map_err(|_| TestCaseError::fail("no original"))?;
        prop_assert_eq!(c, Value::String(cmd));
        prop_assert_eq!(a, args.into_iter().map(Value::String).collect::<Vec<_>>());
    }

    #[test]
    fn float_repr_round_trips(bits in any::<u64>()) {
        let f = f64::from_bits(bits);
        prop_assume!(f.is_finite());
        let s = py_float_repr(f);
        let back: f64 = s.parse().map_err(|_| TestCaseError::fail(s.clone()))?;
        prop_assert_eq!(back.to_bits(), f.to_bits(), "{}", s);
        prop_assert!(s.contains(['.', 'e']), "{}", s);
    }

    #[test]
    fn json_install_is_idempotent_and_uninstall_restores(
        servers in prop::collection::vec((arg(), "[a-z/]{1,8}", prop::collection::vec(arg(), 0..4)), 1..5),
        indent in 0usize..5,
    ) {
        // a plain entry whose args happen to match the oracle's loose wrapped predicate is
        // (correctly) treated as wrapped and unwrapped by uninstall; not this property
        prop_assume!(!servers.iter().any(|(_, _, a)| a.iter().any(|x| x == "decision_os_min.gateway")));
        let tmp = tempfile::tempdir().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let user = tmp.path().join("user");
        let p = user.join(".cursor").join("mcp.json");
        fs::create_dir_all(p.parent().unwrap_or(&user)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let pad = " ".repeat(indent);
        let body: Vec<String> = servers.iter().enumerate().map(|(i, (n, c, a))| {
            let args: Vec<String> = a.iter().map(|x| json_string(x)).collect();
            format!("{pad}{}: {{\"command\": {}, \"args\": [{}]}}", json_string(&format!("{i}{n}")), json_string(c), args.join(", "))
        }).collect();
        let src = format!("{{\"mcpServers\": {{\n{}\n}}, \"x\": [1.50, 1e5]}}\n", body.join(",\n"));
        fs::write(&p, &src).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let env = env_for(&user);
        let home = user.join(".decision-os");
        let r1 = run(&home, &env, &opts(Action::Install, &["cursor"], 0)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert!(r1.iter().all(|r| r.status != Status::Error), "{:?}", r1);
        let once = fs::read(&p).map_err(|e| TestCaseError::fail(e.to_string()))?;
        run(&home, &env, &opts(Action::Install, &["cursor"], 1)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(&fs::read(&p).map_err(|e| TestCaseError::fail(e.to_string()))?, &once);
        run(&home, &env, &opts(Action::Uninstall, &["cursor"], 2)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(fs::read_to_string(&p).map_err(|e| TestCaseError::fail(e.to_string()))?, src);
    }

    #[test]
    fn codex_entry_by_entry_uninstall_restores_servers(
        cmd in "[ -~]{1,10}",
        args in prop::option::of(prop::collection::vec("[ -~]{0,8}", 0..4)),
    ) {
        let tmp = tempfile::tempdir().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let user = tmp.path().join("user");
        let p = user.join(".codex").join("config.toml");
        fs::create_dir_all(p.parent().unwrap_or(&user)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let mut src = format!("# c\n[mcp_servers.s]\ncommand = {}  # k\n", json_string(&cmd));
        if let Some(a) = &args {
            let v: Vec<String> = a.iter().map(|x| json_string(x)).collect();
            src.push_str(&format!("args = [{}]\n", v.join(", ")));
        }
        src.push_str("[other]\nk = 1\n");
        fs::write(&p, &src).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let env = env_for(&user);
        let home = user.join(".decision-os");
        run(&home, &env, &opts(Action::Install, &["codex"], 0)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        // the app touches the file: the exact backup is no longer eligible
        let mut touched = fs::read_to_string(&p).map_err(|e| TestCaseError::fail(e.to_string()))?;
        touched.push_str("# app\n");
        fs::write(&p, &touched).map_err(|e| TestCaseError::fail(e.to_string()))?;
        run(&home, &env, &opts(Action::Uninstall, &["codex"], 1)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let got = fs::read_to_string(&p).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let doc: toml_edit::Document<&str> = toml_edit::Document::parse(got.as_str()).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let s = doc.as_table().get("mcp_servers").and_then(|m| m.get("s")).ok_or_else(|| TestCaseError::fail(got.clone()))?;
        prop_assert_eq!(s.get("command").and_then(|c| c.as_str()), Some(cmd.as_str()));
        let got_args: Option<Vec<String>> = s.get("args").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect());
        prop_assert_eq!(got_args, args);
        prop_assert!(got.ends_with("[other]\nk = 1\n# app\n"), "{}", got);
    }
}
