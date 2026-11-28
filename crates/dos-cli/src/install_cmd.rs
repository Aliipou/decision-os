//! `decision-os install | uninstall | status`: wrap every stdio MCP server in the clients'
//! configs so it starts behind `decision-os mcp-proxy`, and undo it exactly (`dos-install`).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use dos_install::clients::{Env, Os};
use dos_install::{Action, Options, Status, run};

use crate::home::default_home;

fn os() -> Os {
    if cfg!(windows) {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else {
        Os::Linux
    }
}

fn env() -> Env {
    let v = |k: &str| std::env::var_os(k);
    Env {
        os: os(),
        home: v("HOME"),
        userprofile: v("USERPROFILE"),
        homedrive: v("HOMEDRIVE"),
        homepath: v("HOMEPATH"),
        appdata: v("APPDATA"),
        localappdata: v("LOCALAPPDATA"),
        xdg_config_home: v("XDG_CONFIG_HOME"),
        codex_home: v("CODEX_HOME"),
        copilot_home: v("COPILOT_HOME"),
    }
}

pub fn command(action: Action, mut args: impl Iterator<Item = String>) -> ExitCode {
    let mut clients: Vec<String> = Vec::new();
    let mut project: Option<PathBuf> = None;
    let mut home: Option<PathBuf> = None;
    let (mut dry_run, mut force_jsonc) = (false, false);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--client" => match args.next() {
                Some(c) => clients.push(c),
                None => return crate::usage(),
            },
            "--project" => project = args.next().map(PathBuf::from),
            "--home" => home = args.next().map(PathBuf::from),
            "--dry-run" => dry_run = true,
            "--force-jsonc" => force_jsonc = true,
            _ => return crate::usage(),
        }
    }
    let Some(home) = home.or_else(default_home) else {
        eprintln!("decision-os: no home directory (set HOME or pass --home)");
        return ExitCode::from(2);
    };
    let binary = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => {
            eprintln!("decision-os: cannot find this binary: {e}");
            return ExitCode::from(2);
        }
    };
    let opts = Options {
        action,
        clients,
        project,
        dry_run,
        force_jsonc,
        binary,
        now: SystemTime::now(),
    };
    let reports = match run(&home, &env(), &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("decision-os: {e}");
            return ExitCode::from(1);
        }
    };
    let mut bad = false;
    for r in &reports {
        let list = |label: &str, v: &[String]| {
            if !v.is_empty() {
                println!("    {label}: {}", v.join(", "));
            }
        };
        println!(
            "{:<10} {:<10} {}",
            r.status.as_str(),
            r.client,
            r.path.display()
        );
        list("wrapped", &r.wrapped);
        list("unwrapped", &r.unwrapped);
        list("already", &r.already);
        list("plain", &r.plain);
        list("remote", &r.remote);
        if let Some(m) = &r.message {
            println!("    {}", m.detail);
        }
        bad |= r.status == Status::Error;
    }
    if bad {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
