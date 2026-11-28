//! U-ONCE across OS processes (harness = false). The binary re-executes itself with
//! `DOS_STORE_CHILD` set; children print one line: FIRST, ALREADY or ERR <code>.
//!
//! - spend race: 8 processes x 50 rounds per durable backend, one token: one FIRST.
//! - first-start race (PR #9): 16 processes open a brand-new sqlite path at once and
//!   spend: none may fail, exactly one FIRST. Same for a brand-new file store dir.

use dos_store::{FileSpentStore, Spend, SpentStore, SqliteSpentStore};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ENV_ROLE: &str = "DOS_STORE_CHILD";

fn main() {
    let code = match std::env::var(ENV_ROLE) {
        Ok(role) => child(&role),
        Err(_) => parent(),
    };
    std::process::exit(code);
}

// ---- child ---------------------------------------------------------------

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("missing {name}"))
}

fn open(backend: &str, path: &Path) -> Result<Box<dyn SpentStore>, String> {
    match backend {
        "file" => FileSpentStore::open(path)
            .map(|s| Box::new(s) as Box<dyn SpentStore>)
            .map_err(|e| e.code().to_string()),
        "sqlite" => SqliteSpentStore::open(path)
            .map(|s| Box::new(s) as Box<dyn SpentStore>)
            .map_err(|e| e.code().to_string()),
        other => Err(format!("unknown backend {other}")),
    }
}

fn wait_for(go: &Path) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !go.exists() {
        if Instant::now() > deadline {
            return Err("go file never appeared".into());
        }
        std::thread::yield_now();
    }
    Ok(())
}

fn child_run(role: &str) -> Result<Spend, String> {
    let backend = env("DOS_STORE_BACKEND")?;
    let path = PathBuf::from(env("DOS_STORE_PATH")?);
    let token = env("DOS_STORE_TOKEN")?;
    let go = PathBuf::from(env("DOS_STORE_GO")?);
    let store = match role {
        // Open first, then spend together: contention on the spend itself.
        "spend" => {
            let s = open(&backend, &path)?;
            wait_for(&go)?;
            s
        }
        // Start together on a path that does not exist yet: the first-start race.
        "open-spend" => {
            wait_for(&go)?;
            open(&backend, &path)?
        }
        other => return Err(format!("unknown role {other}")),
    };
    store.try_spend(&token, i64::MAX).map_err(|e| e.code().to_string())
}

fn child(role: &str) -> i32 {
    match child_run(role) {
        Ok(Spend::First) => println!("FIRST"),
        Ok(Spend::AlreadySpent) => println!("ALREADY"),
        Err(e) => println!("ERR {e}"),
    }
    0
}

// ---- parent --------------------------------------------------------------

type R = Result<(), String>;

fn run_round(role: &str, backend: &str, path: &Path, token: &str, n: usize, work: &Path) -> R {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let go = work.join(format!("go-{token}"));
    let mut kids = Vec::with_capacity(n);
    for _ in 0..n {
        let kid = Command::new(&exe)
            .env(ENV_ROLE, role)
            .env("DOS_STORE_BACKEND", backend)
            .env("DOS_STORE_PATH", path)
            .env("DOS_STORE_TOKEN", token)
            .env("DOS_STORE_GO", &go)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| e.to_string())?;
        kids.push(kid);
    }
    // Give every child time to reach the barrier (spend role opens first).
    std::thread::sleep(Duration::from_millis(150));
    std::fs::write(&go, b"go").map_err(|e| e.to_string())?;
    let mut lines = Vec::with_capacity(n);
    for kid in kids {
        let out = kid.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("child exited {:?}", out.status));
        }
        lines.push(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    let first = lines.iter().filter(|l| *l == "FIRST").count();
    let already = lines.iter().filter(|l| *l == "ALREADY").count();
    if first != 1 || already != n - 1 {
        return Err(format!(
            "{role} {backend} {token}: first={first} already={already} lines={lines:?}"
        ));
    }
    Ok(())
}

fn spend_race(backend: &str) -> R {
    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let path = match backend {
        "file" => tmp.path().join("spent"),
        _ => tmp.path().join("spent.db"),
    };
    // Create the store once so the children only race the spend.
    drop(open(backend, &path)?);
    for round in 0..50 {
        run_round("spend", backend, &path, &format!("tok-{round}"), 8, tmp.path())?;
    }
    Ok(())
}

fn first_start_race(backend: &str) -> R {
    for round in 0..20 {
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path = match backend {
            "file" => tmp.path().join("home").join("spent"),
            _ => tmp.path().join("home").join("spent.db"),
        };
        run_round("open-spend", backend, &path, &format!("t{round}"), 16, tmp.path())?;
    }
    Ok(())
}

fn parent() -> i32 {
    let filter: Option<String> = std::env::args().skip(1).find(|a| !a.starts_with('-'));
    let tests: [(&str, fn() -> R); 4] = [
        ("multiprocess_spend_race_file_8x50", || spend_race("file")),
        ("multiprocess_spend_race_sqlite_8x50", || spend_race("sqlite")),
        ("multiprocess_first_start_sqlite_16x20", || first_start_race("sqlite")),
        ("multiprocess_first_start_file_16x20", || first_start_race("file")),
    ];
    let mut failed = 0;
    let mut ran = 0;
    for (name, f) in tests {
        if let Some(flt) = &filter
            && !name.contains(flt.as_str())
        {
            continue;
        }
        ran += 1;
        let t = Instant::now();
        match f() {
            Ok(()) => println!("test {name} ... ok ({:.1}s)", t.elapsed().as_secs_f64()),
            Err(e) => {
                println!("test {name} ... FAILED: {e}");
                failed += 1;
            }
        }
    }
    println!("multiprocess: {ran} run, {failed} failed");
    // With no filter all four run; a filter that matches none is not a failure.
    i32::from(failed > 0)
}
