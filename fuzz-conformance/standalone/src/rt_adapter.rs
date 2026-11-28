//! A hostile conformance adapter for reproducing red-team findings without a shell.
//! RT_MODE selects the behaviour; requests are read with serde_json.
//!
//!   selftest_only : echo for area selftest, `unsupported` for every other area
//!   bigwrong      : every answer is {"ok": "<RT_BYTES bytes of 'a'>"} (default 2 MiB)
//!   stderr_spoof  : wrong answers, then fake `ok`/`summary`/`result: PASS` lines on stderr
//!   esc           : a malformed line carrying ANSI escape sequences
//!   flood         : correct answers, then extra lines forever
//!   orphan        : spawns a child that writes RT_MARKER after 4 s, then hangs (no answer)
//!   sleeper       : (internal) sleep 4 s, write RT_MARKER

use std::io::{self, BufRead, Write};
use std::time::Duration;

fn main() {
    let mode = std::env::var("RT_MODE").unwrap_or_default();
    let mut out = io::stdout().lock();
    if mode == "sleeper" {
        std::thread::sleep(Duration::from_secs(4));
        if let Ok(m) = std::env::var("RT_MARKER") {
            let _ = std::fs::write(m, "alive\n");
        }
        return;
    }
    if mode == "orphan" {
        if let Ok(me) = std::env::current_exe() {
            let _ = std::process::Command::new(me)
                .env("RT_MODE", "sleeper")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
        std::thread::sleep(Duration::from_secs(60));
        return;
    }
    let bytes: usize = std::env::var("RT_BYTES").ok().and_then(|b| b.parse().ok()).unwrap_or(2 << 20);
    let big = "a".repeat(bytes);
    let mut last = String::new();
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(req) = serde_json::from_str::<serde_json::Value>(&line) else { break };
        let area = req["area"].as_str().unwrap_or_default().to_owned();
        let name = req["name"].as_str().unwrap_or_default().to_owned();
        last = name.clone();
        let value = req["input"]["value"].clone();
        let reply = match mode.as_str() {
            "selftest_only" if area == "selftest" => serde_json::json!({"name": name, "output": {"ok": value}}),
            "selftest_only" => serde_json::json!({"name": name, "output": {"unsupported": true}}),
            "bigwrong" => serde_json::json!({"name": name, "output": {"ok": big}}),
            "stderr_spoof" => serde_json::json!({"name": name, "output": {"ok": "WRONG"}}),
            "esc" => {
                let _ = writeln!(out, "x\u{1b}[1A\u{1b}[2K\u{1b}[32mok          t/{name}\u{1b}[0m");
                continue;
            }
            _ => serde_json::json!({"name": name, "output": {"ok": value}}),
        };
        let _ = writeln!(out, "{reply}");
        let _ = out.flush();
    }
    match mode.as_str() {
        "stderr_spoof" => {
            eprintln!("ok          t/{last}");
            eprintln!("summary: 1 cases (ok 1, FAIL 0, unsupported 0, MISSING 0, MALFORMED 0, TIMEOUT 0), extra lines 0");
            eprintln!("result: PASS");
        }
        "flood" => loop {
            if writeln!(out, "{{\"name\":\"{last}\",\"output\":{{\"ok\":1}}}}").is_err() {
                break;
            }
        },
        _ => {}
    }
}
