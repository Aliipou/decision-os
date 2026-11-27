//! End-to-end checks of the runner binary against a deliberately broken adapter.
//!
//! This file is both the test and the adapter: when `DOS_TEST_ADAPTER_MODE` is set,
//! `main` speaks the adapter protocol (badly, on purpose); otherwise it runs every
//! check below, each of which spawns the runner with this same binary as `--adapter`.
//! The adapter side reads requests with serde_json, independently of the runner's
//! own parser. Only ever used by these tests.

use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const RUNNER: &str = env!("CARGO_BIN_EXE_dos-conformance");
const MODE: &str = "DOS_TEST_ADAPTER_MODE";
const LINE: &str = "DOS_TEST_ADAPTER_LINE";

type Check = fn() -> Result<(), String>;

fn main() -> ExitCode {
    if let Ok(mode) = std::env::var(MODE) {
        return adapter(&mode);
    }
    let filter: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let checks: &[(&str, Check)] = &[
        ("good_adapter_passes", good_adapter_passes),
        ("late_answers_after_eof_pass", late_answers_after_eof_pass),
        ("wrong_output_fails", wrong_output_fails),
        ("missing_line_fails", missing_line_fails),
        ("extra_line_fails", extra_line_fails),
        ("malformed_json_fails", malformed_json_fails),
        ("malformed_shapes_fail", malformed_shapes_fail),
        ("partial_last_line_fails", partial_last_line_fails),
        ("crash_fails", crash_fails),
        ("nonzero_exit_fails", nonzero_exit_fails),
        ("early_exit_fails", early_exit_fails),
        ("case_timeout_fails", case_timeout_fails),
        ("overall_timeout_fails", overall_timeout_fails),
        (
            "adapter_that_never_exits_fails",
            adapter_that_never_exits_fails,
        ),
        (
            "orphan_holding_stderr_does_not_hang",
            orphan_holding_stderr_does_not_hang,
        ),
        ("missing_adapter_fails", missing_adapter_fails),
        (
            "unsupported_allowed_unless_required",
            unsupported_allowed_unless_required,
        ),
        ("zero_cases_fail", zero_cases_fail),
        ("bad_vectors_are_hard_errors", bad_vectors_are_hard_errors),
        (
            "oracle_mode_uses_oracle_expected",
            oracle_mode_uses_oracle_expected,
        ),
        ("numbers_compare_exactly", numbers_compare_exactly),
        ("area_selection", area_selection),
        ("json_report", json_report),
        ("manifest_required_and_oracle", manifest_required_and_oracle),
        (
            "bad_manifests_are_hard_errors",
            bad_manifests_are_hard_errors,
        ),
        ("usage_errors", usage_errors),
    ];
    let mut failed = 0usize;
    let mut ran = 0usize;
    for (name, check) in checks {
        if !filter.is_empty() && !filter.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        ran += 1;
        match check() {
            Ok(()) => println!("test {name} ... ok"),
            Err(e) => {
                failed += 1;
                println!("test {name} ... FAILED\n{e}\n");
            }
        }
    }
    println!("adapter_failures: {ran} run, {failed} failed");
    if failed == 0 && ran > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------- the broken adapter

fn adapter(mode: &str) -> ExitCode {
    match run_adapter(mode) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("test adapter error: {e}");
            ExitCode::from(9)
        }
    }
}

fn echo(req: &serde_json::Value) -> Result<String, String> {
    let name = req.get("name").and_then(|n| n.as_str()).ok_or("no name")?;
    let value = req
        .get("input")
        .and_then(|i| i.get("value"))
        .ok_or("no input.value")?;
    Ok(serde_json::json!({"name": name, "output": {"ok": value}}).to_string())
}

fn run_adapter(mode: &str) -> Result<ExitCode, String> {
    let mut out = io::stdout().lock();
    let mut w = |s: &str| -> Result<(), String> {
        out.write_all(s.as_bytes())
            .and_then(|()| out.flush())
            .map_err(|e| e.to_string())
    };
    if mode == "early_exit" {
        return Ok(ExitCode::SUCCESS);
    }
    if mode == "sleeper" {
        std::thread::sleep(Duration::from_secs(30));
        return Ok(ExitCode::SUCCESS);
    }
    if mode == "orphan_stderr" {
        // A background grandchild that keeps our stderr open after we exit.
        let me = std::env::current_exe().map_err(|e| e.to_string())?;
        Command::new(me)
            .env(MODE, "sleeper")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    let lines: Vec<String> = if mode == "late" {
        let mut all = String::new();
        io::stdin()
            .read_to_string(&mut all)
            .map_err(|e| e.to_string())?;
        all.lines().map(str::to_owned).collect()
    } else {
        Vec::new()
    };
    let stdin = io::stdin();
    let mut streamed = stdin.lock().lines();
    let mut pre = lines.into_iter();
    loop {
        let line = if mode == "late" {
            match pre.next() {
                Some(l) => l,
                None => break,
            }
        } else {
            match streamed.next() {
                Some(l) => l.map_err(|e| e.to_string())?,
                None => break,
            }
        };
        let req: serde_json::Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        let name = req
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_owned();
        let reply = echo(&req)?;
        match (mode, name.as_str()) {
            ("wrong", "b") => w("{\"name\":\"b\",\"output\":{\"ok\":\"WRONG\"}}\n")?,
            ("missing", "c") => {}
            ("raw", "b") => w(&format!("{}\n", std::env::var(LINE).unwrap_or_default()))?,
            ("partial", "c") => w("{\"name\":\"c\",\"output\":{\"ok\"")?,
            ("crash", "b") => std::process::abort(),
            ("sleep", "b") => std::thread::sleep(Duration::from_secs(60)),
            ("unsupported", _) => w(&format!(
                "{{\"name\":\"{name}\",\"output\":{{\"unsupported\":true}}}}\n"
            ))?,
            ("slow", _) => {
                std::thread::sleep(Duration::from_millis(400));
                w(&format!("{reply}\n"))?;
            }
            _ => w(&format!("{reply}\n"))?,
        }
    }
    match mode {
        "extra" => w("{\"name\":\"c\",\"output\":{\"ok\":1}}\n")?,
        "nonzero" => return Ok(ExitCode::from(3)),
        "hang_open" => std::thread::sleep(Duration::from_secs(60)),
        _ => {}
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------- helpers

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, String> {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("dos-conf-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).map_err(|e| e.to_string())?;
        Ok(TempDir(p))
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn file(&self, rel: &str, content: &str) -> Result<(), String> {
        let p = self.0.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(&p, content).map_err(|e| e.to_string())
    }
    fn vector(&self, area: &str, name: &str, value: &str) -> Result<(), String> {
        self.file(
            &format!("{area}/{name}.json"),
            &vector_text(area, name, value, value),
        )
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn vector_text(area: &str, name: &str, value: &str, expected: &str) -> String {
    format!(
        "{{\n  \"v\": 1,\n  \"area\": \"{area}\",\n  \"name\": \"{name}\",\n  \"input\": {{\"value\": {value}}},\n  \"expected\": {{\"ok\": {expected}}},\n  \"source\": \"test\"\n}}\n"
    )
}

/// Area `t` with cases a, b, c echoing their value.
fn abc() -> Result<TempDir, String> {
    let d = TempDir::new()?;
    d.vector("t", "a", "1")?;
    d.vector("t", "b", "{\"k\": [true, null, \"x\"]}")?;
    d.vector("t", "c", "\"c\"")?;
    Ok(d)
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

impl Out {
    fn show(&self) -> String {
        format!(
            "exit {:?}\n--- stdout\n{}--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
    fn expect_code(&self, code: i32) -> Result<&Self, String> {
        if self.code == Some(code) {
            Ok(self)
        } else {
            Err(format!("want exit {code}\n{}", self.show()))
        }
    }
    fn expect_out(&self, needle: &str) -> Result<&Self, String> {
        if self.stdout.contains(needle) || self.stderr.contains(needle) {
            Ok(self)
        } else {
            Err(format!(
                "want output containing {needle:?}\n{}",
                self.show()
            ))
        }
    }
}

fn runner(vectors: &Path, mode: &str, extra: &[&str], env: &[(&str, &str)]) -> Result<Out, String> {
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(RUNNER);
    cmd.arg("--vectors")
        .arg(vectors)
        .arg("--adapter")
        .arg(&me)
        .args(extra)
        .env(MODE, mode);
    for (k, v) in env {
        cmd.env(k, v);
    }
    run_cmd(cmd)
}

fn run_cmd(mut cmd: Command) -> Result<Out, String> {
    let start = Instant::now();
    let o = cmd.output().map_err(|e| e.to_string())?;
    Ok(Out {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        elapsed: start.elapsed(),
    })
}

fn fails(mode: &str, needle: &str) -> Result<(), String> {
    let d = abc()?;
    runner(d.path(), mode, &[], &[])?
        .expect_code(1)?
        .expect_out(needle)?;
    Ok(())
}

// ---------------------------------------------------------------- checks

fn good_adapter_passes() -> Result<(), String> {
    let d = abc()?;
    let o = runner(d.path(), "good", &["--require", "t"], &[])?;
    o.expect_code(0)?
        .expect_out("ok          t/a")?
        .expect_out("ok          t/c")?;
    o.expect_out("3 cases")?.expect_out("PASS")?;
    Ok(())
}

fn late_answers_after_eof_pass() -> Result<(), String> {
    let d = abc()?;
    runner(d.path(), "late", &[], &[])?.expect_code(0)?;
    Ok(())
}

fn wrong_output_fails() -> Result<(), String> {
    fails("wrong", "FAIL        t/b")
}

fn missing_line_fails() -> Result<(), String> {
    fails("missing", "MISSING     t/c")
}

fn extra_line_fails() -> Result<(), String> {
    fails("extra", "1 extra line(s) after the last response")
}

fn malformed_json_fails() -> Result<(), String> {
    let d = abc()?;
    runner(d.path(), "raw", &[], &[(LINE, "{not json")])?
        .expect_code(1)?
        .expect_out("MALFORMED   t/b")?;
    Ok(())
}

fn malformed_shapes_fail() -> Result<(), String> {
    let bad = [
        "",
        "[]",
        "{\"name\":\"b\"}",
        "{\"output\":{\"ok\":1}}",
        "{\"name\":\"a\",\"output\":{\"ok\":{\"k\":[true,null,\"x\"]}}}",
        "{\"name\":\"b\",\"output\":{\"ok\":1},\"extra\":1}",
        "{\"name\":\"b\",\"output\":{\"ok\":1},\"output\":{\"ok\":1}}",
        "{\"name\":\"b\",\"output\":{\"k\":[true,null,\"x\"],\"k\":1}}",
        "{\"name\":\"b\",\"output\":{}}",
        "{\"name\":\"b\",\"output\":{\"ok\":1,\"error\":\"x\"}}",
        "{\"name\":\"b\",\"output\":{\"error\":5}}",
        "{\"name\":\"b\",\"output\":{\"error\":\"\"}}",
        "{\"name\":\"b\",\"output\":{\"unsupported\":false}}",
        "{\"name\":\"b\",\"output\":{\"unsupported\":1}}",
        "{\"name\":\"b\",\"output\":{\"unsupported\":true,\"x\":1}}",
        "{\"name\":\"b\",\"output\":\"ok\"}",
        "{\"name\":\"b\",\"output\":{\"ok\":{\"k\":[true,null,\"x\"]}}} trailing",
        "{\"name\":\"b\",\"output\":{\"ok\":{\"k\":[true,null,\"x\",]}}}",
        "{\"name\":\"b\",\"output\":{\"ok\":{\"k\":[true,null,\"x\"]}}}\u{1}",
        "{\"name\":\"b\",\"output\":{\"ok\":{\"k\":[true,NaN,\"x\"]}}}",
        "{\"name\":\"b\",\"output\":{\"ok\":{\"$serde_json::private::Number\":\"5\"}}}",
    ];
    for line in bad {
        let d = abc()?;
        let o = runner(d.path(), "raw", &[], &[(LINE, line)])?;
        o.expect_code(1)
            .map_err(|e| format!("line {line:?}: {e}"))?;
        o.expect_out("t/b")
            .map_err(|e| format!("line {line:?}: {e}"))?;
    }
    // Well-formed but differently ordered keys and an escaped string are fine.
    let d = abc()?;
    let ok = "{\"output\":{\"ok\":{\"k\":[true,null,\"\\u0078\"]}},\"name\":\"b\"}\r";
    runner(d.path(), "raw", &[], &[(LINE, ok)])?.expect_code(0)?;
    Ok(())
}

fn partial_last_line_fails() -> Result<(), String> {
    fails("partial", "MALFORMED   t/c  last line has no newline")
}

fn crash_fails() -> Result<(), String> {
    let d = abc()?;
    let o = runner(d.path(), "crash", &[], &[])?;
    o.expect_code(1)?
        .expect_out("- adapter: adapter ")?
        .expect_out("MISSING     t/b")?;
    #[cfg(unix)]
    o.expect_out("crashed (signal 6)")?;
    Ok(())
}

fn nonzero_exit_fails() -> Result<(), String> {
    fails("nonzero", "- adapter: adapter exit 3")
}

fn early_exit_fails() -> Result<(), String> {
    fails("early_exit", "MISSING     t/a")
}

fn case_timeout_fails() -> Result<(), String> {
    let d = abc()?;
    let o = runner(d.path(), "sleep", &["--case-timeout", "1"], &[])?;
    o.expect_code(1)?
        .expect_out("TIMEOUT     t/b")?
        .expect_out("MISSING     t/c")?;
    if o.elapsed > Duration::from_secs(20) {
        return Err(format!("took {:?}", o.elapsed));
    }
    Ok(())
}

fn overall_timeout_fails() -> Result<(), String> {
    let d = abc()?;
    for n in ["d", "e", "f", "g"] {
        d.vector("t", n, "0")?;
    }
    let o = runner(
        d.path(),
        "slow",
        &["--case-timeout", "5", "--timeout", "1"],
        &[],
    )?;
    o.expect_code(1)?.expect_out("TIMEOUT")?;
    if o.elapsed > Duration::from_secs(20) {
        return Err(format!("took {:?}", o.elapsed));
    }
    Ok(())
}

fn adapter_that_never_exits_fails() -> Result<(), String> {
    let d = abc()?;
    let o = runner(d.path(), "hang_open", &["--case-timeout", "1"], &[])?;
    o.expect_code(1)?.expect_out("did not exit")?;
    if o.elapsed > Duration::from_secs(20) {
        return Err(format!("took {:?}", o.elapsed));
    }
    Ok(())
}

fn orphan_holding_stderr_does_not_hang() -> Result<(), String> {
    let d = abc()?;
    let o = runner(d.path(), "orphan_stderr", &["--case-timeout", "2"], &[])?;
    o.expect_code(0)?;
    if o.elapsed > Duration::from_secs(10) {
        return Err(format!(
            "runner waited for the orphan: {:?}\n{}",
            o.elapsed,
            o.show()
        ));
    }
    Ok(())
}

fn missing_adapter_fails() -> Result<(), String> {
    let d = abc()?;
    let mut cmd = Command::new(RUNNER);
    cmd.arg("--vectors")
        .arg(d.path())
        .arg("--adapter")
        .arg(d.path().join("no-such-adapter"));
    run_cmd(cmd)?
        .expect_code(1)?
        .expect_out("MISSING     t/a")?;
    Ok(())
}

fn unsupported_allowed_unless_required() -> Result<(), String> {
    let d = abc()?;
    d.vector("u", "x", "1")?;
    runner(d.path(), "unsupported", &[], &[])?
        .expect_code(0)?
        .expect_out("unsupported t/a")?;
    runner(d.path(), "unsupported", &["--require", "t"], &[])?
        .expect_code(1)?
        .expect_out("unsupported t/a")?
        .expect_out("required")?;
    runner(d.path(), "unsupported", &["--require", "u"], &[])?.expect_code(1)?;
    Ok(())
}

fn zero_cases_fail() -> Result<(), String> {
    // No areas at all.
    let d = TempDir::new()?;
    runner(d.path(), "good", &[], &[])?
        .expect_code(1)?
        .expect_out("zero cases")?;
    // An empty area directory.
    let d = abc()?;
    fs::create_dir_all(d.path().join("empty")).map_err(|e| e.to_string())?;
    runner(d.path(), "good", &[], &[])?
        .expect_code(1)?
        .expect_out("empty")?;
    runner(d.path(), "good", &["--area", "empty"], &[])?.expect_code(1)?;
    // A required or selected area that does not exist is a usage error.
    let d = abc()?;
    runner(d.path(), "good", &["--require", "nope"], &[])?
        .expect_code(2)?
        .expect_out("nope")?;
    runner(d.path(), "good", &["--area", "nope"], &[])?
        .expect_code(2)?
        .expect_out("nope")?;
    // Vectors directory that does not exist.
    runner(&d.path().join("absent"), "good", &[], &[])?.expect_code(2)?;
    Ok(())
}

fn bad_vectors_are_hard_errors() -> Result<(), String> {
    let good = vector_text("t", "x", "1", "1");
    let cases: Vec<(&str, String, String)> = vec![
        (
            "unknown field",
            "t/x.json".into(),
            good.replace("\"source\"", "\"extra\": 1, \"source\""),
        ),
        (
            "missing source",
            "t/x.json".into(),
            good.replace(",\n  \"source\": \"test\"", ""),
        ),
        (
            "missing input",
            "t/x.json".into(),
            good.replace("\"input\": {\"value\": 1},", ""),
        ),
        (
            "missing expected",
            "t/x.json".into(),
            good.replace("\"expected\": {\"ok\": 1},", ""),
        ),
        ("name != file", "t/y.json".into(), good.clone()),
        ("area != dir", "u/x.json".into(), good.clone()),
        (
            "v 2",
            "t/x.json".into(),
            good.replace("\"v\": 1", "\"v\": 2"),
        ),
        (
            "v string",
            "t/x.json".into(),
            good.replace("\"v\": 1", "\"v\": \"1\""),
        ),
        (
            "duplicate key",
            "t/x.json".into(),
            good.replace("\"source\"", "\"area\": \"t\", \"source\""),
        ),
        (
            "expected both",
            "t/x.json".into(),
            good.replace("{\"ok\": 1}", "{\"ok\": 1, \"error\": \"e\"}"),
        ),
        (
            "expected unsupported",
            "t/x.json".into(),
            good.replace("{\"ok\": 1}", "{\"unsupported\": true}"),
        ),
        (
            "expected error number",
            "t/x.json".into(),
            good.replace("{\"ok\": 1}", "{\"error\": 1}"),
        ),
        (
            "expected not object",
            "t/x.json".into(),
            good.replace("{\"ok\": 1}", "1"),
        ),
        (
            "input not object",
            "t/x.json".into(),
            good.replace("{\"value\": 1}", "[1]"),
        ),
        (
            "oracle_expected bad",
            "t/x.json".into(),
            good.replace("\"source\"", "\"oracle_expected\": {}, \"source\""),
        ),
        (
            "gap not string",
            "t/x.json".into(),
            good.replace("\"source\"", "\"gap\": 1, \"source\""),
        ),
        (
            "empty source",
            "t/x.json".into(),
            good.replace("\"test\"", "\"\""),
        ),
        ("crlf", "t/x.json".into(), good.replace('\n', "\r\n")),
        ("bom", "t/x.json".into(), format!("\u{feff}{good}")),
        ("not json", "t/x.json".into(), "{".into()),
        ("trailing data", "t/x.json".into(), format!("{good}{{}}")),
        ("array top", "t/x.json".into(), "[]\n".into()),
        ("stray file", "t/README.md".into(), "hi\n".into()),
        (
            "bad name chars",
            "t/x y.json".into(),
            good.replace("\"x\"", "\"x y\""),
        ),
        ("stray top-level file", "README.md".into(), "hi\n".into()),
    ];
    for (what, path, text) in &cases {
        let d = TempDir::new()?;
        d.file(path, text)?;
        if path.as_str() != "t/x.json" {
            // keep a valid case alongside, so the error is not just "zero cases"
            d.file("t/x.json", &good)?;
        }
        let o = runner(d.path(), "good", &[], &[])?;
        o.expect_code(2)
            .and_then(|o| o.expect_out("vector error"))
            .map_err(|e| format!("{what}: {e}"))?;
    }
    // Names that differ only by case collide on Windows and macOS checkouts.
    let d = TempDir::new()?;
    d.file("t/x.json", &good)?;
    d.file("t/X.json", &vector_text("t", "X", "1", "1"))?;
    let o = runner(d.path(), "good", &[], &[])?;
    // Case-insensitive filesystems cannot even hold both files; then there is one case.
    if fs::read_dir(d.path().join("t"))
        .map_err(|e| e.to_string())?
        .count()
        == 2
    {
        o.expect_code(2)
            .map_err(|e| format!("case collision: {e}"))?;
    }
    Ok(())
}

fn oracle_mode_uses_oracle_expected() -> Result<(), String> {
    let d = TempDir::new()?;
    let text = vector_text("t", "x", "\"O\"", "\"E\"").replace(
        "\"source\"",
        "\"oracle_expected\": {\"ok\": \"O\"}, \"gap\": \"DM-2\", \"source\"",
    );
    d.file("t/x.json", &text)?;
    runner(d.path(), "good", &["--oracle"], &[])?.expect_code(0)?;
    runner(d.path(), "good", &[], &[])?
        .expect_code(1)?
        .expect_out("FAIL        t/x")?;
    // Without oracle_expected, --oracle falls back to expected.
    let d = TempDir::new()?;
    d.file("t/x.json", &vector_text("t", "x", "\"O\"", "\"E\""))?;
    runner(d.path(), "good", &["--oracle"], &[])?.expect_code(1)?;
    Ok(())
}

fn numbers_compare_exactly() -> Result<(), String> {
    let pairs_equal = [
        ("1", "1.0"),
        ("100", "1E2"),
        ("0", "-0.0"),
        ("18446744073709551617", "18446744073709551617"),
    ];
    let pairs_differ = [
        ("9007199254740993", "9007199254740992"),
        ("0.1", "0.10000000000000001"),
        ("1", "\"1\""),
        ("18446744073709551617", "18446744073709551616"),
    ];
    let all = pairs_equal
        .iter()
        .map(|&(e, g)| (e, g, 0))
        .chain(pairs_differ.iter().map(|&(e, g)| (e, g, 1)));
    for (expected, got, code) in all {
        let d = TempDir::new()?;
        d.vector("t", "a", "1")?;
        d.file("t/b.json", &vector_text("t", "b", "1", expected))?;
        d.vector("t", "c", "1")?;
        let line = format!("{{\"name\":\"b\",\"output\":{{\"ok\":{got}}}}}");
        runner(d.path(), "raw", &[], &[(LINE, &line)])?
            .expect_code(code)
            .map_err(|e| format!("expected {expected} got {got}: {e}"))?;
    }
    Ok(())
}

fn area_selection() -> Result<(), String> {
    let d = abc()?;
    d.vector("u", "x", "1")?;
    let o = runner(d.path(), "good", &["--area", "u"], &[])?;
    o.expect_code(0)?.expect_out("ok          u/x")?;
    if o.stdout.contains("t/a") {
        return Err(format!(
            "area t ran although only u was selected\n{}",
            o.show()
        ));
    }
    // --require adds the area to the selection.
    runner(d.path(), "good", &["--area", "u", "--require", "t"], &[])?
        .expect_code(0)?
        .expect_out("t/a")?;
    Ok(())
}

fn json_report() -> Result<(), String> {
    let d = abc()?;
    let report = d.path().join("report.json");
    let r = report.to_string_lossy().into_owned();
    let vec_dir = d.path().join("v");
    d.file("v/t/a.json", &vector_text("t", "a", "1", "1"))?;
    d.file("v/t/b.json", &vector_text("t", "b", "2", "2"))?;
    runner(&vec_dir, "wrong", &["--json", &r], &[])?.expect_code(1)?;
    let text = fs::read_to_string(&report).map_err(|e| e.to_string())?;
    let j: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{e}: {text}"))?;
    let s = j.get("summary").ok_or("no summary")?;
    let num = |k: &str| s.get(k).and_then(serde_json::Value::as_u64);
    if num("cases") != Some(2) || num("ok") != Some(1) || num("fail") != Some(1) {
        return Err(format!("summary wrong: {text}"));
    }
    if j.get("result").and_then(|x| x.as_str()) != Some("fail") {
        return Err(format!("result wrong: {text}"));
    }
    let cases = j
        .get("cases")
        .and_then(|c| c.as_array())
        .ok_or("no cases")?;
    if cases.len() != 2 {
        return Err(format!("cases wrong: {text}"));
    }
    Ok(())
}

fn manifest_required_and_oracle() -> Result<(), String> {
    let d = abc()?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let adapters = TempDir::new()?;
    let me_json = serde_json::to_string(&me.to_string_lossy()).map_err(|e| e.to_string())?;
    let manifest = |name: &str, required: &str| -> Result<PathBuf, String> {
        adapters.file(
            &format!("{name}/manifest.json"),
            &format!("{{\"v\": 1, \"command\": [{me_json}], \"required\": {required}, \"oracle\": false}}\n"),
        )?;
        Ok(adapters.path().join(name).join("manifest.json"))
    };
    let run = |m: &Path, mode: &str| -> Result<Out, String> {
        let mut cmd = Command::new(RUNNER);
        cmd.arg("--vectors")
            .arg(d.path())
            .arg("--manifest")
            .arg(m)
            .env(MODE, mode);
        run_cmd(cmd)
    };
    let m = manifest("m", "[\"t\"]")?;
    run(&m, "good")?.expect_code(0)?;
    run(&m, "unsupported")?
        .expect_code(1)?
        .expect_out("required")?;
    // A required area that does not exist (a typo, or vectors not landed yet) is an
    // error, never a silently weaker requirement.
    let m = manifest("typo", "[\"t\", \"absent\"]")?;
    run(&m, "good")?.expect_code(2)?.expect_out("absent")?;
    Ok(())
}

fn bad_manifests_are_hard_errors() -> Result<(), String> {
    let d = abc()?;
    let bad = [
        "{}",
        "{\"v\": 1, \"command\": [], \"required\": [], \"oracle\": false}",
        "{\"v\": 1, \"command\": \"./adapter\", \"required\": [], \"oracle\": false}",
        "{\"v\": 1, \"command\": [\"./a\"], \"required\": [], \"oracle\": \"no\"}",
        "{\"v\": 1, \"command\": [\"./a\"], \"required\": [], \"oracle\": false, \"x\": 1}",
        "{\"v\": 2, \"command\": [\"./a\"], \"required\": [], \"oracle\": false}",
        "{\"v\": 1, \"command\": [\"./a\"], \"required\": [1], \"oracle\": false}",
        "{\"v\": 1, \"command\": [\"./a\"], \"required\": [], \"required\": [\"t\"], \"oracle\": false}",
    ];
    for m in bad {
        let a = TempDir::new()?;
        a.file("m/manifest.json", m)?;
        let mut cmd = Command::new(RUNNER);
        cmd.arg("--vectors")
            .arg(d.path())
            .arg("--manifest")
            .arg(a.path().join("m/manifest.json"));
        run_cmd(cmd)?
            .expect_code(2)
            .map_err(|e| format!("manifest {m}: {e}"))?;
    }
    Ok(())
}

fn usage_errors() -> Result<(), String> {
    let d = abc()?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let me = me.to_string_lossy().into_owned();
    let v = d.path().to_string_lossy().into_owned();
    let bad: [&[&str]; 6] = [
        &[],
        &["--vectors", &v],
        &["--vectors", &v, "--adapter", &me, "--bogus"],
        &["--vectors", &v, "--adapter", &me, "--case-timeout", "x"],
        &["--vectors", &v, "--adapter", &me, "--case-timeout", "0"],
        &["--vectors", &v, "--adapter", &me, "--manifest", "m.json"],
    ];
    for args in bad {
        let mut cmd = Command::new(RUNNER);
        cmd.args(args).env(MODE, "good");
        run_cmd(cmd)?
            .expect_code(2)
            .map_err(|e| format!("args {args:?}: {e}"))?;
    }
    Ok(())
}
