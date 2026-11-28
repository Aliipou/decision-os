//! Red team (conformance-runner): the runner process, manifests, the vector loader and
//! `conformance/run.sh`, attacked through hostile adapters written as POSIX `sh` scripts.
//!
//! Every test asserts what the spec (or the threat model) requires. A test that FAILS is
//! a finding (see findings/conformance-runner.md); one that passes is a negative result.
//! Needs `bash` (the adapters use bash builtins plus `sleep` and `yes`), and `git` for the
//! run.sh tests. Meant for Linux (CI, WSL); see the findings for the Windows caveats.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const RUNNER: &str = env!("CARGO_BIN_EXE_dos-conformance");

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Tmp {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("dos-rt-conf-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        assert!(fs::create_dir_all(&p).is_ok());
        Tmp(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn file(&self, rel: &str, content: &str) -> PathBuf {
        let p = self.0.join(rel);
        if let Some(parent) = p.parent() {
            assert!(fs::create_dir_all(parent).is_ok());
        }
        assert!(fs::write(&p, content).is_ok(), "write {}", p.display());
        p
    }
    /// `<area>/<name>.json` with input `{"op":"echo","value":<value>}`.
    fn echo_vector(&self, area: &str, name: &str, value: &str, expected: &str) {
        self.file(
            &format!("v/{area}/{name}.json"),
            &format!(
                "{{\n  \"v\": 1,\n  \"area\": \"{area}\",\n  \"name\": \"{name}\",\n  \"input\": {{\"op\": \"echo\", \"value\": {value}}},\n  \"expected\": {{\"ok\": {expected}}},\n  \"source\": \"red team\"\n}}\n"
            ),
        );
    }
    fn vectors(&self) -> PathBuf {
        self.0.join("v")
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn posix(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Shell prelude: `$area` and `$name` of each request, in a loop body called `answer`.
/// bash builtins only (no sed/cat/head), so it needs nothing but bash.
const LOOP: &str = r#"
re_id='^\{"area":"([^"]*)","name":"([^"]*)"'
re_val='"input":\{"op":"echo","value":(.*)\}\}$'
while IFS= read -r line; do
  area=; name=; value=
  if [[ $line =~ $re_id ]]; then area=${BASH_REMATCH[1]}; name=${BASH_REMATCH[2]}; fi
  if [[ $line =~ $re_val ]]; then value=${BASH_REMATCH[1]}; fi
  answer
done
"#;

/// A spawn failure is a FAIL for the runner and would make every "must not pass"
/// assertion vacuous, so every run must show the adapter started.
fn started(o: Out) -> Out {
    assert!(
        !o.stdout.contains("cannot start"),
        "test adapter did not start (bash missing?):\n{}",
        o.show()
    );
    o
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
            "exit {:?} after {:?}\n--- stdout\n{}--- stderr\n{}",
            self.code,
            self.elapsed,
            tail(&self.stdout),
            tail(&self.stderr)
        )
    }
}

fn tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let from = lines.len().saturating_sub(25);
    let mut out = lines.get(from..).unwrap_or_default().join("\n");
    out.push('\n');
    out
}

fn run(mut cmd: Command) -> Out {
    let start = Instant::now();
    let o = cmd.output();
    assert!(o.is_ok(), "spawn: {:?}", o.as_ref().err());
    let o = o.unwrap_or_else(|_| std::process::exit(99));
    Out {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        elapsed: start.elapsed(),
    }
}

/// Run the runner with `bash <script>` as the adapter.
fn runner_sh(t: &Tmp, script: &str, extra: &[&str]) -> Out {
    let s = t.file("adapter.sh", script);
    let mut cmd = Command::new(RUNNER);
    cmd.arg("--vectors")
        .arg(t.vectors())
        .arg("--adapter")
        .arg("bash")
        .arg("--arg")
        .arg(posix(&s))
        .args(extra);
    started(run(cmd))
}

/// A manifest with the same shape as conformance/adapters/*/manifest.json.
fn runner_manifest(t: &Tmp, script: &str, required: &str, oracle: bool, extra: &[&str]) -> Out {
    let s = t.file("adapter.sh", script);
    let m = t.file(
        "m/manifest.json",
        &format!(
            "{{\"v\": 1, \"command\": [\"bash\", \"{}\"], \"required\": {required}, \"oracle\": {oracle}}}\n",
            posix(&s)
        ),
    );
    let mut cmd = Command::new(RUNNER);
    cmd.arg("--vectors")
        .arg(t.vectors())
        .arg("--manifest")
        .arg(m)
        .args(extra);
    started(run(cmd))
}

/// Echoes selftest; answers `unsupported` for every other area (an adapter that
/// implements nothing beyond the pipe).
fn selftest_only() -> String {
    format!(
        r#"answer() {{
  if [ "$area" = selftest ]; then
    printf '{{"name":"%s","output":{{"ok":%s}}}}\n' "$name" "$value"
  else
    printf '{{"name":"%s","output":{{"unsupported":true}}}}\n' "$name"
  fi
}}
{LOOP}"#
    )
}

// ---------------------------------------------------------------- H1, H2: inert areas

/// H1. REDTEAM.md says lock-in vectors go to conformance/vectors/redteam/. That
/// directory is an area named `redteam`; with the manifests as committed
/// (`required: ["selftest"]`) an adapter that implements nothing there passes, even
/// against an expected value no implementation could produce.
#[test]
fn rt_h1_redteam_lock_in_vectors_are_inert() {
    let t = Tmp::new();
    t.echo_vector("selftest", "a", "1", "1");
    t.echo_vector(
        "redteam",
        "impossible",
        "1",
        "\"this expected value is wrong\"",
    );
    let o = runner_manifest(&t, &selftest_only(), "[\"selftest\"]", false, &[]);
    assert!(
        o.code != Some(0),
        "a red-team lock-in vector checked nothing and the run PASSED:\n{}",
        o.show()
    );
}

/// H2. An area with vectors that the adapter answers `unsupported` for passes unless a
/// manifest lists it. Nothing ties "area has vectors" to "the Rust adapter must
/// implement it", so a Rust adapter that drops a handler still passes the gate.
#[test]
fn rt_h2_area_with_vectors_but_not_required_passes_unsupported() {
    let t = Tmp::new();
    t.echo_vector("selftest", "a", "1", "1");
    for n in ["c1", "c2", "c3"] {
        t.echo_vector("canon", n, "1", "1");
    }
    let o = runner_manifest(&t, &selftest_only(), "[\"selftest\"]", false, &[]);
    assert!(
        o.code != Some(0),
        "3 cases in area canon, 0 implemented, run PASSED:\n{}",
        o.show()
    );
}

// ---------------------------------------------------------------- H7: resource bounds

/// H7. Every FAIL keeps the adapter's full answer (up to 16 MiB a line) and the JSON
/// report writes each one in full: memory and report size grow with cases x line size.
#[test]
fn rt_h7_report_and_memory_bounded_for_huge_wrong_answers() {
    let t = Tmp::new();
    let cases = 24;
    for i in 0..cases {
        t.echo_vector("t", &format!("c{i:03}"), "1", "1");
    }
    // 2 MiB wrong string per case.
    let script = format!(
        r#"answer() {{
  printf '{{"name":"%s","output":{{"ok":"%s"}}}}\n' "$name" "$big"
}}
big=$(printf '%*s' 2097152 '')
big=${{big// /a}}
{LOOP}"#
    );
    let report = t.path().join("report.json");
    let r = report.to_string_lossy().into_owned();
    let o = runner_sh(&t, &script, &["--json", &r, "--case-timeout", "60"]);
    assert_eq!(o.code, Some(1), "{}", o.show());
    let size = fs::metadata(&report).map(|m| m.len()).unwrap_or(0);
    assert!(
        size < 8 * 1024 * 1024,
        "report is {size} bytes for {cases} cases (grows with cases x 16 MiB)"
    );
}

/// H11. An endless line without a newline is cut at 16 MiB, quickly.
#[test]
fn rt_h11_endless_line_is_cut() {
    let t = Tmp::new();
    t.echo_vector("t", "a", "1", "1");
    let o = runner_sh(
        &t,
        "c=$(printf '%*s' 65536 '')\nwhile :; do printf '%s' \"$c\" || exit 0; done\n",
        &["--case-timeout", "30"],
    );
    assert_eq!(o.code, Some(1), "{}", o.show());
    assert!(o.stdout.contains("MALFORMED   t/a"), "{}", o.show());
    assert!(o.elapsed < Duration::from_secs(30), "{}", o.show());
}

// ---------------------------------------------------------------- H9: report spoofing

/// H9. The adapter's stderr is printed verbatim (newlines kept) on FAIL, before the real
/// verdict, so it can print its own `result: PASS` and `ok` lines into the log.
#[test]
fn rt_h9_adapter_stderr_cannot_forge_verdict_lines() {
    let t = Tmp::new();
    t.echo_vector("t", "a", "1", "1");
    let script = format!(
        r#"answer() {{
  printf '{{"name":"%s","output":{{"ok":2}}}}\n' "$name"
}}
{LOOP}
printf 'ok          t/a\nsummary: 1 cases (ok 1, FAIL 0, unsupported 0, MISSING 0, MALFORMED 0, TIMEOUT 0), extra lines 0\nresult: PASS\n' >&2
"#
    );
    let o = runner_sh(&t, &script, &[]);
    assert_eq!(o.code, Some(1), "{}", o.show());
    let verdicts = o
        .stdout
        .lines()
        .filter(|l| l.starts_with("result: "))
        .count();
    let oks = o.stdout.lines().filter(|l| l.starts_with("ok ")).count();
    assert!(
        verdicts == 1 && oks == 0,
        "adapter text forged {verdicts} verdict line(s) and {oks} ok line(s) on stdout:\n{}",
        o.show()
    );
}

/// H9. Raw control bytes (ESC) from a malformed response reach the terminal/log.
#[test]
fn rt_h9_no_raw_escape_bytes_from_malformed_lines() {
    let t = Tmp::new();
    t.echo_vector("t", "a", "1", "1");
    let script = format!(
        r#"answer() {{
  printf 'x\033[1A\033[2K\033[32mok          t/a\033[0m\n'
}}
{LOOP}"#
    );
    let o = runner_sh(&t, &script, &[]);
    assert_eq!(o.code, Some(1), "{}", o.show());
    assert!(
        !o.stdout.contains('\u{1b}'),
        "raw ESC from the adapter on the runner's stdout:\n{:?}",
        o.stdout
    );
}

// ---------------------------------------------------------------- H8, H10: processes

/// H8. On a timeout the runner kills the adapter, but not the adapter's children: a
/// grandchild keeps running after the runner has returned its verdict.
#[test]
fn rt_h8_killed_adapter_leaves_no_running_children() {
    let t = Tmp::new();
    t.echo_vector("t", "a", "1", "1");
    let marker = t.path().join("alive");
    let script = format!(
        "(sleep 4; echo alive > '{}') </dev/null >/dev/null 2>&1 &\nsleep 60\n",
        posix(&marker)
    );
    let o = runner_sh(&t, &script, &["--case-timeout", "1"]);
    assert_eq!(o.code, Some(1), "{}", o.show());
    std::thread::sleep(Duration::from_secs(6));
    assert!(
        !marker.exists(),
        "a child of the killed adapter was still running {:?} after the verdict",
        Duration::from_secs(6)
    );
}

/// H10. A flood of extra lines after the last response must not keep the runner busy
/// past the overall timeout.
#[test]
fn rt_h10_flood_after_last_response_is_bounded() {
    let t = Tmp::new();
    t.echo_vector("t", "a", "1", "1");
    let script = format!(
        r#"answer() {{
  printf '{{"name":"%s","output":{{"ok":1}}}}\n' "$name"
}}
{LOOP}
yes '{{"name":"a","output":{{"ok":1}}}}'
"#
    );
    let o = runner_sh(&t, &script, &["--case-timeout", "2", "--timeout", "4"]);
    assert_eq!(o.code, Some(1), "{}", o.show());
    assert!(o.elapsed < Duration::from_secs(20), "{}", o.show());
}

/// H10. An adapter that answers each case just under the per-case timeout is stopped by
/// the overall timeout.
#[test]
fn rt_h10_slow_loris_hits_overall_timeout() {
    let t = Tmp::new();
    for n in ["a", "b", "c", "d", "e"] {
        t.echo_vector("t", n, "1", "1");
    }
    let script = format!(
        r#"answer() {{
  sleep 1
  printf '{{"name":"%s","output":{{"ok":1}}}}\n' "$name"
}}
{LOOP}"#
    );
    let o = runner_sh(&t, &script, &["--case-timeout", "2", "--timeout", "3"]);
    assert_eq!(o.code, Some(1), "{}", o.show());
    assert!(o.stdout.contains("overall timeout"), "{}", o.show());
}

// ---------------------------------------------------------------- H11: framing

#[test]
fn rt_h11_framing_attacks_fail() {
    let lines: &[(&str, &str)] = &[
        (
            "two answers on one line",
            r#"{"name":"a","output":{"ok":1}}{"name":"b","output":{"ok":1}}"#,
        ),
        ("BOM", "\u{feff}{\"name\":\"a\",\"output\":{\"ok\":1}}"),
        ("NUL", "{\"name\":\"a\",\"output\":{\"ok\":1}}\u{0}"),
        ("answer for b at a", r#"{"name":"b","output":{"ok":1}}"#),
        (
            "echo of the request",
            r#"{"area":"t","name":"a","input":{"op":"echo","value":1}}"#,
        ),
        (
            "CR only",
            "{\"name\":\"a\",\"output\":{\"ok\":1}}\r{\"name\":\"b\",\"output\":{\"ok\":1}}",
        ),
    ];
    for (what, line) in lines {
        let t = Tmp::new();
        t.echo_vector("t", "a", "1", "1");
        t.echo_vector("t", "b", "1", "1");
        let f = t.file("line.txt", &format!("{line}\n"));
        let script = format!(
            "IFS= read -r l < '{}'; printf '%s\\n' \"$l\"\nprintf '{{\"name\":\"b\",\"output\":{{\"ok\":1}}}}\\n'\nwhile IFS= read -r _; do :; done\n",
            posix(&f)
        );
        let o = runner_sh(&t, &script, &[]);
        assert_eq!(o.code, Some(1), "{what}: {}", o.show());
    }
}

// ---------------------------------------------------------------- H12: manifests

/// H12. CONFORMANCE-notes says every adapter must support selftest and "both manifests
/// require it", but a manifest with `required: []` is accepted and an adapter that
/// answers `unsupported` to everything then passes.
#[test]
fn rt_h12_manifest_without_selftest_requirement_is_refused() {
    let t = Tmp::new();
    t.echo_vector("selftest", "a", "1", "1");
    let nothing = format!(
        r#"answer() {{
  printf '{{"name":"%s","output":{{"unsupported":true}}}}\n' "$name"
}}
{LOOP}"#
    );
    let o = runner_manifest(&t, &nothing, "[]", false, &[]);
    assert!(
        o.code != Some(0),
        "an adapter supporting nothing PASSED with required []:\n{}",
        o.show()
    );
}

// ---------------------------------------------------------------- H13: vector tree

#[test]
fn rt_h13_json_named_directory_is_an_error() {
    let t = Tmp::new();
    t.echo_vector("t", "a", "1", "1");
    t.echo_vector("t", "b.json", "1", "1"); // creates v/t/b.json.json
    assert!(fs::create_dir_all(t.vectors().join("t").join("c.json")).is_ok());
    let o = runner_sh(&t, &selftest_only(), &[]);
    assert_eq!(o.code, Some(2), "{}", o.show());
}

#[cfg(windows)]
#[test]
fn rt_h13_junction_area_is_an_error() {
    let t = Tmp::new();
    t.echo_vector("t", "a", "1", "1");
    let outside = t.path().join("outside");
    t.file("outside/x.json", "{}");
    let link = t.vectors().join("j");
    let o = Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(&link)
        .arg(&outside)
        .output();
    assert!(
        o.map(|o| o.status.success()).unwrap_or(false),
        "mklink /J failed"
    );
    let o = runner_sh(&t, &selftest_only(), &[]);
    assert_eq!(o.code, Some(2), "{}", o.show());
}

#[cfg(unix)]
#[test]
fn rt_h13_symlinks_and_fifos_are_errors() {
    let t = Tmp::new();
    t.echo_vector("t", "a", "1", "1");
    t.file("outside/x.json", "{}");
    assert!(std::os::unix::fs::symlink(t.path().join("outside"), t.vectors().join("s")).is_ok());
    let o = runner_sh(&t, &selftest_only(), &[]);
    assert_eq!(o.code, Some(2), "symlinked area: {}", o.show());
    let t = Tmp::new();
    t.echo_vector("t", "a", "1", "1");
    let fifo = t.vectors().join("t").join("f.json");
    let mk = Command::new("mkfifo").arg(&fifo).status();
    assert!(mk.map(|s| s.success()).unwrap_or(false));
    let o = runner_sh(&t, &selftest_only(), &["--case-timeout", "2"]);
    assert_eq!(o.code, Some(2), "fifo: {}", o.show());
    assert!(o.elapsed < Duration::from_secs(10));
}

// ---------------------------------------------------------------- H14: oracle adapter

/// H14. A legitimate selftest vector (an integer of 5000 digits; the spec says numbers
/// compare exactly and are never converted) makes the oracle adapter's json.loads
/// raise (Python's int max_str_digits = 4300), the adapter exits 2 and every later case
/// is MISSING: one case takes the whole oracle run down. Runs only if Python is found
/// (DOS_PYTHON or python3).
#[test]
fn rt_h14_oracle_adapter_survives_long_integer() {
    let py = std::env::var("DOS_PYTHON").unwrap_or_else(|_| "python3".into());
    if Command::new(&py).arg("--version").output().is_err() {
        eprintln!("rt_h14: no Python ({py}); not run");
        return;
    }
    let t = Tmp::new();
    let big = format!("1{}", "0".repeat(5000));
    t.echo_vector("selftest", "a-big", &big, &big);
    t.echo_vector("selftest", "b-small", "1", "1");
    let adapter_py = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/adapters/oracle-decision-os-min/adapter.py");
    let mut cmd = Command::new(RUNNER);
    cmd.arg("--vectors")
        .arg(t.vectors())
        .arg("--adapter")
        .arg(&py)
        .args(["--arg", "-I", "--arg", "-B", "--arg"])
        .arg(&adapter_py)
        .arg("--oracle");
    let o = run(cmd);
    assert!(
        o.stdout.contains("ok          selftest/b-small"),
        "one long integer took the oracle adapter down for every later case:\n{}",
        o.show()
    );
}

// ---------------------------------------------------------------- H3: run.sh --changed-since

/// A throwaway git repo holding conformance/run.sh and one selftest vector, committed.
/// `cargo` on PATH is a stub that fails loudly, so "the runner would have run" shows
/// as `FAKE-CARGO` and "skipped" shows as exit 0 with "nothing to run".
fn changed_since_repo() -> Tmp {
    let t = Tmp::new();
    let run_sh = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/run.sh");
    let text = fs::read_to_string(&run_sh).unwrap_or_default();
    assert!(!text.is_empty(), "cannot read {}", run_sh.display());
    t.file("conformance/run.sh", &text);
    t.file(
        "conformance/vectors/selftest/a.json",
        "{\n  \"v\": 1,\n  \"area\": \"selftest\",\n  \"name\": \"a\",\n  \"input\": {\"op\": \"echo\", \"value\": 1},\n  \"expected\": {\"ok\": 1},\n  \"source\": \"rt\"\n}\n",
    );
    t.file(".gitignore", "fakebin/\n");
    t.file(
        "fakebin/cargo",
        "#!/bin/sh\necho FAKE-CARGO \"$@\"\nexit 1\n",
    );
    git(&t, &["init", "-q"]);
    git(&t, &["add", "-A"]);
    git(&t, &["commit", "-q", "-m", "base"]);
    t
}

fn git(t: &Tmp, args: &[&str]) {
    let s = Command::new("git")
        .args([
            "-c",
            "user.name=rt",
            "-c",
            "user.email=rt@example.invalid",
            "-c",
            "core.autocrlf=false",
        ])
        .args(args)
        .current_dir(t.path())
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output();
    assert!(
        s.as_ref().map(|o| o.status.success()).unwrap_or(false),
        "git {args:?}: {s:?}"
    );
}

fn changed_since(t: &Tmp, base: &str) -> Out {
    let mut cmd = Command::new("bash");
    cmd.arg("-c")
        .arg("PATH=\"$PWD/fakebin:$PATH\"; chmod +x fakebin/cargo; exec bash conformance/run.sh --changed-since \"$1\"")
        .arg("_")
        .arg(base)
        .current_dir(t.path())
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    run(cmd)
}

fn base_rev(t: &Tmp) -> String {
    let o = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(t.path())
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output();
    o.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn assert_not_skipped(what: &str, o: &Out) {
    assert!(
        o.stdout.contains("FAKE-CARGO") || o.stderr.contains("FAKE-CARGO") || o.code != Some(0),
        "{what}: --changed-since skipped a change that `--all` refuses (exit 2):\n{}",
        o.show()
    );
}

#[test]
fn rt_h3_changed_since_control_new_vector_runs() {
    let t = changed_since_repo();
    let base = base_rev(&t);
    t.file("conformance/vectors/selftest/b.json", "{}");
    let o = changed_since(&t, &base);
    assert!(
        o.stdout.contains("FAKE-CARGO") || o.stderr.contains("FAKE-CARGO"),
        "{}",
        o.show()
    );
}

#[test]
fn rt_h3_changed_since_non_ascii_vector_name() {
    let t = changed_since_repo();
    let base = base_rev(&t);
    t.file("conformance/vectors/selftest/\u{e9}.json", "{}");
    assert_not_skipped("untracked selftest/é.json", &changed_since(&t, &base));
}

#[test]
fn rt_h3_changed_since_stray_file_in_vectors_root() {
    let t = changed_since_repo();
    let base = base_rev(&t);
    t.file("conformance/vectors/README.md", "hi\n");
    assert_not_skipped("conformance/vectors/README.md", &changed_since(&t, &base));
}

#[test]
fn rt_h3_changed_since_deleted_area() {
    let t = changed_since_repo();
    let base = base_rev(&t);
    git(&t, &["rm", "-q", "-r", "conformance/vectors/selftest"]);
    git(&t, &["commit", "-q", "-m", "drop selftest"]);
    assert_not_skipped("deleted area selftest", &changed_since(&t, &base));
}

#[test]
fn rt_h3_changed_since_gitattributes() {
    let t = changed_since_repo();
    let base = base_rev(&t);
    t.file(".gitattributes", "*.json text eol=crlf\n");
    assert_not_skipped(
        ".gitattributes (vectors become CRLF on checkout)",
        &changed_since(&t, &base),
    );
}
