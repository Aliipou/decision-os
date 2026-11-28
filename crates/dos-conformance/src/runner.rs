//! Runs the selected vectors through one adapter process and judges the answers.

use crate::json::{self, Json};
use crate::protocol::{self, Output};
use crate::vector::{self, Vector};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

/// Longest response line accepted (bytes, newline excluded).
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
/// How much of the adapter's stderr is kept for the report.
const STDERR_KEEP: usize = 16 * 1024;
/// How long to wait for the adapter's stderr to close after it exited.
const STDERR_WAIT: Duration = Duration::from_millis(500);
/// Longest expected/got rendering printed per case.
const SHOW_MAX: usize = 600;

pub const EXIT_PASS: i32 = 0;
pub const EXIT_FAIL: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

#[derive(Debug, Clone)]
pub struct Config {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub vectors: PathBuf,
    /// Selected areas; empty means every area present.
    pub areas: Vec<String>,
    /// Required on the command line: must exist and be fully supported.
    pub require: Vec<String>,
    /// Required by a manifest: fully supported when selected; absent ones are noted.
    pub manifest_required: Vec<String>,
    /// `Some` when the adapter comes from a manifest: `unsupported` is tolerated only in
    /// these areas (and never in required ones). `None` for a bare `--adapter`.
    pub unsupported_ok: Option<Vec<String>>,
    pub oracle: bool,
    pub json: Option<PathBuf>,
    pub case_timeout: Duration,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq)]
enum Status {
    Ok,
    Fail { got: Output },
    Unsupported { required: bool },
    Missing,
    Malformed { why: String },
    Timeout { which: &'static str },
}

impl Status {
    fn label(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Fail { .. } => "FAIL",
            Status::Unsupported { .. } => "unsupported",
            Status::Missing => "MISSING",
            Status::Malformed { .. } => "MALFORMED",
            Status::Timeout { .. } => "TIMEOUT",
        }
    }
    fn passes(&self) -> bool {
        matches!(self, Status::Ok | Status::Unsupported { required: false })
    }
}

enum Msg {
    Line(Vec<u8>),
    Partial,
    TooLong,
    Eof,
    ReadError(String),
}

/// Run and print; returns the process exit code.
pub fn run(cfg: &Config) -> i32 {
    let all = match vector::load_all(&cfg.vectors) {
        Ok(a) => a,
        Err(errors) => {
            for e in &errors {
                eprintln!("vector error: {e}");
            }
            eprintln!("{} vector error(s); nothing was run", errors.len());
            return EXIT_USAGE;
        }
    };
    let mut selected: BTreeSet<String> = if cfg.areas.is_empty() {
        all.keys().cloned().collect()
    } else {
        cfg.areas.iter().cloned().collect()
    };
    selected.extend(cfg.require.iter().cloned());
    for a in &selected {
        if !all.contains_key(a) {
            eprintln!(
                "error: area {a:?} has no directory under {}",
                cfg.vectors.display()
            );
            return EXIT_USAGE;
        }
    }
    let mut reasons: Vec<String> = Vec::new();
    let mut required: BTreeSet<String> = cfg.require.iter().cloned().collect();
    for a in &cfg.manifest_required {
        if !all.contains_key(a) {
            // A typo here would silently weaken the requirement; refuse instead.
            eprintln!(
                "error: the manifest requires area {a:?}, which has no directory under {}",
                cfg.vectors.display()
            );
            return EXIT_USAGE;
        }
        if selected.contains(a) {
            required.insert(a.clone());
        }
    }
    if let Some(ok) = &cfg.unsupported_ok {
        for a in ok {
            if !all.contains_key(a) {
                // A typo here would silently tolerate nothing; refuse instead.
                eprintln!(
                    "error: the manifest tolerates unsupported area {a:?}, which has no directory under {}",
                    cfg.vectors.display()
                );
                return EXIT_USAGE;
            }
        }
    }
    let mut cases: Vec<&Vector> = Vec::new();
    for a in &selected {
        let v = all.get(a).map(Vec::as_slice).unwrap_or_default();
        if v.is_empty() {
            reasons.push(format!("area {a:?} is selected but empty (zero cases)"));
        }
        cases.extend(v.iter());
    }
    if cases.is_empty() {
        reasons.push("zero cases selected".into());
    }

    let mut session = execute(cfg, &cases);
    let mut statuses = std::mem::take(&mut session.statuses);
    for (v, st) in cases.iter().zip(statuses.iter_mut()) {
        if let Status::Unsupported { required: r } = st {
            // `required` here means "this unsupported answer fails the run": the area is
            // required, or a manifest is in use and does not tolerate it (red team H1,
            // H2, H12: an adapter that drops a handler must not pass).
            let tolerated = cfg
                .unsupported_ok
                .as_ref()
                .is_none_or(|ok| ok.contains(&v.area));
            *r = required.contains(&v.area) || !tolerated;
        }
    }

    // Per-case lines.
    let mut counts = [0usize; 6];
    for (v, st) in cases.iter().zip(&statuses) {
        let idx = match st {
            Status::Ok => 0,
            Status::Fail { .. } => 1,
            Status::Unsupported { .. } => 2,
            Status::Missing => 3,
            Status::Malformed { .. } => 4,
            Status::Timeout { .. } => 5,
        };
        if let Some(c) = counts.get_mut(idx) {
            *c += 1;
        }
        let detail = match st {
            Status::Fail { got } => format!(
                "  expected {} got {}",
                show(&json::write(&v.want(cfg.oracle).to_json())),
                show(&json::write(&got.to_json()))
            ),
            Status::Unsupported { required: true } if required.contains(&v.area) => {
                format!("  (area {:?} is required)", v.area)
            }
            Status::Unsupported { required: true } => {
                format!(
                    "  (area {:?} is not listed in the manifest's unsupported_ok)",
                    v.area
                )
            }
            Status::Malformed { why } => format!("  {}", show(why)),
            Status::Timeout { which } => format!("  ({which} timeout)"),
            _ => String::new(),
        };
        println!("{:<12}{}/{}{detail}", st.label(), v.area, v.name);
    }
    let [ok, fail, unsupported, missing, malformed, timeout] = counts;

    if let Some(e) = &session.adapter_error {
        reasons.push(format!("adapter: {e}"));
    }
    if session.extra > 0 {
        reasons.push(format!(
            "{} extra line(s) after the last response",
            session.extra
        ));
    }
    if fail + missing + malformed + timeout > 0 {
        reasons.push("not every case passed".into());
    }
    let required_unsupported = statuses
        .iter()
        .filter(|s| matches!(s, Status::Unsupported { required: true }))
        .count();
    if required_unsupported > 0 {
        reasons.push(format!(
            "{required_unsupported} unsupported case(s) in required area(s)"
        ));
    }
    debug_assert_eq!(
        statuses.iter().all(Status::passes),
        fail + missing + malformed + timeout + required_unsupported == 0
    );

    println!(
        "summary: {} cases (ok {ok}, FAIL {fail}, unsupported {unsupported}, MISSING {missing}, MALFORMED {malformed}, TIMEOUT {timeout}), extra lines {}",
        cases.len(),
        session.extra
    );
    println!("adapter: {}", session.exit_text);
    if !required.is_empty() {
        println!(
            "required areas: {}",
            required.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    let pass = reasons.is_empty();
    if pass {
        println!("result: PASS");
    } else {
        if !session.stderr.is_empty() {
            println!(
                "adapter stderr (last {} bytes):\n{}",
                session.stderr.len(),
                session.stderr.trim_end()
            );
        }
        println!("result: FAIL");
        for r in &reasons {
            println!("  - {r}");
        }
    }

    if let Some(path) = &cfg.json {
        let report = report_json(
            cfg, &cases, &statuses, &required, &session, &reasons, counts,
        );
        if let Err(e) = std::fs::write(path, format!("{}\n", json::write(&report))) {
            eprintln!("error: cannot write report {}: {e}", path.display());
            return EXIT_USAGE;
        }
    }
    if pass { EXIT_PASS } else { EXIT_FAIL }
}

fn show(s: &str) -> String {
    let mut out: String = s.chars().take(SHOW_MAX).collect();
    if out.len() < s.len() {
        out.push_str("...(truncated)");
    }
    // One case, one line: never let adapter text break the line structure.
    out.replace(['\n', '\r'], " ")
}

struct Session {
    statuses: Vec<Status>,
    extra: usize,
    adapter_error: Option<String>,
    exit_text: String,
    stderr: String,
}

fn execute(cfg: &Config, cases: &[&Vector]) -> Session {
    let mut s = Session {
        statuses: Vec::new(),
        extra: 0,
        adapter_error: None,
        exit_text: "not started".into(),
        stderr: String::new(),
    };
    if cases.is_empty() {
        return s;
    }
    let deadline = Instant::now() + cfg.timeout;
    let mut cmd = Command::new(&cfg.program);
    cmd.args(&cfg.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(d) = &cfg.cwd {
        cmd.current_dir(d);
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.as_os_str().to_owned()))
    {
        cmd.env("DOS_CONFORMANCE_BIN_DIR", dir);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            s.statuses = vec![Status::Missing; cases.len()];
            s.adapter_error = Some(format!("cannot start {}: {e}", cfg.program.display()));
            return s;
        }
    };

    // Writer: stream every request, then close stdin (EOF tells the adapter to finish).
    let lines: Vec<String> = cases
        .iter()
        .map(|v| protocol::request_line(&v.area, &v.name, &v.input))
        .collect();
    if let Some(mut stdin) = child.stdin.take() {
        thread::spawn(move || {
            for l in lines {
                if stdin
                    .write_all(l.as_bytes())
                    .and_then(|()| stdin.write_all(b"\n"))
                    .is_err()
                {
                    break; // adapter closed stdin; the reader reports what is missing
                }
            }
            let _ = stdin.flush();
        });
    }
    // Stderr arrives over a channel and is collected with a short wait: a grandchild of
    // the adapter can hold the pipe open forever, and that must not hang the runner.
    let (err_tx, err_rx) = mpsc::channel::<String>();
    if let Some(mut err) = child.stderr.take() {
        thread::spawn(move || {
            let mut keep: Vec<u8> = Vec::new();
            let mut buf = [0u8; 8192];
            while let Ok(n) = err.read(&mut buf) {
                if n == 0 {
                    break;
                }
                keep.extend_from_slice(buf.get(..n).unwrap_or_default());
                if keep.len() > 2 * STDERR_KEEP {
                    keep.drain(..keep.len() - STDERR_KEEP);
                }
            }
            if keep.len() > STDERR_KEEP {
                keep.drain(..keep.len() - STDERR_KEEP);
            }
            let _ = err_tx.send(String::from_utf8_lossy(&keep).into_owned());
        });
    }
    let rx = match child.stdout.take() {
        Some(out) => spawn_reader(out),
        None => {
            s.statuses = vec![Status::Missing; cases.len()];
            s.adapter_error = Some("no stdout pipe".into());
            kill(&mut child);
            return s;
        }
    };

    let mut ended = false; // stdout closed, cut short or abandoned
    let mut killed = false;
    for v in cases {
        if ended {
            s.statuses.push(Status::Missing);
            continue;
        }
        let (wait, which) = budget(cfg.case_timeout, deadline);
        match rx.recv_timeout(wait) {
            Ok(Msg::Line(bytes)) => s.statuses.push(judge(v, &bytes, cfg.oracle)),
            Ok(Msg::Partial) => {
                s.statuses.push(Status::Malformed {
                    why: "last line has no newline (adapter cut short?)".into(),
                });
                ended = true;
            }
            Ok(Msg::TooLong) => {
                s.statuses.push(Status::Malformed {
                    why: format!("line longer than {MAX_LINE_BYTES} bytes"),
                });
                ended = true;
                killed = true;
                kill(&mut child);
            }
            Ok(Msg::ReadError(e)) => {
                s.statuses.push(Status::Malformed {
                    why: format!("read error: {e}"),
                });
                ended = true;
            }
            Ok(Msg::Eof) | Err(RecvTimeoutError::Disconnected) => {
                s.statuses.push(Status::Missing);
                ended = true;
            }
            Err(RecvTimeoutError::Timeout) => {
                s.statuses.push(Status::Timeout { which });
                s.adapter_error = Some(format!(
                    "no response within the {which} timeout; adapter killed"
                ));
                ended = true;
                killed = true;
                kill(&mut child);
            }
        }
    }

    // After the last response: only EOF may follow.
    // A grandchild that inherited the stdout pipe (on Windows every inheritable handle is
    // passed on) keeps it open after the adapter exited. That is not the adapter's fault:
    // once the adapter itself has exited and nothing more is queued, stop waiting.
    let slice = Duration::from_millis(50);
    let started = Instant::now();
    while !ended {
        let (wait, _) = budget(cfg.case_timeout, deadline);
        let exited = matches!(child.try_wait(), Ok(Some(_)));
        let step = if exited {
            Duration::from_millis(100)
        } else {
            wait.min(slice)
        };
        // A flood of extra lines never times out `recv_timeout`, so the budget is checked
        // on every pass, not only when the channel is idle (red team H10).
        let out_of_time = !exited && started.elapsed() >= wait;
        match rx.recv_timeout(step) {
            Ok(Msg::Line(_) | Msg::Partial | Msg::TooLong) if !out_of_time => s.extra += 1,
            Ok(Msg::Eof | Msg::ReadError(_)) | Err(RecvTimeoutError::Disconnected) => ended = true,
            Err(RecvTimeoutError::Timeout) if exited => ended = true,
            Err(RecvTimeoutError::Timeout) if started.elapsed() < wait => {}
            Ok(_) | Err(RecvTimeoutError::Timeout) => {
                s.adapter_error = Some(
                    "adapter did not exit (stdout still open) after the last response; killed"
                        .into(),
                );
                killed = true;
                kill(&mut child);
                ended = true;
            }
        }
    }

    let status = if killed {
        child.wait().ok()
    } else {
        wait_until(&mut child, cfg.case_timeout, deadline)
    };
    s.exit_text = match status {
        None => {
            kill(&mut child);
            let _ = child.wait();
            if s.adapter_error.is_none() {
                s.adapter_error = Some("adapter did not exit after closing stdout; killed".into());
            }
            "did not exit; killed".into()
        }
        Some(st) if killed => format!("killed by the runner ({})", describe(st)),
        Some(st) => {
            if !st.success() && s.adapter_error.is_none() {
                s.adapter_error = Some(format!("adapter {}", describe(st)));
            }
            describe(st)
        }
    };
    s.stderr = err_rx.recv_timeout(STDERR_WAIT).unwrap_or_default();
    s
}

/// The wait for the next event: the case timeout, capped by the overall deadline.
fn budget(case: Duration, deadline: Instant) -> (Duration, &'static str) {
    let left = deadline.saturating_duration_since(Instant::now());
    if left < case {
        (left, "overall")
    } else {
        (case, "per-case")
    }
}

fn wait_until(child: &mut Child, case: Duration, deadline: Instant) -> Option<ExitStatus> {
    let until = Instant::now() + budget(case, deadline).0;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) if Instant::now() < until => thread::sleep(Duration::from_millis(5)),
            _ => return None,
        }
    }
}

fn kill(child: &mut Child) {
    let _ = child.kill();
}

fn describe(st: ExitStatus) -> String {
    if let Some(code) = st.code() {
        return format!("exit {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = st.signal() {
            return format!("crashed (signal {sig})");
        }
    }
    "terminated abnormally".into()
}

fn spawn_reader(out: impl Read + Send + 'static) -> Receiver<Msg> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut r = BufReader::new(out);
        loop {
            let mut buf = Vec::new();
            let cap = u64::try_from(MAX_LINE_BYTES).unwrap_or(u64::MAX) + 2;
            let msg = match (&mut r).take(cap).read_until(b'\n', &mut buf) {
                Err(e) => Msg::ReadError(e.to_string()),
                Ok(0) => Msg::Eof,
                Ok(_) if buf.last() == Some(&b'\n') => {
                    buf.pop();
                    if buf.len() > MAX_LINE_BYTES + 1 {
                        Msg::TooLong
                    } else {
                        Msg::Line(buf)
                    }
                }
                Ok(_) if buf.len() > MAX_LINE_BYTES => Msg::TooLong,
                Ok(_) => Msg::Partial,
            };
            let last = !matches!(msg, Msg::Line(_));
            if tx.send(msg).is_err() || last {
                return;
            }
        }
    });
    rx
}

fn judge(v: &Vector, bytes: &[u8], oracle: bool) -> Status {
    let mut line = bytes;
    if let Some(rest) = line.strip_suffix(b"\r") {
        line = rest;
    }
    if line.len() > MAX_LINE_BYTES {
        return Status::Malformed {
            why: format!("line longer than {MAX_LINE_BYTES} bytes"),
        };
    }
    let Ok(text) = std::str::from_utf8(line) else {
        return Status::Malformed {
            why: "response is not UTF-8".into(),
        };
    };
    let (name, got) = match protocol::parse_response(text) {
        Ok(r) => r,
        Err(e) => {
            return Status::Malformed {
                why: format!("{e}: {}", show(text)),
            };
        }
    };
    if name != v.name {
        return Status::Malformed {
            why: format!(
                "response is for {name:?}, expected {:?} (out of order?)",
                v.name
            ),
        };
    }
    match got {
        Output::Unsupported => Status::Unsupported { required: false },
        got if &got == v.want(oracle) => Status::Ok,
        got => Status::Fail { got },
    }
}

fn report_json(
    cfg: &Config,
    cases: &[&Vector],
    statuses: &[Status],
    required: &BTreeSet<String>,
    s: &Session,
    reasons: &[String],
    counts: [usize; 6],
) -> Json {
    let strs =
        |it: &mut dyn Iterator<Item = String>| Json::Array(it.map(|x| Json::str(&x)).collect());
    let mut argv: Vec<OsString> = vec![cfg.program.clone().into_os_string()];
    argv.extend(cfg.args.iter().map(OsString::from));
    let case_list = cases
        .iter()
        .zip(statuses)
        .map(|(v, st)| {
            let mut m = vec![
                ("area", Json::str(&v.area)),
                ("name", Json::str(&v.name)),
                ("status", Json::str(&st.label().to_ascii_lowercase())),
                ("expected", v.want(cfg.oracle).to_json()),
            ];
            match st {
                Status::Fail { got } => m.push(("got", got.to_json())),
                Status::Malformed { why } => m.push(("detail", Json::str(why))),
                Status::Unsupported { required: true } => {
                    m.push(("detail", Json::str("required area")))
                }
                _ => {}
            }
            Json::obj(m)
        })
        .collect();
    let [ok, fail, unsupported, missing, malformed, timeout] = counts;
    Json::obj([
        ("v", Json::uint(1)),
        (
            "adapter",
            strs(&mut argv.iter().map(|a| a.to_string_lossy().into_owned())),
        ),
        ("oracle", Json::Bool(cfg.oracle)),
        ("required", strs(&mut required.iter().cloned())),
        ("cases", Json::Array(case_list)),
        (
            "summary",
            Json::obj([
                ("cases", Json::usize(cases.len())),
                ("ok", Json::usize(ok)),
                ("fail", Json::usize(fail)),
                ("unsupported", Json::usize(unsupported)),
                ("missing", Json::usize(missing)),
                ("malformed", Json::usize(malformed)),
                ("timeout", Json::usize(timeout)),
                ("extra", Json::usize(s.extra)),
            ]),
        ),
        ("adapter_exit", Json::str(&s.exit_text)),
        ("reasons", strs(&mut reasons.iter().cloned())),
        (
            "result",
            Json::str(if reasons.is_empty() { "pass" } else { "fail" }),
        ),
    ])
}
