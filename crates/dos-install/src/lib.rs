//! Decision OS installer: find every MCP client config, wrap each stdio server so it
//! starts behind `decision-os mcp-proxy`, and undo it exactly.
//!
//! Behavior is the oracle's (`oracle/decision-os-min/decision_os_min/gateway/installer.py`)
//! byte for byte, checked by `conformance/vectors/install/`; deliberate divergences are
//! listed in `spec/install.md`. The library never reads the process environment: the
//! caller passes an [`clients::Env`].

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

pub mod clients;
mod codex;
pub mod entry;
mod fsio;
mod jsonfile;
pub mod pyjson;
mod state;

use clients::{CLIENTS, ClientSpec, Env, Format};
use state::State;

/// What to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Install,
    Uninstall,
    Status,
}

/// One run of the installer.
#[derive(Clone, Debug)]
pub struct Options {
    pub action: Action,
    /// Only these client ids; empty means all. An unknown id refuses the run.
    pub clients: Vec<String>,
    /// Edit the project files of each client under this directory instead of the
    /// global configs.
    pub project: Option<PathBuf>,
    /// Report what would change; create and write nothing.
    pub dry_run: bool,
    /// Rewrite JSON files that contain comments (they are dropped; a backup is kept).
    pub force_jsonc: bool,
    /// The `decision-os` binary that wrapped entries launch.
    pub binary: String,
    /// The clock, for backup directory names and the state's `updated` field.
    pub now: SystemTime,
}

/// The outcome for one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Missing,
    Unchanged,
    Manual,
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Missing => "missing",
            Status::Unchanged => "unchanged",
            Status::Manual => "manual",
            Status::Error => "error",
        }
    }
}

/// Message codes (spec/install.md). A report keeps the last one set, like the oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    RestoredExact,
    Jsonc,
    InvalidJson,
    NotObject,
    VerifyFailed,
    ArgsNotStrings,
    NoOriginalCommand,
    InvalidToml,
    InlineTransport,
    NotPlainTable,
    TableNotFound,
    EditInvalidToml,
    ReadError,
    ReadOnly,
    NonFiniteNumber,
    InvalidUtf8,
    ChangedDuringWrite,
    WriteFailed,
    NonUtf8Path,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::RestoredExact => "restored-exact",
            Code::Jsonc => "jsonc",
            Code::InvalidJson => "invalid-json",
            Code::NotObject => "not-object",
            Code::VerifyFailed => "verify-failed",
            Code::ArgsNotStrings => "args-not-strings",
            Code::NoOriginalCommand => "no-original-command",
            Code::InvalidToml => "invalid-toml",
            Code::InlineTransport => "inline-transport",
            Code::NotPlainTable => "not-plain-table",
            Code::TableNotFound => "table-not-found",
            Code::EditInvalidToml => "edit-invalid-toml",
            Code::ReadError => "read-error",
            Code::ReadOnly => "read-only",
            Code::NonFiniteNumber => "non-finite-number",
            Code::InvalidUtf8 => "invalid-utf8",
            Code::ChangedDuringWrite => "changed-during-write",
            Code::WriteFailed => "write-failed",
            Code::NonUtf8Path => "non-utf8-path",
        }
    }
}

/// A coded message with human detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub code: Code,
    pub detail: String,
}

impl Message {
    pub(crate) fn new(code: Code, detail: impl Into<String>) -> Self {
        Message {
            code,
            detail: detail.into(),
        }
    }
}

/// What happened to one config file. When `status` is `error` or `manual` nothing
/// was written; the lists then show what the run would have done.
#[derive(Clone, Debug)]
pub struct FileReport {
    pub client: &'static str,
    pub path: PathBuf,
    pub fmt: Format,
    pub status: Status,
    pub wrapped: Vec<String>,
    pub unwrapped: Vec<String>,
    pub already: Vec<String>,
    /// The subset of `already` written by the Python gateway (uninstall, then install,
    /// to move them to the binary).
    pub legacy: Vec<String>,
    pub plain: Vec<String>,
    pub remote: Vec<String>,
    pub message: Option<Message>,
}

impl FileReport {
    pub(crate) fn new(client: &'static str, path: &Path, fmt: Format) -> Self {
        FileReport {
            client,
            path: path.to_path_buf(),
            fmt,
            status: Status::Ok,
            wrapped: Vec::new(),
            unwrapped: Vec::new(),
            already: Vec::new(),
            legacy: Vec::new(),
            plain: Vec::new(),
            remote: Vec::new(),
            message: None,
        }
    }

    pub(crate) fn fail(mut self, status: Status, code: Code, detail: impl Into<String>) -> Self {
        self.status = status;
        self.message = Some(Message::new(code, detail));
        self
    }

    pub(crate) fn note(&mut self, code: Code, detail: impl Into<String>) {
        self.message = Some(Message::new(code, detail));
    }
}

/// A run that cannot start or finish. Per-file problems are in [`FileReport`] instead.
#[derive(Debug)]
pub enum InstallError {
    NoHome,
    UnknownClient(String),
    NonUtf8Home(PathBuf),
    StateCorrupt(PathBuf),
    Io(PathBuf, io::Error),
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstallError::NoHome => write!(f, "no home directory in the environment"),
            InstallError::UnknownClient(c) => {
                let known: Vec<&str> = CLIENTS.iter().map(|c| c.id).collect();
                write!(f, "unknown client {c:?}; known: {}", known.join(", "))
            }
            InstallError::NonUtf8Home(p) => write!(f, "home path is not UTF-8: {}", p.display()),
            InstallError::StateCorrupt(p) => write!(
                f,
                "{} is not a valid state file; refusing to overwrite it",
                p.display()
            ),
            InstallError::Io(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for InstallError {}

/// A change to the state, applied only once its file is really written.
#[derive(Clone, Debug)]
pub(crate) enum StateOp {
    Remember {
        pointer: Vec<String>,
        name: String,
        original: Value,
    },
    Forget {
        pointer: Vec<String>,
        name: String,
    },
}

type Hook<'a> = &'a mut dyn FnMut(&Path);

pub(crate) struct Ctx<'a> {
    pub(crate) home: PathBuf,
    pub(crate) home_str: String,
    pub(crate) binary: String,
    pub(crate) stamp: String,
    pub(crate) updated: String,
    pub(crate) dry_run: bool,
    pub(crate) state: State,
    /// Called just before a config file is replaced (tests simulate an app writing).
    pub(crate) before_replace: Option<Hook<'a>>,
}

impl Ctx<'_> {
    /// Back up, record and write one config file (spec/install.md, "Writes").
    /// Install saves the state before the file, uninstall after it: a failure in
    /// between only leaves stale state, which is harmless.
    pub(crate) fn commit(
        &mut self,
        client: &str,
        path: &Path,
        path_str: &str,
        read: &[u8],
        new: &[u8],
        install: bool,
        ops: Vec<StateOp>,
    ) -> Result<(), Message> {
        let meta = std::fs::metadata(path)
            .map_err(|e| Message::new(Code::WriteFailed, e.to_string()))?;
        if meta.permissions().readonly() {
            return Err(Message::new(
                Code::ReadOnly,
                "file is read-only; not written (make it writable or wrap by hand)",
            ));
        }
        let current =
            std::fs::read(path).map_err(|e| Message::new(Code::WriteFailed, e.to_string()))?;
        if current != read {
            return Err(changed());
        }
        let prior = state::sha256_hex(&current);
        let backup_dir = self.home.join("backups").join(&self.stamp).join(client);
        let backup = fsio::write_backup(&backup_dir, &fsio::safe_name(path_str), &current)
            .map_err(|e| Message::new(Code::WriteFailed, format!("backup failed: {e}")))?;
        let snapshot = self.state.clone();
        if install {
            self.state.wrote(path_str, new, &backup, &prior);
            self.apply(path_str, client, ops.clone());
            if let Err(e) = self.state.save(&self.binary, &self.updated) {
                self.state = snapshot;
                return Err(Message::new(Code::WriteFailed, format!("state not saved: {e}")));
            }
        }
        if let Some(h) = self.before_replace.as_mut() {
            h(path);
        }
        if let Err(e) = fsio::atomic_write(path, new, Some(&current), false) {
            if install {
                self.state = snapshot;
                let _ = self.state.save(&self.binary, &self.updated);
            }
            return Err(match e {
                fsio::WriteError::Changed => changed(),
                fsio::WriteError::Io(e) => Message::new(Code::WriteFailed, e.to_string()),
            });
        }
        if !install {
            self.state.drop_file_record(path_str);
            self.apply(path_str, client, ops);
        }
        match std::fs::read(path) {
            Ok(back) if back == new => Ok(()),
            _ => Err(Message::new(
                Code::VerifyFailed,
                "the file does not read back as written",
            )),
        }
    }

    fn apply(&mut self, path_str: &str, client: &str, ops: Vec<StateOp>) {
        for op in ops {
            match op {
                StateOp::Remember {
                    pointer,
                    name,
                    original,
                } => self
                    .state
                    .remember(path_str, &pointer, &name, client, original),
                StateOp::Forget { pointer, name } => self.state.forget(path_str, &pointer, &name),
            }
        }
    }

    /// If the file is byte for byte what we last wrote, put the original back
    /// verbatim (oracle `_restore_exact`).
    fn restore_exact(&mut self, path: &Path, path_str: &str) -> bool {
        let Some((backup, sha)) = self.state.exact_record(path_str) else {
            return false;
        };
        // Only backups this home made; anything else falls back to entry-by-entry.
        if !backup.starts_with(self.home.join("backups")) {
            return false;
        }
        let (Ok(current), Ok(original)) = (std::fs::read(path), std::fs::read(&backup)) else {
            return false;
        };
        if state::sha256_hex(&current) != sha {
            return false;
        }
        if std::fs::metadata(path).is_ok_and(|m| m.permissions().readonly()) {
            return false;
        }
        if let Some(h) = self.before_replace.as_mut() {
            h(path);
        }
        if fsio::atomic_write(path, &original, Some(&current), false).is_err() {
            return false;
        }
        self.state.drop_file(path_str);
        true
    }
}

fn changed() -> Message {
    Message::new(
        Code::ChangedDuringWrite,
        "the file changed while Decision OS was editing it; not written, run again",
    )
}

/// Every (client, file, format) a run looks at, in the oracle's order.
pub fn targets(
    env: &Env,
    clients: &[String],
    project: Option<&Path>,
) -> Result<Vec<(&'static ClientSpec, PathBuf, Format)>, InstallError> {
    for c in clients {
        if clients::get(c).is_none() {
            return Err(InstallError::UnknownClient(c.clone()));
        }
    }
    let mut out = Vec::new();
    for spec in CLIENTS {
        if !clients.is_empty() && !clients.iter().any(|c| c == spec.id) {
            continue;
        }
        match project {
            Some(p) => {
                for (rel, fmt) in spec.project {
                    out.push((spec, p.join(rel), *fmt));
                }
            }
            None => {
                for path in spec.config_paths(env)? {
                    out.push((spec, path, spec.fmt));
                }
            }
        }
    }
    Ok(out)
}

/// Install, uninstall or report on every target. `home` is the gateway state
/// directory (`~/.decision-os`); it is written into wrapped entries as `--home`.
pub fn run(home: &Path, env: &Env, opts: &Options) -> Result<Vec<FileReport>, InstallError> {
    run_with_hook(home, env, opts, None)
}

pub(crate) fn run_with_hook(
    home: &Path,
    env: &Env,
    opts: &Options,
    before_replace: Option<Hook<'_>>,
) -> Result<Vec<FileReport>, InstallError> {
    let home_str = home
        .to_str()
        .ok_or_else(|| InstallError::NonUtf8Home(home.to_path_buf()))?
        .to_string();
    let targets = targets(env, &opts.clients, opts.project.as_deref())?;
    let writes = opts.action != Action::Status && !opts.dry_run;
    let _lock = if writes {
        fsio::ensure_home(home).map_err(|e| InstallError::Io(home.to_path_buf(), e))?;
        Some(fsio::lock(home).map_err(|e| InstallError::Io(home.join("locks"), e))?)
    } else {
        None
    };
    let secs = opts
        .now
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = fsio::civil(secs);
    let mut cx = Ctx {
        home: home.to_path_buf(),
        home_str,
        binary: opts.binary.clone(),
        stamp: format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z"),
        updated: format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}+00:00"),
        dry_run: opts.dry_run,
        state: State::load(home)?,
        before_replace,
    };
    let mut reports = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for (spec, path, fmt) in targets {
        if seen.contains(&path) {
            continue;
        }
        seen.push(path.clone());
        let Some(path_str) = path.to_str().map(str::to_string) else {
            reports.push(FileReport::new(spec.id, &path, fmt).fail(
                Status::Error,
                Code::NonUtf8Path,
                "path is not UTF-8",
            ));
            continue;
        };
        if opts.action == Action::Uninstall && !opts.dry_run && path.exists() {
            let before = process(&mut cx, spec.id, &path, &path_str, fmt, Action::Status, true).already;
            if !before.is_empty() && cx.restore_exact(&path, &path_str) {
                let mut rep = FileReport::new(spec.id, &path, fmt);
                rep.unwrapped = before;
                rep.note(Code::RestoredExact, "(original restored byte for byte)");
                reports.push(rep);
                continue;
            }
        }
        let force = opts.force_jsonc;
        reports.push(process(&mut cx, spec.id, &path, &path_str, fmt, opts.action, force));
    }
    if writes {
        let (binary, updated) = (cx.binary.clone(), cx.updated.clone());
        cx.state.save(&binary, &updated)?;
    }
    Ok(reports)
}

fn process(
    cx: &mut Ctx<'_>,
    client: &'static str,
    path: &Path,
    path_str: &str,
    fmt: Format,
    action: Action,
    force_jsonc: bool,
) -> FileReport {
    match fmt {
        Format::Codex => codex::process(cx, client, path, path_str, action),
        _ => jsonfile::process(cx, client, path, path_str, fmt, action, force_jsonc),
    }
}

/// Read a config file: `Err(report)` for missing, unreadable or non-UTF-8 files.
pub(crate) fn read_config(
    client: &'static str,
    path: &Path,
    fmt: Format,
) -> Result<(Vec<u8>, String), FileReport> {
    let rep = || FileReport::new(client, path, fmt);
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut r = rep();
            r.status = Status::Missing;
            return Err(r);
        }
        Err(e) => return Err(rep().fail(Status::Error, Code::ReadError, e.to_string())),
    };
    match String::from_utf8(bytes.clone()) {
        // Python's read_text uses universal newlines: the oracle edits (and writes back)
        // the text with CRLF and lone CR turned into LF (vectors codex-crlf-*).
        Ok(text) => Ok((bytes, text.replace("\r\n", "\n").replace('\r', "\n"))),
        Err(_) => Err(rep().fail(Status::Error, Code::InvalidUtf8, "file is not UTF-8")),
    }
}

#[cfg(test)]
mod tests;
