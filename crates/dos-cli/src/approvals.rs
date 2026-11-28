//! File-backed approvals: `<home>/approvals/<id>.json`.
//!
//! The proxy writes a `pending` record for an `Ask` and waits. `decision-os approve <id>` or
//! `deny <id>` (or a dashboard) flips the state. An approval is used once: the proxy removes
//! the record when it returns, so the same call needs a new approval next time. A record that
//! nobody resolves expires and is removed. The id is derived from the exact call (server, tool,
//! arguments), so an approval cannot be used for another call.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dos_exec::{ApprovalOutcome, Approvals, CallRequest, CancelToken};
use serde_json::{Value, json};

pub struct FileApprovals {
    dir: PathBuf,
    timeout: Duration,
}

/// Ids are `ask-` plus hex; refuse anything that could name another file.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn record_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

fn write_atomic(path: &Path, v: &Value) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(v.to_string().as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

fn read(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

impl FileApprovals {
    pub fn new(dir: impl Into<PathBuf>, timeout: Duration) -> Self {
        FileApprovals {
            dir: dir.into(),
            timeout,
        }
    }
}

impl Approvals for FileApprovals {
    fn wait(
        &self,
        req: &CallRequest,
        approval_id: &str,
        reason: &str,
        cancel: &CancelToken,
    ) -> ApprovalOutcome {
        if !valid_id(approval_id) || std::fs::create_dir_all(&self.dir).is_err() {
            return ApprovalOutcome::Unavailable;
        }
        let path = record_path(&self.dir, approval_id);
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // A stale record from an earlier run is replaced: only this wait's decision counts.
        let record = json!({
            "id": approval_id,
            "server": req.server,
            "tool": req.tool,
            "reason": reason,
            "state": "pending",
            "created_unix": created,
        });
        if write_atomic(&path, &record).is_err() {
            return ApprovalOutcome::Unavailable;
        }
        let deadline = Instant::now() + self.timeout;
        let outcome = loop {
            match read(&path)
                .as_ref()
                .and_then(|v| v.get("state").and_then(Value::as_str).map(str::to_owned))
                .as_deref()
            {
                Some("approved") => break ApprovalOutcome::Approved,
                Some("denied") => break ApprovalOutcome::Denied,
                Some("pending") => {}
                // Removed or unreadable: nobody can resolve it any more.
                _ => break ApprovalOutcome::Unavailable,
            }
            if cancel.is_cancelled() {
                break ApprovalOutcome::Cancelled;
            }
            if Instant::now() >= deadline {
                break ApprovalOutcome::Expired;
            }
            cancel.wait_timeout(Duration::from_millis(50));
        };
        let _ = std::fs::remove_file(&path);
        outcome
    }
}

/// Pending approvals in `dir`, oldest first: `(id, server, tool, reason)`.
pub fn pending(dir: &Path) -> Vec<(String, String, String, String)> {
    let mut out: Vec<(u64, (String, String, String, String))> = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let Some(v) = read(&p) else { continue };
        if v.get("state").and_then(Value::as_str) != Some("pending") {
            continue;
        }
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        out.push((
            v.get("created_unix").and_then(Value::as_u64).unwrap_or(0),
            (s("id"), s("server"), s("tool"), s("reason")),
        ));
    }
    out.sort();
    out.into_iter().map(|(_, r)| r).collect()
}

/// Sets a pending record to approved or denied. `false` if there is no such pending approval.
pub fn resolve(dir: &Path, id: &str, approve: bool) -> bool {
    if !valid_id(id) {
        return false;
    }
    let path = record_path(dir, id);
    let Some(mut v) = read(&path) else {
        return false;
    };
    if v.get("state").and_then(Value::as_str) != Some("pending") {
        return false;
    }
    let Some(obj) = v.as_object_mut() else {
        return false;
    };
    obj.insert(
        "state".into(),
        json!(if approve { "approved" } else { "denied" }),
    );
    write_atomic(&path, &v).is_ok()
}
