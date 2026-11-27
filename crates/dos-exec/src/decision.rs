//! The seams the executor is wired through: decision engine, approvals, audit.

use serde_json::{Map, Value};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// One governed call, as the engine sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct CallRequest {
    /// Server name, already slugged.
    pub server: String,
    /// Tool name; `resources/read` for resource reads.
    pub tool: String,
    /// The arguments that will be forwarded if the call runs.
    pub arguments: Map<String, Value>,
    /// Annotation hints from `tools/list` (`hint:readonly`, ...).
    pub hints: Vec<String>,
}

/// Verdict for one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow {
        reason: String,
    },
    /// A human must decide. `approval_id` binds the approval to this exact action
    /// (the oracle uses the action fingerprint).
    Ask {
        reason: String,
        approval_id: String,
    },
    Deny {
        reason: String,
    },
}

/// Decision without arguments, used to hide hard-denied tools in `tools/list`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticVerdict {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineError(pub String);

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The decision layer. Built by another task; the executor only calls it.
pub trait DecisionEngine: Send + Sync {
    /// Decide one call. `approval` is `Some(id)` on the second decision, after a
    /// human approved `id`. Only `Allow` lets the call run; `Err` refuses.
    fn decide(&self, req: &CallRequest, approval: Option<&str>) -> Result<Verdict, EngineError>;

    /// Argument-free decision for tool hiding. `Err` counts as `Deny`.
    fn static_decision(
        &self,
        server: &str,
        tool: &str,
        hints: &[String],
    ) -> Result<StaticVerdict, EngineError>;

    /// Remove hard-denied tools from `tools/list` (policy enforce mode with
    /// `hide_denied_tools`).
    fn hide_denied_tools(&self) -> bool;
}

/// How a human approval wait ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    Denied,
    Expired,
    Cancelled,
    /// No human can be asked (non-interactive gateway): refuse with the ask reason.
    Unavailable,
}

/// Set when the client cancels a call, closes its side, or the server exits.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<(Mutex<bool>, Condvar)>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        let (m, c) = &*self.0;
        *m.lock().unwrap_or_else(|e| e.into_inner()) = true;
        c.notify_all();
    }

    pub fn is_cancelled(&self) -> bool {
        *self.0.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sleep up to `d`, waking early on cancel. Returns `is_cancelled()`.
    pub fn wait_timeout(&self, d: Duration) -> bool {
        let (m, c) = &*self.0;
        let g = m.lock().unwrap_or_else(|e| e.into_inner());
        if *g {
            return true;
        }
        let (g, _) = c.wait_timeout(g, d).unwrap_or_else(|e| e.into_inner());
        *g
    }
}

/// Human approval for `Ask`.
pub trait Approvals: Send + Sync {
    /// Block until the approval `approval_id` is resolved, times out, or
    /// `cancel` fires. Must return `Cancelled` promptly after `cancel` fires.
    fn wait(
        &self,
        req: &CallRequest,
        approval_id: &str,
        reason: &str,
        cancel: &CancelToken,
    ) -> ApprovalOutcome;
}

/// One audit record. Written before the effect for executed calls, and for every refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// `server/tool`.
    pub tool: String,
    /// `ALLOW` or `DENY`.
    pub verdict: &'static str,
    pub reason: String,
    pub executed: bool,
}

pub trait AuditSink: Send + Sync {
    /// `Err` before an effect refuses the call.
    fn record(&self, ev: &AuditEvent) -> Result<(), String>;
}

/// An audit sink that keeps nothing. For wiring before the real log exists.
pub struct NoAudit;

impl AuditSink for NoAudit {
    fn record(&self, _ev: &AuditEvent) -> Result<(), String> {
        Ok(())
    }
}
