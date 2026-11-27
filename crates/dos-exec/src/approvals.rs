//! Approval backends that need no files: non-interactive and in-memory.
//! The file store shared with the dashboard belongs to dos-ui.

use crate::decision::{ApprovalOutcome, Approvals, CallRequest, CancelToken};
use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Nobody can be asked: every `Ask` is refused.
pub struct NonInteractive;

impl Approvals for NonInteractive {
    fn wait(&self, _: &CallRequest, _: &str, _: &str, _: &CancelToken) -> ApprovalOutcome {
        ApprovalOutcome::Unavailable
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingApproval {
    pub id: String,
    pub server: String,
    pub tool: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

/// In-process approvals with a timeout, resolved by `resolve`.
pub struct MemoryApprovals {
    timeout: Duration,
    state: Mutex<HashMap<String, (State, PendingApproval)>>,
    changed: Condvar,
}

impl MemoryApprovals {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            state: Mutex::new(HashMap::new()),
            changed: Condvar::new(),
        }
    }

    pub fn pending(&self) -> Vec<PendingApproval> {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = st
            .values()
            .filter(|(s, _)| *s == State::Pending)
            .map(|(_, p)| p.clone())
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// Resolve a pending approval. Returns false if it is unknown or no longer pending.
    pub fn resolve(&self, id: &str, approve: bool) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match st.get_mut(id) {
            Some((s, _)) if *s == State::Pending => {
                *s = if approve {
                    State::Approved
                } else {
                    State::Denied
                };
                self.changed.notify_all();
                true
            }
            _ => false,
        }
    }
}

impl Approvals for MemoryApprovals {
    fn wait(
        &self,
        req: &CallRequest,
        approval_id: &str,
        reason: &str,
        cancel: &CancelToken,
    ) -> ApprovalOutcome {
        let deadline = Instant::now() + self.timeout;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // A resolved record is final: the same action is not asked twice.
        st.entry(approval_id.to_owned()).or_insert_with(|| {
            (
                State::Pending,
                PendingApproval {
                    id: approval_id.to_owned(),
                    server: req.server.clone(),
                    tool: req.tool.clone(),
                    reason: reason.to_owned(),
                },
            )
        });
        loop {
            match st.get(approval_id).map(|(s, _)| *s) {
                Some(State::Approved) => return ApprovalOutcome::Approved,
                Some(State::Denied) => return ApprovalOutcome::Denied,
                Some(State::Expired) | None => return ApprovalOutcome::Expired,
                Some(State::Cancelled) => return ApprovalOutcome::Cancelled,
                Some(State::Pending) => {}
            }
            let finish = if cancel.is_cancelled() {
                Some((State::Cancelled, ApprovalOutcome::Cancelled))
            } else if Instant::now() >= deadline {
                Some((State::Expired, ApprovalOutcome::Expired))
            } else {
                None
            };
            if let Some((s, out)) = finish {
                if let Some(rec) = st.get_mut(approval_id) {
                    rec.0 = s;
                }
                return out;
            }
            // Short slices so a cancel (signalled on another condvar) is seen quickly.
            let slice = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(20));
            st = self
                .changed
                .wait_timeout(st, slice)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}
