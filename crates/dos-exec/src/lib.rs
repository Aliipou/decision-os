//! Decision OS executor: the stdio MCP gateway proxy.
//!
//! [`Proxy`] launches the governed MCP server and gates every `tools/call` and
//! `resources/read` through a [`DecisionEngine`], waiting on [`Approvals`] for
//! `Ask` and recording every outcome to an [`AuditSink`] before any effect.
//! Every error refuses. Design: `design/executor.md`.
#![forbid(unsafe_code)]

pub mod approvals;
pub mod decision;
pub mod launch;
pub mod proxy;
pub mod strict;

pub use approvals::{MemoryApprovals, NonInteractive, PendingApproval};
pub use decision::{
    ApprovalOutcome, Approvals, AuditEvent, AuditSink, CallRequest, CancelToken, DecisionEngine,
    EngineError, NoAudit, StaticVerdict, Verdict,
};
pub use launch::{resolve_argv, slug};
pub use proxy::{BLOCK_HINT, Proxy, tool_hints};
