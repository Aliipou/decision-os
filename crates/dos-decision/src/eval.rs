//! Ruling one call: `classify_tool`, `rule_matches`, `evaluate` (policy.py) and the
//! policy PDP verdict (`GatewayAuthorityPDP.evaluate`, engine.py).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use dos_core::verdict::Verdict;

use crate::glob::{fnmatchcase, glob_ci};
use crate::path::{PathEnv, is_pathlike, normalize_path};
use crate::policy::{Decision, GatewayPolicy, Mode, Profile, Rule};
use crate::py::{Value, dumps_default, dumps_sorted_compact};

const READ_VERBS: &[&str] = &[
    "read", "get", "list", "search", "find", "fetch", "view", "show", "describe", "inspect", "lookup", "look",
    "count", "stat", "head", "tail", "cat", "ls", "grep", "glob", "status", "info", "preview", "browse", "resolve",
    "explain", "query", "snapshot", "screenshot", "diff", "log", "logs", "check", "validate", "summarize", "summary",
    "download", "retrieve", "load", "open", "recall",
];

const WRITE_VERBS: &[&str] = &[
    "write", "create", "delete", "del", "remove", "rm", "rmdir", "unlink", "update", "edit", "set", "put", "post",
    "send", "push", "commit", "merge", "move", "mv", "rename", "copy", "cp", "upload", "install", "uninstall", "run",
    "exec", "execute", "eval", "shell", "bash", "sh", "cmd", "command", "terminal", "powershell", "kill", "start",
    "stop", "restart", "deploy", "publish", "apply", "drop", "truncate", "insert", "patch", "modify", "replace",
    "approve", "pay", "transfer", "buy", "purchase", "order", "book", "invite", "share", "grant", "revoke", "reset",
    "format", "wipe", "click", "type", "fill", "submit", "press", "drag", "navigate", "mkdir", "touch", "chmod",
    "chown", "save", "append", "archive", "close", "cancel", "reply", "forward", "schedule", "trigger", "invoke",
    "call", "spawn", "launch",
];

/// `read`, `write` or `unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolKind {
    Read,
    Write,
    Unknown,
}

impl ToolKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ToolKind::Read => "read",
            ToolKind::Write => "write",
            ToolKind::Unknown => "unknown",
        }
    }
}

/// `tool_tokens`: split camelCase (ASCII `[a-z0-9]` then `[A-Z]`), lowercase, split on
/// anything outside `[a-z0-9]`.
pub fn tool_tokens(name: &str) -> Vec<String> {
    let mut snake = String::new();
    let mut prev: Option<char> = None;
    for c in name.chars() {
        if c.is_ascii_uppercase() && prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit()) {
            snake.push('_');
        }
        snake.push(c);
        prev = Some(c);
    }
    snake
        .to_lowercase()
        .split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit()))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// `classify_tool`: a write verb always wins; hints can only add `read` to an
/// unclassified name or mark any tool destructive.
pub fn classify_tool(name: &str, hints: &[String]) -> ToolKind {
    let hints: Vec<String> = hints.iter().map(|h| h.to_lowercase()).collect();
    let tokens = tool_tokens(name);
    if hints.iter().any(|h| h == "hint:destructive") || tokens.iter().any(|t| WRITE_VERBS.contains(&t.as_str())) {
        return ToolKind::Write;
    }
    if tokens.iter().any(|t| READ_VERBS.contains(&t.as_str())) {
        return ToolKind::Read;
    }
    if hints.iter().any(|h| h == "hint:readonly") {
        return ToolKind::Read;
    }
    ToolKind::Unknown
}

fn arg_matches(value: &Value, patterns: &[String], env: &dyn PathEnv) -> bool {
    let text = match value {
        Value::Str(s) => s.clone(),
        Value::Null | Value::Bool(_) | Value::Int(_) | Value::Float(_) => dumps_default(value),
        Value::Array(_) | Value::Object(_) => dumps_sorted_compact(value),
    };
    patterns.iter().any(|pat| {
        if is_pathlike(pat) && matches!(value, Value::Str(_)) {
            fnmatchcase(&normalize_path(&text, env), &normalize_path(pat, env))
        } else {
            glob_ci(&text, pat)
        }
    })
}

/// One tool call as the policy sees it.
#[derive(Clone, Debug, Default)]
pub struct Call<'a> {
    pub client: &'a str,
    pub server: &'a str,
    pub tool: &'a str,
    pub model: Option<&'a str>,
    /// `None` is the static check (tools/list): argument rules cannot match.
    /// `Some` must be a JSON object; any other value has no members.
    pub args: Option<&'a Value>,
    pub hints: &'a [String],
}

pub fn rule_matches(rule: &Rule, call: &Call<'_>, env: &dyn PathEnv) -> bool {
    if !(glob_ci(call.client, &rule.client) && glob_ci(call.server, &rule.server) && glob_ci(call.tool, &rule.tool)) {
        return false;
    }
    if let Some(m) = rule.model.as_deref() {
        match call.model {
            Some(cm) if glob_ci(cm, m) => {}
            _ => return false,
        }
    }
    if !rule.args.is_empty() {
        let Some(args) = call.args else { return false };
        for (name, pats) in &rule.args {
            match args.get(name) {
                Some(v) if arg_matches(v, pats, env) => {}
                _ => return false,
            }
        }
    }
    true
}

/// Where a decision came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Policy,
    Learned,
    Profile,
}

impl Source {
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Policy => "policy",
            Source::Learned => "learned",
            Source::Profile => "profile",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Match {
    pub decision: Decision,
    /// Bound into the action fingerprint; depends only on the file and the tool.
    pub purpose: String,
    pub reason: String,
    pub redact: Vec<String>,
    pub source: Source,
}

pub fn learned_key(client: &str, server: &str, tool: &str) -> String {
    format!("{client}|{server}|{tool}")
}

/// `evaluate`: first matching rule; a matched deny is final; then remembered
/// choices; then the matched allow/ask; then the profile.
pub fn evaluate(
    policy: &GatewayPolicy,
    call: &Call<'_>,
    learned: &[(String, String)],
    env: &dyn PathEnv,
) -> Match {
    let matched = policy.rules.iter().find(|r| rule_matches(r, call, env));
    let kind = classify_tool(call.tool, call.hints);
    let profile_purpose = format!("profile:{}:{}", policy.profile.as_str(), kind.as_str());
    let purpose = matched.map(Rule::purpose).unwrap_or_else(|| profile_purpose.clone());
    if let Some(r) = matched.filter(|r| r.decision == Decision::Deny) {
        let reason = if r.reason.is_empty() { format!("denied by {}", r.describe()) } else { r.reason.clone() };
        return Match { decision: Decision::Deny, purpose, reason, redact: Vec::new(), source: Source::Policy };
    }
    for key in [learned_key(call.client, call.server, call.tool), learned_key("*", call.server, call.tool)] {
        // Python dict lookup: the last entry for a key wins.
        let remembered = learned.iter().rev().find(|(k, _)| *k == key).map(|(_, v)| v.as_str());
        let d = match remembered {
            Some("allow") => Decision::Allow,
            Some("deny") => Decision::Deny,
            _ => continue,
        };
        return Match {
            decision: d,
            purpose,
            reason: format!("you chose 'always {}' for {}/{}", d.as_str(), call.server, call.tool),
            redact: matched.map(|r| r.redact.clone()).unwrap_or_default(),
            source: Source::Learned,
        };
    }
    if let Some(r) = matched {
        let verb = if r.decision == Decision::Allow { "allowed" } else { "needs approval" };
        let reason = if r.reason.is_empty() { format!("{verb} by {}", r.describe()) } else { r.reason.clone() };
        return Match { decision: r.decision, purpose, reason, redact: r.redact.clone(), source: Source::Policy };
    }
    let decision = match policy.profile {
        Profile::Open => Decision::Allow,
        Profile::Strict => Decision::Ask,
        Profile::Balanced if kind == ToolKind::Read => Decision::Allow,
        Profile::Balanced => Decision::Ask,
    };
    let what = match kind {
        ToolKind::Read => "read-only",
        ToolKind::Write => "state-changing",
        ToolKind::Unknown => "unclassified",
    };
    let verb = if decision == Decision::Allow { "allows" } else { "asks for" };
    Match {
        decision,
        purpose: profile_purpose,
        reason: format!("{} profile {verb} {what} tools", policy.profile.as_str()),
        redact: Vec::new(),
        source: Source::Profile,
    }
}

// ------------------------------------------------------------------ the PDP

pub const AGENT_PREFIX: &str = "agent:";

/// Python `str.isspace` (Rust White_Space plus U+001C..U+001F).
fn py_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// `engine.slug`: runs of whitespace, `/`, `:` and `\` become `-`; empty is `unnamed`.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for c in name.trim_matches(py_space).chars() {
        if py_space(c) || matches!(c, '/' | ':' | '\\') {
            if !in_run {
                out.push('-');
            }
            in_run = true;
        } else {
            out.push(c);
            in_run = false;
        }
    }
    if out.is_empty() { "unnamed".into() } else { out }
}

/// The fields of an action the policy PDP reads.
#[derive(Clone, Debug, Default)]
pub struct Action {
    pub actor: String,
    /// `server/tool`.
    pub tool: String,
    pub action_purpose: Option<String>,
    pub data_labels: Vec<String>,
    /// The tool arguments; `None` and an empty object are the same here.
    pub payload: Option<Value>,
}

/// `engine.parse_action`: (client, server, tool, model, hints).
pub fn parse_action(a: &Action) -> (String, String, String, Option<String>, Vec<String>) {
    let client = a.actor.strip_prefix(AGENT_PREFIX).unwrap_or(&a.actor).to_string();
    let (server, tool) = match a.tool.split_once('/') {
        Some((s, t)) => (s.to_string(), t.to_string()),
        None => (a.tool.clone(), String::new()),
    };
    let model = a.data_labels.iter().find_map(|x| x.strip_prefix("model:")).map(str::to_string);
    let hints = a.data_labels.iter().filter(|x| x.starts_with("hint:")).cloned().collect();
    (client, server, tool, model, hints)
}

/// The authority verdict and its reason.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorityResult {
    pub verdict: Verdict,
    pub reason: String,
}

/// `GatewayAuthorityPDP.evaluate`. `policy` is the loaded file or the load error
/// (fail closed). `is_approved` answers whether a human approved this exact action
/// (the oracle looks up `action_fingerprint(action)`); it is called only for `ask`.
pub fn authority_verdict(
    policy: Result<&GatewayPolicy, &str>,
    action: &Action,
    learned: &[(String, String)],
    env: &dyn PathEnv,
    is_approved: impl FnOnce() -> bool,
) -> AuthorityResult {
    let deny = |reason: String| AuthorityResult { verdict: Verdict::Deny, reason };
    let policy = match policy {
        Ok(p) => p,
        Err(e) => return deny(format!("policy error (fail-closed): {e}")),
    };
    let (client, server, tool, model, hints) = parse_action(action);
    let empty = Value::Object(Vec::new());
    let args = action.payload.as_ref().filter(|v| py_truthy(v)).unwrap_or(&empty);
    let call = Call { client: &client, server: &server, tool: &tool, model: model.as_deref(), args: Some(args), hints: &hints };
    let m = evaluate(policy, &call, learned, env);
    if action.action_purpose.as_deref() != Some(m.purpose.as_str()) {
        return deny("policy changed while this call was being decided; retry".into());
    }
    if policy.mode == Mode::Observe {
        let reason = if m.decision == Decision::Allow {
            m.reason
        } else {
            format!("observe: would {}: {}", m.decision.as_str(), m.reason)
        };
        return AuthorityResult { verdict: Verdict::Allow, reason };
    }
    match m.decision {
        Decision::Allow => AuthorityResult { verdict: Verdict::Allow, reason: m.reason },
        Decision::Deny => deny(m.reason),
        Decision::Ask if is_approved() => {
            AuthorityResult { verdict: Verdict::Allow, reason: format!("approved by you ({})", m.reason) }
        }
        Decision::Ask => AuthorityResult { verdict: Verdict::Defer, reason: m.reason },
    }
}

/// Python truthiness of a JSON value (`action.get("payload") or {}`).
fn py_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Int(i) => *i != 0,
        Value::Float(f) => *f != 0.0,
        Value::Str(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}
