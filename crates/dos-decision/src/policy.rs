//! The policy file: `parse_policy` with the oracle's validation order and messages.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::py::{float_repr, list_repr, str_repr};

pub const DECISIONS: [&str; 3] = ["allow", "ask", "deny"];
pub const PROFILES: [&str; 3] = ["balanced", "strict", "open"];
pub const MODES: [&str; 2] = ["enforce", "observe"];
pub const GUARD_LEVELS: [&str; 3] = ["deny", "ask", "off"];

pub const DEFAULT_UPSTREAMS: [(&str, &str); 11] = [
    ("openai", "https://api.openai.com/v1"),
    ("anthropic", "https://api.anthropic.com"),
    ("ollama", "http://localhost:11434/v1"),
    ("lmstudio", "http://localhost:1234/v1"),
    ("openrouter", "https://openrouter.ai/api/v1"),
    ("groq", "https://api.groq.com/openai/v1"),
    ("deepseek", "https://api.deepseek.com/v1"),
    ("mistral", "https://api.mistral.ai/v1"),
    ("together", "https://api.together.xyz/v1"),
    ("xai", "https://api.x.ai/v1"),
    ("gemini", "https://generativelanguage.googleapis.com/v1beta/openai"),
];

pub const DEFAULT_GUARDRAILS: [(&str, &str); 5] = [
    ("protected_paths", "deny"),
    ("secret_files", "ask"),
    ("secrets_in_arguments", "deny"),
    ("catastrophic_commands", "deny"),
    ("risky_commands", "ask"),
];

const TOP_KEYS: [&str; 10] = [
    "mode",
    "profile",
    "ask_timeout_seconds",
    "hide_denied_tools",
    "notify",
    "open_dashboard",
    "dashboard_port",
    "guardrails",
    "rule",
    "llm",
];
const RULE_KEYS: [&str; 8] = ["client", "server", "tool", "model", "args", "decision", "reason", "redact"];

/// The policy file is missing, unreadable or invalid. The gateway fails closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

/// A rule decision. `Ask` becomes `DEFER` at the PDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

impl Decision {
    pub fn parse(s: &str) -> Option<Decision> {
        match s {
            "allow" => Some(Decision::Allow),
            "ask" => Some(Decision::Ask),
            "deny" => Some(Decision::Deny),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Ask => "ask",
            Decision::Deny => "deny",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Balanced,
    Strict,
    Open,
}

impl Profile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Profile::Balanced => "balanced",
            Profile::Strict => "strict",
            Profile::Open => "open",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    Observe,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// 1-based position in the file.
    pub index: usize,
    pub decision: Decision,
    pub client: String,
    pub server: String,
    pub tool: String,
    pub model: Option<String>,
    pub args: Vec<(String, Vec<String>)>,
    pub reason: String,
    pub redact: Vec<String>,
}

impl Rule {
    /// Bound into the action fingerprint.
    pub fn purpose(&self) -> String {
        format!("rule:{}", self.index)
    }

    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = [("client", &self.client), ("server", &self.server), ("tool", &self.tool)]
            .iter()
            .filter(|(_, v)| v.as_str() != "*")
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        if let Some(m) = self.model.as_deref().filter(|m| !m.is_empty()) {
            parts.push(format!("model={m}"));
        }
        for (k, v) in &self.args {
            parts.push(format!("args.{k}={}", v.join("|")));
        }
        let body = if parts.is_empty() { "everything".to_string() } else { parts.join(", ") };
        format!("rule {} ({body})", self.index)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GuardrailConfig {
    pub enabled: bool,
    pub levels: Vec<(String, String)>,
    pub extra_protected_paths: Vec<String>,
}

impl Default for GuardrailConfig {
    fn default() -> Self {
        GuardrailConfig {
            enabled: true,
            levels: DEFAULT_GUARDRAILS.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            extra_protected_paths: Vec::new(),
        }
    }
}

impl GuardrailConfig {
    pub fn level(&self, name: &str) -> String {
        if !self.enabled {
            return "off".into();
        }
        self.levels
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .or_else(|| DEFAULT_GUARDRAILS.iter().find(|(k, _)| *k == name).map(|(_, v)| v.to_string()))
            .unwrap_or_else(|| "deny".into())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GatewayPolicy {
    pub mode: Mode,
    pub profile: Profile,
    pub ask_timeout_seconds: f64,
    pub hide_denied_tools: bool,
    pub notify: bool,
    pub open_dashboard: bool,
    pub dashboard_port: u16,
    pub guardrails: GuardrailConfig,
    pub rules: Vec<Rule>,
    pub upstreams: Vec<(String, String)>,
    pub revision: String,
}

impl Default for GatewayPolicy {
    fn default() -> Self {
        GatewayPolicy {
            mode: Mode::Enforce,
            profile: Profile::Balanced,
            ask_timeout_seconds: 120.0,
            hide_denied_tools: true,
            notify: true,
            open_dashboard: true,
            dashboard_port: 8766,
            guardrails: GuardrailConfig::default(),
            rules: Vec::new(),
            upstreams: DEFAULT_UPSTREAMS.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            revision: "builtin".into(),
        }
    }
}

// ------------------------------------------------------------------ TOML model

/// A TOML value as `tomllib` returns it.
#[derive(Clone, Debug, PartialEq)]
enum T {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Datetime(String),
    Array(Vec<T>),
    Table(Vec<(String, T)>),
}

impl T {
    fn get(&self, k: &str) -> Option<&T> {
        match self {
            T::Table(m) => m.iter().find(|(a, _)| a == k).map(|(_, v)| v),
            _ => None,
        }
    }
    fn keys(&self) -> Vec<String> {
        match self {
            T::Table(m) => m.iter().map(|(k, _)| k.clone()).collect(),
            _ => Vec::new(),
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            T::Str(s) => Some(s),
            _ => None,
        }
    }
    /// Python truthiness (for `llm.get("upstreams") or {}`).
    fn truthy(&self) -> bool {
        match self {
            T::Str(s) => !s.is_empty(),
            T::Int(i) => *i != 0,
            T::Float(f) => *f != 0.0,
            T::Bool(b) => *b,
            T::Datetime(_) => true,
            T::Array(a) => !a.is_empty(),
            T::Table(t) => !t.is_empty(),
        }
    }
    /// Python `repr`.
    fn repr(&self) -> String {
        match self {
            T::Str(s) => str_repr(s),
            T::Int(i) => i.to_string(),
            T::Float(f) => float_repr(*f),
            T::Bool(true) => "True".into(),
            T::Bool(false) => "False".into(),
            // Approximation: Python prints datetime.datetime(...) here.
            T::Datetime(d) => d.clone(),
            T::Array(a) => format!("[{}]", a.iter().map(T::repr).collect::<Vec<_>>().join(", ")),
            T::Table(t) => format!(
                "{{{}}}",
                t.iter().map(|(k, v)| format!("{}: {}", str_repr(k), v.repr())).collect::<Vec<_>>().join(", ")
            ),
        }
    }
}

fn from_value(v: &toml_edit::Value) -> T {
    use toml_edit::Value as V;
    match v {
        V::String(s) => T::Str(s.value().clone()),
        V::Integer(i) => T::Int(*i.value()),
        V::Float(f) => T::Float(*f.value()),
        V::Boolean(b) => T::Bool(*b.value()),
        V::Datetime(d) => T::Datetime(d.value().to_string()),
        V::Array(a) => T::Array(a.iter().map(from_value).collect()),
        V::InlineTable(t) => T::Table(t.iter().map(|(k, v)| (k.to_string(), from_value(v))).collect()),
    }
}

fn from_item(i: &toml_edit::Item) -> Option<T> {
    use toml_edit::Item as I;
    match i {
        I::None => None,
        I::Value(v) => Some(from_value(v)),
        I::Table(t) => Some(from_table(t)),
        I::ArrayOfTables(a) => Some(T::Array(a.iter().map(from_table).collect())),
    }
}

fn from_table(t: &toml_edit::Table) -> T {
    T::Table(t.iter().filter_map(|(k, v)| from_item(v).map(|x| (k.to_string(), x))).collect())
}

fn one_of(xs: &[&str]) -> String {
    format!("({})", xs.iter().map(|x| str_repr(x)).collect::<Vec<_>>().join(", "))
}

fn expect(cond: bool, msg: impl FnOnce() -> String) -> Result<(), PolicyError> {
    if cond { Ok(()) } else { Err(PolicyError(msg())) }
}

fn in_vocab(v: Option<&T>, vocab: &[&str]) -> Option<String> {
    v.and_then(T::as_str).filter(|s| vocab.contains(s)).map(str::to_string)
}

fn upstream_name_ok(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn sha256_16(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(text.as_bytes());
    let mut s = String::new();
    for b in d.iter().take(8) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `parse_policy(text, source=source)`.
pub fn parse_policy(text: &str, source: &str) -> Result<GatewayPolicy, PolicyError> {
    let doc: toml_edit::Document<String> = text
        .parse()
        .map_err(|e: toml_edit::TomlError| PolicyError(format!("{source}: invalid TOML: {}", e.message())))?;
    let data = from_table(doc.as_table());

    let unknown: Vec<String> = data.keys().into_iter().filter(|k| !TOP_KEYS.contains(&k.as_str())).collect();
    expect(unknown.is_empty(), || format!("{source}: unknown setting(s) {}", list_repr(&unknown)))?;

    let mode_v = data.get("mode");
    let mode = match mode_v {
        None => Some("enforce".to_string()),
        v => in_vocab(v, &MODES),
    };
    let mode = mode.ok_or_else(|| {
        PolicyError(format!(
            "{source}: mode must be one of {}, got {}",
            one_of(&MODES),
            mode_v.map(T::repr).unwrap_or_default()
        ))
    })?;
    let prof_v = data.get("profile");
    let profile = match prof_v {
        None => Some("balanced".to_string()),
        v => in_vocab(v, &PROFILES),
    };
    let profile = profile.ok_or_else(|| {
        PolicyError(format!(
            "{source}: profile must be one of {}, got {}",
            one_of(&PROFILES),
            prof_v.map(T::repr).unwrap_or_default()
        ))
    })?;
    let timeout = match data.get("ask_timeout_seconds") {
        None => Some(120.0),
        Some(T::Int(i)) if *i > 0 => Some(*i as f64),
        Some(T::Float(f)) if *f > 0.0 => Some(*f),
        _ => None,
    };
    let timeout = timeout.ok_or_else(|| PolicyError(format!("{source}: ask_timeout_seconds must be a positive number")))?;
    // isinstance(True, int) holds in Python, so `dashboard_port = true` is port 1.
    let port = match data.get("dashboard_port") {
        None => Some(8766u16),
        Some(T::Int(i)) if *i > 0 && *i < 65536 => u16::try_from(*i).ok(),
        Some(T::Bool(true)) => Some(1),
        _ => None,
    };
    let port = port.ok_or_else(|| PolicyError(format!("{source}: invalid dashboard_port")))?;
    let mut flags = [true; 3];
    for (slot, key) in flags.iter_mut().zip(["hide_denied_tools", "notify", "open_dashboard"]) {
        match data.get(key) {
            None => {}
            Some(T::Bool(b)) => *slot = *b,
            Some(_) => return Err(PolicyError(format!("{source}: {key} must be true or false"))),
        }
    }

    let empty = T::Table(Vec::new());
    let g = data.get("guardrails").unwrap_or(&empty);
    expect(matches!(g, T::Table(_)), || format!("{source}: [guardrails] must be a table"))?;
    let unknown: Vec<String> = g
        .keys()
        .into_iter()
        .filter(|k| k != "enabled" && k != "extra_protected_paths" && !DEFAULT_GUARDRAILS.iter().any(|(n, _)| n == k))
        .collect();
    expect(unknown.is_empty(), || format!("{source}: unknown guardrail setting(s) {}", list_repr(&unknown)))?;
    let enabled = match g.get("enabled") {
        None => true,
        Some(T::Bool(b)) => *b,
        Some(_) => return Err(PolicyError(format!("{source}: guardrails.enabled must be true or false"))),
    };
    let mut levels: Vec<(String, String)> =
        DEFAULT_GUARDRAILS.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    for (key, val) in levels.iter_mut() {
        if let Some(v) = g.get(key) {
            let lv = in_vocab(Some(v), &GUARD_LEVELS)
                .ok_or_else(|| PolicyError(format!("{source}: guardrails.{key} must be one of {}", one_of(&GUARD_LEVELS))))?;
            *val = lv;
        }
    }
    let extra = match g.get("extra_protected_paths") {
        None => Some(Vec::new()),
        Some(T::Array(a)) => a.iter().map(|x| x.as_str().map(str::to_string)).collect::<Option<Vec<_>>>(),
        Some(_) => None,
    };
    let extra = extra.ok_or_else(|| PolicyError(format!("{source}: guardrails.extra_protected_paths must be a list of strings")))?;

    let mut rules = Vec::new();
    let no_rules = T::Array(Vec::new());
    let raw_rules = match data.get("rule").unwrap_or(&no_rules) {
        T::Array(a) => a,
        _ => return Err(PolicyError(format!("{source}: use [[rule]] for rules"))),
    };
    for (i0, r) in raw_rules.iter().enumerate() {
        let i = i0 + 1;
        expect(matches!(r, T::Table(_)), || format!("{source}: rule {i} must be a table"))?;
        let unknown: Vec<String> = r.keys().into_iter().filter(|k| !RULE_KEYS.contains(&k.as_str())).collect();
        expect(unknown.is_empty(), || format!("{source}: rule {i} has unknown field(s) {}", list_repr(&unknown)))?;
        let decision = r
            .get("decision")
            .and_then(T::as_str)
            .and_then(Decision::parse)
            .ok_or_else(|| PolicyError(format!("{source}: rule {i} needs decision = allow | ask | deny")))?;
        for key in ["client", "server", "tool", "model", "reason"] {
            expect(r.get(key).is_none_or(|v| v.as_str().is_some()), || {
                format!("{source}: rule {i}: {key} must be a string")
            })?;
        }
        let no_args = T::Table(Vec::new());
        let args_raw = match r.get("args").unwrap_or(&no_args) {
            T::Table(m) => m,
            _ => return Err(PolicyError(format!("{source}: rule {i}: args must be a table"))),
        };
        let mut args = Vec::new();
        for (name, pat) in args_raw {
            let pats: Option<Vec<String>> = match pat {
                T::Str(s) => Some(alloc::vec![s.clone()]),
                T::Array(a) if !a.is_empty() => a.iter().map(|x| x.as_str().map(str::to_string)).collect(),
                _ => None,
            };
            let pats = pats.ok_or_else(|| {
                PolicyError(format!("{source}: rule {i}: args.{name} must be a glob or a list of globs"))
            })?;
            args.push((name.clone(), pats));
        }
        let redact = match r.get("redact") {
            None => Some(Vec::new()),
            Some(T::Array(a)) => a.iter().map(|x| x.as_str().map(str::to_string)).collect::<Option<Vec<_>>>(),
            Some(_) => None,
        };
        let redact = redact.ok_or_else(|| PolicyError(format!("{source}: rule {i}: redact must be a list of argument names")))?;
        expect(redact.is_empty() || decision != Decision::Deny, || {
            format!("{source}: rule {i}: redact makes no sense on deny")
        })?;
        let s = |k: &str, d: &str| r.get(k).and_then(T::as_str).unwrap_or(d).to_string();
        rules.push(Rule {
            index: i,
            decision,
            client: s("client", "*"),
            server: s("server", "*"),
            tool: s("tool", "*"),
            model: r.get("model").and_then(T::as_str).map(str::to_string),
            args,
            reason: s("reason", ""),
            redact,
        });
    }

    let mut upstreams: Vec<(String, String)> =
        DEFAULT_UPSTREAMS.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let llm = data.get("llm").unwrap_or(&empty);
    expect(matches!(llm, T::Table(_)), || format!("{source}: [llm] must be a table"))?;
    expect(llm.keys().iter().all(|k| k == "upstreams"), || format!("{source}: [llm] only supports upstreams"))?;
    match llm.get("upstreams") {
        Some(T::Table(m)) => {
            for (name, url) in m {
                let u = url.as_str().filter(|u| u.starts_with("http://") || u.starts_with("https://"));
                let u = u.ok_or_else(|| PolicyError(format!("{source}: llm.upstreams.{name} must be an http(s) URL")))?;
                expect(upstream_name_ok(name), || {
                    format!("{source}: llm.upstreams name {} may only use letters, digits, _ . -", str_repr(name))
                })?;
                let u = u.trim_end_matches('/').to_string();
                match upstreams.iter_mut().find(|(k, _)| k == name) {
                    Some(slot) => slot.1 = u,
                    None => upstreams.push((name.clone(), u)),
                }
            }
        }
        Some(v) if v.truthy() => {
            // The oracle raises AttributeError here (not a PolicyError); refuse anyway.
            return Err(PolicyError(format!("{source}: llm.upstreams must be a table")));
        }
        _ => {}
    }

    let [hide_denied_tools, notify, open_dashboard] = flags;
    Ok(GatewayPolicy {
        mode: if mode == "observe" { Mode::Observe } else { Mode::Enforce },
        profile: match profile.as_str() {
            "strict" => Profile::Strict,
            "open" => Profile::Open,
            _ => Profile::Balanced,
        },
        ask_timeout_seconds: timeout,
        hide_denied_tools,
        notify,
        open_dashboard,
        dashboard_port: port,
        guardrails: GuardrailConfig { enabled, levels, extra_protected_paths: extra },
        rules,
        upstreams,
        revision: format!("sha256:{}", sha256_16(text)),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn err(t: &str) -> String {
        match parse_policy(t, "policy.toml") {
            Err(PolicyError(m)) => m,
            Ok(_) => String::from("<ok>"),
        }
    }

    #[test]
    fn oracle_rejections() {
        // tests/gateway/test_policy_guardrails.py::test_invalid_policies_are_rejected_with_a_reason
        for (bad, needle) in [
            ("mode = \"loud\"", "mode"),
            ("typo_setting = 1", "unknown setting"),
            ("[[rule]]\ntool = \"x\"", "decision"),
            ("[[rule]]\ntool = \"x\"\ndecision = \"allow\"\nwhen = 1", "unknown field"),
            ("[[rule]]\ntool = \"x\"\ndecision = \"deny\"\nredact = [\"a\"]", "redact"),
            ("[guardrails]\nprotected_paths = \"maybe\"", "guardrails.protected_paths"),
            ("[llm.upstreams]\nx = \"ftp://nope\"", "http"),
            ("this is not toml", "invalid TOML"),
        ] {
            let m = err(bad);
            assert!(m.contains(needle), "{bad}: {m}");
        }
    }

    #[test]
    fn exact_messages() {
        assert_eq!(err("mode = \"loud\""), "policy.toml: mode must be one of ('enforce', 'observe'), got 'loud'");
        assert_eq!(err("b = 1\na = 2"), "policy.toml: unknown setting(s) ['a', 'b']");
        assert_eq!(err("profile = 3"), "policy.toml: profile must be one of ('balanced', 'strict', 'open'), got 3");
        assert_eq!(err("ask_timeout_seconds = true"), "policy.toml: ask_timeout_seconds must be a positive number");
        assert_eq!(err("rule = 1"), "policy.toml: use [[rule]] for rules");
    }

    #[test]
    fn revision_and_defaults() {
        let p = parse_policy("", "x").unwrap();
        // sha256("") = e3b0c44298fc1c14...
        assert_eq!(p.revision, "sha256:e3b0c44298fc1c14");
        assert_eq!(p.upstreams.len(), 11);
        assert_eq!(p.dashboard_port, 8766);
        let p = parse_policy("dashboard_port = true", "x").unwrap();
        assert_eq!(p.dashboard_port, 1);
    }
}
