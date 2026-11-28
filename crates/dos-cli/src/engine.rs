//! `PolicyEngine`: the gateway policy (`dos-decision`) as the executor's `DecisionEngine`.

use dos_decision::{
    Call, Decision, FixedEnv, Flavor, GatewayPolicy, Mode, Value as PyValue, evaluate,
};
use dos_exec::{CallRequest, DecisionEngine, EngineError, StaticVerdict, Verdict};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub struct PolicyEngine {
    policy: GatewayPolicy,
    client: String,
    env: FixedEnv,
    learned_file: Option<std::path::PathBuf>,
}

impl PolicyEngine {
    /// `client` is the name the policy's `client` globs match (for example `claude-code`).
    pub fn new(policy: GatewayPolicy, client: impl Into<String>) -> Self {
        let flavor = if cfg!(windows) {
            Flavor::Nt
        } else {
            Flavor::Posix
        };
        PolicyEngine {
            policy,
            client: client.into(),
            env: FixedEnv {
                flavor,
                vars: std::env::vars().collect(),
            },
            learned_file: None,
        }
    }

    /// Reads remembered "always allow/deny" choices from `path` on every decision.
    pub fn with_learned_file(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.learned_file = Some(path.into());
        self
    }

    fn learned(&self) -> Vec<(String, String)> {
        self.learned_file
            .as_deref()
            .map(crate::learned::load)
            .unwrap_or_default()
    }

    fn observing(&self) -> bool {
        self.policy.mode == Mode::Observe
    }
}

/// serde_json to the policy engine's Python-shaped value.
pub fn to_py(v: &Value) -> PyValue {
    match v {
        Value::Null => PyValue::Null,
        Value::Bool(b) => PyValue::Bool(*b),
        Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => PyValue::Int(i128::from(i)),
            (None, Some(u)) => PyValue::Int(i128::from(u)),
            _ => n.as_f64().map_or(PyValue::Null, PyValue::Float),
        },
        Value::String(s) => PyValue::Str(s.clone()),
        Value::Array(a) => PyValue::Array(a.iter().map(to_py).collect()),
        Value::Object(m) => PyValue::Object(m.iter().map(|(k, x)| (k.clone(), to_py(x))).collect()),
    }
}

/// A stable id for "this exact call", so an approval cannot be reused for another call.
fn approval_id(req: &CallRequest) -> String {
    let mut h = Sha256::new();
    for part in [req.server.as_str(), req.tool.as_str()] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    h.update(Value::Object(req.arguments.clone()).to_string().as_bytes());
    let d = h.finalize();
    let hex: String = d.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("ask-{hex}")
}

impl DecisionEngine for PolicyEngine {
    fn decide(&self, req: &CallRequest, approval: Option<&str>) -> Result<Verdict, EngineError> {
        let args = to_py(&Value::Object(req.arguments.clone()));
        let call = Call {
            client: &self.client,
            server: &req.server,
            tool: &req.tool,
            model: None,
            args: Some(&args),
            hints: &req.hints,
        };
        let m = evaluate(&self.policy, &call, &self.learned(), &self.env);
        if self.observing() && m.decision != Decision::Allow {
            return Ok(Verdict::Allow {
                reason: format!(
                    "observe mode, would have {}: {}",
                    m.decision.as_str(),
                    m.reason
                ),
            });
        }
        Ok(match m.decision {
            Decision::Allow => Verdict::Allow { reason: m.reason },
            Decision::Deny => Verdict::Deny { reason: m.reason },
            Decision::Ask => {
                let id = approval_id(req);
                // An approval only counts for the exact call it was issued for.
                if approval == Some(id.as_str()) {
                    Verdict::Allow {
                        reason: format!("approved by you ({})", m.reason),
                    }
                } else {
                    Verdict::Ask {
                        reason: m.reason,
                        approval_id: id,
                    }
                }
            }
        })
    }

    fn static_decision(
        &self,
        server: &str,
        tool: &str,
        hints: &[String],
    ) -> Result<StaticVerdict, EngineError> {
        let call = Call {
            client: &self.client,
            server,
            tool,
            model: None,
            args: None,
            hints,
        };
        let m = evaluate(&self.policy, &call, &self.learned(), &self.env);
        if self.observing() {
            return Ok(StaticVerdict::Allow);
        }
        Ok(match m.decision {
            Decision::Allow => StaticVerdict::Allow,
            Decision::Ask => StaticVerdict::Ask,
            Decision::Deny => StaticVerdict::Deny,
        })
    }

    fn hide_denied_tools(&self) -> bool {
        self.policy.hide_denied_tools && !self.observing()
    }
}
