//! Replays every `conformance/vectors/policy/*.json` (generated from the oracle by
//! `conformance/gen/policy_from_oracle.py`) through the Rust engine.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::fs;
use std::path::PathBuf;

use dos_decision::{
    Action, Call, FixedEnv, Flavor, GatewayPolicy, Mode, Value, authority_verdict, classify_tool, evaluate,
    normalize_path, parse_policy, slug,
};
use serde_json::{Value as J, json};

fn to_value(j: &J) -> Value {
    match j {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i128::from(i))
            } else if let Some(u) = n.as_u64() {
                Value::Int(i128::from(u))
            } else {
                Value::Float(n.as_f64().unwrap())
            }
        }
        J::String(s) => Value::Str(s.clone()),
        J::Array(a) => Value::Array(a.iter().map(to_value).collect()),
        J::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), to_value(v))).collect()),
    }
}

fn env(input: &J) -> FixedEnv {
    let flavor = match input["flavor"].as_str().unwrap() {
        "posix" => Flavor::Posix,
        "nt" => Flavor::Nt,
        f => panic!("flavor {f}"),
    };
    let vars = input["env"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect();
    FixedEnv { flavor, vars }
}

fn strs(j: &J) -> Vec<String> {
    j.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

fn learned(j: &J) -> Vec<(String, String)> {
    j.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect()
}

fn summary(p: &GatewayPolicy) -> J {
    json!({
        "mode": if p.mode == Mode::Observe { "observe" } else { "enforce" },
        "profile": p.profile.as_str(),
        "ask_timeout_seconds": if p.ask_timeout_seconds.is_finite() {
            json!(p.ask_timeout_seconds)
        } else {
            json!(dos_decision::py::float_repr(p.ask_timeout_seconds))
        },
        "hide_denied_tools": p.hide_denied_tools,
        "notify": p.notify,
        "open_dashboard": p.open_dashboard,
        "dashboard_port": p.dashboard_port,
        "guardrails": {
            "enabled": p.guardrails.enabled,
            "levels": p.guardrails.levels.iter().map(|(a, b)| json!([a, b])).collect::<Vec<_>>(),
            "extra_protected_paths": p.guardrails.extra_protected_paths,
        },
        "rules": p.rules.iter().map(|r| json!({
            "index": r.index,
            "decision": r.decision.as_str(),
            "client": r.client,
            "server": r.server,
            "tool": r.tool,
            "model": r.model,
            "args": r.args.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
            "reason": r.reason,
            "redact": r.redact,
            "describe": r.describe(),
        })).collect::<Vec<_>>(),
        "upstreams": p.upstreams.iter().map(|(a, b)| json!([a, b])).collect::<Vec<_>>(),
        "revision": p.revision,
    })
}

fn run(input: &J) -> J {
    match input["op"].as_str().unwrap() {
        "parse" => match parse_policy(input["text"].as_str().unwrap(), "policy.toml") {
            Ok(p) => json!({ "ok": summary(&p) }),
            Err(e) if e.0.starts_with("policy.toml: invalid TOML: ") => {
                json!({ "error": "policy.invalid-toml" })
            }
            Err(e) => json!({ "error": e.0 }),
        },
        "classify" => json!({ "ok": classify_tool(input["name"].as_str().unwrap(), &strs(&input["hints"])).as_str() }),
        "normalize_path" => json!({ "ok": normalize_path(input["path"].as_str().unwrap(), &env(input)) }),
        "slug" => json!({ "ok": slug(input["name"].as_str().unwrap()) }),
        "evaluate" => {
            let p = parse_policy(input["policy"].as_str().unwrap(), "policy.toml").unwrap();
            let args = if input["args"].is_null() { None } else { Some(to_value(&input["args"])) };
            let hints = strs(&input["hints"]);
            let call = Call {
                client: input["client"].as_str().unwrap(),
                server: input["server"].as_str().unwrap(),
                tool: input["tool"].as_str().unwrap(),
                model: input["model"].as_str(),
                args: args.as_ref(),
                hints: &hints,
            };
            let m = evaluate(&p, &call, &learned(&input["learned"]), &env(input));
            json!({ "ok": {
                "decision": m.decision.as_str(),
                "purpose": m.purpose,
                "reason": m.reason,
                "redact": m.redact,
                "source": m.source.as_str(),
            }})
        }
        "pdp" => {
            let parsed;
            let policy = if input["policy"].is_null() {
                Err(input["policy_error"].as_str().unwrap())
            } else {
                parsed = parse_policy(input["policy"].as_str().unwrap(), "policy.toml").unwrap();
                Ok(&parsed)
            };
            let a = &input["action"];
            let action = Action {
                actor: a["actor"].as_str().unwrap().to_string(),
                tool: a["tool"].as_str().unwrap().to_string(),
                action_purpose: a["action_purpose"].as_str().map(str::to_string),
                data_labels: strs(&a["data_labels"]),
                payload: if a["payload"].is_null() { None } else { Some(to_value(&a["payload"])) },
            };
            let approved = input["approved"].as_bool().unwrap();
            let r = authority_verdict(policy, &action, &learned(&input["learned"]), &env(input), || approved);
            json!({ "ok": { "verdict": r.verdict.as_str(), "reason": r.reason } })
        }
        op => panic!("unknown op {op}"),
    }
}

#[test]
fn policy_vectors_match_the_oracle() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/policy");
    let mut n = 0;
    let mut failures = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let v: J = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["area"], "policy");
        let got = run(&v["input"]);
        if got != v["expected"] {
            failures.push(format!("{}:\n  want {}\n  got  {}", v["name"], v["expected"], got));
        }
        n += 1;
    }
    assert!(n >= 300, "only {n} policy vectors");
    assert!(failures.is_empty(), "{} of {n} failed:\n{}", failures.len(), failures.join("\n"));
}
