//! Decision OS gateway decision engine: the policy file, rule matching, profiles,
//! learned choices, and the policy PDP verdict on the `dos_core` lattice.
//!
//! Design: `design/decision.md`. Oracle: `oracle/decision-os-min/decision_os_min/
//! gateway/policy.py` and `engine.py` (`GatewayAuthorityPDP`). Vectors:
//! `conformance/vectors/policy/`.
//!
//! Pure: no file, process or clock access. The environment that `normalize_path`
//! reads (`~`, `$VAR`, `os.name`) is a [`path::PathEnv`] parameter.
#![forbid(unsafe_code)]

extern crate alloc;

pub mod eval;
pub mod glob;
pub mod path;
pub mod policy;
pub mod py;

pub use eval::{
    Action, AuthorityResult, Call, Match, Source, ToolKind, authority_verdict, classify_tool, evaluate,
    learned_key, parse_action, rule_matches, slug, tool_tokens,
};
pub use path::{FixedEnv, Flavor, PathEnv, normalize_path};
pub use policy::{Decision, GatewayPolicy, GuardrailConfig, Mode, PolicyError, Profile, Rule, parse_policy};
pub use py::Value;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;
    use dos_core::verdict::Verdict;

    fn env() -> FixedEnv {
        FixedEnv { flavor: Flavor::Posix, vars: alloc::vec![("HOME".into(), "/home/u".into())] }
    }

    fn obj(pairs: &[(&str, &str)]) -> Value {
        Value::Object(pairs.iter().map(|(k, v)| ((*k).into(), Value::Str((*v).into()))).collect())
    }

    fn call<'a>(tool: &'a str, server: &'a str, args: Option<&'a Value>) -> Call<'a> {
        Call { client: "c", server, tool, model: None, args, hints: &[] }
    }

    #[test]
    fn classify_like_oracle() {
        for (n, k) in [
            ("read_file", "read"),
            ("list_directory", "read"),
            ("getIssue", "read"),
            ("search_code", "read"),
            ("browser_snapshot", "read"),
            ("write_file", "write"),
            ("create_pull_request", "write"),
            ("run_command", "write"),
            ("Bash", "write"),
            ("delete_branch", "write"),
            ("get_or_create_user", "write"),
            ("frobnicate", "unknown"),
        ] {
            assert_eq!(classify_tool(n, &[]).as_str(), k, "{n}");
        }
        let ro = [String::from("hint:readonly")];
        let de = [String::from("HINT:DESTRUCTIVE")];
        assert_eq!(classify_tool("frobnicate", &ro), ToolKind::Read);
        assert_eq!(classify_tool("write_file", &ro), ToolKind::Write);
        assert_eq!(classify_tool("read_file", &de), ToolKind::Write);
    }

    #[test]
    fn profiles() {
        for (profile, read, write) in [("balanced", "allow", "ask"), ("strict", "ask", "ask"), ("open", "allow", "allow")] {
            let p = parse_policy(&alloc::format!("profile = \"{profile}\""), "p").unwrap();
            let a = Value::Object(Vec::new());
            assert_eq!(evaluate(&p, &call("read_file", "s", Some(&a)), &[], &env()).decision.as_str(), read);
            assert_eq!(evaluate(&p, &call("write_file", "s", Some(&a)), &[], &env()).decision.as_str(), write);
        }
    }

    #[test]
    fn first_match_and_args_globs() {
        let p = parse_policy(
            "[[rule]]\nserver = \"github\"\ntool = \"*\"\nargs = { repo = [\"me/*\", \"team/public-*\"] }\ndecision = \"allow\"\n\n[[rule]]\nserver = \"github\"\ndecision = \"deny\"\n",
            "p",
        )
        .unwrap();
        let e = env();
        let a = obj(&[("repo", "me/x")]);
        let m = evaluate(&p, &call("create_issue", "github", Some(&a)), &[], &e);
        assert_eq!((m.decision, m.purpose.as_str()), (Decision::Allow, "rule:1"));
        let a = obj(&[("repo", "team/public-site")]);
        assert_eq!(evaluate(&p, &call("create_issue", "github", Some(&a)), &[], &e).decision, Decision::Allow);
        let a = obj(&[("repo", "other/x")]);
        let m = evaluate(&p, &call("create_issue", "github", Some(&a)), &[], &e);
        assert_eq!(m.decision, Decision::Deny);
        assert_eq!(m.reason, "denied by rule 2 (server=github)");
        assert_eq!(evaluate(&p, &call("create_issue", "github", None), &[], &e).decision, Decision::Deny);
    }

    #[test]
    fn learned_keeps_purpose_and_deny_wins() {
        let p = parse_policy("[[rule]]\ntool = \"move_*\"\ndecision = \"ask\"\n[[rule]]\ntool = \"rm\"\ndecision = \"deny\"\n", "p").unwrap();
        let a = Value::Object(Vec::new());
        let before = evaluate(&p, &call("move_file", "fs", Some(&a)), &[], &env());
        let learned = [("c|fs|move_file".into(), "allow".into()), ("*|fs|rm".into(), "allow".into())];
        let after = evaluate(&p, &call("move_file", "fs", Some(&a)), &learned, &env());
        assert_eq!((before.decision, after.decision), (Decision::Ask, Decision::Allow));
        assert_eq!(before.purpose, after.purpose);
        assert_eq!(after.source, Source::Learned);
        assert_eq!(evaluate(&p, &call("rm", "fs", Some(&a)), &learned, &env()).decision, Decision::Deny);
    }

    #[test]
    fn path_rules_normalize() {
        let p = parse_policy("[[rule]]\ntool = \"write_file\"\nargs = { path = \"~/projects/*\" }\ndecision = \"allow\"\n", "p").unwrap();
        let e = env();
        for (path, d) in [
            ("/home/u/projects/a.txt", Decision::Allow),
            ("~/projects/x/y", Decision::Allow),
            ("/home/u/projects/../.ssh/id_rsa", Decision::Ask),
            ("/home/u/Projects/a", Decision::Ask),
        ] {
            let a = obj(&[("path", path)]);
            assert_eq!(evaluate(&p, &call("write_file", "fs", Some(&a)), &[], &e).decision, d, "{path}");
        }
    }

    #[test]
    fn pdp_verdicts() {
        let p = parse_policy("[[rule]]\ntool = \"write_file\"\ndecision = \"ask\"\n", "p").unwrap();
        let mut act = Action {
            actor: "agent:c".into(),
            tool: "fs/write_file".into(),
            action_purpose: Some("rule:1".into()),
            data_labels: Vec::new(),
            payload: None,
        };
        let e = env();
        assert_eq!(authority_verdict(Ok(&p), &act, &[], &e, || false).verdict, Verdict::Defer);
        let r = authority_verdict(Ok(&p), &act, &[], &e, || true);
        assert_eq!(r.verdict, Verdict::Allow);
        assert!(r.reason.starts_with("approved by you"));
        assert_eq!(authority_verdict(Err("boom"), &act, &[], &e, || true).verdict, Verdict::Deny);
        act.action_purpose = Some("profile:balanced:write".into());
        assert_eq!(authority_verdict(Ok(&p), &act, &[], &e, || true).verdict, Verdict::Deny);
        let obs = parse_policy("mode = \"observe\"\n[[rule]]\ntool = \"write_file\"\ndecision = \"deny\"\n", "p").unwrap();
        act.action_purpose = Some("rule:1".into());
        let r = authority_verdict(Ok(&obs), &act, &[], &e, || false);
        assert_eq!(r.verdict, Verdict::Allow);
        assert!(r.reason.starts_with("observe: would deny: "));
    }

    #[test]
    fn slug_like_oracle() {
        assert_eq!(slug("  my server/x:y\\z  "), "my-server-x-y-z");
        assert_eq!(slug(" \t "), "unnamed");
        assert_eq!(slug("a //b"), "a-b");
    }
}
