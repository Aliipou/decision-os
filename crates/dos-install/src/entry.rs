//! The wrapped entry: how a stdio server is put behind `decision-os mcp-proxy`, and how
//! it is recognized and undone (spec/install.md, "Wrapped entry").

use serde_json::{Map, Value};

/// The Python gateway module named in entries written by the oracle.
pub const PY_MODULE: &str = "decision_os_min.gateway";

/// Remote transports: reported, never wrapped (oracle `REMOTE_TYPES`).
const REMOTE_TYPES: &[&str] = &[
    "http",
    "sse",
    "streamable-http",
    "streamablehttp",
    "streamable_http",
    "remote",
];

/// Who wrote a wrapped entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// `<bin> mcp-proxy --home H --client C --server S -- cmd args...`
    Rust,
    /// `<python> [-P] -m decision_os_min.gateway --home H mcp-proxy --client C --server S -- cmd ...`
    Python,
    /// Anything else the oracle's predicate accepts (args contain the module, `mcp-proxy`
    /// and `--`); unwrapped after the first `--`, like the oracle.
    PythonLoose,
}

/// The args of a wrapped entry.
pub fn wrap_args(home: &str, client: &str, server: &str, command: &str, args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = [
        "mcp-proxy", "--home", home, "--client", client, "--server", server, "--", command,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    out.extend(args.iter().cloned());
    out
}

fn is(v: Option<&Value>, s: &str) -> bool {
    v.and_then(Value::as_str) == Some(s)
}

fn is_str(v: Option<&Value>) -> bool {
    v.is_some_and(Value::is_string)
}

/// Index of the original command for the strict shapes.
fn strict(a: &[Value]) -> Option<(Shape, usize)> {
    if is(a.first(), "mcp-proxy")
        && is(a.get(1), "--home")
        && is_str(a.get(2))
        && is(a.get(3), "--client")
        && is_str(a.get(4))
        && is(a.get(5), "--server")
        && is_str(a.get(6))
        && is(a.get(7), "--")
    {
        return Some((Shape::Rust, 8));
    }
    let o = usize::from(is(a.first(), "-P"));
    if is(a.get(o), "-m")
        && is(a.get(o + 1), PY_MODULE)
        && is(a.get(o + 2), "--home")
        && is_str(a.get(o + 3))
        && is(a.get(o + 4), "mcp-proxy")
        && is(a.get(o + 5), "--client")
        && is_str(a.get(o + 6))
        && is(a.get(o + 7), "--server")
        && is_str(a.get(o + 8))
        && is(a.get(o + 9), "--")
    {
        return Some((Shape::Python, o + 10));
    }
    None
}

fn contains(a: &[Value], s: &str) -> bool {
    a.iter().any(|v| v.as_str() == Some(s))
}

/// The shape of a wrapped entry, or `None` when `args` is not a wrapped args list.
pub fn wrapped_shape(args: Option<&Value>) -> Option<Shape> {
    let a = args?.as_array()?;
    if let Some((shape, _)) = strict(a) {
        return Some(shape);
    }
    (contains(a, PY_MODULE) && contains(a, "mcp-proxy") && contains(a, "--")).then_some(Shape::PythonLoose)
}

/// Whether this args value is a wrapped entry (Rust or Python).
pub fn is_wrapped(args: Option<&Value>) -> bool {
    wrapped_shape(args).is_some()
}

/// The wrapped entry has nothing after `--`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoOriginalCommand;

/// The original command and args of a wrapped args list.
pub fn unwrap_args(a: &[Value]) -> Result<(Value, Vec<Value>), NoOriginalCommand> {
    let start = match strict(a) {
        Some((_, i)) => i,
        None => {
            a.iter()
                .position(|v| v.as_str() == Some("--"))
                .ok_or(NoOriginalCommand)?
                + 1
        }
    };
    let rest = a.get(start..).unwrap_or(&[]);
    let (first, tail) = rest.split_first().ok_or(NoOriginalCommand)?;
    Ok((first.clone(), tail.to_vec()))
}

/// Python truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_str().parse::<f64>().map_or(true, |f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// The oracle's `is_remote`: `type or transport` names a remote transport, or a URL key
/// is present.
pub fn is_remote(entry: &Map<String, Value>) -> bool {
    let pick = entry
        .get("type")
        .filter(|v| truthy(v))
        .or_else(|| entry.get("transport").filter(|v| truthy(v)));
    // Only a string can print as one of REMOTE_TYPES (str() of a list, number or bool
    // never does), and no non-ASCII character lowercases into these words.
    let by_type = pick
        .and_then(Value::as_str)
        .is_some_and(|t| REMOTE_TYPES.contains(&t.to_lowercase().as_str()));
    by_type || ["url", "serverUrl", "httpUrl"].iter().any(|k| entry.contains_key(*k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vals(v: &[&str]) -> Vec<Value> {
        v.iter().map(|s| json!(s)).collect()
    }

    #[test]
    fn python_shapes_unwrap_by_position() {
        let a = vals(&[
            "-P", "-m", PY_MODULE, "--home", "/h", "mcp-proxy", "--client", "c", "--server", "--", "--",
            "npx", "x",
        ]);
        assert_eq!(wrapped_shape(Some(&Value::Array(a.clone()))), Some(Shape::Python));
        assert_eq!(unwrap_args(&a), Ok((json!("npx"), vals(&["x"]))));
        let old = vals(&["-m", PY_MODULE, "--home", "/h", "mcp-proxy", "--client", "c", "--server", "s", "--", "u"]);
        assert_eq!(unwrap_args(&old), Ok((json!("u"), vec![])));
    }

    #[test]
    fn loose_shape_uses_first_double_dash() {
        let a = vals(&["-m", PY_MODULE, "mcp-proxy", "--", "x", "--", "y"]);
        assert_eq!(wrapped_shape(Some(&Value::Array(a.clone()))), Some(Shape::PythonLoose));
        assert_eq!(unwrap_args(&a), Ok((json!("x"), vals(&["--", "y"]))));
        assert_eq!(unwrap_args(&vals(&["-m", PY_MODULE, "mcp-proxy", "--"])), Err(NoOriginalCommand));
    }

    #[test]
    fn plain_args_are_not_wrapped() {
        assert!(!is_wrapped(Some(&json!(["mcp-proxy", "--"]))));
        assert!(!is_wrapped(Some(&json!("x"))));
        assert!(!is_wrapped(None));
    }
}
