//! Python formatting the oracle relies on: `json.dumps`, float `repr`, str `repr`.
//!
//! Only what `policy.py` uses: argument values are turned into text with `json.dumps`
//! before glob matching, and validation messages quote values with `repr`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

/// A JSON value as Python's `json.loads` sees it (int and float are distinct).
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// A JSON integer. Python ints are unbounded; this covers every i128.
    Int(i128),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    /// Members in document order; duplicate keys must already be resolved (last wins).
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Look up an object member (last occurrence wins, as a Python dict).
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Python `repr(float)` (shortest round-trip digits, Python exponent rules).
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    // Rust `{:e}` gives the shortest round-trip digits: "-1.2345e-7", "1e16", "0e0".
    let sci = format!("{f:e}");
    let (mant, exp) = match sci.split_once('e') {
        Some((m, e)) => (m, e.parse::<i32>().unwrap_or(0)),
        None => (sci.as_str(), 0),
    };
    let (neg, mant) = match mant.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, mant),
    };
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if (-4..16).contains(&exp) {
        // Fixed notation.
        let n = digits.len() as i32;
        if exp >= 0 {
            let int_len = exp + 1;
            if n <= int_len {
                out.push_str(&digits);
                for _ in 0..(int_len - n) {
                    out.push('0');
                }
                out.push_str(".0");
            } else {
                let (a, b) = digits.split_at(int_len as usize);
                out.push_str(a);
                out.push('.');
                out.push_str(b);
            }
        } else {
            out.push_str("0.");
            for _ in 0..(-exp - 1) {
                out.push('0');
            }
            out.push_str(&digits);
        }
    } else {
        let mut chars = digits.chars();
        if let Some(first) = chars.next() {
            out.push(first);
        }
        let rest: String = chars.collect();
        if !rest.is_empty() {
            out.push('.');
            out.push_str(&rest);
        }
        let sign = if exp < 0 { '-' } else { '+' };
        let _ = write!(out, "e{sign}{:02}", exp.unsigned_abs());
    }
    out
}

/// `json.dumps` float: `repr`, except non-finite values.
fn json_float(f: f64) -> String {
    if f.is_nan() {
        "NaN".into()
    } else if f.is_infinite() {
        if f > 0.0 { "Infinity".into() } else { "-Infinity".into() }
    } else {
        float_repr(f)
    }
}

/// `json.dumps` string with `ensure_ascii=True`.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{:04x}", u);
                }
            }
        }
    }
    out.push('"');
}

fn dumps_into(out: &mut String, v: &Value, sorted_compact: bool) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Value::Float(f) => out.push_str(&json_float(*f)),
        Value::Str(s) => json_str(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(if sorted_compact { "," } else { ", " });
                }
                dumps_into(out, item, sorted_compact);
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut m: Vec<&(String, Value)> = members.iter().collect();
            if sorted_compact {
                m.sort_by(|a, b| a.0.cmp(&b.0));
            }
            out.push('{');
            for (i, (k, val)) in m.iter().map(|p| (&p.0, &p.1)).enumerate() {
                if i > 0 {
                    out.push_str(if sorted_compact { "," } else { ", " });
                }
                json_str(out, k);
                out.push_str(if sorted_compact { ":" } else { ": " });
                dumps_into(out, val, sorted_compact);
            }
            out.push('}');
        }
    }
}

/// `json.dumps(v, sort_keys=True, separators=(",", ":"))`.
pub fn dumps_sorted_compact(v: &Value) -> String {
    let mut s = String::new();
    dumps_into(&mut s, v, true);
    s
}

/// `json.dumps(v)` with default settings (only used for scalars by the policy).
pub fn dumps_default(v: &Value) -> String {
    let mut s = String::new();
    dumps_into(&mut s, v, false);
    s
}

/// Approximation of Python `str.isprintable` for one character.
fn printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    !matches!(c,
        '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{180e}'
        | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}'
        | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{e000}'..='\u{f8ff}'
        | '\u{f0000}'..='\u{10ffff}' | '\u{e0000}'..='\u{e007f}')
}

/// Python `repr(str)`.
pub fn str_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if printable(c) => out.push(c),
            c => {
                let n = c as u32;
                let _ = if n <= 0xff {
                    write!(out, "\\x{n:02x}")
                } else if n <= 0xffff {
                    write!(out, "\\u{n:04x}")
                } else {
                    write!(out, "\\U{n:08x}")
                };
            }
        }
    }
    out.push(q);
    out
}

/// Python `repr` of a sorted list of strings (`sorted(unknown)` in messages).
pub fn list_repr(items: &[String]) -> String {
    let mut sorted: Vec<&String> = items.iter().collect();
    sorted.sort();
    let parts: Vec<String> = sorted.iter().map(|s| str_repr(s)).collect();
    format!("[{}]", parts.join(", "))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn floats_match_python_repr() {
        for (f, want) in [
            (1.0, "1.0"),
            (0.1, "0.1"),
            (1e16, "1e+16"),
            (1.5e-7, "1.5e-07"),
            (123456789012345.6, "123456789012345.6"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (-0.0, "-0.0"),
            (2.5e300, "2.5e+300"),
            (f64::INFINITY, "inf"),
        ] {
            assert_eq!(float_repr(f), want, "{f}");
        }
    }

    #[test]
    fn dumps_matches_python() {
        let v = Value::Object(alloc::vec![
            ("b".into(), Value::Array(alloc::vec![Value::Int(1), Value::Float(2.0), Value::Null])),
            ("a".into(), Value::Str("é\u{7f}\"\u{1f600}".into())),
        ]);
        assert_eq!(
            dumps_sorted_compact(&v),
            "{\"a\":\"\\u00e9\\u007f\\\"\\ud83d\\ude00\",\"b\":[1,2.0,null]}"
        );
        assert_eq!(dumps_default(&Value::Float(f64::NAN)), "NaN");
        assert_eq!(dumps_default(&Value::Bool(true)), "true");
    }

    #[test]
    fn repr_matches_python() {
        assert_eq!(str_repr("loud"), "'loud'");
        assert_eq!(str_repr("it's"), "\"it's\"");
        assert_eq!(str_repr("a'\""), "'a\\'\"'");
        assert_eq!(str_repr("x\u{0}\u{200b}é"), "'x\\x00\\u200bé'");
        assert_eq!(list_repr(&["b".into(), "a".into()]), "['a', 'b']");
    }
}
