//! The bytes Python's `json` module writes, reproduced exactly.
//!
//! The oracle writes configs with `json.dumps(data, indent=<detected>, ensure_ascii=False)`
//! and its state file with `json.dumps(data, indent=2)`. Matching those bytes is what
//! makes an install by Rust indistinguishable from an install by the oracle, and what
//! the vectors check. Every rule here is pinned by a vector in
//! `conformance/vectors/install/` (numbers, escapes, indents).

use serde_json::{Map, Number, Value};

/// `str.isspace()` / regex `\s` in Python 3 (Unicode), which differs from
/// `char::is_whitespace` on U+001C..U+001F.
pub fn is_py_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{0b}'
            | '\u{0c}'
            | '\r'
            | '\u{1c}'..='\u{1f}'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// `not text.strip()` in Python.
pub fn is_blank(text: &str) -> bool {
    text.chars().all(is_py_space)
}

/// The indent unit `json.dumps` is called with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Indent {
    /// `indent=n`: n spaces per level.
    Spaces(usize),
    /// `indent="\t"`.
    Tab,
}

impl Indent {
    fn unit(&self) -> String {
        match self {
            Indent::Spaces(n) => " ".repeat(*n),
            Indent::Tab => "\t".to_string(),
        }
    }
}

/// The oracle's `_indent`: the first `\n([ \t]+)\S`; a tab first means tabs, otherwise
/// the length of the run; 2 when nothing matches.
pub fn detect_indent(text: &str) -> Indent {
    let chars: Vec<char> = text.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c != '\n' {
            continue;
        }
        let run: Vec<char> = chars
            .iter()
            .skip(i + 1)
            .take_while(|c| **c == ' ' || **c == '\t')
            .copied()
            .collect();
        if run.is_empty() {
            continue;
        }
        // The run is maximal, so backtracking cannot help: the next char must be \S.
        match chars.get(i + 1 + run.len()) {
            Some(next) if !is_py_space(*next) => {
                return if run.first() == Some(&'\t') {
                    Indent::Tab
                } else {
                    Indent::Spaces(run.len())
                };
            }
            _ => continue,
        }
    }
    Indent::Spaces(2)
}

/// A JSON string literal as `json.dumps(s, ensure_ascii=False)` writes it.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    push_string(&mut out, s, false);
    out
}

/// A JSON string literal as `json.dumps(s)` (ASCII escaping) writes it.
pub fn json_string_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    push_string(&mut out, s, true);
    out
}

fn push_string(out: &mut String, s: &str, ascii: bool) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => push_u(out, c as u32),
            c if ascii && !(' '..='~').contains(&c) => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    push_u(out, u32::from(*unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_u(out: &mut String, v: u32) {
    out.push_str(&format!("\\u{v:04x}"));
}

/// A number the oracle would write as `Infinity` (not JSON); refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonFinite(pub String);

/// How Python prints the number `json.loads` made of this lexeme: an int as is
/// (`-0` is `0`), a float with `repr`.
pub fn format_number(n: &Number) -> Result<String, NonFinite> {
    let lex = n.as_str();
    if !lex.contains(['.', 'e', 'E']) {
        return Ok(if lex == "-0" {
            "0".to_string()
        } else {
            lex.to_string()
        });
    }
    match lex.parse::<f64>() {
        Ok(f) if f.is_finite() => Ok(py_float_repr(f)),
        _ => Err(NonFinite(lex.to_string())),
    }
}

/// Python's `repr(float)` for a finite double: the shortest round-trip digits, fixed
/// notation when the decimal point position is in -3..=16, else `d.ddde+XX`.
pub fn py_float_repr(f: f64) -> String {
    let sci = format!("{f:e}"); // shortest round-trip digits, e.g. "-1.5e-5"
    let (neg, body) = match sci.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, sci.as_str()),
    };
    let (mant, exp) = body.split_once('e').unwrap_or((body, "0"));
    let exp: i64 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let decpt = exp + 1;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    let len = i64::try_from(digits.len()).unwrap_or(i64::MAX);
    if decpt <= -4 || decpt > 16 {
        let mut chars = digits.chars();
        if let Some(first) = chars.next() {
            out.push(first);
        }
        let rest: String = chars.collect();
        if !rest.is_empty() {
            out.push('.');
            out.push_str(&rest);
        }
        let e = decpt - 1;
        out.push_str(&format!("e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs()));
    } else if decpt <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat(usize::try_from(-decpt).unwrap_or(0)));
        out.push_str(&digits);
    } else if decpt < len {
        let cut = usize::try_from(decpt).unwrap_or(0);
        out.push_str(digits.get(..cut).unwrap_or(""));
        out.push('.');
        out.push_str(digits.get(cut..).unwrap_or(""));
    } else {
        out.push_str(&digits);
        out.push_str(&"0".repeat(usize::try_from(decpt - len).unwrap_or(0)));
        out.push_str(".0");
    }
    out
}

/// `json.dumps(value, indent=indent, ensure_ascii=ascii)`.
pub fn dumps(value: &Value, indent: &Indent, ascii: bool) -> Result<String, NonFinite> {
    let mut out = String::new();
    write_value(&mut out, value, &indent.unit(), 0, ascii)?;
    Ok(out)
}

/// `json.dumps(value)` with the default separators `", "` and `": "` and ASCII escaping.
pub fn dumps_compact_ascii(value: &Value) -> Result<String, NonFinite> {
    let mut out = String::new();
    write_compact(&mut out, value)?;
    Ok(out)
}

fn write_compact(out: &mut String, v: &Value) -> Result<(), NonFinite> {
    match v {
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_compact(out, x)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                push_string(out, k, true);
                out.push_str(": ");
                write_compact(out, x)?;
            }
            out.push('}');
        }
        other => write_scalar(out, other, true)?,
    }
    Ok(())
}

fn write_scalar(out: &mut String, v: &Value, ascii: bool) -> Result<(), NonFinite> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&format_number(n)?),
        Value::String(s) => push_string(out, s, ascii),
        Value::Array(_) | Value::Object(_) => {}
    }
    Ok(())
}

fn newline(out: &mut String, unit: &str, level: usize) {
    out.push('\n');
    for _ in 0..level {
        out.push_str(unit);
    }
}

fn write_value(
    out: &mut String,
    v: &Value,
    unit: &str,
    level: usize,
    ascii: bool,
) -> Result<(), NonFinite> {
    match v {
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Object(m) if m.is_empty() => out.push_str("{}"),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, unit, level + 1);
                write_value(out, x, unit, level + 1, ascii)?;
            }
            newline(out, unit, level);
            out.push(']');
        }
        Value::Object(m) => write_object(out, m, unit, level, ascii)?,
        other => write_scalar(out, other, ascii)?,
    }
    Ok(())
}

fn write_object(
    out: &mut String,
    m: &Map<String, Value>,
    unit: &str,
    level: usize,
    ascii: bool,
) -> Result<(), NonFinite> {
    out.push('{');
    for (i, (k, x)) in m.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        newline(out, unit, level + 1);
        push_string(out, k, ascii);
        out.push_str(": ");
        write_value(out, x, unit, level + 1, ascii)?;
    }
    newline(out, unit, level);
    out.push('}');
    Ok(())
}

/// Remove `//` and `/* */` comments and trailing commas, never touching string
/// contents. (The oracle's trailing-comma regex also rewrote strings; see the vector
/// `json-jsonc-string-with-comma-brace`.)
pub fn strip_jsonc(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut nocomment = Vec::with_capacity(chars.len());
    let (mut i, mut in_str, mut esc) = (0usize, false, false);
    let at = |i: usize| chars.get(i).copied();
    while let Some(c) = at(i) {
        if in_str {
            nocomment.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
        } else if c == '"' {
            in_str = true;
            nocomment.push(c);
            i += 1;
        } else if c == '/' && at(i + 1) == Some('/') {
            while let Some(d) = at(i) {
                if d == '\n' {
                    break;
                }
                i += 1;
            }
        } else if c == '/' && at(i + 1) == Some('*') {
            i += 2;
            loop {
                match (at(i), at(i + 1)) {
                    (Some('*'), Some('/')) => {
                        i += 2;
                        break;
                    }
                    (None, _) => break,
                    _ => i += 1,
                }
            }
        } else {
            nocomment.push(c);
            i += 1;
        }
    }
    let mut out = String::with_capacity(nocomment.len());
    let (mut in_str, mut esc) = (false, false);
    for (k, c) in nocomment.iter().enumerate() {
        let c = *c;
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if c == '"' {
            in_str = true;
        } else if c == ',' {
            let next = nocomment
                .iter()
                .skip(k + 1)
                .find(|d| !is_py_space(**d))
                .copied();
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_matches_python_examples() {
        let cases = [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (1.5, "1.5"),
            (0.1, "0.1"),
            (1e5, "100000.0"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (123456789012345678.0, "1.2345678901234568e+17"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (2.5e-7, "2.5e-07"),
            (-1234.5, "-1234.5"),
        ];
        for (f, want) in cases {
            assert_eq!(py_float_repr(f), want, "{f}");
        }
    }

    #[test]
    fn indent_detection() {
        assert_eq!(detect_indent("{}"), Indent::Spaces(2));
        assert_eq!(detect_indent("{\n    \"a\": 1}"), Indent::Spaces(4));
        assert_eq!(detect_indent("{\n\t\"a\": 1}"), Indent::Tab);
        assert_eq!(detect_indent("{\n  \n   x"), Indent::Spaces(3));
        assert_eq!(detect_indent("{\n \u{3000}x\n  y"), Indent::Spaces(2));
    }

    #[test]
    fn jsonc_keeps_string_contents() {
        assert_eq!(
            strip_jsonc("{\"a\": \"x // y, }\", /* c */ \"b\": [1,2,],}"),
            "{\"a\": \"x // y, }\",  \"b\": [1,2]}"
        );
    }

    #[test]
    fn ascii_escaping() {
        assert_eq!(json_string_ascii("é\u{7f}😀"), "\"\\u00e9\\u007f\\ud83d\\ude00\"");
        assert_eq!(json_string("é\u{7f}\u{1}"), "\"é\u{7f}\\u0001\"");
    }
}
