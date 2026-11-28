//! A strict RFC 8259 JSON reader and a compact writer, for vectors and the adapter protocol.
//!
//! Why not serde_json (see `design/conformance-runner.md`): the comparison must be exact
//! and must not be foolable. This parser
//! - keeps every number's lexeme and compares numbers by exact decimal value
//!   (`1 == 1.0 == 1e0`, `2^53 + 1 != 2^53`, `0.1 != 0.10000000000000001`, `-0 == 0`);
//! - keeps strings as UTF-16 code units, so lone surrogates survive and strings compare
//!   by code points (an escaped and a raw character are the same string);
//! - refuses duplicate object keys at any depth, raw control characters in strings,
//!   a byte order mark, trailing data, nesting deeper than [`MAX_DEPTH`] and exponents
//!   with magnitude of [`MAX_EXPONENT`] or more;
//! - has no magic keys.
//!
//! Object members keep their order (so a request re-emits the vector's input in file
//! order); equality ignores it.

use std::fmt;

/// Deepest nesting of arrays and objects accepted (same bound as serde_json).
pub const MAX_DEPTH: usize = 128;
/// Exponents with this magnitude or more are refused rather than approximated.
pub const MAX_EXPONENT: i64 = 1_000_000_000_000_000;

#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Number(Number),
    String(JStr),
    Array(Vec<Json>),
    Object(Vec<(JStr, Json)>),
}

/// A JSON number: its original lexeme plus its exact normalised decimal value.
#[derive(Debug, Clone)]
pub struct Number {
    lexeme: String,
    // value = (-1)^negative * digits * 10^exponent, digits without leading or trailing
    // zeros; zero is (false, "", 0).
    negative: bool,
    digits: String,
    exponent: i64,
}

impl Number {
    pub fn lexeme(&self) -> &str {
        &self.lexeme
    }

    pub fn from_u64(n: u64) -> Number {
        // A u64's decimal form is always a valid lexeme.
        let lexeme = n.to_string();
        let trimmed = lexeme.trim_end_matches('0');
        let zeros = lexeme.len() - trimmed.len();
        if n == 0 {
            return Number {
                lexeme,
                negative: false,
                digits: String::new(),
                exponent: 0,
            };
        }
        Number {
            digits: trimmed.to_owned(),
            exponent: i64::try_from(zeros).unwrap_or(0),
            negative: false,
            lexeme,
        }
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        self.negative == other.negative
            && self.digits == other.digits
            && self.exponent == other.exponent
    }
}

/// A JSON string as UTF-16 code units (lone surrogates allowed).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JStr(Vec<u16>);

impl JStr {
    pub fn new(s: &str) -> JStr {
        JStr(s.encode_utf16().collect())
    }
    /// The string, if it contains no lone surrogate.
    pub fn to_string_strict(&self) -> Option<String> {
        String::from_utf16(&self.0).ok()
    }
    pub fn is(&self, s: &str) -> bool {
        self.0.iter().copied().eq(s.encode_utf16())
    }
    pub fn units(&self) -> &[u16] {
        &self.0
    }
}

impl PartialEq for Json {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Json::Null, Json::Null) => true,
            (Json::Bool(a), Json::Bool(b)) => a == b,
            (Json::Number(a), Json::Number(b)) => a == b,
            (Json::String(a), Json::String(b)) => a == b,
            (Json::Array(a), Json::Array(b)) => a == b,
            (Json::Object(a), Json::Object(b)) => {
                if a.len() != b.len() {
                    return false;
                }
                // Keys are unique (the parser refuses duplicates; constructors are ours),
                // so sorted member lists compare member by member.
                let mut a: Vec<&(JStr, Json)> = a.iter().collect();
                let mut b: Vec<&(JStr, Json)> = b.iter().collect();
                a.sort_by(|x, y| x.0.cmp(&y.0));
                b.sort_by(|x, y| x.0.cmp(&y.0));
                a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| x.0 == y.0 && x.1 == y.1)
            }
            _ => false,
        }
    }
}

impl Json {
    pub fn str(s: &str) -> Json {
        Json::String(JStr::new(s))
    }
    pub fn uint(n: u64) -> Json {
        Json::Number(Number::from_u64(n))
    }
    pub fn usize(n: usize) -> Json {
        Json::uint(u64::try_from(n).unwrap_or(u64::MAX))
    }
    /// An object from members; callers pass distinct keys.
    pub fn obj<'a>(members: impl IntoIterator<Item = (&'a str, Json)>) -> Json {
        Json::Object(
            members
                .into_iter()
                .map(|(k, v)| (JStr::new(k), v))
                .collect(),
        )
    }
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.iter().find(|(k, _)| k.is(key)).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&[(JStr, Json)]> {
        match self {
            Json::Object(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }
    /// The string value, if this is a string without lone surrogates.
    pub fn as_string(&self) -> Option<String> {
        match self {
            Json::String(s) => s.to_string_strict(),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    /// The keys of an object, in member order.
    pub fn keys(&self) -> Vec<String> {
        self.as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, _)| String::from_utf16_lossy(k.units()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Syntax,
    DuplicateKey,
    NumberRange,
    TooDeep,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub kind: ErrorKind,
    pub offset: usize,
    pub message: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for ParseError {}

/// Parse one complete JSON document (surrounding JSON whitespace allowed).
pub fn parse(text: &str) -> Result<Json, ParseError> {
    let mut p = Parser {
        s: text.as_bytes(),
        text,
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(p.err(ErrorKind::Syntax, "trailing data after the JSON value"));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
}

impl Parser<'_> {
    fn err(&self, kind: ErrorKind, message: &'static str) -> ParseError {
        ParseError {
            kind,
            offset: self.i,
            message,
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn literal(&mut self, word: &str, v: Json) -> Result<Json, ParseError> {
        if self.s.get(self.i..self.i + word.len()) == Some(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err(ErrorKind::Syntax, "invalid literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => Ok(Json::Number(self.number()?)),
            Some(_) => Err(self.err(ErrorKind::Syntax, "unexpected character")),
            None => Err(self.err(ErrorKind::Syntax, "unexpected end of input")),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err(ErrorKind::TooDeep, "nesting too deep"));
        }
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.eat(b']') {
            return Ok(Json::Array(out));
        }
        loop {
            self.ws();
            out.push(self.value(depth)?);
            self.ws();
            if self.eat(b']') {
                return Ok(Json::Array(out));
            }
            if !self.eat(b',') {
                return Err(self.err(ErrorKind::Syntax, "expected ',' or ']'"));
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err(ErrorKind::TooDeep, "nesting too deep"));
        }
        self.i += 1;
        let mut out: Vec<(JStr, Json)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        self.ws();
        if self.eat(b'}') {
            return Ok(Json::Object(out));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err(ErrorKind::Syntax, "expected a string key"));
            }
            let at = self.i;
            let key = self.string()?;
            if !seen.insert(key.clone()) {
                return Err(ParseError {
                    kind: ErrorKind::DuplicateKey,
                    offset: at,
                    message: "duplicate object key",
                });
            }
            self.ws();
            if !self.eat(b':') {
                return Err(self.err(ErrorKind::Syntax, "expected ':'"));
            }
            self.ws();
            let v = self.value(depth)?;
            out.push((key, v));
            self.ws();
            if self.eat(b'}') {
                return Ok(Json::Object(out));
            }
            if !self.eat(b',') {
                return Err(self.err(ErrorKind::Syntax, "expected ',' or '}'"));
            }
        }
    }

    fn string(&mut self) -> Result<JStr, ParseError> {
        self.i += 1; // opening quote
        let mut units: Vec<u16> = Vec::new();
        loop {
            let start = self.i;
            while matches!(self.peek(), Some(b) if b != b'"' && b != b'\\' && b >= 0x20) {
                self.i += 1;
            }
            // The run ends on an ASCII byte or at the end, so it is a char boundary.
            let chunk = self
                .text
                .get(start..self.i)
                .ok_or_else(|| self.err(ErrorKind::Syntax, "invalid UTF-8 boundary"))?;
            units.extend(chunk.encode_utf16());
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(JStr(units));
                }
                Some(b'\\') => {
                    self.i += 1;
                    let c = self
                        .peek()
                        .ok_or_else(|| self.err(ErrorKind::Syntax, "unterminated escape"))?;
                    self.i += 1;
                    let u = match c {
                        b'"' => 0x22,
                        b'\\' => 0x5c,
                        b'/' => 0x2f,
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => 0x0a,
                        b'r' => 0x0d,
                        b't' => 0x09,
                        b'u' => self.hex4()?,
                        _ => return Err(self.err(ErrorKind::Syntax, "invalid escape")),
                    };
                    units.push(u);
                }
                Some(_) => {
                    return Err(self.err(ErrorKind::Syntax, "raw control character in string"));
                }
                None => return Err(self.err(ErrorKind::Syntax, "unterminated string")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, ParseError> {
        let mut v: u16 = 0;
        for _ in 0..4 {
            let d = match self.peek() {
                Some(c @ b'0'..=b'9') => c - b'0',
                Some(c @ b'a'..=b'f') => c - b'a' + 10,
                Some(c @ b'A'..=b'F') => c - b'A' + 10,
                _ => return Err(self.err(ErrorKind::Syntax, "invalid \\u escape")),
            };
            self.i += 1;
            v = (v << 4) | u16::from(d);
        }
        Ok(v)
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<Number, ParseError> {
        let start = self.i;
        let negative = self.eat(b'-');
        let int_start = self.i;
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.err(ErrorKind::Syntax, "invalid number")),
        }
        let int_end = self.i;
        let (mut frac_start, mut frac_end) = (self.i, self.i);
        if self.eat(b'.') {
            frac_start = self.i;
            if self.digits() == 0 {
                return Err(self.err(ErrorKind::Syntax, "digit expected after '.'"));
            }
            frac_end = self.i;
        }
        let mut exp: i64 = 0;
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            let neg_exp = if self.eat(b'-') {
                true
            } else {
                self.eat(b'+');
                false
            };
            let ds = self.i;
            if self.digits() == 0 {
                return Err(self.err(ErrorKind::Syntax, "digit expected in exponent"));
            }
            let text = self
                .text
                .get(ds..self.i)
                .unwrap_or("")
                .trim_start_matches('0');
            if text.len() > 15 {
                return Err(self.err(ErrorKind::NumberRange, "exponent out of supported range"));
            }
            exp = text.parse::<i64>().unwrap_or(0);
            if exp >= MAX_EXPONENT {
                return Err(self.err(ErrorKind::NumberRange, "exponent out of supported range"));
            }
            if neg_exp {
                exp = -exp;
            }
        }
        let lexeme = self.text.get(start..self.i).unwrap_or("").to_owned();
        let int = self.text.get(int_start..int_end).unwrap_or("");
        let frac = self.text.get(frac_start..frac_end).unwrap_or("");
        let all = format!("{int}{frac}");
        let lead = all.trim_start_matches('0');
        let sig = lead.trim_end_matches('0');
        if sig.is_empty() {
            return Ok(Number {
                lexeme,
                negative: false,
                digits: String::new(),
                exponent: 0,
            });
        }
        let frac_len = i64::try_from(frac.len())
            .map_err(|_| self.err(ErrorKind::NumberRange, "number too long"))?;
        let trailing = i64::try_from(lead.len() - sig.len())
            .map_err(|_| self.err(ErrorKind::NumberRange, "number too long"))?;
        Ok(Number {
            lexeme,
            negative,
            digits: sig.to_owned(),
            exponent: exp - frac_len + trailing,
        })
    }
}

/// Compact JSON text on one line: numbers keep their lexeme, members keep their order,
/// control characters, U+007F, U+2028, U+2029 and lone surrogates are `\u` escaped.
pub fn write(j: &Json) -> String {
    let mut out = String::new();
    write_into(&mut out, j);
    out
}

fn write_into(out: &mut String, j: &Json) {
    match j {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(n) => out.push_str(&n.lexeme),
        Json::String(s) => write_str(out, s),
        Json::Array(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_into(out, v);
            }
            out.push(']');
        }
        Json::Object(m) => {
            out.push('{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write_into(out, v);
            }
            out.push('}');
        }
    }
}

fn write_str(out: &mut String, s: &JStr) {
    out.push('"');
    for r in char::decode_utf16(s.0.iter().copied()) {
        match r {
            Ok('"') => out.push_str("\\\""),
            Ok('\\') => out.push_str("\\\\"),
            Ok('\n') => out.push_str("\\n"),
            Ok('\r') => out.push_str("\\r"),
            Ok('\t') => out.push_str("\\t"),
            Ok(c) if (c as u32) < 0x20 || c == '\u{7f}' || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            Ok(c) => out.push(c),
            Err(e) => out.push_str(&format!("\\u{:04x}", e.unpaired_surrogate())),
        }
    }
    out.push('"');
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
