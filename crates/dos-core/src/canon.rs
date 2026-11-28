//! RFC 8785 JSON Canonicalization Scheme over strict I-JSON (RFC 7493) input.
//!
//! Spec: `spec/canon.md`. Design: `design/canon.md`. Vectors: `conformance/vectors/jcs/`.
//!
//! The parser refuses every input that two honest parsers could read differently:
//! duplicate names, lone surrogates, noncharacters, non-finite numbers, integer literals
//! that would be rounded, a byte order mark, invalid UTF-8, trailing data. Nesting is
//! bounded by [`MAX_DEPTH`] before any recursion, so no input can exhaust the stack.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt::{self, Write as _};

/// Deepest allowed nesting of arrays and objects. 128 levels are accepted, 129 refused.
pub const MAX_DEPTH: usize = 128;

/// Why an input or value has no canonical form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonError {
    /// The input starts with a UTF-8 byte order mark.
    LeadingBom,
    /// The input is not valid UTF-8.
    InvalidUtf8,
    /// The input is not JSON.
    Syntax,
    /// Something other than whitespace follows the top-level value.
    TrailingData,
    /// A backslash escape that JSON does not define.
    InvalidEscape,
    /// A UTF-16 surrogate escape without its pair.
    LoneSurrogate,
    /// A Unicode noncharacter (RFC 7493 section 2.1).
    Noncharacter,
    /// An object has the same member name twice.
    DuplicateKey,
    /// More than `MAX_DEPTH` nested arrays and objects.
    DepthExceeded,
    /// NaN, an infinity, or a number that overflows a double.
    NonFiniteNumber,
    /// An integer literal beyond 2^53-1 that would not survive canonicalization as text.
    UnsafeInteger,
}

impl CanonError {
    /// Stable code, used in conformance vectors.
    pub fn code(self) -> &'static str {
        match self {
            CanonError::LeadingBom => "leading_bom",
            CanonError::InvalidUtf8 => "invalid_utf8",
            CanonError::Syntax => "syntax",
            CanonError::TrailingData => "trailing_data",
            CanonError::InvalidEscape => "invalid_escape",
            CanonError::LoneSurrogate => "lone_surrogate",
            CanonError::Noncharacter => "noncharacter",
            CanonError::DuplicateKey => "duplicate_key",
            CanonError::DepthExceeded => "depth_exceeded",
            CanonError::NonFiniteNumber => "non_finite_number",
            CanonError::UnsafeInteger => "unsafe_integer",
        }
    }
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl core::error::Error for CanonError {}

/// A finite IEEE 754 double.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Number(f64);

impl Number {
    /// Refuses NaN and the infinities.
    pub fn new(value: f64) -> Result<Number, CanonError> {
        if value.is_finite() {
            Ok(Number(value))
        } else {
            Err(CanonError::NonFiniteNumber)
        }
    }

    /// The double.
    pub fn get(self) -> f64 {
        self.0
    }
}

/// A JSON value. Objects keep member order as parsed; `to_jcs` sorts.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

/// Parses I-JSON strictly. Error precedence: `leading_bom`, then `invalid_utf8` for the
/// whole input, then the first error of a left-to-right scan (`duplicate_key` is found
/// when its object closes).
pub fn parse_strict(bytes: &[u8]) -> Result<Value, CanonError> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(CanonError::LeadingBom);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| CanonError::InvalidUtf8)?;
    let mut p = Parser {
        text,
        bytes,
        pos: 0,
    };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.pos != bytes.len() {
        return Err(CanonError::TrailingData);
    }
    Ok(value)
}

/// RFC 8785 serialization. Refuses duplicate names, noncharacters and nesting deeper than
/// `MAX_DEPTH`, which a programmatically built value may contain.
pub fn to_jcs(value: &Value) -> Result<Vec<u8>, CanonError> {
    let mut out = String::new();
    write_value(value, 0, &mut out)?;
    Ok(out.into_bytes())
}

/// `parse_strict` then `to_jcs`.
pub fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, CanonError> {
    to_jcs(&parse_strict(bytes)?)
}

// ---- parser ----

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, literal: &[u8]) -> bool {
        let found = self
            .bytes
            .get(self.pos..)
            .is_some_and(|rest| rest.starts_with(literal));
        if found {
            self.pos += literal.len();
        }
        found
    }

    fn expect(&mut self, literal: &[u8], value: Value) -> Result<Value, CanonError> {
        if self.eat(literal) {
            Ok(value)
        } else {
            Err(CanonError::Syntax)
        }
    }

    /// `depth` is the number of containers enclosing this value.
    fn value(&mut self, depth: usize) -> Result<Value, CanonError> {
        match self.peek() {
            Some(b'{' | b'[') if depth >= MAX_DEPTH => Err(CanonError::DepthExceeded),
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.expect(b"true", Value::Bool(true)),
            Some(b'f') => self.expect(b"false", Value::Bool(false)),
            Some(b'n') => self.expect(b"null", Value::Null),
            Some(b'N') | Some(b'I') | Some(b'-')
                if self.eat(b"NaN") || self.eat(b"Infinity") || self.eat(b"-Infinity") =>
            {
                Err(CanonError::NonFiniteNumber)
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(CanonError::Syntax),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, CanonError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Value::Array(items)),
                _ => return Err(CanonError::Syntax),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, CanonError> {
        self.pos += 1; // '{'
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(CanonError::Syntax);
            }
            let key = self.string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(CanonError::Syntax);
            }
            self.skip_ws();
            let value = self.value(depth)?;
            members.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => break,
                _ => return Err(CanonError::Syntax),
            }
        }
        let mut names: Vec<&str> = members.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        if names.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
            return Err(CanonError::DuplicateKey);
        }
        Ok(Value::Object(members))
    }

    fn string(&mut self) -> Result<String, CanonError> {
        self.pos += 1; // '"'
        let mut out = String::new();
        loop {
            let start = self.pos;
            while matches!(self.peek(), Some(b) if b >= 0x20 && b != b'"' && b != b'\\') {
                self.pos += 1;
            }
            // The run ends at an ASCII byte or the end, so both ends are char boundaries.
            let run = self.text.get(start..self.pos).ok_or(CanonError::Syntax)?;
            if run.chars().any(is_noncharacter) {
                return Err(CanonError::Noncharacter);
            }
            out.push_str(run);
            match self.bump() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => out.push(self.escape()?),
                // An unescaped control character, or the input ended inside the string.
                _ => return Err(CanonError::Syntax),
            }
        }
    }

    fn escape(&mut self) -> Result<char, CanonError> {
        match self.bump() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\u{8}'),
            Some(b'f') => Ok('\u{c}'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => self.unicode_escape(),
            _ => Err(CanonError::InvalidEscape),
        }
    }

    fn unicode_escape(&mut self) -> Result<char, CanonError> {
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                if !self.eat(b"\\u") {
                    return Err(CanonError::LoneSurrogate);
                }
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(CanonError::LoneSurrogate);
                }
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(CanonError::LoneSurrogate),
            _ => first,
        };
        let c = char::from_u32(code).ok_or(CanonError::LoneSurrogate)?;
        if is_noncharacter(c) {
            return Err(CanonError::Noncharacter);
        }
        Ok(c)
    }

    fn hex4(&mut self) -> Result<u32, CanonError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = self
                .bump()
                .and_then(|b| char::from(b).to_digit(16))
                .ok_or(CanonError::InvalidEscape)?;
            v = (v << 4) | d;
        }
        Ok(v)
    }

    fn number(&mut self) -> Result<Value, CanonError> {
        let start = self.pos;
        // Take the whole run of number-like bytes, so "01", "1x" and "0x10" are one bad
        // token (syntax) rather than a number followed by trailing data.
        while matches!(self.peek(), Some(b) if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'))
        {
            self.pos += 1;
        }
        let token = self.bytes.get(start..self.pos).ok_or(CanonError::Syntax)?;
        let is_integer = number_token(token).ok_or(CanonError::Syntax)?;
        let text = self.text.get(start..self.pos).ok_or(CanonError::Syntax)?;
        // core's parser rounds correctly to nearest, ties to even; a JSON number token is
        // a subset of what it accepts.
        let f: f64 = text.parse().map_err(|_| CanonError::Syntax)?;
        let n = Number::new(f)?;
        if is_integer && text != "-0" {
            // Inside +-(2^53-1) every integer literal is its own JCS text; outside, only
            // a literal that is exactly the JCS text of its double is accepted.
            let mut canonical = String::new();
            write_number(f, &mut canonical)?;
            if canonical != text {
                return Err(CanonError::UnsafeInteger);
            }
        }
        Ok(Value::Number(n))
    }
}

/// `Some(is_integer_literal)` when `t` is exactly a number token of RFC 8259 section 6.
fn number_token(t: &[u8]) -> Option<bool> {
    let at = |i: usize| t.get(i).copied();
    let digits_from = |mut i: usize| {
        while matches!(at(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        i
    };
    let mut i = 0;
    if at(i) == Some(b'-') {
        i += 1;
    }
    match at(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => i = digits_from(i + 1),
        _ => return None,
    }
    let mut integer = true;
    if at(i) == Some(b'.') {
        integer = false;
        let end = digits_from(i + 1);
        if end == i + 1 {
            return None;
        }
        i = end;
    }
    if matches!(at(i), Some(b'e' | b'E')) {
        integer = false;
        i += 1;
        if matches!(at(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let end = digits_from(i);
        if end == i {
            return None;
        }
        i = end;
    }
    (i == t.len()).then_some(integer)
}

/// U+FDD0..U+FDEF and the last two code points of every plane.
fn is_noncharacter(c: char) -> bool {
    let u = u32::from(c);
    (0xFDD0..=0xFDEF).contains(&u) || (u & 0xFFFE) == 0xFFFE
}

// ---- serializer ----

fn write_value(value: &Value, depth: usize, out: &mut String) -> Result<(), CanonError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n.0, out)?,
        Value::String(s) => write_string(s, out)?,
        Value::Array(items) => {
            if depth >= MAX_DEPTH {
                return Err(CanonError::DepthExceeded);
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, depth + 1, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            if depth >= MAX_DEPTH {
                return Err(CanonError::DepthExceeded);
            }
            let mut sorted: Vec<&(String, Value)> = members.iter().collect();
            sorted.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            if sorted.windows(2).any(|w| matches!(w, [a, b] if a.0 == b.0)) {
                return Err(CanonError::DuplicateKey);
            }
            out.push('{');
            for (i, (key, item)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out)?;
                out.push(':');
                write_value(item, depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 section 3.2.3: compare as arrays of UTF-16 code units.
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// RFC 8785 section 3.2.2.2.
fn write_string(s: &str, out: &mut String) -> Result<(), CanonError> {
    out.push('"');
    for c in s.chars() {
        if is_noncharacter(c) {
            return Err(CanonError::Noncharacter);
        }
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let u = u32::from(c);
                out.push_str("\\u00");
                out.push(char::from_digit(u >> 4, 16).unwrap_or('0'));
                out.push(char::from_digit(u & 0xF, 16).unwrap_or('0'));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(())
}

/// Shortest round-trip digits of a finite double `f > 0` with ECMAScript's choice among
/// them: `(s, x)` with `f` represented by `s * 10^x`, `s` without trailing zeros.
///
/// core's `{:e}` without a precision prints the shortest digit string that round-trips,
/// closest to the exact value, but it breaks an exact tie upwards. ECMA-262 7.1.12.1
/// Note 2 (required by RFC 8785 section 3.2.2.3) takes the even candidate instead, e.g.
/// 1424953923781206.25 prints as 1424953923781206.2 (RFC 8785 Appendix B, note 4).
fn shortest(f: f64) -> Result<(u64, i32), CanonError> {
    let bad = CanonError::NonFiniteNumber; // only reachable if core's format changed
    let mut sci = String::new();
    write!(sci, "{f:e}").map_err(|_| bad)?;
    let (mantissa, exponent) = sci.split_once('e').ok_or(bad)?;
    let exponent: i32 = exponent.parse().map_err(|_| bad)?;
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    if digits.is_empty() || digits.len() > 17 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad);
    }
    let s: u64 = digits.parse().map_err(|_| bad)?;
    let k = i32::try_from(digits.len()).map_err(|_| bad)?;
    let x = exponent - (k - 1);

    // f = m * 2^q exactly.
    let bits = f.to_bits();
    let biased = i32::try_from((bits >> 52) & 0x7FF).map_err(|_| bad)?;
    let fraction = bits & ((1u64 << 52) - 1);
    let (m, q) = if biased == 0 {
        (fraction, -1074)
    } else {
        (fraction | (1u64 << 52), biased - 1075)
    };

    // A tie means f lies exactly halfway between s and a neighbour: f = (2s -+ 1) * 5 * 10^(x-1).
    let below = (s.checked_mul(2), s.checked_sub(1));
    let above = (s.checked_mul(2), s.checked_add(1));
    for (twice, neighbour, is_below) in [(below.0, below.1, true), (above.0, above.1, false)] {
        let (Some(twice), Some(neighbour)) = (twice, neighbour) else {
            continue;
        };
        let mid = if is_below {
            twice.checked_sub(1)
        } else {
            twice.checked_add(1)
        };
        let Some(mid5) = mid.and_then(|v| v.checked_mul(5)) else {
            continue;
        };
        if exact_eq(m, q, mid5, x - 1) {
            if s % 2 == 1 && neighbour != 0 && parses_to(neighbour, x, f) {
                return Ok(strip_zeros(neighbour, x));
            }
            break;
        }
    }
    Ok((s, x))
}

/// `m * 2^q == n * 10^p`, exactly, by comparing factorizations (no overflow possible).
fn exact_eq(m: u64, q: i32, n: u64, p: i32) -> bool {
    fn split(mut v: u64) -> (i64, i64, u64) {
        let (mut twos, mut fives) = (0i64, 0i64);
        while v != 0 && v.is_multiple_of(2) {
            v /= 2;
            twos += 1;
        }
        while v != 0 && v.is_multiple_of(5) {
            v /= 5;
            fives += 1;
        }
        (twos, fives, v)
    }
    if m == 0 || n == 0 {
        return m == n;
    }
    let (a1, b1, t1) = split(m);
    let (a2, b2, t2) = split(n);
    let (q, p) = (i64::from(q), i64::from(p));
    t1 == t2 && a1 + q == a2 + p && b1 == b2 + p
}

fn parses_to(s: u64, x: i32, f: f64) -> bool {
    let mut text = String::new();
    write!(text, "{s}e{x}").is_ok() && text.parse::<f64>().is_ok_and(|g| g == f)
}

fn strip_zeros(mut s: u64, mut x: i32) -> (u64, i32) {
    while s != 0 && s.is_multiple_of(10) {
        s /= 10;
        x += 1;
    }
    (s, x)
}

/// ECMAScript Number::toString (ECMA-262 7.1.12.1 with Note 2), RFC 8785 section 3.2.2.3.
fn write_number(f: f64, out: &mut String) -> Result<(), CanonError> {
    if !f.is_finite() {
        return Err(CanonError::NonFiniteNumber);
    }
    if f == 0.0 {
        out.push('0');
        return Ok(());
    }
    if f < 0.0 {
        out.push('-');
    }
    let (s, x) = shortest(f.abs())?;
    let mut digits = String::new();
    write!(digits, "{s}").map_err(|_| CanonError::NonFiniteNumber)?;
    let k = i32::try_from(digits.len()).map_err(|_| CanonError::NonFiniteNumber)?;
    // ECMAScript's n: the value is 0.d1d2...dk * 10^n.
    let exponent = x + k - 1;
    let n = exponent + 1;
    let zeros = |out: &mut String, count: i32| {
        for _ in 0..count {
            out.push('0');
        }
    };
    if k <= n && n <= 21 {
        out.push_str(&digits);
        zeros(out, n - k);
    } else if 0 < n && n <= 21 {
        let split = usize::try_from(n).map_err(|_| CanonError::NonFiniteNumber)?;
        let (int_part, frac_part) = digits
            .split_at_checked(split)
            .ok_or(CanonError::NonFiniteNumber)?;
        out.push_str(int_part);
        out.push('.');
        out.push_str(frac_part);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        zeros(out, -n);
        out.push_str(&digits);
    } else {
        let (first, rest) = digits
            .split_at_checked(1)
            .ok_or(CanonError::NonFiniteNumber)?;
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        out.push(if n > 0 { '+' } else { '-' });
        write!(out, "{}", (n - 1).unsigned_abs()).map_err(|_| CanonError::NonFiniteNumber)?;
    }
    Ok(())
}
