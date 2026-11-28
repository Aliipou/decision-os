//! Time-boxed differential fuzzer for `dos_conformance::json`.
//!
//! Properties checked on every input:
//! 1. `parse` never panics (caught with catch_unwind; a panic is saved as an artifact);
//! 2. if it parses: `parse(write(v)) == v` and `write` is idempotent;
//! 3. acceptance agrees with serde_json except for the documented differences
//!    (duplicate keys, exponent magnitude >= 10^15, lone surrogates, f64 overflow, depth);
//! 4. values agree with serde_json (strings, structure, integers exactly);
//! 5. number equality agrees with an independent oracle (fixed-point expansion) on
//!    generated pairs of spellings;
//! 6. string equality agrees with code-point equality on generated pairs of escapings.
//!
//! Usage: json_diff <seconds> <corpus-dir> [seed-files...]
//! Inputs found interesting are written to <corpus-dir>; failures to <corpus-dir>/../artifacts.

use dos_conformance::json::{self, ErrorKind, Json};
use std::collections::HashSet;
use std::fs;
use std::panic;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

const TOKENS: &[&str] = &[
    "{", "}", "[", "]", ",", ":", "\"", "\\", "\\u", "\\ud800", "\\udc00", "\\ud83d\\ude00", "\\u0000",
    "0", "-", "-0", "1", "9", ".", "e", "E", "+", "e999999999999999", "e1000000000000000", "e-999999999999999",
    "00", "true", "false", "null", " ", "\n", "\r", "\t", "\u{feff}", "\u{2028}", "\u{e9}", "e\u{301}",
    "\u{1F600}", "\u{7f}", "\"a\":", "\"a\":1,\"a\":2", "1e", "1.", ".5", "NaN", "Infinity", "\u{10FFFF}",
    "123456789012345678901234567890", "0.10000000000000001", "18446744073709551617", "\\/", "\\b", "\\x",
];

fn gen_value(r: &mut Rng, depth: usize) -> String {
    match r.below(if depth > 6 { 5 } else { 8 }) {
        0 => "null".into(),
        1 => if r.chance(50) { "true".into() } else { "false".into() },
        2 | 3 => gen_number(r),
        4 => gen_string(r, &gen_codepoints(r)),
        5 => {
            let n = r.below(4);
            let items: Vec<String> = (0..n).map(|_| gen_value(r, depth + 1)).collect();
            format!("[{}]", items.join(","))
        }
        _ => {
            let n = r.below(4);
            let mut keys = HashSet::new();
            let mut items = Vec::new();
            for _ in 0..n {
                let k = gen_codepoints(r);
                if keys.insert(k.clone()) {
                    items.push(format!("{}:{}", gen_string(r, &k), gen_value(r, depth + 1)));
                }
            }
            if r.chance(5) && !items.is_empty() {
                let dup = items[0].clone();
                items.push(dup); // duplicate key on purpose
            }
            format!("{{{}}}", items.join(","))
        }
    }
}

/// Sequences of UTF-16 code units, including lone surrogates.
fn gen_codepoints(r: &mut Rng) -> Vec<u16> {
    let n = r.below(6);
    let mut out = Vec::new();
    for _ in 0..n {
        match r.below(8) {
            0 => out.push(0xD800 + r.below(0x400) as u16),
            1 => out.push(0xDC00 + r.below(0x400) as u16),
            2 => out.extend("\u{1F600}".encode_utf16()),
            3 => out.push(r.below(0x20) as u16),
            4 => out.extend(['\u{e9}', 'e', '\u{301}', '\u{2028}', '\u{7f}', '"', '\\', '/'][r.below(8)].to_string().encode_utf16()),
            _ => out.push(0x20 + r.below(0x5f) as u16),
        }
    }
    out
}

/// Render code units as a JSON string with random escaping choices.
fn gen_string(r: &mut Rng, units: &[u16]) -> String {
    let mut s = String::from("\"");
    let decoded: Vec<Result<char, u16>> = char::decode_utf16(units.iter().copied())
        .map(|x| x.map_err(|e| e.unpaired_surrogate()))
        .collect();
    for d in decoded {
        match d {
            Err(u) => s.push_str(&format!("\\u{u:04x}")),
            Ok(c) => {
                let cu = c as u32;
                let must = cu < 0x20 || c == '"' || c == '\\';
                if must || r.chance(30) {
                    match (c, r.below(3)) {
                        ('"', 0) => s.push_str("\\\""),
                        ('\\', 0) => s.push_str("\\\\"),
                        ('\n', 0) => s.push_str("\\n"),
                        ('/', 0) => s.push_str("\\/"),
                        _ => {
                            let mut b = [0u16; 2];
                            for u in c.encode_utf16(&mut b) {
                                if r.chance(50) {
                                    s.push_str(&format!("\\u{:04X}", u));
                                } else {
                                    s.push_str(&format!("\\u{:04x}", u));
                                }
                            }
                        }
                    }
                } else {
                    s.push(c);
                }
            }
        }
    }
    s.push('"');
    s
}

/// A random number lexeme with a small exponent (so the oracle can expand it).
fn gen_number_parts(r: &mut Rng) -> (bool, String, String, i64) {
    let neg = r.chance(30);
    let int = if r.chance(30) {
        "0".to_string()
    } else {
        let mut d = ((b'1' + r.below(9) as u8) as char).to_string();
        for _ in 0..r.below(20) {
            d.push((b'0' + r.below(10) as u8) as char);
        }
        d
    };
    let mut frac = String::new();
    if r.chance(50) {
        for _ in 0..1 + r.below(20) {
            frac.push((b'0' + r.below(10) as u8) as char);
        }
    }
    let exp = if r.chance(50) { r.below(81) as i64 - 40 } else { 0 };
    (neg, int, frac, exp)
}

fn render_number(r: &mut Rng, neg: bool, int: &str, frac: &str, exp: i64) -> String {
    let mut s = String::new();
    if neg {
        s.push('-');
    }
    s.push_str(int);
    if !frac.is_empty() {
        s.push('.');
        s.push_str(frac);
    }
    if exp != 0 || r.chance(10) {
        s.push(if r.chance(50) { 'e' } else { 'E' });
        if exp < 0 {
            s.push('-');
        } else if r.chance(30) {
            s.push('+');
        }
        if r.chance(20) {
            s.push_str("000");
        }
        s.push_str(&exp.abs().to_string());
    }
    s
}

fn gen_number(r: &mut Rng) -> String {
    if r.chance(10) {
        return ["1e999999999999999", "1e1000000000000000", "-0", "0e5", "1E-999999999999999", "18446744073709551616"][r.below(6)].into();
    }
    let (n, i, f, e) = gen_number_parts(r);
    render_number(r, n, &i, &f, e)
}

/// Independent oracle: the exact value as a canonical fixed-point string.
fn fixed_point(neg: bool, int: &str, frac: &str, exp: i64) -> String {
    let digits = format!("{int}{frac}");
    let point = int.len() as i64 + exp; // position of the decimal point in `digits`
    let mut d: Vec<u8> = digits.into_bytes();
    let mut point = point;
    while point < 0 {
        d.insert(0, b'0');
        point += 1;
    }
    while (d.len() as i64) < point {
        d.push(b'0');
    }
    let (ip, fp) = d.split_at(point as usize);
    let ip = String::from_utf8_lossy(ip).trim_start_matches('0').to_string();
    let fp = String::from_utf8_lossy(fp).trim_end_matches('0').to_string();
    if ip.is_empty() && fp.is_empty() {
        return "0".into();
    }
    format!("{}{}.{}", if neg { "-" } else { "" }, if ip.is_empty() { "0" } else { &ip }, fp)
}

/// Same value, different spelling: move the decimal point and compensate.
fn respell(r: &mut Rng, neg: bool, int: &str, frac: &str, exp: i64) -> (bool, String, String, i64) {
    let mut all = format!("{int}{frac}");
    let mut point = int.len() as i64;
    let mut e = exp;
    // add leading/trailing zeros
    for _ in 0..r.below(3) {
        all.insert(0, '0');
        point += 1;
    }
    for _ in 0..r.below(3) {
        all.push('0');
    }
    let shift = r.below(7) as i64 - 3;
    let new_point = (point + shift).clamp(1, all.len() as i64);
    e += point - new_point;
    let (i, f) = all.split_at(new_point as usize);
    let mut i = i.trim_start_matches('0').to_string();
    if i.is_empty() {
        i = "0".into();
    }
    (neg, i, f.to_string(), e)
}

fn same_as_serde(a: &Json, b: &serde_json::Value) -> Result<(), String> {
    use serde_json::Value as V;
    let ok = match (a, b) {
        (Json::Null, V::Null) => true,
        (Json::Bool(x), V::Bool(y)) => x == y,
        (Json::String(_), V::String(s)) => a.as_string().as_deref() == Some(s.as_str()),
        (Json::Array(x), V::Array(y)) => {
            if x.len() != y.len() {
                false
            } else {
                for (p, q) in x.iter().zip(y) {
                    same_as_serde(p, q)?;
                }
                true
            }
        }
        (Json::Object(m), V::Object(n)) => {
            if m.len() != n.len() {
                false
            } else {
                for (k, v) in m {
                    let k = k.to_string_strict().ok_or("lone surrogate key accepted by serde?")?;
                    let w = n.get(&k).ok_or(format!("key {k:?} missing in serde"))?;
                    same_as_serde(v, w)?;
                }
                true
            }
        }
        (Json::Number(x), V::Number(y)) => {
            if y.is_u64() || y.is_i64() {
                json::parse(&y.to_string()).is_ok_and(|n| n == Json::Number(x.clone()))
            } else {
                // f64: our exact value must round to serde's f64.
                match (x.lexeme().parse::<f64>(), y.as_f64()) {
                    (Ok(p), Some(q)) => p == q || (p - q).abs() <= q.abs() * 4.0 * f64::EPSILON,
                    _ => false,
                }
            }
        }
        _ => false,
    };
    if ok { Ok(()) } else { Err(format!("ours {} vs serde {b}", json::write(a))) }
}

enum Verdict {
    Fine,
    Interesting,
    Bug(String),
}

fn check(s: &str) -> Verdict {
    let ours = match panic::catch_unwind(|| json::parse(s)) {
        Ok(r) => r,
        Err(_) => return Verdict::Bug("panic in parse".into()),
    };
    let theirs = serde_json::from_str::<serde_json::Value>(s);
    let mut interesting = false;
    match (&ours, &theirs) {
        (Ok(v), Ok(w)) => {
            if let Err(e) = same_as_serde(v, w) {
                return Verdict::Bug(format!("value mismatch: {e}"));
            }
        }
        (Ok(_), Err(e)) => {
            let m = e.to_string();
            if !(m.contains("surrogate") || m.contains("out of range") || m.contains("recursion")) {
                return Verdict::Bug(format!("we accept, serde refuses: {m}"));
            }
            interesting = true;
        }
        (Err(e), Ok(_)) => {
            if !matches!(e.kind, ErrorKind::DuplicateKey | ErrorKind::NumberRange | ErrorKind::TooDeep) {
                return Verdict::Bug(format!("we refuse ({e}), serde accepts"));
            }
            interesting = true;
        }
        (Err(_), Err(_)) => {}
    }
    if let Ok(v) = &ours {
        let w = json::write(v);
        if w.contains('\n') || w.contains('\r') {
            return Verdict::Bug(format!("writer emitted a line break: {w:?}"));
        }
        match json::parse(&w) {
            Ok(v2) if v2 == *v => {
                if json::write(&v2) != w {
                    return Verdict::Bug("writer not idempotent".into());
                }
            }
            Ok(_) => return Verdict::Bug(format!("round trip changed the value: {w}")),
            Err(e) => return Verdict::Bug(format!("writer output does not parse ({e}): {w}")),
        }
        if !(v == v) {
            return Verdict::Bug("not reflexive".into());
        }
    }
    if interesting { Verdict::Interesting } else { Verdict::Fine }
}

fn mutate(r: &mut Rng, s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    for _ in 0..1 + r.below(4) {
        let pos = r.below(chars.len() + 1);
        match r.below(4) {
            0 if !chars.is_empty() && pos < chars.len() => {
                chars.remove(pos);
            }
            1 => {
                let t: Vec<char> = TOKENS[r.below(TOKENS.len())].chars().collect();
                for (k, c) in t.into_iter().enumerate() {
                    chars.insert(pos + k, c);
                }
            }
            2 if pos < chars.len() => {
                chars[pos] = TOKENS[r.below(TOKENS.len())].chars().next().unwrap_or(' ');
            }
            _ => {
                let v: Vec<char> = gen_value(r, 3).chars().collect();
                for (k, c) in v.into_iter().enumerate() {
                    chars.insert(pos + k, c);
                }
            }
        }
    }
    chars.into_iter().collect()
}

fn hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn save(dir: &Path, s: &str) {
    let _ = fs::create_dir_all(dir);
    let _ = fs::write(dir.join(format!("{:016x}", hash(s))), s);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(60);
    let corpus = PathBuf::from(args.get(2).cloned().unwrap_or_else(|| "fuzz/corpus/json".into()));
    let artifacts = corpus.parent().map(|p| p.join("artifacts")).unwrap_or_else(|| "artifacts".into());
    panic::set_hook(Box::new(|_| {}));

    let mut seeds: Vec<String> = Vec::new();
    if let Ok(rd) = fs::read_dir(&corpus) {
        for e in rd.flatten() {
            if let Ok(t) = fs::read_to_string(e.path()) {
                seeds.push(t);
            }
        }
    }
    for f in args.iter().skip(3) {
        if let Ok(t) = fs::read_to_string(f) {
            seeds.push(t);
        }
    }
    seeds.push("{\"a\":[1,2.5e3,\"x\\ud800\",{\"b\":null}]}".into());
    let start_seeds = seeds.len();

    let mut r = Rng(0x9E3779B97F4A7C15 ^ u64::from(std::process::id()));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut docs, mut nums, mut strs, mut bugs, mut interesting) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut saved = 0usize;
    while Instant::now() < deadline {
        for _ in 0..200 {
            // (a) documents
            let s = match r.below(3) {
                0 => gen_value(&mut r, 0),
                _ => {
                    let base = seeds[r.below(seeds.len())].clone();
                    mutate(&mut r, &base)
                }
            };
            docs += 1;
            match check(&s) {
                Verdict::Bug(why) => {
                    bugs += 1;
                    eprintln!("BUG: {why}\n  input: {s:?}");
                    save(&artifacts, &s);
                }
                Verdict::Interesting => {
                    interesting += 1;
                    if saved < 2000 && r.chance(5) {
                        save(&corpus, &s);
                        seeds.push(s);
                        saved += 1;
                    }
                }
                Verdict::Fine => {
                    if saved < 2000 && r.chance(1) && s.len() < 4096 {
                        save(&corpus, &s);
                        seeds.push(s);
                        saved += 1;
                    }
                }
            }

            // (b) number equality vs the fixed-point oracle
            let (n, i, f, e) = gen_number_parts(&mut r);
            let (n2, i2, f2, e2) = if r.chance(60) { respell(&mut r, n, &i, &f, e) } else { gen_number_parts(&mut r) };
            let a = render_number(&mut r, n, &i, &f, e);
            let b = render_number(&mut r, n2, &i2, &f2, e2);
            let truth = fixed_point(n, &i, &f, e) == fixed_point(n2, &i2, &f2, e2);
            nums += 1;
            match (json::parse(&a), json::parse(&b)) {
                (Ok(x), Ok(y)) => {
                    if (x == y) != truth {
                        bugs += 1;
                        eprintln!("BUG: number equality {a} vs {b}: ours {} oracle {truth}", x == y);
                        save(&artifacts, &format!("[{a},{b}]"));
                    }
                }
                _ => {
                    bugs += 1;
                    eprintln!("BUG: generated number refused: {a} / {b}");
                }
            }

            // (c) string equality vs code units
            let u1 = gen_codepoints(&mut r);
            let u2 = if r.chance(60) { u1.clone() } else { gen_codepoints(&mut r) };
            let s1 = gen_string(&mut r, &u1);
            let s2 = gen_string(&mut r, &u2);
            strs += 1;
            match (json::parse(&s1), json::parse(&s2)) {
                (Ok(x), Ok(y)) => {
                    if (x == y) != (u1 == u2) {
                        bugs += 1;
                        eprintln!("BUG: string equality {s1} vs {s2}");
                        save(&artifacts, &format!("[{s1},{s2}]"));
                    }
                }
                _ => {
                    bugs += 1;
                    eprintln!("BUG: generated string refused: {s1:?} / {s2:?}");
                }
            }
        }
    }
    println!(
        "json_diff: {secs}s, seeds {start_seeds}, documents {docs}, number pairs {nums}, string pairs {strs}, documented-difference inputs {interesting}, saved {saved}, BUGS {bugs}"
    );
    std::process::exit(if bugs == 0 { 0 } else { 1 });
}
