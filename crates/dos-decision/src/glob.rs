//! Python 3.13 `fnmatch.fnmatchcase`, code point for code point.
//!
//! Python translates the pattern into a regex; this module builds the same
//! character-class text (`_translate`) and reads it back the way `sre_parse` does, so
//! the odd cases (unclosed `[`, reversed ranges, `[!]`, `[]]`) agree.

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq)]
enum Item {
    Char(char),
    Range(char, char),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Lit(char),
    Any,
    Star,
    Never,
    Class { negated: bool, items: Vec<Item> },
}

impl Tok {
    fn matches(&self, c: char) -> bool {
        match self {
            Tok::Lit(l) => *l == c,
            Tok::Any => true,
            Tok::Star | Tok::Never => false,
            Tok::Class { negated, items } => {
                let hit = items.iter().any(|i| match i {
                    Item::Char(x) => *x == c,
                    Item::Range(a, b) => *a <= c && c <= *b,
                });
                hit != *negated
            }
        }
    }
}

/// Read a regex class body (without the brackets) like `sre_parse`.
fn parse_class(body: &[char]) -> Tok {
    let (negated, body) = match body.split_first() {
        Some(('^', rest)) => (true, rest),
        _ => (false, body),
    };
    let mut atoms: Vec<(char, bool)> = Vec::new(); // (char, is_unescaped_dash)
    let mut it = body.iter().copied();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                atoms.push((n, false));
            }
        } else {
            atoms.push((c, c == '-'));
        }
    }
    let mut items = Vec::new();
    let mut i = 0usize;
    while let Some(&(c, _)) = atoms.get(i) {
        match (atoms.get(i + 1), atoms.get(i + 2)) {
            (Some(&(_, true)), Some(&(hi, _))) => {
                items.push(Item::Range(c, hi));
                i += 3;
            }
            _ => {
                items.push(Item::Char(c));
                i += 1;
            }
        }
    }
    Tok::Class { negated, items }
}

fn escape_into(out: &mut Vec<char>, s: &[char], escape_dash: bool) {
    for &c in s {
        if c == '\\' || (escape_dash && c == '-') || matches!(c, '&' | '~' | '|') {
            out.push('\\');
        }
        out.push(c);
    }
}

fn translate(pat: &[char]) -> Vec<Tok> {
    let mut res: Vec<Tok> = Vec::new();
    let n = pat.len();
    let mut i = 0usize;
    let at = |k: usize| pat.get(k).copied();
    while let Some(c) = at(i) {
        i += 1;
        match c {
            '*' => {
                if res.last() != Some(&Tok::Star) {
                    res.push(Tok::Star);
                }
            }
            '?' => res.push(Tok::Any),
            '[' => {
                let mut j = i;
                if at(j) == Some('!') {
                    j += 1;
                }
                if at(j) == Some(']') {
                    j += 1;
                }
                while j < n && at(j) != Some(']') {
                    j += 1;
                }
                if j >= n {
                    res.push(Tok::Lit('['));
                    continue;
                }
                let stuff_raw = pat.get(i..j).unwrap_or(&[]);
                let mut stuff: Vec<char> = Vec::new();
                if !stuff_raw.contains(&'-') {
                    escape_into(&mut stuff, stuff_raw, false);
                } else {
                    let mut chunks: Vec<Vec<char>> = Vec::new();
                    let mut k = if at(i) == Some('!') { i + 2 } else { i + 1 };
                    loop {
                        let found = (k..j).find(|&x| at(x) == Some('-'));
                        let Some(kk) = found else { break };
                        chunks.push(pat.get(i..kk).unwrap_or(&[]).to_vec());
                        i = kk + 1;
                        k = kk + 3;
                    }
                    let chunk = pat.get(i..j).unwrap_or(&[]).to_vec();
                    if !chunk.is_empty() {
                        chunks.push(chunk);
                    } else if let Some(last) = chunks.last_mut() {
                        last.push('-');
                    }
                    // Remove empty ranges.
                    let mut k = chunks.len().saturating_sub(1);
                    while k > 0 {
                        let prev_last = chunks.get(k - 1).and_then(|c| c.last()).copied();
                        let cur_first = chunks.get(k).and_then(|c| c.first()).copied();
                        if let (Some(a), Some(b)) = (prev_last, cur_first) {
                            if a > b {
                                let cur = chunks.remove(k);
                                if let Some(p) = chunks.get_mut(k - 1) {
                                    p.pop();
                                    p.extend(cur.iter().skip(1));
                                }
                            }
                        }
                        k -= 1;
                    }
                    for (idx, ch) in chunks.iter().enumerate() {
                        if idx > 0 {
                            stuff.push('-');
                        }
                        escape_into(&mut stuff, ch, true);
                    }
                    // `_translate` escapes &~| after joining; escape_into did it per chunk.
                }
                i = j + 1;
                if stuff.is_empty() {
                    res.push(Tok::Never);
                } else if stuff == ['!'] {
                    res.push(Tok::Any);
                } else {
                    let body: Vec<char> = match stuff.first() {
                        Some('!') => core::iter::once('^').chain(stuff.iter().skip(1).copied()).collect(),
                        Some('^' | '[') => core::iter::once('\\').chain(stuff.iter().copied()).collect(),
                        _ => stuff,
                    };
                    res.push(parse_class(&body));
                }
            }
            c => res.push(Tok::Lit(c)),
        }
    }
    res
}

/// `fnmatch.fnmatchcase(name, pat)`: whole-string match, `*` crosses `/` and newlines.
pub fn fnmatchcase(name: &str, pat: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let toks = translate(&p);
    let s: Vec<char> = name.chars().collect();
    // Classic linear glob match with single-star backtracking.
    let (mut si, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    loop {
        let tok = toks.get(ti);
        let ch = s.get(si).copied();
        match (tok, ch) {
            (Some(Tok::Star), _) => {
                star = Some((ti, si));
                ti += 1;
                continue;
            }
            (Some(t), Some(c)) if t.matches(c) => {
                ti += 1;
                si += 1;
                continue;
            }
            (None, None) => return true,
            _ => {}
        }
        match star {
            Some((st, ss)) if ss < s.len() => {
                star = Some((st, ss + 1));
                ti = st + 1;
                si = ss + 1;
            }
            _ => return false,
        }
    }
}

/// Owned helper used by tests.
#[allow(dead_code)]
fn tokens(pat: &str) -> usize {
    let p: Vec<char> = pat.chars().collect();
    translate(&p).len()
}

/// The policy's case-insensitive glob: `fnmatchcase(value.lower(), pattern.lower())`.
pub fn glob_ci(value: &str, pattern: &str) -> bool {
    let v: String = value.to_lowercase();
    let p: String = pattern.to_lowercase();
    fnmatchcase(&v, &p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        assert!(fnmatchcase("abc", "*"));
        assert!(fnmatchcase("", "*"));
        assert!(fnmatchcase("a/b\nc", "a*c"));
        assert!(fnmatchcase("move_file", "move_*"));
        assert!(!fnmatchcase("xmove_file", "move_*"));
        assert!(fnmatchcase("abc", "a?c"));
        assert!(!fnmatchcase("ac", "a?c"));
        assert!(fnmatchcase("a[b", "a[b"));
        assert!(fnmatchcase("b", "[abc]"));
        assert!(!fnmatchcase("b", "[!abc]"));
        assert!(fnmatchcase("]", "[]]"));
        assert!(fnmatchcase("x", "[!]]"));
        assert!(fnmatchcase("m", "[a-z]"));
        assert!(!fnmatchcase("m", "[z-a]"));
        assert!(fnmatchcase("-", "[a-]"));
        assert!(fnmatchcase("\\", "[\\]"));
        assert!(fnmatchcase("q", "[!z-a]"));
        assert!(!fnmatchcase("q", "[z-a]"));
        assert!(fnmatchcase("[!]", "[!]"));
        assert!(fnmatchcase("&", "[&]"));
        assert!(fnmatchcase("^", "[^]"));
        assert!(fnmatchcase("aXbXc", "a*b*c"));
        assert!(!fnmatchcase("aXbX", "a*b*c"));
        assert!(fnmatchcase("team/public-site", "team/public-*"));
        assert!(glob_ci("Me/X", "me/*"));
        assert!(tokens("**a") == 2);
    }
}
