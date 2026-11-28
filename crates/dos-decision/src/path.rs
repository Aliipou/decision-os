//! `policy.normalize_path`: `expanduser`, `expandvars`, `normpath`, `normcase` as
//! Python's `ntpath` and `posixpath` do them. The environment is a parameter.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Which `os.path` flavour the oracle would run (`os.name`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    Posix,
    Nt,
}

/// What `normalize_path` reads from the process: environment variables and `os.name`.
pub trait PathEnv {
    fn var(&self, name: &str) -> Option<String>;
    fn flavor(&self) -> Flavor;
}

/// A fixed environment, for tests, vectors and callers that snapshot the process.
#[derive(Clone, Debug)]
pub struct FixedEnv {
    pub flavor: Flavor,
    pub vars: Vec<(String, String)>,
}

impl PathEnv for FixedEnv {
    fn var(&self, name: &str) -> Option<String> {
        // Windows environment names are case-insensitive (os.environ upper-cases keys).
        let nt = self.flavor == Flavor::Nt;
        self.vars
            .iter()
            .rev()
            .find(|(k, _)| if nt { k.eq_ignore_ascii_case(name) } else { k == name })
            .map(|(_, v)| v.clone())
    }
    fn flavor(&self) -> Flavor {
        self.flavor
    }
}

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

fn sub(v: &[char], a: usize, b: usize) -> String {
    v.get(a..b.min(v.len())).map(|x| x.iter().collect()).unwrap_or_default()
}

// ------------------------------------------------------------------ posixpath

fn posix_expanduser(path: &str, env: &dyn PathEnv) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    let i = path.get(1..).and_then(|r| r.find('/')).map(|x| x + 1).unwrap_or(path.len());
    if i != 1 {
        // ~user needs the password database; the Rust port does no I/O here.
        return path.to_string();
    }
    let Some(home) = env.var("HOME") else {
        return path.to_string();
    };
    let home = home.trim_end_matches('/');
    let out = alloc::format!("{home}{}", path.get(i..).unwrap_or(""));
    if out.is_empty() { "/".into() } else { out }
}

fn is_word_ascii(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn posix_expandvars(path: &str, env: &dyn PathEnv) -> String {
    if !path.contains('$') {
        return path.to_string();
    }
    let mut p = chars(path);
    let mut i = 0usize;
    loop {
        // search r'\$(\w+|\{[^}]*\})' from i
        let mut found = None;
        let mut s = i;
        while s < p.len() {
            if p.get(s) == Some(&'$') {
                let mut e = s + 1;
                if p.get(e) == Some(&'{') {
                    let mut f = e + 1;
                    while p.get(f).is_some_and(|c| *c != '}') {
                        f += 1;
                    }
                    if p.get(f) == Some(&'}') {
                        found = Some((s, f + 1, sub(&p, e + 1, f)));
                        break;
                    }
                } else {
                    while p.get(e).is_some_and(|c| is_word_ascii(*c)) {
                        e += 1;
                    }
                    if e > s + 1 {
                        found = Some((s, e, sub(&p, s + 1, e)));
                        break;
                    }
                }
            }
            s += 1;
        }
        let Some((a, b, name)) = found else { break };
        match env.var(&name) {
            None => i = b,
            Some(value) => {
                let tail: Vec<char> = p.get(b..).unwrap_or(&[]).to_vec();
                p.truncate(a);
                p.extend(value.chars());
                i = p.len();
                p.extend(tail);
            }
        }
    }
    p.into_iter().collect()
}

fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let (initial, rest) = if !path.starts_with('/') {
        ("", path)
    } else if !path.get(1..).unwrap_or("").starts_with('/') || path.get(2..).unwrap_or("").starts_with('/') {
        ("/", path.get(1..).unwrap_or(""))
    } else {
        ("//", path.get(2..).unwrap_or(""))
    };
    let mut comps: Vec<&str> = Vec::new();
    for comp in rest.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".." || (initial.is_empty() && comps.is_empty()) || comps.last() == Some(&"..") {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let out = alloc::format!("{initial}{}", comps.join("/"));
    if out.is_empty() { ".".into() } else { out }
}

// --------------------------------------------------------------------- ntpath

fn is_sep(c: char) -> bool {
    c == '\\' || c == '/'
}

/// `ntpath.splitroot` (pure Python version), returns (drive, root, tail).
fn nt_splitroot(p: &str) -> (String, String, String) {
    let v = chars(p);
    let norm: Vec<char> = v.iter().map(|c| if *c == '/' { '\\' } else { *c }).collect();
    let find = |from: usize| (from..norm.len()).find(|&x| norm.get(x) == Some(&'\\'));
    if norm.first() == Some(&'\\') {
        if norm.get(1) == Some(&'\\') {
            let head: String = norm.iter().take(8).collect::<String>().to_uppercase();
            let start = if head == "\\\\?\\UNC\\" { 8 } else { 2 };
            let Some(index) = find(start) else { return (p.into(), String::new(), String::new()) };
            let Some(index2) = find(index + 1) else { return (p.into(), String::new(), String::new()) };
            (sub(&v, 0, index2), sub(&v, index2, index2 + 1), sub(&v, index2 + 1, v.len()))
        } else {
            (String::new(), sub(&v, 0, 1), sub(&v, 1, v.len()))
        }
    } else if norm.get(1) == Some(&':') {
        if norm.get(2) == Some(&'\\') {
            (sub(&v, 0, 2), sub(&v, 2, 3), sub(&v, 3, v.len()))
        } else {
            (sub(&v, 0, 2), String::new(), sub(&v, 2, v.len()))
        }
    } else {
        (String::new(), String::new(), p.into())
    }
}

fn nt_join(a: &str, b: &str) -> String {
    let (mut rd, mut rr, mut rp) = nt_splitroot(a);
    let (pd, pr, pp) = nt_splitroot(b);
    if !pr.is_empty() {
        if !pd.is_empty() || rd.is_empty() {
            rd = pd;
        }
        rr = pr;
        rp = pp;
    } else if !pd.is_empty() && pd != rd && pd.to_lowercase() != rd.to_lowercase() {
        rd = pd;
        rr = pr;
        rp = pp;
    } else {
        if !pd.is_empty() {
            rd = pd;
        }
        if rp.chars().last().is_some_and(|c| !is_sep(c)) {
            rp.push('\\');
        }
        rp.push_str(&pp);
    }
    if !rp.is_empty() && rr.is_empty() && rd.chars().last().is_some_and(|c| !(c == ':' || is_sep(c))) {
        return alloc::format!("{rd}\\{rp}");
    }
    alloc::format!("{rd}{rr}{rp}")
}

fn nt_split(p: &str) -> (String, String) {
    let (d, r, rest) = nt_splitroot(p);
    let v = chars(&rest);
    let mut i = v.len();
    while i > 0 && v.get(i - 1).is_some_and(|c| !is_sep(*c)) {
        i -= 1;
    }
    let head = sub(&v, 0, i);
    let tail = sub(&v, i, v.len());
    (alloc::format!("{d}{r}{}", head.trim_end_matches(is_sep)), tail)
}

fn nt_expanduser(path: &str, env: &dyn PathEnv) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    let v = chars(path);
    let mut i = 1usize;
    while v.get(i).is_some_and(|c| !is_sep(*c)) {
        i += 1;
    }
    let mut userhome = if let Some(h) = env.var("USERPROFILE") {
        h
    } else if let Some(hp) = env.var("HOMEPATH") {
        nt_join(&env.var("HOMEDRIVE").unwrap_or_default(), &hp)
    } else {
        return path.to_string();
    };
    if i != 1 {
        let target = sub(&v, 1, i);
        let current = env.var("USERNAME");
        if current.as_deref() != Some(target.as_str()) {
            let base = nt_split(&userhome).1;
            if current.as_deref() != Some(base.as_str()) {
                return path.to_string();
            }
            userhome = nt_join(&nt_split(&userhome).0, &target);
        }
    }
    alloc::format!("{userhome}{}", sub(&v, i, v.len()))
}

fn nt_expandvars(path: &str, env: &dyn PathEnv) -> String {
    if !path.contains('$') && !path.contains('%') {
        return path.to_string();
    }
    let varchar = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let mut p = chars(path);
    let mut res = String::new();
    let mut index = 0usize;
    let pos = |p: &[char], from: usize, c: char| (from..p.len()).find(|&x| p.get(x) == Some(&c));
    while index < p.len() {
        let Some(&c) = p.get(index) else { break };
        if c == '\'' {
            p = p.get(index + 1..).unwrap_or(&[]).to_vec();
            match pos(&p, 0, '\'') {
                Some(ix) => {
                    res.push(c);
                    res.push_str(&sub(&p, 0, ix + 1));
                    index = ix;
                }
                None => {
                    res.push(c);
                    res.extend(p.iter());
                    index = p.len().saturating_sub(1);
                    if p.is_empty() {
                        break;
                    }
                }
            }
        } else if c == '%' {
            if p.get(index + 1) == Some(&'%') {
                res.push(c);
                index += 1;
            } else {
                p = p.get(index + 1..).unwrap_or(&[]).to_vec();
                match pos(&p, 0, '%') {
                    None => {
                        res.push('%');
                        res.extend(p.iter());
                        index = p.len().saturating_sub(1);
                        if p.is_empty() {
                            break;
                        }
                    }
                    Some(ix) => {
                        let var = sub(&p, 0, ix);
                        match env.var(&var) {
                            Some(v) => res.push_str(&v),
                            None => {
                                res.push('%');
                                res.push_str(&var);
                                res.push('%');
                            }
                        }
                        index = ix;
                    }
                }
            }
        } else if c == '$' {
            if p.get(index + 1) == Some(&'$') {
                res.push(c);
                index += 1;
            } else if p.get(index + 1) == Some(&'{') {
                p = p.get(index + 2..).unwrap_or(&[]).to_vec();
                match pos(&p, 0, '}') {
                    None => {
                        res.push_str("${");
                        res.extend(p.iter());
                        index = p.len().saturating_sub(1);
                        if p.is_empty() {
                            break;
                        }
                    }
                    Some(ix) => {
                        let var = sub(&p, 0, ix);
                        match env.var(&var) {
                            Some(v) => res.push_str(&v),
                            None => {
                                res.push_str("${");
                                res.push_str(&var);
                                res.push('}');
                            }
                        }
                        index = ix;
                    }
                }
            } else {
                let mut var = String::new();
                index += 1;
                let mut cur = p.get(index).copied();
                while let Some(ch) = cur.filter(|ch| varchar(*ch)) {
                    var.push(ch);
                    index += 1;
                    cur = p.get(index).copied();
                }
                match env.var(&var) {
                    Some(v) => res.push_str(&v),
                    None => {
                        res.push('$');
                        res.push_str(&var);
                    }
                }
                if cur.is_some() {
                    index -= 1;
                }
            }
        } else {
            res.push(c);
        }
        index += 1;
    }
    res
}

fn nt_normpath(path: &str) -> String {
    let path: String = path.chars().map(|c| if c == '/' { '\\' } else { c }).collect();
    let (drive, root, rest) = nt_splitroot(&path);
    let prefix = alloc::format!("{drive}{root}");
    let mut comps: Vec<&str> = rest.split('\\').collect();
    let mut i = 0usize;
    while let Some(&comp) = comps.get(i) {
        if comp.is_empty() || comp == "." {
            comps.remove(i);
        } else if comp == ".." {
            if i > 0 && comps.get(i - 1) != Some(&"..") {
                comps.drain(i - 1..=i);
                i -= 1;
            } else if i == 0 && !root.is_empty() {
                comps.remove(i);
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    if prefix.is_empty() && comps.is_empty() {
        comps.push(".");
    }
    alloc::format!("{prefix}{}", comps.join("\\"))
}

fn nt_normcase(s: &str) -> String {
    s.replace('/', "\\").to_lowercase()
}

fn starts_with_drive(s: &str) -> bool {
    let mut c = s.chars();
    matches!((c.next(), c.next(), c.next()), (Some(a), Some(':'), Some(b)) if a.is_ascii_alphabetic() && is_sep(b))
}

/// Python `os.path.expandvars(os.path.expanduser(s))` for the given flavour.
fn expand(s: &str, env: &dyn PathEnv) -> String {
    match env.flavor() {
        Flavor::Posix => posix_expandvars(&posix_expanduser(s, env), env),
        Flavor::Nt => nt_expandvars(&nt_expanduser(s, env), env),
    }
}

/// `policy.normalize_path`.
pub fn normalize_path(s: &str, env: &dyn PathEnv) -> String {
    let s = s.strip_prefix("file://").unwrap_or(s);
    let s = expand(s, env);
    if starts_with_drive(&s) || s.starts_with("\\\\") || env.flavor() == Flavor::Nt {
        nt_normcase(&nt_normpath(&s)).replace('\\', "/")
    } else {
        posix_normpath(&s)
    }
}

/// `policy._is_pathlike`.
pub fn is_pathlike(s: &str) -> bool {
    !s.is_empty()
        && (["~", "/", "./", "../", "\\\\", "file://"].iter().any(|p| s.starts_with(p))
            || starts_with_drive(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posix() -> FixedEnv {
        FixedEnv { flavor: Flavor::Posix, vars: alloc::vec![("HOME".into(), "/home/u/".into()), ("X".into(), "xv".into())] }
    }
    fn nt() -> FixedEnv {
        FixedEnv {
            flavor: Flavor::Nt,
            vars: alloc::vec![
                ("USERPROFILE".into(), "C:\\Users\\Bob".into()),
                ("USERNAME".into(), "Bob".into()),
                ("X".into(), "xv".into()),
            ],
        }
    }

    #[test]
    fn posix_paths() {
        let e = posix();
        assert_eq!(normalize_path("~/.ssh/id_rsa", &e), "/home/u/.ssh/id_rsa");
        assert_eq!(normalize_path("/a/b/../../../c", &e), "/c");
        assert_eq!(normalize_path("//a//b/", &e), "//a/b");
        assert_eq!(normalize_path("///a", &e), "/a");
        assert_eq!(normalize_path("$X/${X}/$Y", &e), "xv/xv/$Y");
        assert_eq!(normalize_path("file:///etc/./passwd", &e), "/etc/passwd");
        assert_eq!(normalize_path("../x", &e), "../x");
        assert_eq!(normalize_path("C:\\Users\\A\\..\\B", &e), "c:/users/b");
        assert_eq!(normalize_path("~", &e), "/home/u");
    }

    #[test]
    fn nt_paths() {
        let e = nt();
        assert_eq!(normalize_path("~/.ssh", &e), "c:/users/bob/.ssh");
        assert_eq!(normalize_path("~alice/x", &e), "c:/users/alice/x");
        assert_eq!(normalize_path("%X%\\a\\..\\b", &e), "xv/b");
        assert_eq!(normalize_path("'%X%'", &e), "'%x%'");
        assert_eq!(normalize_path("/etc/passwd", &e), "/etc/passwd");
        assert_eq!(normalize_path("\\\\srv\\share\\..\\x", &e), "//srv/share/x");
        assert_eq!(normalize_path("$X-$$", &e), "$x-$");
        assert_eq!(normalize_path("100%", &e), "100%");
    }

    #[test]
    fn pathlike() {
        for s in ["~", "/x", "./x", "../x", "\\\\h", "file://x", "c:\\x", "Z:/x"] {
            assert!(is_pathlike(s), "{s}");
        }
        for s in ["", "x", ".x", "c:x", "1:/x", "me/*"] {
            assert!(!is_pathlike(s), "{s}");
        }
    }
}
