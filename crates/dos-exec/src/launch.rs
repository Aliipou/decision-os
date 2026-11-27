//! Server names and launching the governed server.

use std::path::{Path, PathBuf};

/// Python `str.isspace` (what `\s` and `strip()` use in the oracle).
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Oracle `slug`: strip, collapse runs of whitespace, `/`, `:` and `\` to `-`;
/// empty becomes `unnamed`.
pub fn slug(name: &str) -> String {
    let t = name.trim_matches(py_space);
    let mut out = String::with_capacity(t.len());
    let mut in_run = false;
    for c in t.chars() {
        if py_space(c) || matches!(c, '/' | ':' | '\\') {
            if !in_run {
                out.push('-');
            }
            in_run = true;
        } else {
            out.push(c);
            in_run = false;
        }
    }
    if out.is_empty() {
        "unnamed".to_owned()
    } else {
        out
    }
}

/// Split one command line on whitespace with double and single quotes. On
/// Windows (`posix == false`) single quotes and backslashes are literal, as in
/// `shlex.split(posix=False)` for the common cases; quotes are removed.
pub fn split_command(s: &str, posix: bool) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut have = false;
    let mut quote: Option<char> = None;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some('"') if posix && c == '\\' => match chars.next() {
                Some(n) if matches!(n, '"' | '\\' | '$' | '`') => cur.push(n),
                Some(n) => {
                    cur.push('\\');
                    cur.push(n);
                }
                None => return Err("unterminated escape".into()),
            },
            Some(_) => cur.push(c),
            None if c == '"' || (posix && c == '\'') => {
                quote = Some(c);
                have = true;
            }
            None if posix && c == '\\' => match chars.next() {
                Some(n) => {
                    cur.push(n);
                    have = true;
                }
                None => return Err("unterminated escape".into()),
            },
            None if c.is_whitespace() => {
                if have {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            None => {
                cur.push(c);
                have = true;
            }
        }
    }
    if quote.is_some() {
        return Err("unterminated quote".into());
    }
    if have {
        out.push(cur);
    }
    Ok(out)
}

/// Oracle `resolve_argv`: a single argument with a space that is not a file is
/// a whole command line; the program is looked up on PATH (with PATHEXT on
/// Windows, so `npx` finds `npx.cmd`).
pub fn resolve_argv(argv: &[String]) -> Result<Vec<String>, String> {
    let mut argv = argv.to_vec();
    if let [one] = argv.as_slice()
        && one.contains(' ')
        && !Path::new(one).exists()
    {
        argv = split_command(one, !cfg!(windows))?;
    }
    let Some((first, rest)) = argv.split_first() else {
        return Err("no upstream command given".into());
    };
    let prog = which(first).map_or_else(|| first.clone(), |p| p.to_string_lossy().into_owned());
    let mut out = vec![prog];
    out.extend(rest.iter().cloned());
    Ok(out)
}

fn which(prog: &str) -> Option<PathBuf> {
    let p = Path::new(prog);
    let exts: Vec<String> = if cfg!(windows) {
        let pe = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        let mut v = vec![String::new()];
        v.extend(pe.split(';').filter(|e| !e.is_empty()).map(str::to_owned));
        v
    } else {
        vec![String::new()]
    };
    let has_ext = p.extension().is_some();
    let try_in = |dir: &Path| -> Option<PathBuf> {
        for e in &exts {
            if e.is_empty() && cfg!(windows) && !has_ext {
                continue; // Windows only runs files with an executable extension
            }
            let cand = dir.join(format!("{prog}{e}"));
            if cand.is_file() {
                return Some(cand);
            }
        }
        None
    };
    if p.components().count() > 1 || p.is_absolute() {
        return try_in(Path::new(""));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|d| try_in(&d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_matches_oracle() {
        assert_eq!(slug("  my server/x:y\\z "), "my-server-x-y-z");
        assert_eq!(slug("a / b"), "a-b");
        assert_eq!(slug(" \t "), "unnamed");
        assert_eq!(slug("a\u{1f}b"), "a-b");
        assert_eq!(slug("fs"), "fs");
    }

    #[test]
    fn split_quotes() {
        assert_eq!(
            split_command(r#"npx -y "my pkg" 'a b'"#, true).unwrap_or_default(),
            vec!["npx", "-y", "my pkg", "a b"]
        );
        assert!(split_command("a \"b", true).is_err());
        assert!(resolve_argv(&[]).is_err());
    }
}
