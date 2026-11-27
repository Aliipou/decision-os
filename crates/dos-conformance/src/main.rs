//! `dos-conformance`: run conformance vectors through an adapter (spec/CONFORMANCE.md).

use dos_conformance::{manifest, runner};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
usage: dos-conformance (--adapter <program> [--arg <a>]... | --manifest <manifest.json>)
                       [--vectors <dir>] [--area <a>]... [--require <a>]... [--oracle]
                       [--json <report>] [--case-timeout <secs>] [--timeout <secs>]

  --adapter       adapter executable (argv[0]; never split by a shell)
  --arg           one more argument for the adapter (repeatable)
  --manifest      adapter manifest; its required areas apply when selected
  --vectors       vectors directory (default conformance/vectors)
  --area          run only this area (repeatable; default every area)
  --require       this area must exist and be fully supported (repeatable)
  --oracle        check oracle_expected when a vector has one
  --json          write a JSON report to this path
  --case-timeout  seconds to wait for each response line (default 10)
  --timeout       seconds for the whole run (default 300)

exit 0 pass, 1 conformance failure, 2 usage or vector-format error";

fn main() -> ExitCode {
    match parse(std::env::args().skip(1).collect()) {
        Ok(cfg) => ExitCode::from(u8::try_from(runner::run(&cfg)).unwrap_or(1)),
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn parse(args: Vec<String>) -> Result<runner::Config, String> {
    let mut adapter: Option<PathBuf> = None;
    let mut manifest_path: Option<PathBuf> = None;
    let mut extra_args = Vec::new();
    let mut vectors = PathBuf::from("conformance/vectors");
    let (mut areas, mut require) = (Vec::new(), Vec::new());
    let mut oracle = false;
    let mut json = None;
    let mut case_timeout = Duration::from_secs(10);
    let mut timeout = Duration::from_secs(300);
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--adapter" => set_once(&mut adapter, PathBuf::from(value()?), "--adapter")?,
            "--manifest" => set_once(&mut manifest_path, PathBuf::from(value()?), "--manifest")?,
            "--arg" => extra_args.push(value()?),
            "--vectors" => vectors = PathBuf::from(value()?),
            "--area" => areas.push(ident(value()?)?),
            "--require" => require.push(ident(value()?)?),
            "--oracle" => oracle = true,
            "--json" => json = Some(PathBuf::from(value()?)),
            "--case-timeout" => case_timeout = secs(&value()?)?,
            "--timeout" => timeout = secs(&value()?)?,
            "-h" | "--help" => return Err("help requested".into()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let (program, args, cwd, manifest_required) = match (adapter, manifest_path) {
        (Some(p), None) => (p, extra_args, None, Vec::new()),
        (None, Some(m)) => {
            if !extra_args.is_empty() {
                return Err("--arg goes with --adapter; a manifest has its own command".into());
            }
            let m = manifest::load(&m)?;
            oracle |= m.oracle;
            (m.program, m.args, Some(m.dir), m.required)
        }
        (Some(_), Some(_)) => return Err("give --adapter or --manifest, not both".into()),
        (None, None) => return Err("--adapter or --manifest is required".into()),
    };
    Ok(runner::Config {
        program,
        args,
        cwd,
        vectors,
        areas,
        require,
        manifest_required,
        oracle,
        json,
        case_timeout,
        timeout,
    })
}

fn set_once<T>(slot: &mut Option<T>, v: T, flag: &str) -> Result<(), String> {
    if slot.replace(v).is_some() {
        return Err(format!("{flag} given twice"));
    }
    Ok(())
}

fn ident(a: String) -> Result<String, String> {
    if dos_conformance::vector::valid_ident(&a) {
        Ok(a)
    } else {
        Err(format!("invalid area name {a:?}"))
    }
}

fn secs(s: &str) -> Result<Duration, String> {
    match s.parse::<u64>() {
        Ok(n) if n > 0 && n <= 86_400 => Ok(Duration::from_secs(n)),
        _ => Err(format!(
            "timeout must be a whole number of seconds in 1..=86400, got {s:?}"
        )),
    }
}
