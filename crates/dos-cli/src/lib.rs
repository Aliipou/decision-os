//! The `decision-os` command line.
//!
//! ```text
//! decision-os keygen <key-file>
//! decision-os proxy --key-file <f> [--policy <toml>] [--audit <log>] [--client <name>]
//!                   [--server-name <name>] -- <server command...>
//! decision-os audit verify <log> --key <pubkey-hex>... [--anchor-file <p>] [--python-compat]
//! ```
//!
//! `proxy` sits between an MCP client (its own stdin and stdout) and the server command,
//! gates every `tools/call` and `resources/read` with the policy, and writes every outcome
//! to the signed, hash-chained audit log before any effect. `Ask` is refused (there is no
//! interactive approval in this binary yet). Exit codes: the server's for `proxy`, 0, 1 or
//! 2 (usage) otherwise.

mod engine;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use dos_audit::FileSink;
use dos_core::sign::{SigningKey, hex_decode_array, hex_encode};
use dos_decision::{GatewayPolicy, parse_policy};
use dos_exec::{CoreAudit, Proxy};

pub use engine::{PolicyEngine, to_py};

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  decision-os keygen <key-file>\n  decision-os proxy --key-file <f> [--policy <toml>] [--audit <log>] [--client <name>] [--server-name <name>] -- <server command...>\n  decision-os audit verify <log> --key <pubkey-hex>... [--anchor-file <p>] [--python-compat] [--no-anchor]"
    );
    ExitCode::from(2)
}

/// Runs the command line; `args` excludes the program name.
pub fn run(mut args: impl Iterator<Item = String>) -> ExitCode {
    match args.next().as_deref() {
        Some("keygen") => match args.next() {
            Some(p) if args.next().is_none() => keygen(Path::new(&p)),
            _ => usage(),
        },
        Some("audit") => dos_audit::cli::run(args),
        Some("proxy") => proxy(args),
        _ => usage(),
    }
}

/// Writes a fresh 32-byte secret key as lowercase hex, refusing to overwrite a file, and
/// prints the public key (what `audit verify --key` needs).
fn keygen(path: &Path) -> ExitCode {
    let mut secret = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut secret) {
        eprintln!("decision-os: no randomness: {e}");
        return ExitCode::from(1);
    }
    use std::io::Write as _;
    let mut f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("decision-os: cannot create {}: {e}", path.display());
            return ExitCode::from(1);
        }
    };
    if let Err(e) = writeln!(f, "{}", hex_encode(&secret)).and_then(|()| f.sync_all()) {
        eprintln!("decision-os: cannot write {}: {e}", path.display());
        return ExitCode::from(1);
    }
    println!(
        "public key: {}",
        SigningKey::from_bytes(&secret).verifying_key().to_hex()
    );
    ExitCode::SUCCESS
}

fn read_key(path: &Path) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read key file: {e}"))?;
    hex_decode_array::<32>(text.trim()).map_err(|e| format!("key file is not 32 bytes of hex: {e}"))
}

fn proxy(mut args: impl Iterator<Item = String>) -> ExitCode {
    let mut key_file: Option<PathBuf> = None;
    let mut policy_file: Option<PathBuf> = None;
    let mut audit = PathBuf::from("decision-os-audit.jsonl");
    let mut client = "decision-os".to_owned();
    let mut server_name: Option<String> = None;
    let mut server: Vec<String> = Vec::new();
    while let Some(a) = args.next() {
        let value = |args: &mut dyn Iterator<Item = String>| args.next();
        match a.as_str() {
            "--key-file" => key_file = value(&mut args).map(PathBuf::from),
            "--policy" => policy_file = value(&mut args).map(PathBuf::from),
            "--audit" => match value(&mut args) {
                Some(p) => audit = PathBuf::from(p),
                None => return usage(),
            },
            "--client" => match value(&mut args) {
                Some(c) => client = c,
                None => return usage(),
            },
            "--server-name" => server_name = value(&mut args),
            "--" => {
                server = args.by_ref().collect();
                break;
            }
            _ => return usage(),
        }
    }
    let (Some(key_file), false) = (key_file, server.is_empty()) else {
        return usage();
    };
    let secret = match read_key(&key_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("decision-os: {e}");
            return ExitCode::from(2);
        }
    };
    let policy = match &policy_file {
        None => GatewayPolicy::default(),
        Some(p) => match std::fs::read_to_string(p)
            .map_err(|e| e.to_string())
            .and_then(|t| parse_policy(&t, &p.display().to_string()).map_err(|e| e.to_string()))
        {
            Ok(pol) => pol,
            Err(e) => {
                eprintln!("decision-os: policy: {e}");
                return ExitCode::from(2);
            }
        },
    };
    let sink = match FileSink::open(&audit, &secret) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "decision-os: cannot open the audit log {}: {}",
                audit.display(),
                e.code()
            );
            return ExitCode::from(2);
        }
    };
    let name = server_name.unwrap_or_else(|| {
        server
            .first()
            .map(|s| {
                Path::new(s)
                    .file_stem()
                    .map_or_else(|| s.clone(), |x| x.to_string_lossy().into_owned())
            })
            .unwrap_or_default()
    });
    let proxy = Proxy::new(Arc::new(PolicyEngine::new(policy, client)), &name)
        .with_audit(Arc::new(CoreAudit::new(sink)));
    let code = proxy.run_stdio(&server);
    u8::try_from(code).map_or(ExitCode::from(1), ExitCode::from)
}
