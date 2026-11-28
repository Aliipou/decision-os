//! The `decision-os` command line.
//!
//! ```text
//! decision-os install | uninstall | status [--client <id>]... [--project <dir>] [--home <dir>]
//!                                          [--dry-run] [--force-jsonc]
//! decision-os mcp-proxy --home <dir> --client <id> --server <name> -- <server command...>
//! decision-os proxy --key-file <f> [--policy <toml>] [--audit <log>] [--client <name>]
//!                   [--server-name <name>] -- <server command...>
//! decision-os keygen <key-file>
//! decision-os audit verify <log> --key <pubkey-hex>... [--anchor-file <p>] [--python-compat]
//! ```
//!
//! `install` wraps every stdio MCP server in the clients' configs so it starts behind
//! `decision-os mcp-proxy` (and `uninstall` restores them exactly). `mcp-proxy` and `proxy`
//! sit between an MCP client (their own stdin and stdout) and the server command, gate every
//! `tools/call` and `resources/read` with the policy, and write every outcome to the signed,
//! hash-chained audit log before any effect. `mcp-proxy` takes everything from the gateway
//! home (`policy.toml`, `audit.jsonl`, `keys/audit.key` created on first use,
//! `locks/audit.lock`, the layout the Python gateway uses); `proxy` takes explicit paths.
//! `Ask` is refused (there is no interactive approval in this binary yet). Exit codes: the
//! server's for the proxies; 0, 1 or 2 (usage) otherwise.

mod engine;
mod home;
mod install_cmd;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use dos_audit::FileSink;
use dos_core::sign::SigningKey;
use dos_decision::{GatewayPolicy, parse_policy};
use dos_exec::{CoreAudit, Proxy};
use dos_install::Action;

pub use engine::{PolicyEngine, to_py};

use home::{Home, create_new_file, default_home, ensure_key, new_secret_hex, read_key};

pub(crate) fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  decision-os install|uninstall|status [--client <id>]... [--project <dir>] [--home <dir>] [--dry-run] [--force-jsonc]\n  decision-os mcp-proxy --home <dir> --client <id> --server <name> -- <server command...>\n  decision-os proxy --key-file <f> [--policy <toml>] [--audit <log>] [--client <name>] [--server-name <name>] -- <server command...>\n  decision-os keygen <key-file>\n  decision-os audit verify <log> --key <pubkey-hex>... [--anchor-file <p>] [--python-compat] [--no-anchor]"
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
        Some("install") => install_cmd::command(Action::Install, args),
        Some("uninstall") => install_cmd::command(Action::Uninstall, args),
        Some("status") => install_cmd::command(Action::Status, args),
        Some("proxy") => proxy(args),
        Some("mcp-proxy") => mcp_proxy(args),
        _ => usage(),
    }
}

/// Writes a fresh 32-byte secret key as lowercase hex, refusing to overwrite a file, and
/// prints the public key (what `audit verify --key` needs).
fn keygen(path: &Path) -> ExitCode {
    let hex = match new_secret_hex() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("decision-os: {e}");
            return ExitCode::from(1);
        }
    };
    match create_new_file(path, &hex) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("decision-os: {} exists; not overwritten", path.display());
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("decision-os: cannot create {}: {e}", path.display());
            return ExitCode::from(1);
        }
    }
    match read_key(path) {
        Ok(secret) => {
            println!(
                "public key: {}",
                SigningKey::from_bytes(&secret).verifying_key().to_hex()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("decision-os: {e}");
            ExitCode::from(1)
        }
    }
}

/// Everything a proxy run needs.
struct Settings {
    secret: [u8; 32],
    policy: GatewayPolicy,
    audit: PathBuf,
    lock: Option<PathBuf>,
    client: String,
    server_name: String,
    server: Vec<String>,
}

fn load_policy(path: &Path, required: bool) -> Result<GatewayPolicy, String> {
    if !required && !path.exists() {
        return Ok(GatewayPolicy::default());
    }
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("policy {}: {e}", path.display()))?;
    parse_policy(&text, &path.display().to_string()).map_err(|e| format!("policy: {e}"))
}

fn serve(s: Settings) -> ExitCode {
    let mut sink = match FileSink::open(&s.audit, &s.secret) {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "decision-os: cannot open the audit log {}: {}",
                s.audit.display(),
                e.code()
            );
            return ExitCode::from(2);
        }
    };
    if let Some(lock) = s.lock {
        sink = sink.with_lock_path(lock);
    }
    let proxy = Proxy::new(
        Arc::new(PolicyEngine::new(s.policy, s.client)),
        &s.server_name,
    )
    .with_audit(Arc::new(CoreAudit::new(sink)));
    let code = proxy.run_stdio(&s.server);
    u8::try_from(code).map_or(ExitCode::from(1), ExitCode::from)
}

/// `--flag value` pairs, then the server command that followed `--`.
type Parsed = (Vec<(String, String)>, Vec<String>);

/// Splits the flags before `--` from the server command after it.
fn parse_flags(mut args: impl Iterator<Item = String>, known: &[&str]) -> Option<Parsed> {
    let mut flags = Vec::new();
    while let Some(a) = args.next() {
        if a == "--" {
            return Some((flags, args.collect()));
        }
        if !known.contains(&a.as_str()) {
            return None;
        }
        flags.push((a, args.next()?));
    }
    Some((flags, Vec::new()))
}

fn flag<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags
        .iter()
        .rev()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn proxy(args: impl Iterator<Item = String>) -> ExitCode {
    let Some((flags, server)) = parse_flags(
        args,
        &[
            "--key-file",
            "--policy",
            "--audit",
            "--client",
            "--server-name",
        ],
    ) else {
        return usage();
    };
    let (Some(key_file), false) = (flag(&flags, "--key-file"), server.is_empty()) else {
        return usage();
    };
    let secret = match read_key(Path::new(key_file)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("decision-os: {e}");
            return ExitCode::from(2);
        }
    };
    let policy = match flag(&flags, "--policy") {
        None => GatewayPolicy::default(),
        Some(p) => match load_policy(Path::new(p), true) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("decision-os: {e}");
                return ExitCode::from(2);
            }
        },
    };
    let server_name = flag(&flags, "--server-name")
        .map(str::to_owned)
        .unwrap_or_else(|| {
            server
                .first()
                .map(|s| {
                    Path::new(s)
                        .file_stem()
                        .map_or_else(|| s.clone(), |x| x.to_string_lossy().into_owned())
                })
                .unwrap_or_default()
        });
    serve(Settings {
        secret,
        policy,
        audit: PathBuf::from(flag(&flags, "--audit").unwrap_or("decision-os-audit.jsonl")),
        lock: None,
        client: flag(&flags, "--client").unwrap_or("decision-os").to_owned(),
        server_name,
        server,
    })
}

/// The entry `install` writes: everything comes from the gateway home.
fn mcp_proxy(args: impl Iterator<Item = String>) -> ExitCode {
    let Some((flags, server)) = parse_flags(args, &["--home", "--client", "--server"]) else {
        return usage();
    };
    if server.is_empty() {
        return usage();
    }
    let Some(home) = flag(&flags, "--home")
        .map(PathBuf::from)
        .or_else(default_home)
        .map(Home)
    else {
        eprintln!("decision-os: no home directory (set HOME or pass --home)");
        return ExitCode::from(2);
    };
    let secret = match ensure_key(&home) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("decision-os: {e}");
            return ExitCode::from(2);
        }
    };
    let policy = match load_policy(&home.policy(), false) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("decision-os: {e}");
            return ExitCode::from(2);
        }
    };
    serve(Settings {
        secret,
        policy,
        audit: home.audit(),
        lock: Some(home.lock()),
        client: flag(&flags, "--client").unwrap_or("decision-os").to_owned(),
        server_name: flag(&flags, "--server").unwrap_or("server").to_owned(),
        server,
    })
}
