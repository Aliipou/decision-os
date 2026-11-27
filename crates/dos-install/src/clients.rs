//! Known MCP clients and where each keeps its server list (oracle `clients.py`).
//!
//! Paths come only from an explicit [`Env`]; this module never reads the process
//! environment, so tests and the throwaway-HOME rule are enforceable.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::InstallError;

/// The platform whose layout the registry follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
}

/// The four config shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// `{"mcpServers": {name: {command, args, env}}}`
    McpServers,
    /// VS Code: `{"servers": {...}}`
    Servers,
    /// `~/.claude.json`: top-level `mcpServers` plus `projects[<path>].mcpServers`
    ClaudeCode,
    /// Codex `config.toml` with `[mcp_servers.<name>]` tables
    Codex,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::McpServers => "mcpServers",
            Format::Servers => "servers",
            Format::ClaudeCode => "claude-code",
            Format::Codex => "codex",
        }
    }
}

/// The environment variables the registry reads, passed in by the caller. An empty
/// value counts as unset, as in the oracle (`os.environ.get(...) or default`).
#[derive(Clone, Debug)]
pub struct Env {
    pub os: Os,
    pub home: Option<OsString>,
    pub userprofile: Option<OsString>,
    pub homedrive: Option<OsString>,
    pub homepath: Option<OsString>,
    pub appdata: Option<OsString>,
    pub localappdata: Option<OsString>,
    pub xdg_config_home: Option<OsString>,
    pub codex_home: Option<OsString>,
    pub copilot_home: Option<OsString>,
}

fn set(v: &Option<OsString>) -> Option<&OsStr> {
    v.as_deref().filter(|s| !s.is_empty())
}

impl Env {
    /// An environment with nothing set.
    pub fn new(os: Os) -> Self {
        Env {
            os,
            home: None,
            userprofile: None,
            homedrive: None,
            homepath: None,
            appdata: None,
            localappdata: None,
            xdg_config_home: None,
            codex_home: None,
            copilot_home: None,
        }
    }

    /// Python's `Path.home()`: `HOME` on POSIX; `USERPROFILE`, else `HOMEDRIVE` +
    /// `HOMEPATH`, on Windows.
    pub fn home_dir(&self) -> Result<PathBuf, InstallError> {
        let found = match self.os {
            Os::Windows => set(&self.userprofile).map(PathBuf::from).or_else(|| {
                set(&self.homepath).map(|p| {
                    let mut s = set(&self.homedrive).map(OsStr::to_os_string).unwrap_or_default();
                    s.push(p);
                    PathBuf::from(s)
                })
            }),
            Os::Linux | Os::MacOs => set(&self.home).map(PathBuf::from),
        };
        found.ok_or(InstallError::NoHome)
    }

    /// `Path(p).expanduser()` for `~` and `~/...` (and `~\...` on Windows). `~user`
    /// is left as is.
    fn expanduser(&self, p: &OsStr) -> Result<PathBuf, InstallError> {
        let Some(s) = p.to_str() else {
            return Ok(PathBuf::from(p));
        };
        if s == "~" {
            return self.home_dir();
        }
        let rest = s
            .strip_prefix("~/")
            .or_else(|| (self.os == Os::Windows).then(|| s.strip_prefix("~\\")).flatten());
        match rest {
            Some(rest) => Ok(self.home_dir()?.join(rest)),
            None => Ok(PathBuf::from(p)),
        }
    }

    /// Roaming on Windows, Application Support on macOS, XDG config on Linux.
    fn app_support(&self) -> Result<PathBuf, InstallError> {
        let home = self.home_dir()?;
        Ok(match self.os {
            Os::Windows => set(&self.appdata)
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("AppData").join("Roaming")),
            Os::MacOs => home.join("Library").join("Application Support"),
            Os::Linux => set(&self.xdg_config_home)
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config")),
        })
    }

    fn vscode_user_dirs(&self) -> Result<Vec<PathBuf>, InstallError> {
        let base = self.app_support()?;
        Ok(["Code", "Code - Insiders", "VSCodium"]
            .iter()
            .map(|n| base.join(n).join("User"))
            .collect())
    }

    fn claude_desktop(&self) -> Result<Vec<PathBuf>, InstallError> {
        let mut paths = vec![
            self.app_support()?
                .join("Claude")
                .join("claude_desktop_config.json"),
        ];
        if self.os == Os::Windows {
            // MSIX installs keep a virtualized copy:
            // %LOCALAPPDATA%/Packages/Claude_*/LocalCache/Roaming/Claude/claude_desktop_config.json
            let local = match set(&self.localappdata) {
                Some(l) => PathBuf::from(l),
                None => self.home_dir()?.join("AppData").join("Local"),
            };
            let mut found: Vec<PathBuf> = Vec::new();
            if let Ok(rd) = std::fs::read_dir(local.join("Packages")) {
                for entry in rd.flatten() {
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    if !name
                        .get(..7)
                        .is_some_and(|p| p.eq_ignore_ascii_case("claude_"))
                    {
                        continue;
                    }
                    let p = entry
                        .path()
                        .join("LocalCache")
                        .join("Roaming")
                        .join("Claude")
                        .join("claude_desktop_config.json");
                    if p.exists() {
                        found.push(p);
                    }
                }
            }
            // pathlib sorts Windows paths case-insensitively
            found.sort_by_key(|p| p.to_string_lossy().to_lowercase());
            paths.extend(found);
        }
        Ok(paths)
    }

    fn rooted(&self, var: &Option<OsString>, default: &str) -> Result<PathBuf, InstallError> {
        match set(var) {
            Some(v) => self.expanduser(v),
            None => Ok(self.home_dir()?.join(default)),
        }
    }
}

/// One MCP client.
#[derive(Debug)]
pub struct ClientSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub fmt: Format,
    /// (path relative to a project directory, format)
    pub project: &'static [(&'static str, Format)],
    pub restart_hint: &'static str,
}

const fn spec(
    id: &'static str,
    name: &'static str,
    fmt: Format,
    project: &'static [(&'static str, Format)],
    restart_hint: &'static str,
) -> ClientSpec {
    ClientSpec {
        id,
        name,
        fmt,
        project,
        restart_hint,
    }
}

/// Every client the oracle knows, in the oracle's order.
pub const CLIENTS: &[ClientSpec] = &[
    spec(
        "claude-desktop",
        "Claude Desktop",
        Format::McpServers,
        &[],
        "quit and reopen Claude Desktop",
    ),
    spec(
        "claude-code",
        "Claude Code",
        Format::ClaudeCode,
        &[(".mcp.json", Format::McpServers)],
        "start a new Claude Code session",
    ),
    spec(
        "cursor",
        "Cursor",
        Format::McpServers,
        &[(".cursor/mcp.json", Format::McpServers)],
        "Cursor reloads MCP config automatically",
    ),
    spec(
        "vscode",
        "VS Code",
        Format::Servers,
        &[(".vscode/mcp.json", Format::Servers)],
        "run 'MCP: List Servers' and restart them",
    ),
    spec(
        "copilot",
        "GitHub Copilot CLI",
        Format::McpServers,
        &[],
        "",
    ),
    spec(
        "windsurf",
        "Windsurf",
        Format::McpServers,
        &[],
        "refresh MCP servers in Windsurf",
    ),
    spec(
        "gemini-cli",
        "Gemini CLI",
        Format::McpServers,
        &[(".gemini/settings.json", Format::McpServers)],
        "",
    ),
    spec(
        "codex",
        "OpenAI Codex",
        Format::Codex,
        &[(".codex/config.toml", Format::Codex)],
        "",
    ),
    spec("lm-studio", "LM Studio", Format::McpServers, &[], ""),
    spec(
        "kiro",
        "Kiro",
        Format::McpServers,
        &[(".kiro/settings/mcp.json", Format::McpServers)],
        "",
    ),
    spec(
        "amazon-q",
        "Amazon Q Developer",
        Format::McpServers,
        &[],
        "",
    ),
    spec("cline", "Cline", Format::McpServers, &[], ""),
    spec("roo-code", "Roo Code", Format::McpServers, &[], ""),
];

/// The client with this id.
pub fn get(id: &str) -> Option<&'static ClientSpec> {
    CLIENTS.iter().find(|c| c.id == id)
}

fn under(base: &Path, parts: &[&str]) -> PathBuf {
    parts.iter().fold(base.to_path_buf(), |p, s| p.join(s))
}

impl ClientSpec {
    /// The global config files of this client (existing or not).
    pub fn config_paths(&self, env: &Env) -> Result<Vec<PathBuf>, InstallError> {
        let home = env.home_dir()?;
        let h = |parts: &[&str]| under(&home, parts);
        Ok(match self.id {
            "claude-desktop" => env.claude_desktop()?,
            "claude-code" => vec![h(&[".claude.json"])],
            "cursor" => vec![h(&[".cursor", "mcp.json"])],
            "vscode" => env
                .vscode_user_dirs()?
                .into_iter()
                .map(|d| d.join("mcp.json"))
                .collect(),
            "copilot" => vec![env.rooted(&env.copilot_home, ".copilot")?.join("mcp-config.json")],
            "windsurf" => vec![h(&[".codeium", "windsurf", "mcp_config.json"])],
            "gemini-cli" => vec![h(&[".gemini", "settings.json"])],
            "codex" => vec![env.rooted(&env.codex_home, ".codex")?.join("config.toml")],
            "lm-studio" => vec![
                h(&[".lmstudio", "mcp.json"]),
                h(&[".cache", "lm-studio", "mcp.json"]),
            ],
            "kiro" => vec![h(&[".kiro", "settings", "mcp.json"])],
            "amazon-q" => vec![h(&[".aws", "amazonq", "mcp.json"])],
            "cline" => env
                .vscode_user_dirs()?
                .into_iter()
                .map(|d| {
                    under(
                        &d,
                        &[
                            "globalStorage",
                            "saoudrizwan.claude-dev",
                            "settings",
                            "cline_mcp_settings.json",
                        ],
                    )
                })
                .collect(),
            "roo-code" => env
                .vscode_user_dirs()?
                .into_iter()
                .map(|d| {
                    under(
                        &d,
                        &[
                            "globalStorage",
                            "rooveterinaryinc.roo-cline",
                            "settings",
                            "mcp_settings.json",
                        ],
                    )
                })
                .collect(),
            _ => Vec::new(),
        })
    }
}

/// Every global client config path, existing or not (for self-protection).
pub fn all_config_paths(env: &Env) -> Vec<PathBuf> {
    CLIENTS
        .iter()
        .filter_map(|c| c.config_paths(env).ok())
        .flatten()
        .collect()
}
