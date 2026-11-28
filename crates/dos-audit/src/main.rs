//! `dos-audit verify <log> --key <pubkey-hex>... [--anchor-file <path>] [--python-compat] [--no-anchor]`
//!
//! Exit 0: the log verifies. Exit 1: it does not (reason on stderr). Exit 2: usage.

fn main() -> std::process::ExitCode {
    dos_audit::cli::run(std::env::args().skip(1))
}
