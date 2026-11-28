//! `decision-os`: see `dos_cli::run`.

fn main() -> std::process::ExitCode {
    dos_cli::run(std::env::args().skip(1))
}
