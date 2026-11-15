use clap::Parser;
use clap::error::{ContextKind, ContextValue, ErrorKind};
use std::process::ExitCode;
use zkeytool::cli::{Cli, Command};
use zkeytool::{commands, hygiene};

fn main() -> ExitCode {
    hygiene::disable_core_dumps();

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => return usage_error(e),
    };

    let result = match cli.command {
        Command::Create(args) => commands::create(args),
        Command::Import(args) => commands::import(args),
        Command::Display(args) => commands::display(args),
        Command::Reveal(args) => commands::reveal(args),
        Command::Derive(args) => commands::derive(args),
        Command::Rekey(args) => commands::rekey(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Render clap's own parse error, then add the `--field` misuse hint. Help and
/// version render to stdout and exit 0. Every real usage error exits 2.
fn usage_error(e: clap::Error) -> ExitCode {
    let _ = e.print();
    if let Some(hint) = field_hint(&e) {
        eprintln!("{hint}");
    }
    if e.use_stderr() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// A misuse of `--field` answered with a pointer at `--json | jq`: the flag
/// repeated, or a comma list clap read as one unknown value.
fn field_hint(e: &clap::Error) -> Option<&'static str> {
    let about_field = matches!(
        e.get(ContextKind::InvalidArg),
        Some(ContextValue::String(arg)) if arg.contains("--field")
    );
    if !about_field {
        return None;
    }
    match e.kind() {
        ErrorKind::ArgumentConflict => {
            Some("hint: for multiple fields use --json and filter with jq")
        }
        ErrorKind::InvalidValue => match e.get(ContextKind::InvalidValue) {
            Some(ContextValue::String(value)) if value.contains(',') => {
                Some("hint: --field takes one field. For multiple, use --json and filter with jq")
            }
            _ => None,
        },
        _ => None,
    }
}
