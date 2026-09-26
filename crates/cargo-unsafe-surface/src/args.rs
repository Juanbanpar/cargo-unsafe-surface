//! Command-line argument handling.
//!
//! Implements the standard Cargo subcommand convention: when invoked as
//! `cargo unsafe-surface …`, Cargo passes the subcommand name as the first
//! argument, so the CLI is modelled as `cargo unsafe-surface [ARGS]`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

/// Well-known exit codes of the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCodes {
    /// Analysis succeeded, no policy violations.
    Success,
    /// Operational failure (discovery, I/O, usage).
    OperationalError,
    /// Policy violations were found.
    PolicyViolation,
}

impl ExitCodes {
    /// Numeric value.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::OperationalError => 1,
            Self::PolicyViolation => 2,
        }
    }

    /// Process exit code.
    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(self.code())
    }

    /// Maps a clap parse result to the tool's exit codes: help and version
    /// requests succeed, every other parse failure is an operational error.
    ///
    /// Clap's own exit code for usage errors is `2`, which this tool
    /// reserves for policy violations, so parse results are reported
    /// manually instead of via [`clap::Error::exit`].
    #[must_use]
    pub fn for_parse_error(error: &clap::Error) -> Self {
        match error.kind() {
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                Self::Success
            }
            _ => Self::OperationalError,
        }
    }
}

/// Top-level CLI: mimics `cargo unsafe-surface`.
#[derive(Debug, Parser)]
#[command(name = "cargo-unsafe-surface", bin_name = "cargo", version, about)]
enum CargoInvocation {
    /// Determine the unsafe surface of a Rust program.
    UnsafeSurface(Cli),
}

/// Arguments of `cargo unsafe-surface`.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Path to the workspace `Cargo.toml`.
    #[arg(long, value_name = "PATH")]
    pub manifest_path: Option<PathBuf>,

    /// Package(s) to analyse (default: workspace default members).
    #[arg(short, long = "package", value_name = "SPEC")]
    pub packages: Vec<String>,

    /// Analyse the library target(s) of the selected packages.
    #[arg(long)]
    pub lib: bool,

    /// Analyse the given binary target(s).
    #[arg(long = "bin", value_name = "NAME")]
    pub bins: Vec<String>,

    /// Additional explicit entry points (`crate::path::to::function`).
    #[arg(long = "entry", value_name = "PATH")]
    pub entries: Vec<String>,

    /// Analyse dependency sources available locally (workspace members and
    /// downloaded registry/git checkouts). Sources are never downloaded.
    #[arg(long)]
    pub include_dependencies: bool,

    /// Include dev-dependencies in the analysis universe (excluded by
    /// default because they do not ship).
    #[arg(long, conflicts_with = "exclude_dev_dependencies")]
    pub include_dev_dependencies: bool,

    /// Exclude dev-dependencies (the default; kept for explicitness in
    /// scripts and CI configurations).
    #[arg(long)]
    pub exclude_dev_dependencies: bool,

    /// Output format: text, json or sarif.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: String,

    /// Write the report to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Policy file to evaluate after the analysis; violations exit with
    /// code 2.
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Space- or comma-separated Cargo features to enable.
    #[arg(long, value_name = "FEATURES", num_args = 1.., value_delimiter = ',')]
    pub features: Vec<String>,

    /// Enable all Cargo features.
    #[arg(long)]
    pub all_features: bool,

    /// Disable default Cargo features.
    #[arg(long)]
    pub no_default_features: bool,

    /// Analyse for the given compilation target triple (affects #[cfg]).
    #[arg(long, value_name = "TRIPLE")]
    pub target: Option<String>,

    /// Run cargo metadata offline (no network access during resolution).
    #[arg(long)]
    pub offline: bool,
}

impl Cli {
    /// Parses the invocation, accepting both `cargo-unsafe-surface …` and
    /// `cargo unsafe-surface …` forms.
    ///
    /// # Errors
    ///
    /// Returns the clap error for invalid arguments, or a help/version
    /// request; use [`ExitCodes::for_parse_error`] for the exit code and
    /// [`clap::Error::print`] for the message.
    pub fn parse_from_cargo() -> Result<Self, clap::Error> {
        let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
        // Cargo invokes subcommands as `cargo-unsafe-surface unsafe-surface
        // <args…>`: the first argument after the binary name is the
        // subcommand name. `try_parse_from` also expects a leading argv[0],
        // so a synthetic one is prepended.
        let rest: Vec<std::ffi::OsString> =
            std::iter::once(std::ffi::OsString::from("cargo-unsafe-surface"))
                .chain(
                    args.iter()
                        .skip(1)
                        .skip_while(|a| *a == "unsafe-surface")
                        .cloned(),
                )
                .collect();
        Self::try_parse_from(rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_documented_values() {
        assert_eq!(ExitCodes::Success.code(), 0);
        assert_eq!(ExitCodes::OperationalError.code(), 1);
        assert_eq!(ExitCodes::PolicyViolation.code(), 2);
    }

    #[test]
    fn parses_typical_invocations() {
        let cli = Cli::try_parse_from([
            "cargo-unsafe-surface",
            "--bin",
            "server",
            "--format",
            "json",
        ])
        .unwrap();
        assert_eq!(cli.bins, vec!["server"]);
        assert_eq!(cli.format, "json");
        assert!(!cli.lib);

        let cli = Cli::try_parse_from([
            "cargo-unsafe-surface",
            "--lib",
            "--include-dependencies",
            "--entry",
            "crate::api::process",
            "--features",
            "tls,compress",
        ])
        .unwrap();
        assert!(cli.lib);
        assert!(cli.include_dependencies);
        assert_eq!(cli.entries, vec!["crate::api::process"]);
        assert_eq!(cli.features, vec!["tls", "compress"]);
    }

    #[test]
    fn dev_dependency_flags_conflict() {
        assert!(Cli::try_parse_from([
            "cargo-unsafe-surface",
            "--include-dev-dependencies",
            "--exclude-dev-dependencies"
        ])
        .is_err());
    }

    #[test]
    fn usage_errors_are_operational_errors() {
        // Clap exits with code 2 on usage errors; that is the tool's
        // policy-violation code, so parse failures must be mapped to 1.
        let error = Cli::try_parse_from(["cargo-unsafe-surface", "--polciy", "x"]).unwrap_err();
        assert_eq!(
            ExitCodes::for_parse_error(&error),
            ExitCodes::OperationalError
        );
    }

    #[test]
    fn help_and_version_requests_succeed() {
        for flag in ["--help", "--version"] {
            let error = Cli::try_parse_from(["cargo-unsafe-surface", flag]).unwrap_err();
            assert_eq!(
                ExitCodes::for_parse_error(&error),
                ExitCodes::Success,
                "{flag} must exit 0"
            );
        }
    }
}
