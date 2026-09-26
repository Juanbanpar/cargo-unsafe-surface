//! `cargo-unsafe-surface` — reports the reachable unsafe and foreign-code
//! surface of a Rust program.
//!
//! This binary is a thin shell over the discovery, analysis and reporting
//! libraries. Exit codes:
//!
//! * `0` — analysis succeeded, no policy violations;
//! * `1` — operational failure (discovery, I/O, usage errors);
//! * `2` — policy violations were found (see `--policy`).

#![forbid(unsafe_code)]

mod args;
mod policy;

use std::process::ExitCode;

use anyhow::{Context, Result};
use unsafe_surface_analysis::{analyze, AnalysisConfig};
use unsafe_surface_cargo::{discover, query_rustc_cfg, DiscoveryOptions};
use unsafe_surface_report::{render, OutputFormat};

use crate::args::{Cli, ExitCodes};

fn main() -> ExitCode {
    let cli = match Cli::parse_from_cargo() {
        Ok(cli) => cli,
        Err(error) => {
            // Clap streams help and version to stdout and errors to
            // stderr; its exit code would collide with ours (see
            // `ExitCodes::for_parse_error`).
            error.print().ok();
            return ExitCodes::for_parse_error(&error).exit_code();
        }
    };
    match run(cli) {
        Ok(code) => code.exit_code(),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCodes::OperationalError.exit_code()
        }
    }
}

fn run(cli: Cli) -> Result<ExitCodes> {
    let format = OutputFormat::parse(&cli.format)
        .with_context(|| format!("unknown format `{}`", cli.format))
        .context("supported formats: text, json, sarif")?;

    let discovery_options = DiscoveryOptions {
        manifest_path: cli.manifest_path.clone(),
        packages: cli.packages.clone(),
        features: cli.features.clone(),
        all_features: cli.all_features,
        no_default_features: cli.no_default_features,
        offline: cli.offline,
    };
    let include_dev = cli.include_dev_dependencies;
    let workspace = discover(&discovery_options, cli.include_dependencies, include_dev)
        .context("workspace discovery failed")?;
    let targets = workspace
        .select_targets(cli.lib, &cli.bins)
        .context("target selection failed")?;

    let cfg = query_rustc_cfg(cli.target.as_deref())
        .context("failed to query the rustc target configuration")?;

    let config = AnalysisConfig {
        packages: cli.packages.clone(),
        include_dependencies: cli.include_dependencies,
        include_dev_dependencies: include_dev,
        explicit_entries: cli.entries.clone(),
        features: cli.features.clone(),
        all_features: cli.all_features,
        no_default_features: cli.no_default_features,
        target: cli.target.clone(),
        limits: Default::default(),
    };

    let outcome = analyze(&workspace, &targets, &cfg, &config).context("analysis failed")?;

    let output = render(&outcome.report, format).context("report rendering failed")?;
    write_output(&output, cli.output.as_deref())?;

    if let Some(policy_path) = &cli.policy {
        let policy = policy::Policy::load(policy_path)
            .with_context(|| format!("failed to load policy {}", policy_path.display()))?;
        let evaluation = policy.evaluate(&outcome.report);
        evaluation.print_summary();
        if evaluation.has_violations() {
            return Ok(ExitCodes::PolicyViolation);
        }
    }
    Ok(ExitCodes::Success)
}

/// Writes the report to a file or stdout.
fn write_output(output: &str, path: Option<&std::path::Path>) -> Result<()> {
    match path {
        Some(path) => {
            std::fs::write(path, output)
                .with_context(|| format!("cannot write report to {}", path.display()))?;
        }
        None => {
            use std::io::Write as _;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(output.as_bytes())
                .context("failed to write report to stdout")?;
            if !output.ends_with('\n') {
                lock.write_all(b"\n").ok();
            }
        }
    }
    Ok(())
}
