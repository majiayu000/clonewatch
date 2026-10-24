use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use clonewatch::github::{self, GitHub};
use clonewatch::scan::{Options, Report, Scanner};
use clonewatch::{report, signals};

/// Find non-fork GitHub repositories that copy your project's files
/// (by git blob SHA) and add archives or executables.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan an account (all public non-fork repos) or specific owner/repo targets.
    Scan(ScanArgs),
    /// Re-render a saved `--format json` report without calling GitHub.
    Render {
        report: PathBuf,
        #[command(flatten)]
        out: OutputArgs,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Md,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// `owner` or `owner/repo`, repeatable.
    #[arg(required = true)]
    targets: Vec<String>,
    /// For owner targets, only the N most-starred repos.
    #[arg(long)]
    top: Option<usize>,
    /// Candidates per search query (GitHub caps at 1000).
    #[arg(long, default_value_t = 100)]
    max_candidates: usize,
    /// Minimum shared distinctive blobs to count as a clone.
    #[arg(long, default_value_t = 3)]
    min_shared: usize,
    /// Minimum overlap ratio (0-1) to count as a clone.
    #[arg(long, default_value_t = 0.5)]
    min_overlap: f64,
    /// Blobs smaller than this many bytes are ignored when fingerprinting.
    #[arg(long, default_value_t = 64)]
    min_blob_size: u64,
    /// Never report this owner/repo (repeatable).
    #[arg(long)]
    allow: Vec<String>,
    /// File with one owner/repo per line (# comments) to never report.
    #[arg(long)]
    allow_file: Option<PathBuf>,
    #[command(flatten)]
    out: OutputArgs,
}

#[derive(clap::Args)]
struct OutputArgs {
    /// Show every clone, not just medium and high.
    #[arg(long)]
    all: bool,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Write the report here instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Exit with status 1 if any finding scores at least this much.
    #[arg(long)]
    fail_on: Option<u32>,
}

fn scan(args: &ScanArgs) -> Result<Report> {
    let mut allow: HashSet<String> = args.allow.iter().map(|a| a.trim().to_lowercase()).collect();
    if let Some(path) = &args.allow_file {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        allow.extend(
            text.lines()
                .map(|l| l.split('#').next().unwrap_or("").trim().to_lowercase())
                .filter(|l| !l.is_empty()),
        );
    }
    let gh = GitHub::new(github::token()?);
    let opts = Options {
        top: args.top,
        max_candidates: args.max_candidates,
        min_shared: args.min_shared,
        min_overlap: args.min_overlap,
        min_blob_size: args.min_blob_size,
        allow,
    };
    Scanner::new(&gh, opts, chrono::Utc::now()).run(&args.targets)
}

/// Writes the report; returns whether `--fail-on` was hit.
fn emit(report: &Report, args: &OutputArgs) -> Result<bool> {
    let min_score = if args.all { 0 } else { signals::MEDIUM };
    let out = match args.format {
        Format::Text => report::text(report, min_score),
        Format::Json => report::json(report),
        Format::Md => report::markdown(report, min_score),
    };
    match &args.output {
        Some(p) => std::fs::write(p, out).with_context(|| format!("write {}", p.display()))?,
        None => print!("{out}"),
    }
    let failed = args.fail_on.is_some_and(|n| {
        report
            .sources
            .iter()
            .flat_map(|s| &s.findings)
            .any(|f| f.signals.score >= n)
    });
    Ok(failed)
}

fn run(cmd: Cmd) -> Result<bool> {
    match cmd {
        Cmd::Scan(args) => emit(&scan(&args)?, &args.out),
        Cmd::Render { report, out } => {
            let text = std::fs::read_to_string(&report)
                .with_context(|| format!("read {}", report.display()))?;
            let parsed: Report = serde_json::from_str(&text)
                .with_context(|| format!("{} is not a clonewatch JSON report", report.display()))?;
            emit(&parsed, &out)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse().cmd) {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(1),
        Err(e) => {
            eprintln!("clonewatch: error: {e:#}");
            ExitCode::from(2)
        }
    }
}
