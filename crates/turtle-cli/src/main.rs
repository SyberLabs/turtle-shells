//! Turtle owner CLI. P0 inspects policy; it does not enforce a sandbox.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use turtle_policy::plan::enforcement_plan;
use turtle_policy::{diff_authority, parse_manifest, policy_digest, CLAIM_CEILING};

#[derive(Parser)]
#[command(
    name = "turtle",
    version,
    about = "Turtle P0 policy tools. No containment claim."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Parse and validate a manifest.
    Check { manifest: PathBuf },
    /// Explain correlated grant clauses. Runtime mechanisms are not deployed in P0.
    Explain { manifest: PathBuf },
    /// Report semantic authority changes.
    Diff {
        old: PathBuf,
        new: PathBuf,
        #[arg(long, value_enum, default_value_t = DiffFormat::Text)]
        format: DiffFormat,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum DiffFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Commands::Policy { command } => match command {
            PolicyCommands::Check { manifest } => check(&manifest),
            PolicyCommands::Explain { manifest } => explain(&manifest),
            PolicyCommands::Diff { old, new, format } => diff(&old, &new, format),
        },
    }
}

fn check(path: &PathBuf) -> ExitCode {
    match load(path) {
        Ok(policy) => {
            let digest = policy_digest(&policy).expect("canonical digest");
            println!("digest={digest}");
            println!(
                "valid TurtlePolicy `{}` with {} correlated grant clauses",
                policy.name(),
                policy.clauses().len()
            );
            println!("{CLAIM_CEILING}");
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

fn explain(path: &PathBuf) -> ExitCode {
    match load(path) {
        Ok(policy) => {
            println!("Turtle P0 policy explanation");
            println!("claim_ceiling: {CLAIM_CEILING}");
            println!("name: {}", policy.name());
            println!("lifetime.maxSeconds: {}", policy.lifetime().max_seconds);
            println!(
                "budgets.domain.providerAttempts: {} (simulated only)",
                policy.limits().domain.provider_attempts
            );
            println!("clauses:");
            for clause in policy.clauses() {
                println!(
                    "  - id={} effect={:?} actions={:?} resources={:?} credential={:?} recipients={:?} approval={:?}",
                    clause.id,
                    clause.effect,
                    clause.actions.iter().map(|a| a.as_str().to_string()).collect::<Vec<_>>(),
                    clause.resources.iter().map(|a| a.as_str().to_string()).collect::<Vec<_>>(),
                    clause.credential.as_ref().map(|c| c.as_str().to_string()),
                    clause.recipients.iter().map(|a| a.as_str().to_string()).collect::<Vec<_>>(),
                    clause.obligations.approval
                );
            }
            let plan = enforcement_plan(&policy);
            println!("enforcement plan (not deployed in P0):");
            for req in plan.requirements {
                println!(
                    "  - {} plane={} mechanism={} status={:?} limitation={}",
                    req.constraint_id, req.plane, req.mechanism, req.status, req.limitation
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

fn diff(old: &PathBuf, new: &PathBuf, format: DiffFormat) -> ExitCode {
    let old_policy = match load(old) {
        Ok(p) => p,
        Err(err) => return fail(&err),
    };
    let new_policy = match load(new) {
        Ok(p) => p,
        Err(err) => return fail(&err),
    };
    let diff = diff_authority(&old_policy, &new_policy);
    match format {
        DiffFormat::Json => match serde_json::to_string_pretty(&diff) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        },
        DiffFormat::Text => {
            println!("widening:");
            for item in &diff.widening {
                println!("  - {}: {}", item.dimension, item.detail);
            }
            println!("narrowing:");
            for item in &diff.narrowing {
                println!("  - {}: {}", item.dimension, item.detail);
            }
            println!("potentially_widening: {}", diff.potentially_widening);
        }
    }
    if diff.potentially_widening || !diff.widening.is_empty() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn load(path: &PathBuf) -> Result<turtle_policy::TurtlePolicy, turtle_policy::PolicyError> {
    let bytes =
        std::fs::read(path).map_err(|e| turtle_policy::PolicyError::schema(e.to_string()))?;
    parse_manifest(&bytes)
}

fn fail(err: &turtle_policy::PolicyError) -> ExitCode {
    let body = serde_json::json!({
        "code": err.reason_code().to_string(),
        "explanation": err.to_string(),
        "retryable": false
    });
    eprintln!("{body}");
    ExitCode::from(1)
}
