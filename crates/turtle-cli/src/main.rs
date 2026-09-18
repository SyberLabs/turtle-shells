//! Turtle owner CLI. P1 admits a sandbox only on a certified backend.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use turtle_launcher::backend::{SandboxBackend, UnsupportedBackend};
use turtle_launcher::{compile_launch_plan, probe_host, P1_CLAIM_CEILING};
use turtle_policy::path::RelPath;
use turtle_policy::plan::enforcement_plan;
use turtle_policy::{diff_authority, parse_manifest, policy_digest, CLAIM_CEILING};
use turtle_snapshot::{export_patch, import_snapshot, ExportRequest, ImportRequest};

#[derive(Parser)]
#[command(
    name = "turtle",
    version,
    about = "Turtle owner tools. Containment requires a certified Linux/gVisor backend."
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
    /// Probe whether this host can enforce P1 containment.
    Doctor,
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommands,
    },
    /// Export a bounded patch of allowed regular-file changes.
    Export {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        work: PathBuf,
        #[arg(long = "subtree")]
        subtree: Vec<String>,
    },
    /// Compile a launch plan and refuse to start on an uncertified host.
    Run {
        #[arg(long)]
        manifest: PathBuf,
    },
}

#[derive(Subcommand)]
enum SnapshotCommands {
    Import {
        #[arg(long = "from")]
        from: PathBuf,
        #[arg(long = "into")]
        into: PathBuf,
        #[arg(long = "select")]
        select: Vec<String>,
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
        Commands::Doctor => doctor(),
        Commands::Snapshot { command } => match command {
            SnapshotCommands::Import { from, into, select } => {
                snapshot_import(&from, &into, &select)
            }
        },
        Commands::Export {
            snapshot,
            work,
            subtree,
        } => export(&snapshot, &work, &subtree),
        Commands::Run { manifest } => run(&manifest),
    }
}

fn doctor() -> ExitCode {
    let probe = probe_host();
    println!("claim_ceiling: {P1_CLAIM_CEILING}");
    println!("os={}", probe.os);
    println!("openat2={}", probe.openat2);
    println!("runsc={}", probe.runsc.as_deref().unwrap_or("none"));
    println!("certified={}", probe.certified);
    for failure in &probe.failures {
        println!("failure={failure}");
    }
    if probe.certified {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn snapshot_import(from: &PathBuf, into: &PathBuf, select: &[String]) -> ExitCode {
    let mut selected = Vec::new();
    for raw in select {
        match RelPath::parse(raw) {
            Ok(path) => selected.push(path),
            Err(err) => return fail(&err),
        }
    }
    match import_snapshot(&ImportRequest {
        source_root: from,
        selected: &selected,
        dest_root: into,
    }) {
        Ok(snap) => {
            println!(
                "imported {} files into {}",
                snap.files.len(),
                snap.dest_root.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

fn export(snapshot: &PathBuf, work: &PathBuf, subtree: &[String]) -> ExitCode {
    let mut subtrees = Vec::new();
    for raw in subtree {
        match RelPath::parse(raw) {
            Ok(path) => subtrees.push(path),
            Err(err) => return fail(&err),
        }
    }
    match export_patch(&ExportRequest {
        snapshot_root: snapshot,
        work_root: work,
        export_subtrees: &subtrees,
    }) {
        Ok(artifact) => {
            println!("exported {} files", artifact.files.len());
            for file in artifact.files {
                println!(
                    "{} sha256={} deleted={}",
                    file.path, file.sha256, file.deleted
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

fn run(path: &PathBuf) -> ExitCode {
    let policy = match load(path) {
        Ok(policy) => policy,
        Err(err) => return fail(&err),
    };
    let plan = match compile_launch_plan(&policy) {
        Ok(plan) => plan,
        Err(err) => return fail(&err),
    };
    println!("launch_plan_cwd={}", plan.cwd);
    println!("host_network={}", plan.host_network);
    println!("claim_ceiling: {P1_CLAIM_CEILING}");
    match UnsupportedBackend.create_frozen(&plan) {
        Ok(_) => {
            eprintln!("certified backend started; this path is not implemented");
            ExitCode::from(1)
        }
        Err(err) => fail(&err),
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
