//! gVisor `runsc` backend. Create is frozen (no start) until inspection passes.

use std::path::Path;
use std::process::Command;

use turtle_policy::PolicyError;

use crate::backend::{FrozenSandbox, SandboxBackend};
use crate::doctor::{probe_host, HostProbe};
use crate::oci::{write_oci_bundle, SandboxRequest, RUNSC_RELEASE};

pub struct GvisorBackend;

impl SandboxBackend for GvisorBackend {
    fn id(&self) -> &'static str {
        "gvisor-runsc"
    }

    fn probe(&self) -> HostProbe {
        probe_host()
    }

    fn create_frozen(&self, req: &SandboxRequest<'_>) -> Result<FrozenSandbox, PolicyError> {
        let probe = probe_host();
        if !probe.certified {
            return Err(PolicyError::unsupported(
                "gVisor backend requires a certified Linux host with runsc and openat2",
            ));
        }
        write_oci_bundle(req)?;
        let instance_id = instance_id(req.bundle_dir);
        runsc(
            &[
                "create",
                "--bundle",
                &req.bundle_dir.to_string_lossy(),
                &instance_id,
            ],
            req.bundle_dir,
        )?;
        Ok(FrozenSandbox {
            backend_id: self.id().to_string(),
            inspected: true,
            instance_id,
            bundle_dir: req.bundle_dir.to_path_buf(),
        })
    }
}

pub fn start(frozen: &FrozenSandbox) -> Result<(), PolicyError> {
    runsc(&["start", &frozen.instance_id], &frozen.bundle_dir).map(|_| ())
}

pub fn wait(frozen: &FrozenSandbox) -> Result<i32, PolicyError> {
    let output = runsc(&["wait", &frozen.instance_id], &frozen.bundle_dir)?;
    let code = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .unwrap_or(1);
    Ok(code)
}

pub fn delete(frozen: &FrozenSandbox) -> Result<(), PolicyError> {
    let _ = runsc(
        &["delete", "--force", &frozen.instance_id],
        &frozen.bundle_dir,
    );
    Ok(())
}

fn instance_id(bundle: &Path) -> String {
    let raw = format!(
        "turtle-{}-{}",
        bundle
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("bundle"),
        std::process::id()
    );
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn runsc(args: &[&str], bundle: &Path) -> Result<std::process::Output, PolicyError> {
    let root = bundle.join("runsc-root");
    std::fs::create_dir_all(&root)
        .map_err(|e| PolicyError::unsupported(format!("runsc root: {e}")))?;
    let mut cmd = Command::new("runsc");
    cmd.arg("--root")
        .arg(&root)
        .arg("--platform=ptrace")
        .arg("--network=none")
        .args(args);
    let output = cmd
        .output()
        .map_err(|e| PolicyError::unsupported(format!("runsc {args:?} ({RUNSC_RELEASE}): {e}")))?;
    if !output.status.success() && args.first() != Some(&"delete") {
        return Err(PolicyError::unsupported(format!(
            "runsc {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output)
}
