//! Fail-closed host capability probe.

use std::process::Command;

pub const P1_CLAIM_CEILING: &str = "Local execution containment within tested backend assumptions.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProbe {
    pub os: &'static str,
    pub openat2: bool,
    pub runsc: Option<String>,
    pub certified: bool,
    pub failures: Vec<String>,
}

pub fn probe_host() -> HostProbe {
    let mut failures = Vec::new();
    let os = std::env::consts::OS;
    let openat2 = turtle_snapshot::openat2_available();
    if !cfg!(target_os = "linux") {
        failures.push(format!("host is {os}, not Linux"));
    }
    if !openat2 {
        failures.push("openat2 unavailable".to_string());
    }
    let runsc = find_runsc();
    if runsc.is_none() {
        failures.push("gVisor runsc not found on PATH".to_string());
    }
    let certified = failures.is_empty();
    HostProbe {
        os,
        openat2,
        runsc,
        certified,
        failures,
    }
}

fn find_runsc() -> Option<String> {
    let output = Command::new("runsc").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next().unwrap_or("runsc").trim();
    if line.is_empty() {
        Some("runsc".to_string())
    } else {
        Some(line.to_string())
    }
}
