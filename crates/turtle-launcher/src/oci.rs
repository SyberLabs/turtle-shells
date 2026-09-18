//! OCI runtime spec compiler and fail-closed inspection.
//!
//! Writing a spec is not enforcement. Inspection must reject host network,
//! inherited secrets, and host control sockets before `runsc create`.

use std::path::Path;

use serde_json::{json, Value};
use turtle_policy::PolicyError;

use crate::plan::LaunchPlan;

pub const RUNSC_RELEASE: &str = "release-20260817.0";
pub const NETWORK_ANNOTATION: &str = "org.syberlabs.turtle.network";

const FORBIDDEN_ENV: &[&str] = &[
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN",
    "DOCKER_HOST",
    "DOCKER_SECRET",
    "DISPLAY",
];

const FORBIDDEN_MOUNT_NEEDLES: &[&str] = &[
    "docker.sock",
    "ssh-agent",
    "SSH_AUTH_SOCK",
    "chrome-debug",
    "browser-debug",
    "/run/docker.sock",
    "/var/run/docker.sock",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxRequest<'a> {
    pub plan: &'a LaunchPlan,
    pub bundle_dir: &'a Path,
    pub rootfs: &'a Path,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub host_network: bool,
    pub has_network_namespace: bool,
    pub network_none: bool,
    pub forbidden_mounts: Vec<String>,
    pub forbidden_env: Vec<String>,
    pub no_new_privs: bool,
}

pub fn write_oci_bundle(req: &SandboxRequest<'_>) -> Result<Value, PolicyError> {
    if req.plan.host_network || req.plan.privileged {
        return Err(PolicyError::unsupported(
            "host network and privileged containers are not admitted",
        ));
    }
    if !req.plan.no_new_privs {
        return Err(PolicyError::unsupported("no_new_privs is required"));
    }
    std::fs::create_dir_all(req.bundle_dir)
        .map_err(|e| PolicyError::unsupported(format!("create bundle dir: {e}")))?;
    if !req.rootfs.is_dir() {
        return Err(PolicyError::unsupported(
            "runtime image not materialized: rootfs is missing",
        ));
    }
    let mut env = Vec::new();
    for key in &req.plan.env.allowlist {
        let value = match key.as_str() {
            "PATH" => "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME" => "/home/agent",
            "LANG" => "C",
            "TZ" => "UTC",
            "TURTLE_BROKER_URL" => "unix:/run/turtle/broker.sock",
            "TURTLE_INSTANCE" => "unset",
            _ => "",
        };
        env.push(format!("{key}={value}"));
    }
    let rootfs = req.rootfs.to_string_lossy().replace('\\', "/");
    let config = json!({
        "ociVersion": "1.1.0",
        "annotations": {
            "org.syberlabs.turtle.network": "none",
            "org.syberlabs.turtle.runsc": RUNSC_RELEASE
        },
        "process": {
            "terminal": false,
            "user": { "uid": 65534, "gid": 65534 },
            "args": req.plan.argv,
            "env": env,
            "cwd": if req.plan.cwd.is_empty() { "/" } else { req.plan.cwd.as_str() },
            "noNewPrivileges": true,
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": []
            }
        },
        "root": { "path": rootfs, "readonly": true },
        "hostname": "turtle",
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "noexec", "nodev"] },
            { "destination": "/home/agent", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev"] },
            { "destination": "/run/turtle", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "noexec", "nodev"] }
        ],
        "linux": {
            "namespaces": [
                { "type": "pid" },
                { "type": "network" },
                { "type": "ipc" },
                { "type": "uts" },
                { "type": "mount" }
            ],
            "maskedPaths": [
                "/proc/acpi",
                "/proc/kcore",
                "/proc/keys",
                "/proc/latency_stats",
                "/proc/timer_list",
                "/proc/timer_stats",
                "/proc/sched_debug",
                "/sys/firmware"
            ],
            "readonlyPaths": [
                "/proc/asound",
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger"
            ]
        }
    });
    inspect_oci(&config)?;
    let path = req.bundle_dir.join("config.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&config).map_err(|e| PolicyError::schema(e.to_string()))?,
    )
    .map_err(|e| PolicyError::unsupported(format!("write config.json: {e}")))?;
    Ok(config)
}

pub fn inspect_oci(config: &Value) -> Result<Inspection, PolicyError> {
    let process = config.get("process").cloned().unwrap_or(json!({}));
    let no_new_privs = process
        .get("noNewPrivileges")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let env = process
        .get("env")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut forbidden_env = Vec::new();
    for entry in &env {
        let Some(text) = entry.as_str() else {
            continue;
        };
        let key = text.split('=').next().unwrap_or(text);
        if FORBIDDEN_ENV.contains(&key) {
            forbidden_env.push(key.to_string());
        }
    }
    let mounts = config
        .get("mounts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut forbidden_mounts = Vec::new();
    for mount in &mounts {
        let dest = mount
            .get("destination")
            .and_then(Value::as_str)
            .unwrap_or("");
        let source = mount.get("source").and_then(Value::as_str).unwrap_or("");
        let ty = mount.get("type").and_then(Value::as_str).unwrap_or("");
        let blob = format!("{dest} {source} {ty}");
        if FORBIDDEN_MOUNT_NEEDLES.iter().any(|n| blob.contains(n)) {
            forbidden_mounts.push(dest.to_string());
        }
        if dest == "/proc" && ty == "bind" {
            forbidden_mounts.push(dest.to_string());
        }
    }
    let namespaces = config
        .pointer("/linux/namespaces")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has_network_namespace = namespaces
        .iter()
        .any(|ns| ns.get("type").and_then(Value::as_str) == Some("network"));
    let network_none = config
        .pointer("/annotations")
        .and_then(Value::as_object)
        .and_then(|m| m.get(NETWORK_ANNOTATION))
        .and_then(Value::as_str)
        == Some("none");
    let host_network = !has_network_namespace;
    let inspection = Inspection {
        host_network,
        has_network_namespace,
        network_none,
        forbidden_mounts,
        forbidden_env,
        no_new_privs,
    };
    if inspection.host_network
        || !inspection.network_none
        || !inspection.no_new_privs
        || !inspection.forbidden_env.is_empty()
        || !inspection.forbidden_mounts.is_empty()
    {
        return Err(PolicyError::unsupported(
            "OCI spec failed T04/T05/T07 inspection",
        ));
    }
    Ok(inspection)
}
