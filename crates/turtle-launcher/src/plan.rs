//! Compile a policy into a launch plan. This is not runtime enforcement.

use std::collections::BTreeSet;

use turtle_policy::{PolicyError, TurtlePolicy};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountSource {
    Snapshot,
    Scratch,
    RuntimeImage,
    WritableCopy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountSpec {
    pub destination: String,
    pub source_kind: MountSource,
    pub writable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkPlan {
    pub mode: String,
    pub raw_destinations_forbidden: bool,
    pub allow_dns: bool,
    pub allow_udp: bool,
    pub broker_endpoint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvPlan {
    pub allowlist: BTreeSet<String>,
    pub inherit_none: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccupancyPlan {
    pub memory_mib: Option<u64>,
    pub pids: Option<u64>,
    pub cpu_millis_per_second: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchPlan {
    pub mounts: Vec<MountSpec>,
    pub network: NetworkPlan,
    pub env: EnvPlan,
    pub no_new_privs: bool,
    pub host_network: bool,
    pub privileged: bool,
    pub occupancy: OccupancyPlan,
    pub argv: Vec<String>,
    pub cwd: String,
}

const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "TZ",
    "TURTLE_BROKER_URL",
    "TURTLE_INSTANCE",
];

pub fn compile_launch_plan(policy: &TurtlePolicy) -> Result<LaunchPlan, PolicyError> {
    if policy.network().mode != "broker-only" {
        return Err(PolicyError::unsupported(
            "P1 launch requires network.mode=broker-only",
        ));
    }
    let mount_at = policy.filesystem().mount_at.clone();
    let mut mounts = vec![
        MountSpec {
            destination: "/usr".to_string(),
            source_kind: MountSource::RuntimeImage,
            writable: false,
        },
        MountSpec {
            destination: "/opt/agent".to_string(),
            source_kind: MountSource::RuntimeImage,
            writable: false,
        },
        MountSpec {
            destination: mount_at.clone(),
            source_kind: MountSource::Snapshot,
            writable: false,
        },
        MountSpec {
            destination: "/tmp".to_string(),
            source_kind: MountSource::Scratch,
            writable: true,
        },
        MountSpec {
            destination: "/home/agent".to_string(),
            source_kind: MountSource::Scratch,
            writable: true,
        },
        MountSpec {
            destination: "/run/turtle".to_string(),
            source_kind: MountSource::RuntimeImage,
            writable: false,
        },
    ];
    for subtree in &policy.filesystem().writable_subtrees {
        mounts.push(MountSpec {
            destination: format!("{mount_at}/{subtree}"),
            source_kind: MountSource::WritableCopy,
            writable: true,
        });
    }
    let mut allowlist = BTreeSet::new();
    for key in ENV_ALLOWLIST {
        allowlist.insert((*key).to_string());
    }
    Ok(LaunchPlan {
        mounts,
        network: NetworkPlan {
            mode: "broker-only".to_string(),
            raw_destinations_forbidden: true,
            allow_dns: false,
            allow_udp: false,
            broker_endpoint: None,
        },
        env: EnvPlan {
            allowlist,
            inherit_none: true,
        },
        no_new_privs: true,
        host_network: false,
        privileged: false,
        occupancy: OccupancyPlan {
            memory_mib: policy.limits().local.memory_mib,
            pids: policy.limits().local.pids,
            cpu_millis_per_second: policy.limits().local.cpu_millis_per_second,
        },
        argv: policy.runtime().argv.clone(),
        cwd: policy.runtime().cwd.clone(),
    })
}
