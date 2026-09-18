//! Machine-readable enforcement plan. P0 never claims runtime enforcement.

use serde::{Deserialize, Serialize};

use crate::digest::policy_digest;
use crate::grant::TurtlePolicy;
use crate::CLAIM_CEILING;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementStatus {
    Enforced,
    Unsupported,
    NotRequested,
    ExternalAssumption,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementRequirement {
    pub constraint_id: String,
    pub plane: String,
    pub mechanism: String,
    pub backend_version: Option<String>,
    pub status: EnforcementStatus,
    pub test_profile: Option<String>,
    pub limitation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPlan {
    pub policy_digest: String,
    pub claim_ceiling: String,
    pub requirements: Vec<EnforcementRequirement>,
}

pub fn enforcement_plan(policy: &TurtlePolicy) -> EnforcementPlan {
    let digest = policy_digest(policy)
        .map(|d| d.hex())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut requirements = vec![
        req(
            "grants",
            "policy",
            "semantic-check-only",
            EnforcementStatus::Unsupported,
        ),
        req(
            "attenuation",
            "policy",
            "semantic-check-only",
            EnforcementStatus::Unsupported,
        ),
        req(
            "budgets",
            "accounting",
            "in-memory-simulated-ledger",
            EnforcementStatus::Unsupported,
        ),
        req(
            "filesystem",
            "sandbox",
            "snapshot-and-writable-subtrees",
            EnforcementStatus::Unsupported,
        ),
        req(
            "network",
            "sandbox",
            "broker-only-dataplane",
            EnforcementStatus::Unsupported,
        ),
        req(
            "credentials",
            "broker",
            "driver-held-bindings",
            EnforcementStatus::Unsupported,
        ),
        req(
            "mcp",
            "broker",
            "typed-tool-gateway",
            EnforcementStatus::Unsupported,
        ),
        req(
            "occupancy",
            "cgroup",
            "memory-pid-cpu",
            EnforcementStatus::Unsupported,
        ),
    ];
    if policy.filesystem().writable_subtrees.is_empty()
        && policy.limits().domain.external_mutations == 0
    {
        requirements.push(req(
            "external-mutations",
            "policy",
            "no-mutation-grant",
            EnforcementStatus::NotRequested,
        ));
    }
    EnforcementPlan {
        policy_digest: digest,
        claim_ceiling: CLAIM_CEILING.to_string(),
        requirements,
    }
}

fn req(
    constraint_id: &str,
    plane: &str,
    mechanism: &str,
    status: EnforcementStatus,
) -> EnforcementRequirement {
    EnforcementRequirement {
        constraint_id: constraint_id.to_string(),
        plane: plane.to_string(),
        mechanism: mechanism.to_string(),
        backend_version: None,
        status,
        test_profile: None,
        limitation: "not deployed in P0".to_string(),
    }
}
