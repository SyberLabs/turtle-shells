//! Canonical internal grant types. Clauses remain correlated tuples.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::constraints::{ConstraintSet, ObligationSet};
use crate::ids::{ActionId, ClauseId, CredentialBindingId, RecipientId, ResourceId, TemplateId};
use crate::path::RelPath;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClauseEffect {
    Permit,
    Deny,
}

pub type ActionSet = BTreeSet<ActionId>;
pub type ResourceSet = BTreeSet<ResourceId>;
pub type RecipientSet = BTreeSet<RecipientId>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantClause {
    pub id: ClauseId,
    pub effect: ClauseEffect,
    pub actions: ActionSet,
    pub resources: ResourceSet,
    pub credential: Option<CredentialBindingId>,
    pub recipients: RecipientSet,
    pub constraints: ConstraintSet,
    pub obligations: ObligationSet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurtleIdentity {
    pub id: String,
    pub root_id: String,
    pub parent_id: Option<String>,
    pub subject_binding: String,
}

impl TurtleIdentity {
    pub fn root(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            root_id: id.clone(),
            parent_id: None,
            subject_binding: id.clone(),
            id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainBudgets {
    pub provider_attempts: u64,
    pub external_mutations: u64,
    pub inference_output_tokens: u64,
    pub outbound_payload_bytes: u64,
    pub memory_mib: Option<u64>,
    pub pids: Option<u64>,
    pub cpu_millis_per_second: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalBudgets {
    pub memory_mib: Option<u64>,
    pub pids: Option<u64>,
    pub cpu_millis_per_second: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitSet {
    pub domain: DomainBudgets,
    pub local: LocalBudgets,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationPolicy {
    pub max_depth: u8,
    pub max_live_children: u32,
    pub max_total_descendants: u32,
    pub allowed_templates: BTreeSet<TemplateId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lifetime {
    pub max_seconds: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionVector {
    pub policy: u64,
    pub registry: u64,
    pub runtime: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureEnvelope {
    pub readable_classes: BTreeSet<String>,
    pub recipients: RecipientSet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemSpec {
    pub snapshot_ref: String,
    pub mount_at: String,
    pub writable_subtrees: Vec<RelPath>,
    pub scratch_mib: u64,
    pub export_subtrees: Vec<RelPath>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSpec {
    pub mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSpec {
    pub bindings: BTreeSet<CredentialBindingId>,
    pub export: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSpec {
    pub enabled_tools: Vec<String>,
    pub resource_reads: bool,
    pub prompts: bool,
    pub sampling: bool,
    pub elicitation: bool,
    pub async_tasks: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSpec {
    pub image_ref: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub shell: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSpec {
    pub required: bool,
    pub payload_mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveGrant {
    pub identity: TurtleIdentity,
    pub clauses: Vec<GrantClause>,
    pub limits: LimitSet,
    pub delegation: DelegationPolicy,
    pub lifetime: Lifetime,
    pub revisions: RevisionVector,
    pub disclosure: DisclosureEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurtlePolicy {
    name: String,
    canonical: serde_json::Value,
    clauses: Vec<GrantClause>,
    limits: LimitSet,
    delegation: DelegationPolicy,
    lifetime: Lifetime,
    disclosure: DisclosureEnvelope,
    filesystem: FilesystemSpec,
    network: NetworkSpec,
    credentials: CredentialSpec,
    mcp: McpSpec,
    runtime: RuntimeSpec,
    audit: AuditSpec,
}

impl TurtlePolicy {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        name: String,
        canonical: serde_json::Value,
        clauses: Vec<GrantClause>,
        limits: LimitSet,
        delegation: DelegationPolicy,
        lifetime: Lifetime,
        disclosure: DisclosureEnvelope,
        filesystem: FilesystemSpec,
        network: NetworkSpec,
        credentials: CredentialSpec,
        mcp: McpSpec,
        runtime: RuntimeSpec,
        audit: AuditSpec,
    ) -> Self {
        Self {
            name,
            canonical,
            clauses,
            limits,
            delegation,
            lifetime,
            disclosure,
            filesystem,
            network,
            credentials,
            mcp,
            runtime,
            audit,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn clauses(&self) -> &[GrantClause] {
        &self.clauses
    }

    pub fn canonical_json(&self) -> &serde_json::Value {
        &self.canonical
    }

    pub fn limits(&self) -> &LimitSet {
        &self.limits
    }

    pub fn delegation(&self) -> &DelegationPolicy {
        &self.delegation
    }

    pub fn lifetime(&self) -> &Lifetime {
        &self.lifetime
    }

    pub fn disclosure(&self) -> &DisclosureEnvelope {
        &self.disclosure
    }

    pub fn filesystem(&self) -> &FilesystemSpec {
        &self.filesystem
    }

    pub fn network(&self) -> &NetworkSpec {
        &self.network
    }

    pub fn credentials(&self) -> &CredentialSpec {
        &self.credentials
    }

    pub fn mcp(&self) -> &McpSpec {
        &self.mcp
    }

    pub fn runtime(&self) -> &RuntimeSpec {
        &self.runtime
    }

    pub fn audit(&self) -> &AuditSpec {
        &self.audit
    }

    pub fn compile(&self, identity: TurtleIdentity) -> EffectiveGrant {
        EffectiveGrant {
            identity,
            clauses: self.clauses.clone(),
            limits: self.limits.clone(),
            delegation: self.delegation.clone(),
            lifetime: self.lifetime.clone(),
            revisions: RevisionVector::default(),
            disclosure: self.disclosure.clone(),
        }
    }
}
