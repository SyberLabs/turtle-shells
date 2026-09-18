//! Strict manifest parse and compile.

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::actions::is_registered_action_str;
use crate::constraints::{ConstraintSet, ObligationSet};
use crate::error::PolicyError;
use crate::grant::{
    AuditSpec, ClauseEffect, CredentialSpec, DelegationPolicy, DisclosureEnvelope, DomainBudgets,
    FilesystemSpec, GrantClause, Lifetime, LimitSet, LocalBudgets, McpSpec, NetworkSpec,
    RuntimeSpec, TurtlePolicy,
};
use crate::ids::{
    ActionId, ClauseId, CredentialBindingId, PolicyName, RecipientId, ResourceId, TemplateId,
};
use crate::limits::{MAX_GRANT_CLAUSES, MAX_RESOURCE_IDS_PER_CLAUSE};
use crate::path::RelPath;
use crate::schema::validate_instance;
use crate::yaml::yaml_to_json;

const ALLOWED_MOUNT: &str = "/workspace/repo";
const ALLOWED_CWD: &str = "/workspace/repo";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireDoc {
    api_version: String,
    kind: String,
    metadata: WireMeta,
    spec: WireSpec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMeta {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireSpec {
    profile: String,
    runtime: WireRuntime,
    lifetime: WireLifetime,
    filesystem: WireFilesystem,
    network: WireNetwork,
    data: WireData,
    credentials: WireCredentials,
    grants: Vec<Value>,
    mcp: WireMcp,
    limits: WireLimits,
    delegation: WireDelegation,
    audit: WireAudit,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireRuntime {
    image_ref: String,
    argv: Vec<String>,
    cwd: String,
    shell: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireLifetime {
    max_seconds: u64,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireFilesystem {
    snapshot_ref: String,
    mount_at: String,
    writable_subtrees: Vec<String>,
    #[serde(rename = "scratchMiB")]
    scratch_mib: u64,
    export_subtrees: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireNetwork {
    mode: String,
    raw_destinations: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireData {
    readable_classes: Vec<String>,
    recipients: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCredentials {
    bindings: Vec<String>,
    export: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireMcp {
    enabled_tools: Vec<String>,
    resource_reads: bool,
    prompts: bool,
    sampling: bool,
    elicitation: bool,
    async_tasks: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLimits {
    domain: WireDomain,
    local: WireLocal,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireDomain {
    provider_attempts: u64,
    external_mutations: u64,
    inference_output_tokens: u64,
    outbound_payload_bytes: u64,
    #[serde(rename = "memoryMiB")]
    memory_mib: u64,
    pids: u64,
    cpu_millis_per_second: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireLocal {
    #[serde(rename = "memoryMiB")]
    memory_mib: u64,
    pids: u64,
    cpu_millis_per_second: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireDelegation {
    max_depth: u8,
    max_live_children: u32,
    max_total_descendants: u32,
    allowed_templates: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireAudit {
    required: bool,
    payload_mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGrant {
    id: String,
    #[serde(default)]
    effect: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    actions: Option<Vec<String>>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    resources: Option<Vec<String>>,
    #[serde(default)]
    credential: Option<String>,
    recipients: Vec<String>,
    #[serde(default)]
    constraints: Map<String, Value>,
    #[serde(default)]
    obligations: Option<WireObligations>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireObligations {
    #[serde(default)]
    approval: Option<String>,
}

pub fn parse_manifest(bytes: &[u8]) -> Result<TurtlePolicy, PolicyError> {
    let json = yaml_to_json(bytes)?;
    validate_instance(&json)?;
    let wire: WireDoc =
        serde_json::from_value(json).map_err(|e| PolicyError::schema(e.to_string()))?;
    compile_wire(wire)
}

fn compile_wire(wire: WireDoc) -> Result<TurtlePolicy, PolicyError> {
    if wire.api_version != crate::API_VERSION {
        return Err(PolicyError::schema("unsupported apiVersion"));
    }
    if wire.kind != "TurtlePolicy" {
        return Err(PolicyError::schema("kind must be TurtlePolicy"));
    }
    if wire.spec.profile != "strict-local-v1" {
        return Err(PolicyError::unsupported("unsupported profile"));
    }
    let name = PolicyName::new(wire.metadata.name)?;
    if wire.spec.runtime.cwd != ALLOWED_CWD {
        return Err(PolicyError::schema(format!(
            "cwd must be {ALLOWED_CWD} in P0"
        )));
    }
    if wire.spec.filesystem.mount_at != ALLOWED_MOUNT {
        return Err(PolicyError::schema(format!(
            "mountAt must be {ALLOWED_MOUNT} in P0"
        )));
    }
    if wire.spec.network.mode != "broker-only" {
        return Err(PolicyError::unsupported("network.mode must be broker-only"));
    }
    if !wire.spec.network.raw_destinations.is_empty() {
        return Err(PolicyError::unsupported("rawDestinations are not allowed"));
    }
    if wire.spec.credentials.export {
        return Err(PolicyError::unsupported("credential export is not allowed"));
    }
    if wire.spec.lifetime.max_seconds == 0 || wire.spec.lifetime.max_seconds > 86_400 {
        return Err(PolicyError::schema("maxSeconds out of range"));
    }
    if wire.spec.delegation.max_depth > crate::limits::MAX_DELEGATION_DEPTH {
        return Err(PolicyError::schema("delegation depth exceeds maximum of 4"));
    }
    if wire.spec.audit.payload_mode != "digest-and-metadata" {
        return Err(PolicyError::unsupported("unsupported audit payloadMode"));
    }

    let writable = parse_paths(&wire.spec.filesystem.writable_subtrees)?;
    let export = parse_paths(&wire.spec.filesystem.export_subtrees)?;
    reject_overlaps(&writable)?;
    reject_overlaps(&export)?;

    let mut envelope_recipients = BTreeSet::new();
    for recipient in &wire.spec.data.recipients {
        envelope_recipients.insert(RecipientId::new(recipient.clone())?);
    }
    let mut bindings = BTreeSet::new();
    for binding in &wire.spec.credentials.bindings {
        bindings.insert(CredentialBindingId::new(binding.clone())?);
    }

    if wire.spec.grants.len() > MAX_GRANT_CLAUSES {
        return Err(PolicyError::schema("too many grant clauses"));
    }

    let mut clauses = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for grant in wire.spec.grants {
        let clause = compile_grant(grant, &bindings, &envelope_recipients)?;
        if !seen_ids.insert(clause.id.as_str().to_string()) {
            return Err(PolicyError::schema(format!(
                "duplicate grant id `{}`",
                clause.id
            )));
        }
        clauses.push(clause);
    }

    let lifetime = Lifetime {
        max_seconds: wire.spec.lifetime.max_seconds,
        expires_at: match wire.spec.lifetime.expires_at {
            Some(raw) => Some(parse_expires_at(&raw)?),
            None => None,
        },
    };

    let mut templates = BTreeSet::new();
    for template in wire.spec.delegation.allowed_templates {
        templates.insert(TemplateId::new(template)?);
    }

    let filesystem = FilesystemSpec {
        snapshot_ref: wire.spec.filesystem.snapshot_ref,
        mount_at: wire.spec.filesystem.mount_at,
        writable_subtrees: writable,
        scratch_mib: wire.spec.filesystem.scratch_mib,
        export_subtrees: export,
    };
    let disclosure = DisclosureEnvelope {
        readable_classes: wire.spec.data.readable_classes.into_iter().collect(),
        recipients: envelope_recipients,
    };
    let credentials = CredentialSpec {
        bindings,
        export: false,
    };
    let limits = LimitSet {
        domain: DomainBudgets {
            provider_attempts: wire.spec.limits.domain.provider_attempts,
            external_mutations: wire.spec.limits.domain.external_mutations,
            inference_output_tokens: wire.spec.limits.domain.inference_output_tokens,
            outbound_payload_bytes: wire.spec.limits.domain.outbound_payload_bytes,
            memory_mib: Some(wire.spec.limits.domain.memory_mib),
            pids: Some(wire.spec.limits.domain.pids),
            cpu_millis_per_second: Some(wire.spec.limits.domain.cpu_millis_per_second),
        },
        local: LocalBudgets {
            memory_mib: Some(wire.spec.limits.local.memory_mib),
            pids: Some(wire.spec.limits.local.pids),
            cpu_millis_per_second: Some(wire.spec.limits.local.cpu_millis_per_second),
        },
    };
    let delegation = DelegationPolicy {
        max_depth: wire.spec.delegation.max_depth,
        max_live_children: wire.spec.delegation.max_live_children,
        max_total_descendants: wire.spec.delegation.max_total_descendants,
        allowed_templates: templates,
    };
    let runtime = RuntimeSpec {
        image_ref: wire.spec.runtime.image_ref,
        argv: wire.spec.runtime.argv,
        cwd: wire.spec.runtime.cwd,
        shell: wire.spec.runtime.shell,
    };
    let mcp = McpSpec {
        enabled_tools: wire.spec.mcp.enabled_tools,
        resource_reads: wire.spec.mcp.resource_reads,
        prompts: wire.spec.mcp.prompts,
        sampling: wire.spec.mcp.sampling,
        elicitation: wire.spec.mcp.elicitation,
        async_tasks: wire.spec.mcp.async_tasks,
    };
    let audit = AuditSpec {
        required: wire.spec.audit.required,
        payload_mode: wire.spec.audit.payload_mode,
    };

    let canonical = canonical_policy(
        name.as_str(),
        &clauses,
        &limits,
        &delegation,
        &lifetime,
        &disclosure,
        &filesystem,
        &credentials,
        &mcp,
        &runtime,
        &audit,
    );

    Ok(TurtlePolicy::new(
        name.as_str().to_string(),
        canonical,
        clauses,
        limits,
        delegation,
        lifetime,
        disclosure,
        filesystem,
        NetworkSpec {
            mode: "broker-only".to_string(),
        },
        credentials,
        mcp,
        runtime,
        audit,
    ))
}

fn compile_grant(
    value: Value,
    bindings: &BTreeSet<CredentialBindingId>,
    envelope_recipients: &BTreeSet<RecipientId>,
) -> Result<GrantClause, PolicyError> {
    let wire: WireGrant =
        serde_json::from_value(value).map_err(|e| PolicyError::schema(e.to_string()))?;
    let actions = exclusive_set(wire.action, wire.actions, "action")?;
    let resources = exclusive_set(wire.resource, wire.resources, "resource")?;
    if resources.len() > MAX_RESOURCE_IDS_PER_CLAUSE {
        return Err(PolicyError::schema("too many resource IDs in clause"));
    }
    let mut action_set = BTreeSet::new();
    for action in actions {
        if !is_registered_action_str(&action) {
            return Err(PolicyError::unknown_action(format!(
                "unknown action `{action}`"
            )));
        }
        action_set.insert(ActionId::new(action)?);
    }
    let mut resource_set = BTreeSet::new();
    for resource in resources {
        resource_set.insert(ResourceId::new(resource)?);
    }
    let mut recipients = BTreeSet::new();
    for recipient in wire.recipients {
        let id = RecipientId::new(recipient)?;
        if !envelope_recipients.contains(&id) {
            return Err(PolicyError::schema(format!(
                "recipient `{id}` is not in the disclosure envelope"
            )));
        }
        recipients.insert(id);
    }
    let credential = match wire.credential {
        Some(raw) => {
            let id = CredentialBindingId::new(raw)?;
            if !bindings.contains(&id) {
                return Err(PolicyError::schema(format!(
                    "credential binding `{id}` is not declared"
                )));
            }
            Some(id)
        }
        None => None,
    };
    let constraints = ConstraintSet::from_yaml_map(&wire.constraints)?;
    let mut obligations = ObligationSet::from_constraints(&constraints);
    if let Some(extra) = wire.obligations {
        if let Some(approval) = extra.approval {
            obligations.approval = match approval.as_str() {
                "none" => crate::constraints::ApprovalObligation::None,
                "exact" => crate::constraints::ApprovalObligation::Exact,
                other => {
                    return Err(PolicyError::unsupported(format!(
                        "unsupported approval obligation `{other}`"
                    )));
                }
            };
        }
    }
    let effect = match wire.effect.as_deref() {
        None | Some("permit") => ClauseEffect::Permit,
        Some("deny") => ClauseEffect::Deny,
        Some(other) => return Err(PolicyError::schema(format!("unsupported effect `{other}`"))),
    };
    Ok(GrantClause {
        id: ClauseId::new(wire.id)?,
        effect,
        actions: action_set,
        resources: resource_set,
        credential,
        recipients,
        constraints,
        obligations,
    })
}

fn exclusive_set(
    singular: Option<String>,
    plural: Option<Vec<String>>,
    field: &str,
) -> Result<Vec<String>, PolicyError> {
    match (singular, plural) {
        (Some(one), None) => Ok(vec![one]),
        (None, Some(many)) => {
            if many.is_empty() {
                Err(PolicyError::schema(format!("{field}s must not be empty")))
            } else {
                Ok(many)
            }
        }
        (Some(_), Some(_)) => Err(PolicyError::schema(format!(
            "specify `{field}` or `{field}s`, not both"
        ))),
        (None, None) => Err(PolicyError::schema(format!("missing {field}"))),
    }
}

fn parse_paths(items: &[String]) -> Result<Vec<RelPath>, PolicyError> {
    if items.len() > crate::limits::MAX_PATH_ROOTS {
        return Err(PolicyError::schema("too many path roots"));
    }
    items.iter().map(|p| RelPath::parse(p)).collect()
}

fn reject_overlaps(paths: &[RelPath]) -> Result<(), PolicyError> {
    for (i, a) in paths.iter().enumerate() {
        for b in paths.iter().skip(i + 1) {
            if a.overlaps(b) {
                return Err(PolicyError::schema(format!(
                    "overlapping path roots `{a}` and `{b}`"
                )));
            }
        }
    }
    Ok(())
}

fn parse_expires_at(raw: &str) -> Result<u64, PolicyError> {
    if let Ok(n) = raw.parse::<u64>() {
        return Ok(n);
    }
    Err(PolicyError::schema(
        "expiresAt must be a decimal unix timestamp string",
    ))
}

#[allow(clippy::too_many_arguments)]
fn canonical_policy(
    name: &str,
    clauses: &[GrantClause],
    limits: &LimitSet,
    delegation: &DelegationPolicy,
    lifetime: &Lifetime,
    disclosure: &DisclosureEnvelope,
    filesystem: &FilesystemSpec,
    credentials: &CredentialSpec,
    mcp: &McpSpec,
    runtime: &RuntimeSpec,
    audit: &AuditSpec,
) -> Value {
    serde_json::json!({
        "apiVersion": crate::API_VERSION,
        "kind": "TurtlePolicy",
        "metadata": { "name": name },
        "spec": {
            "profile": "strict-local-v1",
            "runtime": runtime,
            "lifetime": lifetime,
            "filesystem": filesystem,
            "network": { "mode": "broker-only", "rawDestinations": [] },
            "data": disclosure,
            "credentials": credentials,
            "grants": clauses,
            "mcp": mcp,
            "limits": limits,
            "delegation": delegation,
            "audit": audit,
        }
    })
}
