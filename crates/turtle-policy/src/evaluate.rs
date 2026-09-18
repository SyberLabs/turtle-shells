//! Deterministic policy evaluation. Subject and grant come from trusted context.

use serde::{Deserialize, Serialize};

use crate::actions::is_registered_action;
use crate::budget::{BudgetLedger, BudgetMetric};
use crate::constraints::{Constraint, ObligationSet};
use crate::digest::Digest;
use crate::grant::{ClauseEffect, EffectiveGrant, GrantClause};
use crate::ids::{ActionId, OperationKey, RecipientId, ResourceId};
use crate::path::RelPath;
use crate::reason::{Decision, DecisionEvidence, Denial, ReasonCode};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Preconditions {
    #[serde(default)]
    pub elapsed_seconds: u64,
    pub input_bytes: Option<u64>,
    pub output_tokens: Option<u64>,
    pub response_bytes: Option<u64>,
    pub path: Option<RelPath>,
    pub model: Option<String>,
    #[serde(default)]
    pub approval_stale: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EffectRequest {
    pub operation_key: OperationKey,
    pub action: ActionId,
    pub resource: ResourceId,
    pub arguments_digest: Digest,
    pub recipient: RecipientId,
    pub preconditions: Preconditions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedContext {
    pub subject: crate::grant::TurtleIdentity,
    pub turtle_active: bool,
    pub ancestors_active: bool,
    pub adapter_valid: bool,
    pub approval_valid: bool,
    pub now: u64,
    pub layers: Vec<EffectiveGrant>,
}

impl TrustedContext {
    pub fn for_grant(grant: EffectiveGrant) -> Self {
        Self {
            subject: grant.identity.clone(),
            turtle_active: true,
            ancestors_active: true,
            adapter_valid: false,
            approval_valid: false,
            now: 0,
            layers: vec![grant],
        }
    }
}

pub fn evaluate(
    grant: &EffectiveGrant,
    request: &EffectRequest,
    ctx: &TrustedContext,
    budget: Option<&BudgetLedger>,
) -> Decision {
    let mut ctx = ctx.clone();
    if ctx.layers.is_empty() {
        ctx.layers = vec![grant.clone()];
    }
    evaluate_layers(&ctx, request, budget)
}

pub fn evaluate_layers(
    ctx: &TrustedContext,
    request: &EffectRequest,
    budget: Option<&BudgetLedger>,
) -> Decision {
    if !ctx.turtle_active {
        return Decision::deny(ReasonCode::ENotActive, "turtle is not active");
    }
    if !ctx.ancestors_active {
        return Decision::deny(
            ReasonCode::EAncestorRevoked,
            "an ancestor turtle is revoked",
        );
    }
    if !is_registered_action(&request.action) {
        return Decision::deny(ReasonCode::EUnknownAction, "action is not registered");
    }
    if ctx.layers.is_empty() {
        return Decision::deny(ReasonCode::EIdentity, "missing trusted grant layers");
    }
    for layer in &ctx.layers {
        if let Some(denial) = lifetime_denial(layer, request) {
            return Decision::Deny(denial);
        }
    }
    if !ctx.adapter_valid {
        return Decision::deny(
            ReasonCode::EUnsupportedEnforcement,
            "adapter validity was unsatisfied",
        );
    }

    let mut evidence: Option<DecisionEvidence> = None;
    let mut matched_obligations = ObligationSet::default();
    for (index, layer) in ctx.layers.iter().enumerate() {
        match layer_decision(layer, request, index) {
            Decision::Deny(denial) => return Decision::Deny(denial),
            Decision::Allow(ev) => {
                if let Some(clause) = layer.clauses.iter().find(|c| c.id.as_str() == ev.clause_id) {
                    matched_obligations = clause.obligations.clone();
                }
                evidence = Some(ev);
            }
        }
    }

    if request.preconditions.approval_stale {
        return Decision::deny(ReasonCode::EApprovalStale, "approval is stale");
    }
    if !matched_obligations.is_satisfied(ctx.approval_valid) {
        return Decision::deny(ReasonCode::EApprovalRequired, "exact approval is required");
    }

    if let Some(denial) = reserve_budget(request, budget) {
        return Decision::Deny(denial);
    }

    Decision::Allow(evidence.unwrap_or(DecisionEvidence {
        clause_id: "unknown".to_string(),
        layer: "owner".to_string(),
        policy_digest: String::new(),
    }))
}

fn lifetime_denial(grant: &EffectiveGrant, request: &EffectRequest) -> Option<Denial> {
    if request.preconditions.elapsed_seconds > grant.lifetime.max_seconds {
        return Some(Denial::new(
            ReasonCode::EExpired,
            "elapsed runtime exceeds maxSeconds",
        ));
    }
    if let Some(expires_at) = grant.lifetime.expires_at {
        if expires_at == 0 {
            return Some(Denial::new(ReasonCode::EExpired, "grant expiry is invalid"));
        }
    }
    None
}

fn layer_decision(layer: &EffectiveGrant, request: &EffectRequest, index: usize) -> Decision {
    if !layer.disclosure.recipients.contains(&request.recipient) {
        return Decision::deny(
            ReasonCode::EDisclosure,
            "recipient is outside the disclosure envelope",
        );
    }
    if !disclosure_compatible(
        &layer.disclosure.readable_classes,
        request.recipient.as_str(),
    ) {
        return Decision::deny(
            ReasonCode::EDisclosure,
            "recipient is incompatible with readable data classes",
        );
    }

    let mut permit: Option<&GrantClause> = None;
    for clause in &layer.clauses {
        if !clause_matches(clause, request) {
            continue;
        }
        if let Some(denial) = constraint_denial(clause, request) {
            return Decision::Deny(denial);
        }
        match clause.effect {
            ClauseEffect::Deny => {
                return Decision::Deny(
                    Denial::new(ReasonCode::EPolicyDeny, "matching deny clause")
                        .with_constraint(clause.id.as_str()),
                );
            }
            ClauseEffect::Permit => permit = Some(clause),
        }
    }
    match permit {
        Some(clause) => Decision::Allow(DecisionEvidence {
            clause_id: clause.id.as_str().to_string(),
            layer: if index == 0 {
                "owner".to_string()
            } else {
                format!("layer-{index}")
            },
            policy_digest: String::new(),
        }),
        None => Decision::deny(
            ReasonCode::EResourceOutsideGrant,
            "no complete grant clause matches the request",
        ),
    }
}

fn clause_matches(clause: &GrantClause, request: &EffectRequest) -> bool {
    clause.actions.contains(&request.action)
        && clause.resources.contains(&request.resource)
        && clause.recipients.contains(&request.recipient)
}

fn constraint_denial(clause: &GrantClause, request: &EffectRequest) -> Option<Denial> {
    for (name, constraint) in clause.constraints.iter() {
        match constraint {
            Constraint::NumericMax { value, .. } => {
                let actual = match name.as_str() {
                    "maxInputBytes" => request.preconditions.input_bytes,
                    "maxOutputTokens" => request.preconditions.output_tokens,
                    "maxResponseBytes" => request.preconditions.response_bytes,
                    _ => {
                        return Some(Denial::new(
                            ReasonCode::EUnsupportedEnforcement,
                            format!("unsupported numeric maximum `{name}`"),
                        ));
                    }
                };
                let Some(actual) = actual else {
                    return Some(Denial::new(
                        ReasonCode::EPrecondition,
                        format!("missing precondition for `{name}`"),
                    ));
                };
                if actual > *value {
                    return Some(
                        Denial::new(ReasonCode::EPrecondition, format!("`{name}` exceeded"))
                            .with_constraint(clause.id.as_str()),
                    );
                }
            }
            Constraint::NumericMin { value, .. } => {
                let Some(actual) = request.preconditions.input_bytes else {
                    return Some(Denial::new(
                        ReasonCode::EPrecondition,
                        format!("missing precondition for `{name}`"),
                    ));
                };
                if actual < *value {
                    return Some(Denial::new(
                        ReasonCode::EPrecondition,
                        format!("`{name}` not met"),
                    ));
                }
            }
            Constraint::Exact { value, .. } => {
                let Some(model) = request.preconditions.model.as_deref() else {
                    return Some(Denial::new(
                        ReasonCode::EPrecondition,
                        "missing exact model",
                    ));
                };
                if model != value {
                    return Some(Denial::new(
                        ReasonCode::EPrecondition,
                        "exact field mismatch",
                    ));
                }
            }
            Constraint::PathSubtrees { paths } => {
                let Some(path) = request.preconditions.path.as_ref() else {
                    return Some(Denial::new(ReasonCode::EPrecondition, "missing path"));
                };
                if !paths.iter().any(|root| path.is_under(root)) {
                    return Some(Denial::new(
                        ReasonCode::EResourceOutsideGrant,
                        "path is outside granted subtrees",
                    ));
                }
            }
            Constraint::Approval { .. } => {}
        }
    }
    None
}

fn disclosure_compatible(readable: &std::collections::BTreeSet<String>, recipient: &str) -> bool {
    if readable.is_empty() {
        return true;
    }
    for class in readable {
        match class.as_str() {
            "internal-source" => {
                if !matches!(
                    recipient,
                    "owner-local" | "approved-inference-provider" | "approved-code-provider"
                ) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn reserve_budget(request: &EffectRequest, budget: Option<&BudgetLedger>) -> Option<Denial> {
    let costs = costs_for(request);
    if costs.iter().all(|(_, amount)| *amount == 0) {
        return None;
    }
    let Some(ledger) = budget else {
        return Some(Denial::new(
            ReasonCode::EBudget,
            "budget ledger missing for a costly operation",
        ));
    };
    for (metric, amount) in costs {
        if let Err(denial) = ledger.try_reserve(metric, amount, &request.operation_key) {
            return Some(denial);
        }
    }
    None
}

fn costs_for(request: &EffectRequest) -> Vec<(BudgetMetric, u64)> {
    match request.action.as_str() {
        "github.repository.read" => vec![(BudgetMetric::ProviderAttempts, 1)],
        "github.repository.write" => vec![
            (BudgetMetric::ProviderAttempts, 1),
            (BudgetMetric::ExternalMutations, 1),
        ],
        "inference.generate" => vec![
            (BudgetMetric::ProviderAttempts, 1),
            (
                BudgetMetric::InferenceOutputTokens,
                request.preconditions.output_tokens.unwrap_or(1),
            ),
        ],
        "artifact.export" => vec![(
            BudgetMetric::OutboundPayloadBytes,
            request.preconditions.response_bytes.unwrap_or(1),
        )],
        _ => vec![],
    }
}
