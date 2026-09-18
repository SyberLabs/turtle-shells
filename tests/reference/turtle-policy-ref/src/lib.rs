//! Independent reference evaluator.
//!
//! This crate reimplements the P0 eligibility formula and must not call
//! the production decision function.

use turtle_policy::actions::is_registered_action;
use turtle_policy::constraints::Constraint;
use turtle_policy::grant::{ClauseEffect, EffectiveGrant, GrantClause};
use turtle_policy::reason::{Decision, DecisionEvidence, ReasonCode};
use turtle_policy::{EffectRequest, TrustedContext};

pub fn decide(grant: &EffectiveGrant, request: &EffectRequest, ctx: &TrustedContext) -> Decision {
    if !ctx.turtle_active {
        return Decision::deny(ReasonCode::ENotActive, "inactive");
    }
    if !ctx.ancestors_active {
        return Decision::deny(ReasonCode::EAncestorRevoked, "ancestor revoked");
    }
    if !is_registered_action(&request.action) {
        return Decision::deny(ReasonCode::EUnknownAction, "unknown action");
    }
    if !ctx.adapter_valid {
        return Decision::deny(ReasonCode::EUnsupportedEnforcement, "adapter unsatisfied");
    }
    let layers = if ctx.layers.is_empty() {
        vec![grant.clone()]
    } else {
        ctx.layers.clone()
    };
    let mut last_allow: Option<DecisionEvidence> = None;
    let mut approval_needed = false;
    for layer in &layers {
        if request.preconditions.elapsed_seconds > layer.lifetime.max_seconds {
            return Decision::deny(ReasonCode::EExpired, "expired");
        }
        if !layer.disclosure.recipients.contains(&request.recipient) {
            return Decision::deny(ReasonCode::EDisclosure, "recipient not in envelope");
        }
        let mut deny_hit = false;
        let mut permit_hit: Option<&GrantClause> = None;
        for clause in &layer.clauses {
            if !matches_complete(clause, request) {
                continue;
            }
            if let Some(code) = constraints_block(clause, request) {
                return Decision::deny(code, "constraint");
            }
            match clause.effect {
                ClauseEffect::Deny => deny_hit = true,
                ClauseEffect::Permit => permit_hit = Some(clause),
            }
        }
        if deny_hit {
            return Decision::deny(ReasonCode::EPolicyDeny, "deny clause");
        }
        let Some(clause) = permit_hit else {
            return Decision::deny(ReasonCode::EResourceOutsideGrant, "no match");
        };
        if !matches!(
            clause.obligations.approval,
            turtle_policy::constraints::ApprovalObligation::None
        ) {
            approval_needed = true;
        }
        last_allow = Some(DecisionEvidence {
            clause_id: clause.id.as_str().to_string(),
            layer: "ref".to_string(),
            policy_digest: String::new(),
        });
    }
    if approval_needed && !ctx.approval_valid {
        return Decision::deny(ReasonCode::EApprovalRequired, "approval");
    }
    if request.preconditions.approval_stale {
        return Decision::deny(ReasonCode::EApprovalStale, "stale");
    }
    Decision::Allow(last_allow.unwrap_or(DecisionEvidence {
        clause_id: "none".to_string(),
        layer: "ref".to_string(),
        policy_digest: String::new(),
    }))
}

fn matches_complete(clause: &GrantClause, request: &EffectRequest) -> bool {
    clause.actions.iter().any(|a| a == &request.action)
        && clause.resources.iter().any(|r| r == &request.resource)
        && clause.recipients.iter().any(|r| r == &request.recipient)
}

fn constraints_block(clause: &GrantClause, request: &EffectRequest) -> Option<ReasonCode> {
    for (name, constraint) in clause.constraints.iter() {
        match constraint {
            Constraint::NumericMax { value, .. } => {
                let actual = match name.as_str() {
                    "maxInputBytes" => request.preconditions.input_bytes,
                    "maxOutputTokens" => request.preconditions.output_tokens,
                    "maxResponseBytes" => request.preconditions.response_bytes,
                    _ => return Some(ReasonCode::EUnsupportedEnforcement),
                }?;
                if actual > *value {
                    return Some(ReasonCode::EPrecondition);
                }
            }
            Constraint::NumericMin { value, .. } => {
                let actual = request.preconditions.input_bytes?;
                if actual < *value {
                    return Some(ReasonCode::EPrecondition);
                }
            }
            Constraint::Exact { value, .. } => {
                if request.preconditions.model.as_deref() != Some(value) {
                    return Some(ReasonCode::EPrecondition);
                }
            }
            Constraint::PathSubtrees { paths } => {
                let path = request.preconditions.path.as_ref()?;
                if !paths.iter().any(|root| path.is_under(root)) {
                    return Some(ReasonCode::EResourceOutsideGrant);
                }
            }
            Constraint::Approval { .. } => {}
        }
    }
    None
}
