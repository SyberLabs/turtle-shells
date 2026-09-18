//! Conservative one-parent-clause subsumption. Unions are rejected.

use crate::constraints::{Constraint, ObligationSet};
use crate::grant::{ClauseEffect, EffectiveGrant, GrantClause};
use crate::reason::{Denial, ReasonCode};

pub fn check_attenuation(parent: &EffectiveGrant, child: &EffectiveGrant) -> Result<(), Denial> {
    if child.identity.root_id != parent.identity.root_id {
        return Err(Denial::new(
            ReasonCode::EIdentity,
            "child root_id does not match parent root",
        ));
    }
    if child.identity.parent_id.as_deref() != Some(parent.identity.id.as_str()) {
        return Err(Denial::new(
            ReasonCode::EIdentity,
            "child parent_id does not match parent id",
        ));
    }
    let remaining_depth = parent.delegation.max_depth.saturating_sub(1);
    if child.delegation.max_depth > remaining_depth {
        return Err(Denial::new(
            ReasonCode::EDepth,
            "child delegation depth exceeds remaining ancestor capacity",
        ));
    }
    if child.delegation.max_live_children > parent.delegation.max_live_children {
        return Err(Denial::new(
            ReasonCode::EDelegationWidens,
            "child live-children ceiling exceeds parent",
        ));
    }
    if child.delegation.max_total_descendants > parent.delegation.max_total_descendants {
        return Err(Denial::new(
            ReasonCode::EDelegationWidens,
            "child descendant ceiling exceeds parent",
        ));
    }
    if child.lifetime.max_seconds > parent.lifetime.max_seconds {
        return Err(Denial::new(
            ReasonCode::EDelegationWidens,
            "child lifetime exceeds parent",
        ));
    }
    match (child.lifetime.expires_at, parent.lifetime.expires_at) {
        (Some(c), Some(p)) if c > p => {
            return Err(Denial::new(
                ReasonCode::EDelegationWidens,
                "child expires later than parent",
            ));
        }
        (None, Some(_)) => {
            return Err(Denial::new(
                ReasonCode::EDelegationWidens,
                "child removes parent expiry",
            ));
        }
        _ => {}
    }
    if child.limits.domain.provider_attempts > parent.limits.domain.provider_attempts
        || child.limits.domain.external_mutations > parent.limits.domain.external_mutations
        || child.limits.domain.inference_output_tokens
            > parent.limits.domain.inference_output_tokens
        || child.limits.domain.outbound_payload_bytes > parent.limits.domain.outbound_payload_bytes
    {
        return Err(Denial::new(
            ReasonCode::EDelegationWidens,
            "child domain budget exceeds parent",
        ));
    }
    for clause in &child.clauses {
        if !parent
            .clauses
            .iter()
            .any(|parent_clause| clause_subsumes(parent_clause, clause))
        {
            return Err(Denial::new(
                ReasonCode::EDelegationWidens,
                format!(
                    "no single parent clause subsumes child clause `{}`",
                    clause.id
                ),
            ));
        }
    }
    Ok(())
}

pub fn clause_subsumes(parent: &GrantClause, child: &GrantClause) -> bool {
    if matches!(child.effect, ClauseEffect::Permit) && matches!(parent.effect, ClauseEffect::Deny) {
        return false;
    }
    if !child.actions.is_subset(&parent.actions) {
        return false;
    }
    if !child.resources.is_subset(&parent.resources) {
        return false;
    }
    if !child.recipients.is_subset(&parent.recipients) {
        return false;
    }
    match (&child.credential, &parent.credential) {
        (None, _) => {}
        (Some(c), Some(p)) if c == p => {}
        (Some(_), _) => return false,
    }
    if !constraints_subsume(&parent.constraints, &child.constraints) {
        return false;
    }
    obligations_subsume(&parent.obligations, &child.obligations)
}

fn constraints_subsume(
    parent: &crate::constraints::ConstraintSet,
    child: &crate::constraints::ConstraintSet,
) -> bool {
    for (name, parent_c) in parent.iter() {
        let Some(child_c) = child.get(name) else {
            return false;
        };
        if !constraint_narrower_or_equal(parent_c, child_c) {
            return false;
        }
    }
    true
}

fn constraint_narrower_or_equal(parent: &Constraint, child: &Constraint) -> bool {
    match (parent, child) {
        (Constraint::NumericMax { value: p, .. }, Constraint::NumericMax { value: c, .. }) => {
            c <= p
        }
        (Constraint::NumericMin { value: p, .. }, Constraint::NumericMin { value: c, .. }) => {
            c >= p
        }
        (Constraint::Exact { value: p, .. }, Constraint::Exact { value: c, .. }) => p == c,
        (Constraint::PathSubtrees { paths: p }, Constraint::PathSubtrees { paths: c }) => c
            .iter()
            .all(|child_path| p.iter().any(|parent_path| child_path.is_under(parent_path))),
        (Constraint::Approval { obligation: p }, Constraint::Approval { obligation: c }) => {
            c.is_stronger_or_equal(*p)
        }
        _ => false,
    }
}

fn obligations_subsume(parent: &ObligationSet, child: &ObligationSet) -> bool {
    child.approval.is_stronger_or_equal(parent.approval)
}
