//! Stable public reason codes. Serialized representations are part of the P0 contract.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Stable, machine-readable denial/error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::enum_variant_names)] // Codes are specified as E_* in the design contract.
pub enum ReasonCode {
    ESchema,
    EUnknownAction,
    EIdentity,
    ENotActive,
    EAncestorRevoked,
    EExpired,
    EPolicyDeny,
    EResourceOutsideGrant,
    EDisclosure,
    EApprovalRequired,
    EApprovalStale,
    EBudget,
    EDelegationWidens,
    EDepth,
    EUnsupportedEnforcement,
    EDriverDrift,
    EPrecondition,
    EOperationConflict,
    EOutcomeUnknown,
    EAuditUnavailable,
}

impl ReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ESchema => "E_SCHEMA",
            Self::EUnknownAction => "E_UNKNOWN_ACTION",
            Self::EIdentity => "E_IDENTITY",
            Self::ENotActive => "E_NOT_ACTIVE",
            Self::EAncestorRevoked => "E_ANCESTOR_REVOKED",
            Self::EExpired => "E_EXPIRED",
            Self::EPolicyDeny => "E_POLICY_DENY",
            Self::EResourceOutsideGrant => "E_RESOURCE_OUTSIDE_GRANT",
            Self::EDisclosure => "E_DISCLOSURE",
            Self::EApprovalRequired => "E_APPROVAL_REQUIRED",
            Self::EApprovalStale => "E_APPROVAL_STALE",
            Self::EBudget => "E_BUDGET",
            Self::EDelegationWidens => "E_DELEGATION_WIDENS",
            Self::EDepth => "E_DEPTH",
            Self::EUnsupportedEnforcement => "E_UNSUPPORTED_ENFORCEMENT",
            Self::EDriverDrift => "E_DRIVER_DRIFT",
            Self::EPrecondition => "E_PRECONDITION",
            Self::EOperationConflict => "E_OPERATION_CONFLICT",
            Self::EOutcomeUnknown => "E_OUTCOME_UNKNOWN",
            Self::EAuditUnavailable => "E_AUDIT_UNAVAILABLE",
        }
    }

    pub fn retryable(self) -> bool {
        matches!(self, Self::EBudget | Self::EApprovalRequired)
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReasonCode {
    type Err = ParseReasonCodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "E_SCHEMA" => Ok(Self::ESchema),
            "E_UNKNOWN_ACTION" => Ok(Self::EUnknownAction),
            "E_IDENTITY" => Ok(Self::EIdentity),
            "E_NOT_ACTIVE" => Ok(Self::ENotActive),
            "E_ANCESTOR_REVOKED" => Ok(Self::EAncestorRevoked),
            "E_EXPIRED" => Ok(Self::EExpired),
            "E_POLICY_DENY" => Ok(Self::EPolicyDeny),
            "E_RESOURCE_OUTSIDE_GRANT" => Ok(Self::EResourceOutsideGrant),
            "E_DISCLOSURE" => Ok(Self::EDisclosure),
            "E_APPROVAL_REQUIRED" => Ok(Self::EApprovalRequired),
            "E_APPROVAL_STALE" => Ok(Self::EApprovalStale),
            "E_BUDGET" => Ok(Self::EBudget),
            "E_DELEGATION_WIDENS" => Ok(Self::EDelegationWidens),
            "E_DEPTH" => Ok(Self::EDepth),
            "E_UNSUPPORTED_ENFORCEMENT" => Ok(Self::EUnsupportedEnforcement),
            "E_DRIVER_DRIFT" => Ok(Self::EDriverDrift),
            "E_PRECONDITION" => Ok(Self::EPrecondition),
            "E_OPERATION_CONFLICT" => Ok(Self::EOperationConflict),
            "E_OUTCOME_UNKNOWN" => Ok(Self::EOutcomeUnknown),
            "E_AUDIT_UNAVAILABLE" => Ok(Self::EAuditUnavailable),
            other => Err(ParseReasonCodeError(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseReasonCodeError(pub String);

impl fmt::Display for ParseReasonCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown reason code {}", self.0)
    }
}

impl std::error::Error for ParseReasonCodeError {}

/// Public denial payload. Explanations must not include secrets or unrelated resource identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    pub code: ReasonCode,
    pub constraint_id: Option<String>,
    pub explanation: String,
    pub retryable: bool,
}

impl Denial {
    pub fn new(code: ReasonCode, explanation: impl Into<String>) -> Self {
        Self {
            code,
            constraint_id: None,
            explanation: explanation.into(),
            retryable: code.retryable(),
        }
    }

    pub fn with_constraint(mut self, constraint_id: impl Into<String>) -> Self {
        self.constraint_id = Some(constraint_id.into());
        self
    }
}

/// Evidence for an allow decision. P0 records which clause matched; it is not an enforcement proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionEvidence {
    pub clause_id: String,
    pub layer: String,
    pub policy_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Decision {
    Allow(DecisionEvidence),
    Deny(Denial),
}

impl Decision {
    pub fn deny(code: ReasonCode, explanation: impl Into<String>) -> Self {
        Self::Deny(Denial::new(code, explanation))
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow(_))
    }
}
