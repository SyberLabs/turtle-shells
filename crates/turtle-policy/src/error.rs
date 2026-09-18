//! Typed internal errors. Public surfaces expose [`crate::reason::ReasonCode`].

use thiserror::Error;

use crate::reason::ReasonCode;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("{0}")]
    Schema(String),
    #[error("{0}")]
    UnknownAction(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Identity(String),
}

impl PolicyError {
    pub fn schema(msg: impl Into<String>) -> Self {
        Self::Schema(msg.into())
    }

    pub fn unknown_action(msg: impl Into<String>) -> Self {
        Self::UnknownAction(msg.into())
    }

    pub fn unsupported(msg: impl Into<String>) -> Self {
        Self::Unsupported(msg.into())
    }

    pub fn identity(msg: impl Into<String>) -> Self {
        Self::Identity(msg.into())
    }

    pub fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Schema(_) => ReasonCode::ESchema,
            Self::UnknownAction(_) => ReasonCode::EUnknownAction,
            Self::Unsupported(_) => ReasonCode::EUnsupportedEnforcement,
            Self::Identity(_) => ReasonCode::EIdentity,
        }
    }
}
