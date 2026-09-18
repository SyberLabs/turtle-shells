//! Strict identifier types. Ambiguous or caller-invented syntax fails closed.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

macro_rules! strict_id {
    ($name:ident, $pred:expr, $label:expr) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(raw: impl Into<String>) -> Result<Self, PolicyError> {
                let raw = raw.into();
                if $pred(&raw) {
                    Ok(Self(raw))
                } else {
                    Err(PolicyError::schema(format!("invalid {} `{raw}`", $label)))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = PolicyError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

fn action_ok(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && s.len() <= 128
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn name_ok(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && s.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn registry_ok(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z' | '0'..='9'))
        && s.len() <= 128
        && chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, ':' | '.' | '_' | '-')
        })
}

strict_id!(ActionId, action_ok, "action id");
strict_id!(PolicyName, name_ok, "policy name");
strict_id!(ClauseId, name_ok, "clause id");
strict_id!(ResourceId, registry_ok, "resource id");
strict_id!(CredentialBindingId, registry_ok, "credential binding id");
strict_id!(RecipientId, registry_ok, "recipient id");
strict_id!(TemplateId, registry_ok, "template id");
strict_id!(OperationKey, registry_ok, "operation key");
