//! Registered constraint forms. Unknown kinds fail closed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;
use crate::path::RelPath;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalObligation {
    #[default]
    None,
    Exact,
}

impl ApprovalObligation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Exact => "exact",
        }
    }

    pub fn is_stronger_or_equal(self, other: Self) -> bool {
        self >= other
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "form", rename_all = "kebab-case")]
pub enum Constraint {
    NumericMax { name: String, value: u64 },
    NumericMin { name: String, value: u64 },
    Exact { name: String, value: String },
    PathSubtrees { paths: Vec<RelPath> },
    Approval { obligation: ApprovalObligation },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintSet {
    fields: BTreeMap<String, Constraint>,
}

impl ConstraintSet {
    pub fn from_yaml_map(
        map: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, PolicyError> {
        if map.len() > crate::limits::MAX_CONSTRAINT_FIELDS_PER_CLAUSE {
            return Err(PolicyError::schema("too many constraint fields in clause"));
        }
        let mut fields = BTreeMap::new();
        for (key, value) in map {
            let constraint = parse_constraint(key, value)?;
            fields.insert(key.clone(), constraint);
        }
        Ok(Self { fields })
    }

    pub fn get(&self, name: &str) -> Option<&Constraint> {
        self.fields.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Constraint)> {
        self.fields.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

fn parse_constraint(key: &str, value: &serde_json::Value) -> Result<Constraint, PolicyError> {
    match key {
        "maxInputBytes" | "maxOutputTokens" | "maxResponseBytes" => Ok(Constraint::NumericMax {
            name: key.to_string(),
            value: expect_u64(key, value)?,
        }),
        "minInputBytes" => Ok(Constraint::NumericMin {
            name: key.to_string(),
            value: expect_u64(key, value)?,
        }),
        "exactModel" => Ok(Constraint::Exact {
            name: key.to_string(),
            value: expect_string(key, value)?,
        }),
        "pathSubtrees" => {
            let Some(items) = value.as_array() else {
                return Err(PolicyError::schema("pathSubtrees must be an array"));
            };
            if items.len() > crate::limits::MAX_PATH_ROOTS {
                return Err(PolicyError::schema("too many path roots"));
            }
            let mut paths = Vec::new();
            for item in items {
                let Some(s) = item.as_str() else {
                    return Err(PolicyError::schema("pathSubtrees entries must be strings"));
                };
                paths.push(RelPath::parse(s)?);
            }
            Ok(Constraint::PathSubtrees { paths })
        }
        "approval" => {
            let Some(s) = value.as_str() else {
                return Err(PolicyError::schema("approval must be a string"));
            };
            let obligation = match s {
                "none" => ApprovalObligation::None,
                "exact" => ApprovalObligation::Exact,
                _ => {
                    return Err(PolicyError::unsupported(format!(
                        "unsupported approval obligation `{s}`"
                    )));
                }
            };
            Ok(Constraint::Approval { obligation })
        }
        other => Err(PolicyError::unsupported(format!(
            "unsupported constraint kind `{other}`"
        ))),
    }
}

fn expect_u64(key: &str, value: &serde_json::Value) -> Result<u64, PolicyError> {
    value.as_u64().ok_or_else(|| {
        PolicyError::schema(format!("constraint `{key}` must be a non-negative integer"))
    })
}

fn expect_string(key: &str, value: &serde_json::Value) -> Result<String, PolicyError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| PolicyError::schema(format!("constraint `{key}` must be a string")))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationSet {
    pub approval: ApprovalObligation,
}

impl ObligationSet {
    pub fn from_constraints(constraints: &ConstraintSet) -> Self {
        let approval = constraints
            .get("approval")
            .and_then(|c| match c {
                Constraint::Approval { obligation } => Some(*obligation),
                _ => None,
            })
            .unwrap_or(ApprovalObligation::None);
        Self { approval }
    }

    pub fn is_satisfied(&self, approval_valid: bool) -> bool {
        match self.approval {
            ApprovalObligation::None => true,
            ApprovalObligation::Exact => approval_valid,
        }
    }
}
