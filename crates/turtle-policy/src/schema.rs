//! Embedded JSON Schema. Validation does not retrieve network resources.

use serde_json::Value;

use crate::error::PolicyError;

pub const SCHEMA_JSON: &str = include_str!("../../../schemas/turtle-policy-v0alpha1.schema.json");

pub fn validate_instance(instance: &Value) -> Result<(), PolicyError> {
    let schema: Value = serde_json::from_str(SCHEMA_JSON)
        .expect("embedded turtle-policy schema must be valid JSON");
    check_object(
        instance,
        schema.get("properties"),
        schema.get("required"),
        true,
    )?;
    let spec_schema = schema
        .pointer("/properties/spec")
        .ok_or_else(|| PolicyError::schema("embedded schema missing spec"))?;
    let spec = instance
        .get("spec")
        .ok_or_else(|| PolicyError::schema("missing spec"))?;
    check_object(
        spec,
        spec_schema.get("properties"),
        spec_schema.get("required"),
        true,
    )?;
    Ok(())
}

fn check_object(
    instance: &Value,
    properties: Option<&Value>,
    required: Option<&Value>,
    deny_unknown: bool,
) -> Result<(), PolicyError> {
    let Some(obj) = instance.as_object() else {
        return Err(PolicyError::schema("expected object"));
    };
    if let Some(Value::Array(req)) = required {
        for key in req {
            let Some(name) = key.as_str() else { continue };
            if !obj.contains_key(name) {
                return Err(PolicyError::schema(format!(
                    "missing required field `{name}`"
                )));
            }
        }
    }
    if deny_unknown {
        if let Some(Value::Object(props)) = properties {
            for key in obj.keys() {
                if !props.contains_key(key) {
                    return Err(PolicyError::schema(format!("unknown field `{key}`")));
                }
            }
        }
    }
    Ok(())
}
