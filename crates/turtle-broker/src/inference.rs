//! Typed `inference.generate` authorization. No caller-selected upstream.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use turtle_policy::PolicyError;

use crate::identity::{presented_secret_matches, InstanceBinding};

const FORBIDDEN: &[&str] = &[
    "baseUrl",
    "base_url",
    "tools",
    "file_ids",
    "uploads",
    "background",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceMessage {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceGenerateRequest {
    pub model: String,
    pub messages: Vec<InferenceMessage>,
    pub max_output_tokens: u32,
}

pub fn authorize_inference(
    binding: &InstanceBinding,
    presented: Option<&[u8]>,
    body: &Value,
) -> Result<InferenceGenerateRequest, PolicyError> {
    let Some(secret) = presented else {
        return Err(PolicyError::identity("instance binding missing"));
    };
    if !presented_secret_matches(binding, secret) {
        return Err(PolicyError::identity("instance binding mismatch"));
    }
    let obj = body
        .as_object()
        .ok_or_else(|| PolicyError::schema("inference body must be an object"))?;
    for key in obj.keys() {
        if FORBIDDEN.contains(&key.as_str()) {
            return Err(PolicyError::unsupported(format!(
                "inference field `{key}` is not supported"
            )));
        }
        if !matches!(key.as_str(), "model" | "messages" | "maxOutputTokens") {
            return Err(PolicyError::unsupported(format!(
                "unknown inference field `{key}`"
            )));
        }
    }
    let model = obj
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyError::schema("model is required"))?
        .to_string();
    let messages = obj
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| PolicyError::schema("messages is required"))?;
    let mut parsed = Vec::new();
    for msg in messages {
        let role = msg
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| PolicyError::schema("message.role is required"))?;
        let content = msg
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| PolicyError::schema("message.content is required"))?;
        parsed.push(InferenceMessage {
            role: role.to_string(),
            content: content.to_string(),
        });
    }
    let max_output_tokens = obj
        .get("maxOutputTokens")
        .and_then(Value::as_u64)
        .ok_or_else(|| PolicyError::schema("maxOutputTokens is required"))?;
    if max_output_tokens > u64::from(u32::MAX) {
        return Err(PolicyError::schema("maxOutputTokens is too large"));
    }
    Ok(InferenceGenerateRequest {
        model,
        messages: parsed,
        max_output_tokens: max_output_tokens as u32,
    })
}
