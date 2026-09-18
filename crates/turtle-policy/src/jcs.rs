//! RFC 8785-compatible canonical JSON for the P0 integer JSON subset.

use serde_json::{Map, Value};

use crate::error::PolicyError;

pub fn canonical_json(value: &Value) -> Result<String, PolicyError> {
    let mut out = String::new();
    write_canonical(&mut out, value)?;
    Ok(out)
}

fn write_canonical(out: &mut String, value: &Value) -> Result<(), PolicyError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if n.as_f64().is_some() && n.as_i64().is_none() && n.as_u64().is_none() {
                return Err(PolicyError::schema(
                    "non-integer JSON numbers cannot be canonicalized",
                ));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).map_err(|e| PolicyError::schema(e.to_string()))?)
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(out, map)?,
    }
    Ok(())
}

fn write_object(out: &mut String, map: &Map<String, Value>) -> Result<(), PolicyError> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|a| utf16_code_units(a));
    out.push('{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(key).map_err(|e| PolicyError::schema(e.to_string()))?);
        out.push(':');
        write_canonical(out, &map[*key])?;
    }
    out.push('}');
    Ok(())
}

fn utf16_code_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
