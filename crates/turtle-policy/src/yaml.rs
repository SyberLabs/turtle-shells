//! Strict YAML 1.2 frontend. Aliases, merge keys, tags, and ambiguous scalars fail closed.

use std::collections::HashSet;

use saphyr_parser::{Event, Parser, ScalarStyle};
use serde_json::{Map, Number, Value};

use crate::error::PolicyError;
use crate::limits::{MAX_MANIFEST_BYTES, MAX_NESTING, MAX_SAFE_INTEGER};

pub fn yaml_to_json(bytes: &[u8]) -> Result<Value, PolicyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(PolicyError::schema(format!(
            "manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PolicyError::schema("manifest is not valid UTF-8"))?;
    let mut parser = Parser::new_from_str(text);
    expect(&mut parser, |e| matches!(e, Event::StreamStart))?;
    expect(&mut parser, |e| matches!(e, Event::DocumentStart(_)))?;
    let value = parse_node(&mut parser, 1)?;
    expect(&mut parser, |e| matches!(e, Event::DocumentEnd))?;
    expect(&mut parser, |e| matches!(e, Event::StreamEnd))?;
    if parser.next_event().is_some() {
        return Err(PolicyError::schema("unexpected trailing YAML content"));
    }
    Ok(value)
}

type ParseEvent<'a> = Event<'a>;

fn next_event<'a>(
    parser: &mut Parser<'a, impl saphyr_parser::Input>,
) -> Result<ParseEvent<'a>, PolicyError> {
    match parser.next_event() {
        Some(Ok((event, _span))) => Ok(event),
        Some(Err(err)) => Err(PolicyError::schema(format!("YAML parse error: {err}"))),
        None => Err(PolicyError::schema("unexpected end of YAML stream")),
    }
}

fn expect<'a>(
    parser: &mut Parser<'a, impl saphyr_parser::Input>,
    pred: impl FnOnce(&ParseEvent<'a>) -> bool,
) -> Result<ParseEvent<'a>, PolicyError> {
    let event = next_event(parser)?;
    if pred(&event) {
        Ok(event)
    } else {
        Err(PolicyError::schema(format!(
            "unexpected YAML event {event:?}"
        )))
    }
}

fn parse_node<'a>(
    parser: &mut Parser<'a, impl saphyr_parser::Input>,
    depth: usize,
) -> Result<Value, PolicyError> {
    if depth > MAX_NESTING {
        return Err(PolicyError::schema(format!(
            "YAML nesting exceeds {MAX_NESTING} levels"
        )));
    }
    match next_event(parser)? {
        Event::Nothing => parse_node(parser, depth),
        Event::Alias(_) => Err(PolicyError::schema("YAML aliases are not allowed")),
        Event::Scalar(value, style, anchor, tag) => {
            reject_anchor(anchor)?;
            reject_tag(tag.as_deref())?;
            parse_scalar(value.as_ref(), style)
        }
        Event::SequenceStart(anchor, tag) => {
            reject_anchor(anchor)?;
            reject_tag(tag.as_deref())?;
            parse_sequence(parser, depth)
        }
        Event::MappingStart(anchor, tag) => {
            reject_anchor(anchor)?;
            reject_tag(tag.as_deref())?;
            parse_mapping(parser, depth)
        }
        other => Err(PolicyError::schema(format!(
            "unexpected YAML node event {other:?}"
        ))),
    }
}

fn parse_sequence<'a>(
    parser: &mut Parser<'a, impl saphyr_parser::Input>,
    depth: usize,
) -> Result<Value, PolicyError> {
    let mut items = Vec::new();
    loop {
        match parser.peek() {
            Some(Ok((Event::SequenceEnd, _))) => {
                let _ = next_event(parser)?;
                break;
            }
            Some(Ok(_)) => items.push(parse_node(parser, depth + 1)?),
            Some(Err(err)) => return Err(PolicyError::schema(format!("YAML parse error: {err}"))),
            None => return Err(PolicyError::schema("unterminated YAML sequence")),
        }
    }
    Ok(Value::Array(items))
}

fn parse_mapping<'a>(
    parser: &mut Parser<'a, impl saphyr_parser::Input>,
    depth: usize,
) -> Result<Value, PolicyError> {
    let mut map = Map::new();
    let mut seen = HashSet::new();
    loop {
        match parser.peek() {
            Some(Ok((Event::MappingEnd, _))) => {
                let _ = next_event(parser)?;
                break;
            }
            Some(Ok(_)) => {
                let key = parse_mapping_key(parser, depth + 1)?;
                if key == "<<" {
                    return Err(PolicyError::schema("YAML merge keys are not allowed"));
                }
                if !seen.insert(key.clone()) {
                    return Err(PolicyError::schema(format!("duplicate YAML key `{key}`")));
                }
                let value = parse_node(parser, depth + 1)?;
                map.insert(key, value);
            }
            Some(Err(err)) => return Err(PolicyError::schema(format!("YAML parse error: {err}"))),
            None => return Err(PolicyError::schema("unterminated YAML mapping")),
        }
    }
    Ok(Value::Object(map))
}

fn parse_mapping_key<'a>(
    parser: &mut Parser<'a, impl saphyr_parser::Input>,
    depth: usize,
) -> Result<String, PolicyError> {
    match parse_node(parser, depth)? {
        Value::String(s) => Ok(s),
        other => Err(PolicyError::schema(format!(
            "YAML mapping keys must be strings, got {other}"
        ))),
    }
}

fn parse_scalar(value: &str, style: ScalarStyle) -> Result<Value, PolicyError> {
    match style {
        ScalarStyle::Plain => parse_plain_scalar(value),
        ScalarStyle::SingleQuoted
        | ScalarStyle::DoubleQuoted
        | ScalarStyle::Literal
        | ScalarStyle::Folded => Ok(Value::String(value.to_string())),
    }
}

fn parse_plain_scalar(value: &str) -> Result<Value, PolicyError> {
    match value {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        "null" | "~" => return Ok(Value::Null),
        _ => {}
    }
    if is_ambiguous_plain(value) {
        return Err(PolicyError::schema(format!(
            "ambiguous or unsupported YAML scalar `{value}`"
        )));
    }
    if let Some(number) = parse_strict_int(value) {
        return Ok(Value::Number(Number::from(number)));
    }
    if looks_like_non_integer_number(value) {
        return Err(PolicyError::schema(format!(
            "non-integer YAML numbers are not allowed (`{value}`)"
        )));
    }
    if value.is_empty() {
        return Err(PolicyError::schema(
            "empty plain YAML scalars are not allowed",
        ));
    }
    Ok(Value::String(value.to_string()))
}

fn parse_strict_int(value: &str) -> Option<i64> {
    let ok = value == "0" || {
        let mut chars = value.chars();
        match chars.next()? {
            '-' => {
                let rest: String = chars.collect();
                let mut r = rest.chars();
                matches!(r.next(), Some('1'..='9')) && r.all(|c| c.is_ascii_digit())
            }
            '1'..='9' => chars.all(|c| c.is_ascii_digit()),
            _ => false,
        }
    };
    if !ok {
        return None;
    }
    let parsed: i64 = value.parse().ok()?;
    if parsed.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
        return None;
    }
    Some(parsed)
}

fn looks_like_non_integer_number(value: &str) -> bool {
    let stripped = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    if stripped.is_empty() {
        return false;
    }
    let mut saw_digit = false;
    let mut saw_dot_or_exp = false;
    for c in stripped.chars() {
        match c {
            '0'..='9' => saw_digit = true,
            '.' | 'e' | 'E' | '+' | '-' => saw_dot_or_exp = true,
            _ => return false,
        }
    }
    saw_digit && saw_dot_or_exp
}

fn is_ambiguous_plain(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "yes" | "no" | "on" | "off" | "y" | "n" | ".inf" | "-.inf" | "+.inf" | ".nan"
    ) || value.starts_with('+')
        || lower.starts_with("0x")
        || lower.starts_with("0o")
        || lower.starts_with("0b")
        || (value.len() > 1 && value.starts_with('0') && value.chars().all(|c| c.is_ascii_digit()))
}

fn reject_anchor(anchor: usize) -> Result<(), PolicyError> {
    if anchor != 0 {
        Err(PolicyError::schema(
            "YAML anchors and aliases are not allowed",
        ))
    } else {
        Ok(())
    }
}

fn reject_tag(tag: Option<&saphyr_parser::Tag>) -> Result<(), PolicyError> {
    if tag.is_some() {
        Err(PolicyError::schema("YAML tags are not allowed"))
    } else {
        Ok(())
    }
}
