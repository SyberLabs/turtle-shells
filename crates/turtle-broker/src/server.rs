//! Bounded std HTTP/1.1 inference stub.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use serde_json::{json, Value};
use turtle_policy::PolicyError;

use crate::identity::InstanceBinding;
use crate::inference::authorize_inference;

const MAX_HEADER: usize = 8192;
const MAX_BODY: usize = 1024 * 1024;

pub fn serve(binding: &InstanceBinding, listener: TcpListener) -> std::io::Result<()> {
    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(err) = handle(binding, &mut stream) {
            let _ = write_json(
                &mut stream,
                400,
                &json!({"code": "E_SCHEMA", "explanation": err.to_string()}),
            );
        }
    }
    Ok(())
}

fn handle(binding: &InstanceBinding, stream: &mut TcpStream) -> Result<(), PolicyError> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| PolicyError::schema(e.to_string()))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEADER + MAX_BODY {
            return Err(PolicyError::schema("request too large"));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| PolicyError::schema("incomplete HTTP headers"))?;
    let header_bytes = &buf[..header_end];
    let header = std::str::from_utf8(header_bytes)
        .map_err(|_| PolicyError::schema("headers are not UTF-8"))?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| PolicyError::schema("missing request line"))?;
    if request_line != "POST /v1/inference.generate HTTP/1.1" {
        return Err(PolicyError::unsupported("unknown broker path"));
    }
    let mut content_length = 0usize;
    let mut presented: Option<Vec<u8>> = None;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
        if let Some(v) = line.strip_prefix("Authorization: Turtle ") {
            presented = hex::decode(v.trim()).ok();
        }
    }
    if content_length > MAX_BODY {
        return Err(PolicyError::schema("body exceeds 1 MiB"));
    }
    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| PolicyError::schema(e.to_string()))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body_bytes = buf
        .get(body_start..body_start + content_length)
        .ok_or_else(|| PolicyError::schema("truncated body"))?;
    let body: Value =
        serde_json::from_slice(body_bytes).map_err(|e| PolicyError::schema(e.to_string()))?;
    match authorize_inference(binding, presented.as_deref(), &body) {
        Ok(req) => {
            write_json(
                stream,
                200,
                &json!({"ok": true, "model": req.model, "maxOutputTokens": req.max_output_tokens}),
            )
            .map_err(|e| PolicyError::schema(e.to_string()))?;
            Ok(())
        }
        Err(err) => {
            write_json(
                stream,
                403,
                &json!({
                    "code": err.reason_code().to_string(),
                    "explanation": err.to_string(),
                }),
            )
            .map_err(|e| PolicyError::schema(e.to_string()))?;
            Ok(())
        }
    }
}

fn write_json(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    let payload = serde_json::to_vec(body)?;
    let reason = if status == 200 { "OK" } else { "Forbidden" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&payload)?;
    Ok(())
}
