use anyhow::{Context, Result};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};
use tapestry_core::Observation;
use url::Url;

mod cdp;

pub use cdp::{
    record, CaptureOptions, CaptureSummary, CdpObservationBuilder, RecordOptions, RecordResult,
};

const MAX_HAR_BYTES: u64 = 200 * 1024 * 1024;

pub fn import_har(path: impl AsRef<Path>) -> Result<Vec<Observation>> {
    let size = fs::metadata(path.as_ref())
        .context("failed to stat HAR file")?
        .len();
    if size > MAX_HAR_BYTES {
        anyhow::bail!(
            "HAR file is {:.1} MB, exceeds 200 MB limit. Split or trim the capture.",
            size as f64 / (1024.0 * 1024.0)
        );
    }
    let raw = fs::read_to_string(path.as_ref()).context("failed to read HAR file")?;
    let json: Value = serde_json::from_str(&raw).context("failed to parse HAR JSON")?;
    let entries = json
        .get("log")
        .and_then(|v| v.get("entries"))
        .and_then(|v| v.as_array())
        .context("HAR missing log.entries array")?;

    let mut observations = Vec::new();
    for entry in entries {
        if let Some(obs) = parse_entry(entry) {
            observations.push(obs);
        }
    }
    Ok(observations)
}

pub fn redact_har(path: impl AsRef<Path>) -> Result<Value> {
    let raw = fs::read_to_string(path.as_ref()).context("failed to read HAR file")?;
    let mut json: Value = serde_json::from_str(&raw).context("failed to parse HAR JSON")?;
    if let Some(entries) = json
        .get_mut("log")
        .and_then(|v| v.get_mut("entries"))
        .and_then(|v| v.as_array_mut())
    {
        for entry in entries {
            redact_entry(entry);
        }
    }
    Ok(json)
}

fn parse_entry(entry: &Value) -> Option<Observation> {
    let request = entry.get("request")?;
    let response = entry.get("response");
    let method = request.get("method")?.as_str()?.trim().to_ascii_uppercase();
    if method.is_empty() {
        return None;
    }
    let url_str = request.get("url")?.as_str()?.to_string();
    let url = Url::parse(&url_str).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let path = url.path().to_string();

    let mut query = BTreeMap::new();
    for (k, v) in url.query_pairs() {
        query.insert(k.to_string(), infer_scalar(v.as_ref()));
    }

    let request_headers = parse_headers(request.get("headers"));
    let response_headers = response
        .and_then(|r| Some(parse_headers(r.get("headers"))))
        .unwrap_or_default();
    let response_status = response
        .and_then(|r| r.get("status"))
        .and_then(|s| s.as_u64())
        .map(|s| s as u16);

    let request_body = request
        .get("postData")
        .and_then(|p| p.get("text"))
        .and_then(|t| t.as_str())
        .and_then(parse_json_maybe);

    let response_body = response
        .and_then(|r| r.get("content"))
        .and_then(|c| decode_content_body(c));

    Some(Observation {
        method,
        url: url_str,
        path,
        query,
        request_headers,
        request_body: request_body.map(redact_body_value),
        response_status,
        response_headers,
        response_body: response_body.map(redact_body_value),
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_simple_fixture() {
        let observations = import_har("../../examples/fixtures/simple.har").unwrap();

        assert_eq!(observations.len(), 4);
        assert!(observations.iter().all(|obs| !obs.method.is_empty()));
    }

    #[test]
    fn skips_blank_method_and_non_http_entries_in_browser_fixture() {
        let observations = import_har("../../examples/fixtures/dummyjson.com.har").unwrap();

        assert!(!observations.is_empty());
        assert!(observations.iter().all(|obs| !obs.method.is_empty()));
        assert!(observations.iter().all(|obs| obs.url.starts_with("http")));
    }
}

fn redact_entry(entry: &mut Value) {
    if let Some(request_headers) = entry
        .get_mut("request")
        .and_then(|request| request.get_mut("headers"))
        .and_then(|headers| headers.as_array_mut())
    {
        redact_headers_in_place(request_headers);
    }

    if let Some(response_headers) = entry
        .get_mut("response")
        .and_then(|response| response.get_mut("headers"))
        .and_then(|headers| headers.as_array_mut())
    {
        redact_headers_in_place(response_headers);
    }

    if let Some(text) = entry
        .get_mut("request")
        .and_then(|r| r.get_mut("postData"))
        .and_then(|p| p.get_mut("text"))
    {
        if let Some(s) = text.as_str() {
            *text = Value::String(redact_body_text(s));
        }
    }

    if let Some(text) = entry
        .get_mut("response")
        .and_then(|r| r.get_mut("content"))
        .and_then(|c| c.get_mut("text"))
    {
        if let Some(s) = text.as_str() {
            *text = Value::String(redact_body_text(s));
        }
    }
}

fn redact_body_text(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(json) => {
            serde_json::to_string(&redact_body_value(json)).unwrap_or_else(|_| text.to_string())
        }
        Err(_) => text.to_string(),
    }
}

fn redact_body_value(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, val)| {
                    if is_secret_body_key(&key) {
                        (key, Value::String("<redacted>".to_string()))
                    } else {
                        (key, redact_body_value(val))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_body_value).collect()),
        other => other,
    }
}

fn is_secret_body_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "password",
        "secret",
        "api_key",
    ]
    .iter()
    .any(|secret| key == *secret || key.contains(secret))
}

fn redact_headers_in_place(headers: &mut [Value]) {
    for header in headers {
        let Some(name) = header.get("name").and_then(Value::as_str) else {
            continue;
        };
        if is_secret_header(name) {
            if let Some(value) = header.get_mut("value") {
                *value = Value::String("<redacted>".to_string());
            }
        }
    }
}

fn parse_headers(headers: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(arr) = headers.and_then(|v| v.as_array()) {
        for h in arr {
            if let (Some(name), Some(value)) = (
                h.get("name").and_then(|v| v.as_str()),
                h.get("value").and_then(|v| v.as_str()),
            ) {
                out.insert(name.to_string(), redact_header(name, value));
            }
        }
    }
    out
}

fn redact_header(name: &str, value: &str) -> String {
    if is_secret_header(name) {
        "<redacted>".to_string()
    } else {
        value.to_string()
    }
}

fn is_secret_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "x-csrf-token"
            | "x-xsrf-token"
            | "x-api-key"
            | "x-auth-token"
            | "x-access-token"
            | "x-session-token"
            | "proxy-authorization"
    ) || (lower.starts_with("x-") && lower.contains("token"))
}

fn decode_content_body(content: &Value) -> Option<Value> {
    let text = content.get("text")?.as_str()?;
    let encoding = content
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or("");
    if encoding.eq_ignore_ascii_case("base64") {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(text)
            .ok()?;
        let s = std::str::from_utf8(&decoded).ok()?;
        parse_json_maybe(s)
    } else {
        parse_json_maybe(text)
    }
}

fn parse_json_maybe(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok()
}

fn infer_scalar(s: &str) -> Value {
    if let Ok(i) = s.parse::<i64>() {
        Value::from(i)
    } else if let Ok(f) = s.parse::<f64>() {
        Value::from(f)
    } else if let Ok(b) = s.parse::<bool>() {
        Value::from(b)
    } else {
        Value::from(s)
    }
}
