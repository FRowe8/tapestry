use anyhow::{Context, Result};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};
use tapestry_core::Observation;
use url::Url;

mod cdp;

pub use cdp::{
    reauth, record, resolve_browser, CaptureOptions, CaptureSummary, CdpObservationBuilder,
    CredentialHarvester, ReauthOptions, RecordOptions, RecordResult,
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

/// Secrets also travel in query strings (`?access_token=…`, `?sig=…`).
/// Redacting headers and bodies while persisting raw URLs would leak them
/// into observations, tool examples, and evidence.
pub(crate) fn is_secret_query_param(name: &str) -> bool {
    const SECRET_WORDS: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "authorization",
        "key",
        "apikey",
        "sig",
        "signature",
        "session",
        "sid",
        "credential",
        "credentials",
    ];
    // Match whole words, not substrings, so benign names like `author`
    // (contains "auth") or `sortkey` (contains "key") are not redacted.
    split_identifier_words(name)
        .iter()
        .any(|word| SECRET_WORDS.contains(&word.as_str()))
}

/// Split an identifier into lowercase words on separators and camelCase
/// boundaries: `access_token` -> [access, token], `apiKey` -> [api, key].
fn split_identifier_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower_or_digit = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if prev_lower_or_digit && c.is_ascii_uppercase() && !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            current.push(c.to_ascii_lowercase());
            prev_lower_or_digit = c.is_ascii_lowercase() || c.is_ascii_digit();
        } else {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prev_lower_or_digit = false;
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Replace secret query parameter values in a full URL string.
///
/// Returns the URL unchanged when no secret parameter is present, so clean
/// URLs keep their original byte-for-byte encoding — otherwise re-serializing
/// (e.g. `%20` -> `+`) would defeat duplicate detection when the same capture
/// is imported again.
pub(crate) fn redact_url_query(url: &Url) -> String {
    let has_secret = url
        .query_pairs()
        .any(|(name, _)| is_secret_query_param(&name));
    if !has_secret {
        return url.to_string();
    }
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| {
            let value = if is_secret_query_param(&name) {
                "<redacted>".to_string()
            } else {
                value.to_string()
            };
            (name.to_string(), value)
        })
        .collect();
    let mut redacted = url.clone();
    {
        let mut serializer = redacted.query_pairs_mut();
        serializer.clear();
        for (name, value) in &pairs {
            serializer.append_pair(name, value);
        }
    }
    redacted.to_string()
}

pub(crate) fn redacted_query_map(url: &Url) -> BTreeMap<String, Value> {
    let mut query = BTreeMap::new();
    for (name, value) in url.query_pairs() {
        let value = if is_secret_query_param(&name) {
            Value::String("<redacted>".to_string())
        } else {
            infer_scalar(value.as_ref())
        };
        query.insert(name.to_string(), value);
    }
    query
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
    let query = redacted_query_map(&url);
    let url_str = redact_url_query(&url);

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
        let observations = import_har("../../examples/fixtures/browser-noise.har").unwrap();

        assert!(!observations.is_empty());
        assert!(observations.iter().all(|obs| !obs.method.is_empty()));
        assert!(observations.iter().all(|obs| obs.url.starts_with("http")));
    }

    #[test]
    fn no_seeded_secret_survives_har_import() {
        let observations = import_har("../../examples/fixtures/redaction.har").unwrap();
        let serialized = serde_json::to_string(&observations).unwrap();

        assert!(
            !serialized.contains("FAKESECRET"),
            "a seeded secret leaked into observations: {serialized}"
        );
        // Redaction must not have destroyed the useful payload.
        assert!(serialized.contains("\"title\":\"One\""));
        assert!(serialized.contains("access_token"));
        assert!(serialized.contains("\"limit\":5"));
    }

    #[test]
    fn secret_query_params_are_redacted_in_url_and_query_map() {
        let url =
            Url::parse("http://x.test/api?access_token=tok123&limit=5&sig=abc&q=shoes").unwrap();
        let redacted_url = redact_url_query(&url);
        assert!(!redacted_url.contains("tok123"));
        assert!(!redacted_url.contains("sig=abc"));
        assert!(redacted_url.contains("limit=5"));
        assert!(redacted_url.contains("q=shoes"));

        let query = redacted_query_map(&url);
        assert_eq!(query["access_token"], "<redacted>");
        assert_eq!(query["sig"], "<redacted>");
        assert_eq!(query["limit"], 5);
        assert_eq!(query["q"], "shoes");
    }

    #[test]
    fn benign_params_that_contain_secret_substrings_are_not_redacted() {
        assert!(!is_secret_query_param("author"));
        assert!(!is_secret_query_param("sortkey"));
        assert!(!is_secret_query_param("keyword"));
        assert!(!is_secret_query_param("userId"));
        assert!(is_secret_query_param("access_token"));
        assert!(is_secret_query_param("apiKey"));
        assert!(is_secret_query_param("x-api-key"));
        assert!(is_secret_query_param("sessionId"));
    }

    #[test]
    fn clean_url_query_is_not_re_encoded() {
        // No secret present: bytes must be preserved so re-import dedup works.
        let url = Url::parse("http://x.test/api?q=a%20b&sort=name").unwrap();
        assert_eq!(redact_url_query(&url), url.to_string());
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
    tapestry_core::redact_sensitive_fields(value)
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
