pub mod signal;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A site's full set of generated tools, written by `tapestry generate` and
/// read by every downstream command (`review`, `serve`, `agent-task`, ...).
/// This is the on-disk contract between the analyzer and everything else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub site: SiteInfo,
    pub tools: Vec<ToolDefinition>,
}

/// Metadata about the captured site a `ToolSpec` was generated from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteInfo {
    pub name: String,
    pub base_url: Option<String>,
    /// Capture method(s) that contributed observations, e.g. `"har"` or `"cdp:<url>"`.
    pub source: Vec<String>,
    pub generated_at: Option<String>,
    pub spec_version: String,
}

/// One inferred tool: a single API endpoint (or GraphQL operation) with its
/// schema, safety classification, confidence scores, and supporting evidence.
/// This is what an agent sees via `get_tool_schema` and executes via `call_tool`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub resource_kind: ResourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphql: Option<GraphqlInfo>,
    pub path_params: Vec<PathParameter>,
    pub input_schema: Value,
    pub response_schema: Value,
    pub example_response: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example_input: Option<Value>,
    pub auth: AuthRequirement,
    pub safety: SafetyInfo,
    pub confidence: ConfidenceScores,
    pub evidence: Vec<Evidence>,
    pub warnings: Vec<String>,
    pub idempotency: IdempotencyInfo,
    pub pagination: Option<PaginationInfo>,
    pub rate_limit: Option<RateLimitInfo>,
    pub approved: bool,
}

/// Coarse classification of what a tool actually does, used to rank and
/// filter search results (e.g. deprioritizing `Telemetry`/`ConfigResource`
/// tools against a user's task).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    #[default]
    ApiAction,
    StaticJsonResource,
    ConfigResource,
    LocalizationResource,
    Telemetry,
    PlatformResource,
    CommerceApi,
    Unknown,
}

/// Present when a tool wraps a GraphQL operation instead of a plain REST
/// endpoint; carries the operation name/type and whether it was observed as
/// part of a batched request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlInfo {
    pub operation_name: Option<String>,
    pub operation_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default)]
    pub batched: bool,
}

/// A `{placeholder}` segment inferred from a tool's URL path (e.g. the `id`
/// in `/items/{id}`), with its inferred type and observed example values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathParameter {
    pub name: String,
    pub schema: Value,
    pub confidence: f64,
    pub examples: Vec<Value>,
}

/// Whether a tool's captured requests required authentication, and which
/// mechanism (bearer token, cookie, etc.) was detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequirement {
    pub required: bool,
    pub method: Option<String>,
}

/// The runtime's safety gate: `Read` tools execute freely, `Write` and
/// `Unknown` tools are blocked until a human runs `tapestry approve`. This
/// classification is the core of the project's safety model — see
/// `docs/SAFETY_SECURITY.md`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SafetyClassification {
    Read,
    Write,
    Unknown,
}

/// A tool's safety classification plus the confidence and human-readable
/// reasoning behind it (surfaced in `tapestry review` and approval prompts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyInfo {
    pub classification: SafetyClassification,
    pub confidence: f64,
    pub reasoning: String,
}

/// Per-dimension confidence scores (0.0-1.0) for how well a tool's shape was
/// inferred from evidence. `overall` is the number gating approval
/// requirements (`DEFAULT_CONFIDENCE_THRESHOLD` in tapestry-runtime).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfidenceScores {
    pub overall: f64,
    pub path: f64,
    pub path_params: f64,
    pub method: f64,
    pub input_schema: f64,
    pub response_schema: f64,
    pub auth: f64,
    pub safety: f64,
}

/// One piece of support for a tool's inferred shape (e.g. "N observations
/// showed this response field"), surfaced via `get_evidence` so an agent or
/// human can judge whether to trust or approve a tool before using it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub evidence_type: String,
    pub count: usize,
    pub confidence: f64,
    pub detail: Option<String>,
}

/// Whether repeating a tool's call is safe (informs retry behavior).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyInfo {
    pub safe_to_retry: bool,
    pub confidence: f64,
    pub reasoning: String,
}

/// Inferred pagination mechanism for a list-returning tool, if any.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationInfo {
    pub pagination_type: String,
    pub auto: bool,
    pub page_param: Option<String>,
    pub limit_param: Option<String>,
    pub total_path: Option<String>,
}

/// Inferred rate-limit hints for a tool, used to pace repeated live calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub recommended_delay_ms: u64,
    pub max_parallel: u64,
}

/// A single captured request/response pair, redacted before it ever reaches
/// this struct. This is the analyzer's raw input: every `ToolDefinition` is
/// inferred from a cluster of `Observation`s that share a method+path shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub method: String,
    pub url: String,
    pub path: String,
    pub query: BTreeMap<String, Value>,
    pub request_headers: BTreeMap<String, String>,
    pub request_body: Option<Value>,
    pub response_status: Option<u16>,
    pub response_headers: BTreeMap<String, String>,
    pub response_body: Option<Value>,
    /// Browser resource type for the request (lowercased, e.g. "xhr",
    /// "fetch", "document"), from CDP `Network.requestWillBeSent`'s `type`
    /// or a Chrome HAR entry's `_resourceType`. `None` when the capture
    /// source did not record one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Observation {
    /// True when this request was made by page JavaScript (XHR/fetch) but
    /// returned server-rendered HTML instead of JSON — the "HTML fragment
    /// endpoint" pattern some sites use for listing/search flows. Tapestry's
    /// pipeline is JSON-native, so these endpoints cannot become tools today
    /// (see docs/LIMITATIONS.md); this shared predicate lets capture
    /// summaries and diagnostics report that plainly instead of silently
    /// filtering the traffic as page noise.
    pub fn is_html_fragment(&self) -> bool {
        let html_response = self.response_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && value.to_ascii_lowercase().contains("text/html")
        });
        if !html_response {
            return false;
        }
        let xhr_initiated = self
            .resource_type
            .as_deref()
            .is_some_and(|kind| matches!(kind, "xhr" | "fetch"));
        let header_signal = self.request_headers.iter().any(|(name, value)| {
            (name.eq_ignore_ascii_case("sec-fetch-dest") && value.eq_ignore_ascii_case("empty"))
                || (name.eq_ignore_ascii_case("x-requested-with")
                    && value.eq_ignore_ascii_case("xmlhttprequest"))
        });
        xhr_initiated || header_signal
    }
}

/// The JSON shape the runtime returns for every error (auth expiry, approval
/// gate, schema mismatch, network failure, ...). Agents branch on
/// `error_type`, not on parsing free-text messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeErrorResponse {
    pub status: String,
    pub error_type: String,
    pub retryable: bool,
    pub message: String,
    pub action: Option<String>,
    pub details: Option<Value>,
    pub http_status: Option<u16>,
}

/// Field names whose values are treated as secrets wherever a JSON body is
/// persisted or handed to an agent. Shared by the import redaction and the
/// runtime's live-response masking so stored examples and live payloads
/// cannot disagree about what is sensitive.
pub fn is_secret_field_name(key: &str) -> bool {
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

/// Recursively replace values of secret-named fields with `<redacted>`.
pub fn redact_sensitive_fields(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, val)| {
                    if is_secret_field_name(&key) {
                        (key, Value::String("<redacted>".to_string()))
                    } else {
                        (key, redact_sensitive_fields(val))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(redact_sensitive_fields).collect())
        }
        other => other,
    }
}

/// Mask token-shaped substrings in free text: JWTs, `Bearer <token>` values,
/// long hex digests, and dense base64-like runs. Complements
/// `redact_sensitive_fields`, which only works on structured JSON — this is
/// the guard for text that has no field names (non-JSON error bodies today;
/// HTML fragment bodies in the Tier 2 design). Heuristic by nature: it
/// catches credential *shapes*, not every possible secret.
pub fn mask_token_like(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    let mut previous_word_was_bearer = false;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '=' | '+' | '/') {
            word.push(ch);
        } else {
            previous_word_was_bearer = flush_masked(&mut out, &mut word, previous_word_was_bearer);
            out.push(ch);
        }
    }
    flush_masked(&mut out, &mut word, previous_word_was_bearer);
    out
}

fn flush_masked(out: &mut String, word: &mut String, after_bearer: bool) -> bool {
    if word.is_empty() {
        return after_bearer;
    }
    let is_bearer_keyword = word.eq_ignore_ascii_case("bearer");
    if (after_bearer && word.len() >= 8) || looks_token_like(word) {
        out.push_str("<redacted>");
    } else {
        out.push_str(word);
    }
    word.clear();
    is_bearer_keyword
}

fn looks_token_like(word: &str) -> bool {
    // JWT: three dot-separated base64url segments starting with header "eyJ".
    if word.starts_with("eyJ") && word.matches('.').count() >= 2 {
        return true;
    }
    // Long hex digest/token (sha256 hex is 64, session ids commonly 32+).
    if word.len() >= 32
        && word.chars().all(|c| c.is_ascii_hexdigit())
        && word.chars().any(|c| c.is_ascii_alphabetic())
    {
        return true;
    }
    // Dense base64-ish run: long, only token alphabet, mixed upper/lower/digit.
    if word.len() >= 24
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '=' | '+' | '/'))
    {
        let upper = word.chars().filter(|c| c.is_ascii_uppercase()).count();
        let lower = word.chars().filter(|c| c.is_ascii_lowercase()).count();
        let digits = word.chars().filter(|c| c.is_ascii_digit()).count();
        return upper >= 3 && lower >= 3 && digits >= 3;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(resource_type: Option<&str>, response_content_type: &str) -> Observation {
        Observation {
            method: "GET".to_string(),
            url: "https://shop.test/products-fragment?q=shoes".to_string(),
            path: "/products-fragment".to_string(),
            query: BTreeMap::new(),
            request_headers: BTreeMap::new(),
            request_body: None,
            response_status: Some(200),
            response_headers: BTreeMap::from([(
                "Content-Type".to_string(),
                response_content_type.to_string(),
            )]),
            response_body: None,
            resource_type: resource_type.map(str::to_string),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn html_fragment_requires_html_response_and_xhr_signal() {
        assert!(observation(Some("xhr"), "text/html; charset=utf-8").is_html_fragment());
        assert!(observation(Some("fetch"), "text/html").is_html_fragment());
        // JSON XHR responses are the supported path, not fragments.
        assert!(!observation(Some("xhr"), "application/json").is_html_fragment());
        // Plain navigations are pages, not fragments.
        assert!(!observation(Some("document"), "text/html").is_html_fragment());
        assert!(!observation(None, "text/html").is_html_fragment());
    }

    #[test]
    fn mask_token_like_masks_credential_shapes_and_keeps_prose() {
        // JWT
        assert_eq!(
            mask_token_like("invalid token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def"),
            "invalid token: <redacted>"
        );
        // Bearer value (even a short opaque one)
        assert_eq!(
            mask_token_like("Authorization Bearer sk-live-4242 rejected"),
            "Authorization Bearer <redacted> rejected"
        );
        // Long hex session id
        assert_eq!(
            mask_token_like("session deadbeefcafe1234deadbeefcafe1234 expired"),
            "session <redacted> expired"
        );
        // Dense base64-ish API key
        assert_eq!(
            mask_token_like("key AbC1dEf2GhI3jKl4MnO5pQr6StU7 is not valid"),
            "key <redacted> is not valid"
        );
        // Ordinary prose, URLs, and error codes survive untouched.
        let prose = "Rate limit exceeded, see https://docs.example.com/errors/rate-limits (code RATE_LIMIT_429)";
        assert_eq!(mask_token_like(prose), prose);
    }

    #[test]
    fn html_fragment_detected_from_request_headers_without_resource_type() {
        let mut obs = observation(None, "text/html");
        obs.request_headers
            .insert("Sec-Fetch-Dest".to_string(), "empty".to_string());
        assert!(obs.is_html_fragment());

        let mut obs = observation(None, "text/html");
        obs.request_headers
            .insert("X-Requested-With".to_string(), "XMLHttpRequest".to_string());
        assert!(obs.is_html_fragment());
    }
}
