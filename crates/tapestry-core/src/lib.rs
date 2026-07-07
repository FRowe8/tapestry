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
    #[serde(default)]
    pub warnings: Vec<String>,
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
