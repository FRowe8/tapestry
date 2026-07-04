use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub site: SiteInfo,
    pub tools: Vec<ToolDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteInfo {
    pub name: String,
    pub base_url: Option<String>,
    pub source: Vec<String>,
    pub generated_at: Option<String>,
    pub spec_version: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    ApiAction,
    StaticJsonResource,
    ConfigResource,
    LocalizationResource,
    Telemetry,
    PlatformResource,
    CommerceApi,
    Unknown,
}

impl Default for ResourceKind {
    fn default() -> Self {
        Self::ApiAction
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlInfo {
    pub operation_name: Option<String>,
    pub operation_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default)]
    pub batched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathParameter {
    pub name: String,
    pub schema: Value,
    pub confidence: f64,
    pub examples: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequirement {
    pub required: bool,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SafetyClassification {
    Read,
    Write,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyInfo {
    pub classification: SafetyClassification,
    pub confidence: f64,
    pub reasoning: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub evidence_type: String,
    pub count: usize,
    pub confidence: f64,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyInfo {
    pub safe_to_retry: bool,
    pub confidence: f64,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationInfo {
    pub pagination_type: String,
    pub auto: bool,
    pub page_param: Option<String>,
    pub limit_param: Option<String>,
    pub total_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub recommended_delay_ms: u64,
    pub max_parallel: u64,
}

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
