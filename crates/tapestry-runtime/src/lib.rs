use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{collections::BTreeSet, fs, path::Path, time::Duration};
use tapestry_core::{
    ResourceKind, RuntimeErrorResponse, SafetyClassification, ToolDefinition, ToolSpec,
};
use tracing::info;
use url::Url;

const DEFAULT_CONFIDENCE_THRESHOLD: f64 = 0.70;

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub confidence_threshold: f64,
    pub allow_har_replay: bool,
    pub prefer_har_replay: bool,
    pub offline_har_replay: bool,
    pub max_pages: usize,
    pub request_timeout_secs: u64,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
            allow_har_replay: true,
            prefer_har_replay: false,
            offline_har_replay: false,
            max_pages: 1,
            request_timeout_secs: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub safety: SafetyClassification,
    pub confidence: f64,
    pub score: usize,
}

#[derive(Debug, Clone)]
struct RuntimeRequest {
    method: String,
    path: String,
    query: Vec<(String, Value)>,
    body: Option<Value>,
}

pub fn load_toolspec(path: impl AsRef<Path>) -> Result<ToolSpec> {
    let raw = fs::read_to_string(path).context("failed to read ToolSpec")?;
    Ok(serde_json::from_str(&raw).context("failed to parse ToolSpec")?)
}

pub fn search_tools(spec: &ToolSpec, query: &str, limit: usize) -> Vec<SearchResult> {
    info!(
        target: "tapestry::runtime",
        method = "search_tools",
        site = %spec.site.name,
        query,
        limit,
        "runtime request"
    );

    let tokens = query_tokens(query);
    let mut scored: Vec<(usize, &ToolDefinition)> = spec
        .tools
        .iter()
        .filter_map(|tool| {
            let score = search_score(tool, &tokens);
            (score > 0 || query.trim().is_empty()).then_some((score, tool))
        })
        .collect();

    scored.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| right.confidence.overall.total_cmp(&left.confidence.overall))
    });

    scored
        .into_iter()
        .take(limit)
        .map(|(score, tool)| SearchResult {
            id: tool.id.clone(),
            name: tool.name.clone(),
            summary: tool.description.clone(),
            safety: tool.safety.classification.clone(),
            confidence: tool.confidence.overall,
            score,
        })
        .collect()
}

pub fn get_tool_schema(spec: &ToolSpec, tool_id: &str) -> Option<Value> {
    info!(
        target: "tapestry::runtime",
        method = "get_tool_schema",
        site = %spec.site.name,
        tool_id,
        "runtime request"
    );
    spec.tools
        .iter()
        .find(|tool| matches_tool(tool, tool_id))
        .map(|tool| serde_json::to_value(tool).expect("ToolDefinition serializes"))
}

pub fn get_evidence(spec: &ToolSpec, tool_id: &str) -> Value {
    info!(
        target: "tapestry::runtime",
        method = "get_evidence",
        site = %spec.site.name,
        tool_id,
        "runtime request"
    );

    let Some(tool) = spec.tools.iter().find(|tool| matches_tool(tool, tool_id)) else {
        return runtime_error(
            "tool_not_found",
            false,
            "Tool not found",
            json!({ "tool_id": tool_id }),
            None,
            None,
        );
    };

    json!({
        "status": "success",
        "evidence": tool.evidence,
        "warnings": tool.warnings,
        "confidence": tool.confidence
    })
}

pub fn call_tool(spec: &ToolSpec, tool_id: &str, arguments: Value) -> Value {
    call_tool_with_options(spec, tool_id, arguments, &RuntimeOptions::default())
}

pub fn call_tool_with_options(
    spec: &ToolSpec,
    tool_id: &str,
    arguments: Value,
    options: &RuntimeOptions,
) -> Value {
    info!(
        target: "tapestry::runtime",
        method = "call_tool",
        site = %spec.site.name,
        tool_id,
        "runtime request"
    );

    let Some(tool) = spec.tools.iter().find(|tool| matches_tool(tool, tool_id)) else {
        return runtime_error(
            "tool_not_found",
            false,
            "Tool not found",
            json!({ "tool_id": tool_id }),
            None,
            None,
        );
    };

    if let Some(error) = enforce_approval(tool, tool_id, options.confidence_threshold) {
        return error;
    }

    let Some(args) = arguments.as_object() else {
        return runtime_error(
            "schema_mismatch",
            false,
            "Arguments must be a JSON object",
            json!({ "tool_id": tool_id }),
            Some("fix_arguments"),
            None,
        );
    };

    let effective_args = apply_defaults(tool, args);

    if let Err(error) = validate_arguments(tool, tool_id, &effective_args) {
        return error;
    }

    let request = build_request(tool, &effective_args);

    if options.offline_har_replay {
        return replay_or_not_found(
            tool,
            tool_id,
            &request,
            "Replayed the observed HAR response because offline mode was requested",
        );
    }

    if options.prefer_har_replay && options.allow_har_replay && tool.example_response.is_some() {
        info!(
            target: "tapestry::runtime",
            tool_id,
            "using HAR replay before live execution"
        );
        return har_replay_response(
            tool,
            &request,
            "Replayed the observed HAR response because HAR replay was preferred",
        );
    }

    if let Some(base_url) = &spec.site.base_url {
        match execute_request(base_url, tool, &request, options) {
            Ok(value) => return value,
            Err(error) if options.allow_har_replay && tool.example_response.is_some() => {
                info!(
                    target: "tapestry::runtime",
                    error = %error,
                    tool_id,
                    "live execution failed; falling back to HAR replay"
                );
            }
            Err(error) => {
                return runtime_error(
                    "network_error",
                    true,
                    &format!("Network request failed: {error}"),
                    json!({ "tool_id": tool_id }),
                    None,
                    None,
                );
            }
        }
    }

    if options.allow_har_replay {
        return replay_or_not_found(
            tool,
            tool_id,
            &request,
            "Replayed the observed HAR response because live execution was unavailable",
        );
    }

    runtime_error(
        "network_error",
        true,
        "No base_url available for live execution",
        json!({ "tool_id": tool_id }),
        None,
        None,
    )
}

fn replay_or_not_found(
    tool: &ToolDefinition,
    tool_id: &str,
    request: &RuntimeRequest,
    note: &str,
) -> Value {
    if tool.example_response.is_some() {
        return har_replay_response(tool, request, note);
    }

    runtime_error(
        "replay_not_found",
        false,
        "No captured HAR response matched this request",
        json!({
            "tool_id": tool_id,
            "request": request_to_json(request)
        }),
        Some("recapture_with_response_body"),
        None,
    )
}

fn har_replay_response(tool: &ToolDefinition, request: &RuntimeRequest, note: &str) -> Value {
    json!({
        "status": "success",
        "data": tool.example_response.clone().unwrap_or(Value::Null),
        "request": request_to_json(request),
        "execution": {
            "mode": "har_replay",
            "note": note
        }
    })
}

pub fn call_tool_dry_run(spec: &ToolSpec, tool_id: &str, arguments: Value) -> Value {
    let Some(tool) = spec.tools.iter().find(|t| matches_tool(t, tool_id)) else {
        return runtime_error(
            "tool_not_found",
            false,
            "Tool not found",
            json!({ "tool_id": tool_id }),
            None,
            None,
        );
    };
    if let Some(err) = enforce_approval(tool, tool_id, DEFAULT_CONFIDENCE_THRESHOLD) {
        return err;
    }
    let Some(args) = arguments.as_object() else {
        return runtime_error(
            "schema_mismatch",
            false,
            "Arguments must be a JSON object",
            json!({ "tool_id": tool_id }),
            Some("fix_arguments"),
            None,
        );
    };
    let effective_args = apply_defaults(tool, args);
    if let Err(err) = validate_arguments(tool, tool_id, &effective_args) {
        return err;
    }
    let request = build_request(tool, &effective_args);
    json!({
        "status": "dry_run",
        "tool_id": tool_id,
        "would_execute": request_to_json(&request)
    })
}

fn enforce_approval(tool: &ToolDefinition, tool_id: &str, threshold: f64) -> Option<Value> {
    if tool.safety.classification == SafetyClassification::Unknown {
        return Some(runtime_error(
            "approval_required",
            false,
            "Tool safety is unknown and requires explicit approval",
            json!({ "tool_id": tool_id, "safety": tool.safety.classification }),
            Some("approval_required"),
            None,
        ));
    }

    if tool.confidence.overall < threshold && !tool.approved {
        return Some(runtime_error(
            "approval_required",
            false,
            "Tool confidence is below the execution threshold",
            json!({ "tool_id": tool_id, "confidence": tool.confidence.overall, "threshold": threshold }),
            Some("approval_required"),
            None,
        ));
    }

    if tool.safety.classification != SafetyClassification::Read && !tool.approved {
        return Some(runtime_error(
            "approval_required",
            false,
            "Tool requires approval before execution",
            json!({ "tool_id": tool_id, "safety": tool.safety.classification }),
            Some("approval_required"),
            None,
        ));
    }

    None
}

fn validate_arguments(
    tool: &ToolDefinition,
    tool_id: &str,
    args: &Map<String, Value>,
) -> std::result::Result<(), Value> {
    let required = tool
        .input_schema
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for field in required {
        let Some(field) = field.as_str() else {
            continue;
        };
        if !args.contains_key(field) {
            return Err(runtime_error(
                "missing_required_argument",
                false,
                &format!("Missing required argument: {field}"),
                json!({ "tool_id": tool_id, "argument": field }),
                None,
                None,
            ));
        }
    }

    let Some(properties) = tool
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    let allow_passthrough = tool
        .input_schema
        .get("additionalProperties")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || tool
            .input_schema
            .get("x_passthrough")
            .and_then(Value::as_bool)
            .unwrap_or(false);

    for (name, value) in args {
        let Some(schema) = properties.get(name) else {
            if allow_passthrough {
                continue;
            }
            return Err(runtime_error(
                "invalid_argument_type",
                false,
                &format!("Unknown argument: {name}"),
                json!({ "tool_id": tool_id, "argument": name }),
                None,
                None,
            ));
        };
        if !value_matches_schema(value, schema) {
            return Err(runtime_error(
                "invalid_argument_type",
                false,
                &format!(
                    "Invalid type for argument: {name}; expected {}",
                    schema
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                ),
                json!({ "tool_id": tool_id, "argument": name, "expected": schema.get("type").cloned().unwrap_or(Value::Null) }),
                None,
                None,
            ));
        }
    }

    Ok(())
}

fn apply_defaults(tool: &ToolDefinition, args: &Map<String, Value>) -> Map<String, Value> {
    let mut effective = args.clone();
    let Some(properties) = tool
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
    else {
        return effective;
    };

    for (name, schema) in properties {
        if effective.contains_key(name) {
            continue;
        }
        if let Some(default) = schema.get("default") {
            effective.insert(name.clone(), default.clone());
        }
    }

    effective
}

fn value_matches_schema(value: &Value, schema: &Value) -> bool {
    if value.is_null() {
        return schema
            .get("nullable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("string") => value.is_string(),
        Some("integer") => value.as_i64().is_some() || value.as_u64().is_some(),
        Some("number") => value.is_number(),
        Some("boolean") => value.is_boolean(),
        Some("object") => value.is_object(),
        Some("array") => value.is_array(),
        Some(_) | None => true,
    }
}

fn build_request(tool: &ToolDefinition, args: &Map<String, Value>) -> RuntimeRequest {
    let mut path = tool.path.clone();
    let path_param_names: BTreeSet<String> = tool
        .path_params
        .iter()
        .map(|param| param.name.clone())
        .collect();

    for name in &path_param_names {
        if let Some(value) = args.get(name) {
            path = path.replace(&format!("{{{name}}}"), &url_component(value));
        }
    }

    let mut query = Vec::new();
    let mut body = Map::new();
    let method_is_body = matches!(tool.method.as_str(), "POST" | "PUT" | "PATCH");

    for (name, value) in args {
        if path_param_names.contains(name) {
            continue;
        }
        if method_is_body {
            body.insert(name.clone(), value.clone());
        } else {
            query.push((name.clone(), value.clone()));
        }
    }

    RuntimeRequest {
        method: tool.method.clone(),
        path,
        query,
        body: method_is_body.then(|| Value::Object(body)),
    }
}

fn execute_request(
    base_url: &str,
    tool: &ToolDefinition,
    request: &RuntimeRequest,
    options: &RuntimeOptions,
) -> std::result::Result<Value, String> {
    if tool
        .pagination
        .as_ref()
        .map(|pagination| pagination.auto)
        .unwrap_or(false)
        && options.max_pages > 1
        && request.method == "GET"
    {
        return execute_paginated_request(base_url, tool, request, options);
    }

    execute_single_request(base_url, tool, request, options)
}

fn execute_paginated_request(
    base_url: &str,
    tool: &ToolDefinition,
    request: &RuntimeRequest,
    options: &RuntimeOptions,
) -> std::result::Result<Value, String> {
    let page_param = tool
        .pagination
        .as_ref()
        .and_then(|pagination| pagination.page_param.clone())
        .unwrap_or_else(|| "page".to_string());
    let mut data = Vec::new();
    let mut stopped_early = false;

    for page in 1..=options.max_pages {
        let mut page_request = request.clone();
        page_request.query.retain(|(name, _)| name != &page_param);
        page_request
            .query
            .push((page_param.clone(), Value::from(page as i64)));
        let response = execute_single_request(base_url, tool, &page_request, options)?;
        if response["status"] == "error" {
            return Ok(response);
        }
        let page_data = response.get("data").cloned().unwrap_or(Value::Null);
        if page_data == Value::Null
            || page_data
                .as_array()
                .map(|items| items.is_empty())
                .unwrap_or(false)
        {
            break;
        }
        data.push(page_data);
        if page == options.max_pages {
            stopped_early = true;
        }
    }

    Ok(json!({
        "status": "success",
        "data": data,
        "warnings": stopped_early.then(|| vec!["pagination_stopped_at_max_pages"])
    }))
}

const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

fn read_response_body(response: ureq::Response) -> Option<String> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(4096);
    let mut reader = response.into_reader();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(_) => return None,
        }
    }
    String::from_utf8(buf).ok()
}

fn execute_single_request(
    base_url: &str,
    tool: &ToolDefinition,
    request: &RuntimeRequest,
    options: &RuntimeOptions,
) -> std::result::Result<Value, String> {
    let url = build_url(base_url, request)?;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(options.request_timeout_secs))
        .build();
    let req = agent.request(&request.method, url.as_str());

    let response = if let Some(body) = &request.body {
        req.set("content-type", "application/json")
            .send_json(body.clone())
    } else {
        req.call()
    };

    match response {
        Ok(response) => handle_http_response(tool, response.status(), read_response_body(response)),
        Err(ureq::Error::Status(status, response)) => Ok(handle_error_status(
            status,
            read_response_body(response),
            tool,
        )),
        Err(error) => Err(error.to_string()),
    }
}

fn handle_http_response(
    tool: &ToolDefinition,
    status: u16,
    body: Option<String>,
) -> std::result::Result<Value, String> {
    if !(200..=299).contains(&status) {
        return Ok(handle_error_status(status, body, tool));
    }
    let data = parse_response_body(body)?;
    if !response_matches_schema(&data, &tool.response_schema) {
        return Ok(runtime_error(
            "schema_mismatch",
            false,
            "Response did not match the inferred response schema",
            json!({ "tool_id": tool.id }),
            None,
            Some(status),
        ));
    }
    Ok(json!({
        "status": "success",
        "data": data
    }))
}

fn handle_error_status(status: u16, body: Option<String>, tool: &ToolDefinition) -> Value {
    match status {
        401 | 403 => runtime_error(
            "auth_expired",
            false,
            "Authentication expired or was rejected",
            json!({ "tool_id": tool.id }),
            Some("reauth_required"),
            Some(status),
        ),
        429 => runtime_error(
            "rate_limited",
            true,
            "Endpoint rate limit exceeded",
            json!({ "tool_id": tool.id }),
            Some("retry_later"),
            Some(status),
        ),
        _ => runtime_error(
            "endpoint_error",
            false,
            &format!("Endpoint returned HTTP {status}"),
            json!({
                "tool_id": tool.id,
                "body": body.unwrap_or_default().chars().take(200).collect::<String>()
            }),
            None,
            Some(status),
        ),
    }
}

fn parse_response_body(body: Option<String>) -> std::result::Result<Value, String> {
    let Some(body) = body else {
        return Ok(Value::Null);
    };
    if body.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&body).map_err(|error| format!("failed to parse JSON response: {error}"))
}

fn response_matches_schema(data: &Value, schema: &Value) -> bool {
    let Some(schema_type) = schema.get("type").and_then(Value::as_str) else {
        return true;
    };
    if data.is_null() {
        return schema
            .get("nullable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || schema_type == "null";
    }
    match schema_type {
        "object" => data.is_object(),
        "array" => data.is_array(),
        "string" => data.is_string(),
        "integer" => data.as_i64().is_some() || data.as_u64().is_some(),
        "number" => data.is_number(),
        "boolean" => data.is_boolean(),
        _ => true,
    }
}

fn build_url(base_url: &str, request: &RuntimeRequest) -> std::result::Result<Url, String> {
    let mut url = Url::parse(base_url).map_err(|error| error.to_string())?;
    url.set_path(&request.path);
    {
        let mut pairs = url.query_pairs_mut();
        for (name, value) in &request.query {
            pairs.append_pair(name, &query_value(value));
        }
    }
    Ok(url)
}

fn request_to_json(request: &RuntimeRequest) -> Value {
    let mut path = request.path.clone();
    if !request.query.is_empty() {
        let query = request
            .query
            .iter()
            .map(|(name, value)| format!("{name}={}", query_value(value)))
            .collect::<Vec<_>>()
            .join("&");
        path = format!("{path}?{query}");
    }
    json!({
        "method": request.method,
        "path": path,
        "query": request.query.iter().map(|(name, value)| json!({"name": name, "value": value})).collect::<Vec<_>>(),
        "body": request.body
    })
}

fn matches_tool(tool: &ToolDefinition, tool_id: &str) -> bool {
    tool.id == tool_id || tool.name == tool_id
}

fn query_tokens(query: &str) -> Vec<String> {
    query
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| token.len() > 1)
        .map(ToOwned::to_owned)
        .collect()
}

fn search_score(tool: &ToolDefinition, tokens: &[String]) -> usize {
    let name = tool.name.to_ascii_lowercase();
    let description = tool.description.to_ascii_lowercase();
    let path = tool.path.to_ascii_lowercase();
    let graphql = tool
        .graphql
        .as_ref()
        .map(|info| {
            serde_json::to_string(info)
                .unwrap_or_default()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let input_schema = tool.input_schema.to_string().to_ascii_lowercase();
    let evidence = tool
        .evidence
        .iter()
        .filter_map(|evidence| evidence.detail.as_deref())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let warnings = tool.warnings.join(" ").to_ascii_lowercase();
    let resource_keywords = resource_search_keywords(&tool.resource_kind);
    let mut raw_score: usize = tokens
        .iter()
        .map(|token| {
            if name.contains(token) {
                12
            } else if description.contains(token) {
                6
            } else if graphql.contains(token) {
                5
            } else if input_schema.contains(token) {
                4
            } else if evidence.contains(token) {
                4
            } else if path.contains(token) {
                3
            } else if warnings.contains(token) {
                1
            } else if resource_keywords
                .iter()
                .any(|keyword| *keyword == token.as_str())
            {
                3
            } else {
                0
            }
        })
        .sum();

    if tool.resource_kind == ResourceKind::CommerceApi
        && has_resource_intent(tokens, &tool.resource_kind)
    {
        raw_score += 25;
    }
    if tool.resource_kind == ResourceKind::ApiAction && has_commerce_intent(tokens) {
        let commerce_text = format!("{name} {description} {path} {input_schema} {evidence}");
        if commerce_keywords()
            .iter()
            .any(|keyword| commerce_text.contains(keyword))
        {
            raw_score += 10;
        }
    }
    if is_static_resource_kind(&tool.resource_kind)
        && !has_resource_intent(tokens, &tool.resource_kind)
    {
        return raw_score / 8;
    }
    raw_score
}

fn is_static_resource_kind(kind: &ResourceKind) -> bool {
    matches!(
        kind,
        ResourceKind::StaticJsonResource
            | ResourceKind::ConfigResource
            | ResourceKind::LocalizationResource
            | ResourceKind::PlatformResource
            | ResourceKind::Telemetry
    )
}

fn has_resource_intent(tokens: &[String], kind: &ResourceKind) -> bool {
    tokens.iter().any(|token| {
        resource_search_keywords(kind)
            .iter()
            .any(|keyword| *keyword == token.as_str())
    })
}

fn resource_search_keywords(kind: &ResourceKind) -> &'static [&'static str] {
    match kind {
        ResourceKind::LocalizationResource => &[
            "language",
            "lang",
            "translation",
            "translations",
            "locale",
            "localization",
            "i18n",
            "strings",
            "text",
        ],
        ResourceKind::ConfigResource => &[
            "config",
            "configuration",
            "settings",
            "manifest",
            "metadata",
        ],
        ResourceKind::StaticJsonResource => &["dictionary", "metadata", "resource", "static"],
        ResourceKind::PlatformResource => &[
            "wix",
            "platform",
            "manifest",
            "thunderbolt",
            "corvid",
            "editor",
        ],
        ResourceKind::Telemetry => &["telemetry", "monitoring", "log", "analytics", "event"],
        ResourceKind::CommerceApi => commerce_keywords(),
        _ => &[],
    }
}

fn has_commerce_intent(tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|token| commerce_keywords().contains(&token.as_str()))
}

fn commerce_keywords() -> &'static [&'static str] {
    &[
        "product", "products", "item", "items", "query", "search", "filter", "cart", "basket",
        "checkout", "sweets", "candy", "add", "estimate", "store", "stores", "catalog", "ecom",
    ]
}

fn url_component(value: &Value) -> String {
    query_value(value)
}

fn query_value(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn runtime_error(
    error_type: &str,
    retryable: bool,
    message: &str,
    details: Value,
    action: Option<&str>,
    http_status: Option<u16>,
) -> Value {
    let response = RuntimeErrorResponse {
        status: "error".to_string(),
        error_type: error_type.to_string(),
        retryable,
        message: message.to_string(),
        action: action.map(ToOwned::to_owned),
        details: Some(details),
        http_status,
    };
    info!(
        target: "tapestry::runtime",
        error_type,
        retryable,
        action = ?response.action,
        http_status,
        "structured error"
    );
    serde_json::to_value(response).expect("RuntimeErrorResponse serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
        thread,
    };
    use tapestry_core::*;

    #[test]
    fn successful_get_maps_path_and_query_args() {
        let server = MockServer::new(vec![MockResponse::ok(
            json!({"id":42,"includeDetails":true}),
        )]);
        let spec = spec_with_base(
            &server.base_url(),
            vec![tool(
                "get_item",
                "GET",
                "/api/items/{id}",
                true,
                SafetyClassification::Read,
            )],
        );

        let response = call_tool_with_options(
            &spec,
            "get_item",
            json!({"id":42,"includeDetails":true}),
            &live_options(),
        );

        assert_eq!(response["status"], "success");
        assert_eq!(response["data"]["id"], 42);
        assert_eq!(
            server.requests()[0].path,
            "/api/items/42?includeDetails=true"
        );
    }

    #[test]
    fn write_tool_is_blocked_until_approved() {
        let mut create = tool(
            "create_item",
            "POST",
            "/api/items",
            false,
            SafetyClassification::Write,
        );
        create.approved = false;
        let spec = spec_with_base("http://127.0.0.1:1", vec![create]);

        let response =
            call_tool_with_options(&spec, "create_item", json!({"name":"A"}), &live_options());

        assert_eq!(response["status"], "error");
        assert_eq!(response["error_type"], "approval_required");
    }

    #[test]
    fn approved_post_sends_json_body() {
        let server = MockServer::new(vec![MockResponse::ok(json!({"id":1,"name":"A"}))]);
        let mut create = tool(
            "create_item",
            "POST",
            "/api/items",
            false,
            SafetyClassification::Write,
        );
        create.approved = true;
        let spec = spec_with_base(&server.base_url(), vec![create]);

        let response =
            call_tool_with_options(&spec, "create_item", json!({"name":"A"}), &live_options());

        assert_eq!(response["status"], "success");
        assert!(server.requests()[0].body.contains("\"name\":\"A\""));
    }

    #[test]
    fn unknown_safety_requires_approval() {
        let spec = spec_with_base(
            "http://127.0.0.1:1",
            vec![tool(
                "unknown",
                "TRACE",
                "/api/items",
                true,
                SafetyClassification::Unknown,
            )],
        );

        let response = call_tool_with_options(&spec, "unknown", json!({}), &live_options());

        assert_eq!(response["error_type"], "approval_required");
    }

    #[test]
    fn low_confidence_read_requires_approval() {
        let mut read = tool(
            "low_read",
            "GET",
            "/api/items",
            true,
            SafetyClassification::Read,
        );
        read.confidence.overall = 0.3;
        read.approved = false;
        let spec = spec_with_base("http://127.0.0.1:1", vec![read]);

        let response = call_tool_with_options(&spec, "low_read", json!({}), &live_options());

        assert_eq!(response["error_type"], "approval_required");
    }

    #[test]
    fn missing_required_argument_returns_typed_error() {
        let spec = spec_with_base(
            "http://127.0.0.1:1",
            vec![tool(
                "get_item",
                "GET",
                "/api/items/{id}",
                true,
                SafetyClassification::Read,
            )],
        );

        let response = call_tool_with_options(&spec, "get_item", json!({}), &live_options());

        assert_eq!(response["error_type"], "missing_required_argument");
        assert_eq!(response["details"]["argument"], "id");
    }

    #[test]
    fn invalid_argument_type_returns_typed_error() {
        let spec = spec_with_base(
            "http://127.0.0.1:1",
            vec![tool(
                "get_item",
                "GET",
                "/api/items/{id}",
                true,
                SafetyClassification::Read,
            )],
        );

        let response = call_tool_with_options(
            &spec,
            "get_item",
            json!({"id":"not-int","includeDetails":true}),
            &live_options(),
        );

        assert_eq!(response["error_type"], "invalid_argument_type");
        assert_eq!(response["details"]["argument"], "id");
    }

    #[test]
    fn unknown_argument_is_rejected() {
        let spec = spec_with_base(
            "http://127.0.0.1:1",
            vec![tool(
                "list_items",
                "GET",
                "/api/items",
                true,
                SafetyClassification::Read,
            )],
        );

        let response =
            call_tool_with_options(&spec, "list_items", json!({"extra":1}), &live_options());

        assert_eq!(response["error_type"], "invalid_argument_type");
    }

    #[test]
    fn status_401_maps_to_auth_expired() {
        let server = MockServer::new(vec![MockResponse::status(401, json!({"error":"no"}))]);
        let spec = spec_with_base(
            &server.base_url(),
            vec![tool(
                "list_items",
                "GET",
                "/api/items",
                true,
                SafetyClassification::Read,
            )],
        );

        let response = call_tool_with_options(&spec, "list_items", json!({}), &live_options());

        assert_eq!(response["error_type"], "auth_expired");
        assert_eq!(response["http_status"], 401);
    }

    #[test]
    fn status_429_maps_to_rate_limited() {
        let server = MockServer::new(vec![MockResponse::status(429, json!({"error":"slow"}))]);
        let spec = spec_with_base(
            &server.base_url(),
            vec![tool(
                "list_items",
                "GET",
                "/api/items",
                true,
                SafetyClassification::Read,
            )],
        );

        let response = call_tool_with_options(&spec, "list_items", json!({}), &live_options());

        assert_eq!(response["error_type"], "rate_limited");
        assert_eq!(response["retryable"], true);
    }

    #[test]
    fn status_500_maps_to_endpoint_error() {
        let server = MockServer::new(vec![MockResponse::status(500, json!({"error":"boom"}))]);
        let spec = spec_with_base(
            &server.base_url(),
            vec![tool(
                "list_items",
                "GET",
                "/api/items",
                true,
                SafetyClassification::Read,
            )],
        );

        let response = call_tool_with_options(&spec, "list_items", json!({}), &live_options());

        assert_eq!(response["error_type"], "endpoint_error");
        assert_eq!(response["http_status"], 500);
    }

    #[test]
    fn response_schema_mismatch_returns_schema_mismatch() {
        let server = MockServer::new(vec![MockResponse::ok(json!([1, 2, 3]))]);
        let spec = spec_with_base(
            &server.base_url(),
            vec![tool(
                "list_items",
                "GET",
                "/api/items",
                true,
                SafetyClassification::Read,
            )],
        );

        let response = call_tool_with_options(&spec, "list_items", json!({}), &live_options());

        assert_eq!(response["error_type"], "schema_mismatch");
    }

    #[test]
    fn preferred_har_replay_does_not_attempt_live_network_first() {
        let server = MockServer::new(vec![MockResponse::ok(json!({"source":"live"}))]);
        let mut read_tool = tool(
            "list_items",
            "GET",
            "/api/items",
            true,
            SafetyClassification::Read,
        );
        read_tool.example_response = Some(json!({"source":"har"}));
        let spec = spec_with_base(&server.base_url(), vec![read_tool]);
        let options = RuntimeOptions {
            prefer_har_replay: true,
            ..RuntimeOptions::default()
        };

        let response = call_tool_with_options(&spec, "list_items", json!({}), &options);

        assert_eq!(response["status"], "success");
        assert_eq!(response["data"]["source"], "har");
        assert_eq!(response["execution"]["mode"], "har_replay");
        assert!(server.requests().is_empty());
    }

    #[test]
    fn offline_har_replay_does_not_attempt_live_network() {
        let server = MockServer::new(vec![MockResponse::ok(json!({"source":"live"}))]);
        let mut read_tool = tool(
            "list_items",
            "GET",
            "/api/items",
            true,
            SafetyClassification::Read,
        );
        read_tool.example_response = Some(json!({"source":"har"}));
        let spec = spec_with_base(&server.base_url(), vec![read_tool]);
        let options = RuntimeOptions {
            offline_har_replay: true,
            ..RuntimeOptions::default()
        };

        let response = call_tool_with_options(&spec, "list_items", json!({}), &options);

        assert_eq!(response["status"], "success");
        assert_eq!(response["data"]["source"], "har");
        assert_eq!(response["execution"]["mode"], "har_replay");
        assert!(server.requests().is_empty());
    }

    #[test]
    fn offline_har_replay_returns_replay_not_found_without_example() {
        let server = MockServer::new(vec![MockResponse::ok(json!({"source":"live"}))]);
        let read_tool = tool(
            "list_items",
            "GET",
            "/api/items",
            true,
            SafetyClassification::Read,
        );
        let spec = spec_with_base(&server.base_url(), vec![read_tool]);
        let options = RuntimeOptions {
            offline_har_replay: true,
            ..RuntimeOptions::default()
        };

        let response = call_tool_with_options(&spec, "list_items", json!({}), &options);

        assert_eq!(response["status"], "error");
        assert_eq!(response["error_type"], "replay_not_found");
        assert_eq!(response["retryable"], false);
        assert!(server.requests().is_empty());
    }

    #[test]
    fn network_failure_returns_network_error_without_replay() {
        let spec = spec_with_base(
            "http://127.0.0.1:9",
            vec![tool(
                "list_items",
                "GET",
                "/api/items",
                true,
                SafetyClassification::Read,
            )],
        );

        let response = call_tool_with_options(&spec, "list_items", json!({}), &live_options());

        assert_eq!(response["error_type"], "network_error");
        assert_eq!(response["retryable"], true);
    }

    #[test]
    fn search_prefers_name_match_and_evidence_returns_data() {
        let spec = spec_with_base(
            "http://127.0.0.1:1",
            vec![
                tool(
                    "get_item",
                    "GET",
                    "/api/items/{id}",
                    true,
                    SafetyClassification::Read,
                ),
                tool(
                    "list_items",
                    "GET",
                    "/api/items",
                    true,
                    SafetyClassification::Read,
                ),
            ],
        );

        let results = search_tools(&spec, "list items", 1);
        let evidence = get_evidence(&spec, "list_items");

        assert_eq!(results[0].name, "list_items");
        assert_eq!(evidence["status"], "success");
        assert_eq!(evidence["evidence"][0]["source"], "har");
    }

    #[test]
    fn search_indexes_graphql_query_variables_and_evidence() {
        let mut tool = tool(
            "search_groceries",
            "POST",
            "/",
            true,
            SafetyClassification::Read,
        );
        tool.description = "Observed GraphQL query SearchGroceries at POST /".to_string();
        tool.graphql = Some(GraphqlInfo {
            operation_name: Some("SearchGroceries".to_string()),
            operation_type: Some("query".to_string()),
            query: Some(
                "query SearchGroceries($basketId: ID) { basket { groceries { title } } }"
                    .to_string(),
            ),
            batched: false,
        });
        tool.input_schema = json!({
            "type": "object",
            "properties": {
                "basketId": {"type":"string"}
            },
            "required": []
        });
        tool.evidence[0].detail =
            Some("POST / GraphQL SearchGroceries basket groceries".to_string());
        let spec = spec_with_base("http://127.0.0.1:1", vec![tool]);

        let results = search_tools(&spec, "basket search groceries", 1);

        assert_eq!(results[0].name, "search_groceries");
        assert!(results[0].score > 0);
    }

    #[test]
    fn search_penalizes_localization_resource_for_app_action_query() {
        let spec = spec_with_base("http://127.0.0.1:1", vec![localization_tool()]);

        let results = search_tools(&spec, "game data save cloud playfab", 5);

        assert!(results.is_empty());
    }

    #[test]
    fn search_allows_localization_resource_for_language_query() {
        let spec = spec_with_base("http://127.0.0.1:1", vec![localization_tool()]);

        let results = search_tools(&spec, "language translations", 5);

        assert_eq!(results[0].name, "list_en.json");
        assert!(results[0].score > 0);
    }

    #[test]
    fn search_ranks_commerce_product_tool_above_wix_manifest() {
        let spec = spec_with_base(
            "http://127.0.0.1:1",
            vec![wix_manifest_tool(), commerce_query_tool()],
        );

        let results = search_tools(&spec, "products sweets candy", 5);

        assert_eq!(results[0].name, "list_query");
    }

    #[test]
    fn search_ranks_cart_api_above_platform_resource() {
        let spec = spec_with_base("http://127.0.0.1:1", vec![wix_manifest_tool(), cart_tool()]);

        let results = search_tools(&spec, "cart checkout basket", 5);

        assert_eq!(results[0].name, "create_add-line-items");
    }

    #[test]
    fn tool_not_found_is_typed() {
        let spec = spec_with_base("http://127.0.0.1:1", vec![]);
        let response = call_tool_with_options(&spec, "missing", json!({}), &live_options());

        assert_eq!(response["error_type"], "tool_not_found");
    }

    fn live_options() -> RuntimeOptions {
        RuntimeOptions {
            allow_har_replay: false,
            ..RuntimeOptions::default()
        }
    }

    fn spec_with_base(base_url: &str, tools: Vec<ToolDefinition>) -> ToolSpec {
        ToolSpec {
            site: SiteInfo {
                name: "test".to_string(),
                base_url: Some(base_url.to_string()),
                source: vec!["test".to_string()],
                generated_at: None,
                spec_version: "0.1.0".to_string(),
            },
            tools,
        }
    }

    fn tool(
        name: &str,
        method: &str,
        path: &str,
        approved: bool,
        safety: SafetyClassification,
    ) -> ToolDefinition {
        let has_id = path.contains("{id}");
        let path_params = has_id
            .then(|| PathParameter {
                name: "id".to_string(),
                schema: json!({"type":"integer"}),
                confidence: 0.9,
                examples: vec![json!(1)],
            })
            .into_iter()
            .collect::<Vec<_>>();

        let mut properties = Map::new();
        if has_id {
            properties.insert("id".to_string(), json!({"type":"integer"}));
        }
        if method == "GET" && name == "get_item" {
            properties.insert(
                "includeDetails".to_string(),
                json!({"type":"boolean", "optional": true}),
            );
        }
        if method == "POST" {
            properties.insert("name".to_string(), json!({"type":"string"}));
        }

        ToolDefinition {
            id: name.to_string(),
            name: name.to_string(),
            description: format!("{method} {path}"),
            method: method.to_string(),
            path: path.to_string(),
            resource_kind: ResourceKind::ApiAction,
            graphql: None,
            path_params,
            input_schema: json!({
                "type": "object",
                "properties": properties,
                "required": if has_id {
                    vec![json!("id")]
                } else if method == "POST" {
                    vec![json!("name")]
                } else {
                    Vec::<Value>::new()
                }
            }),
            response_schema: json!({"type":"object","properties":{},"required":[]}),
            example_response: None,
            example_input: None,
            auth: AuthRequirement {
                required: false,
                method: None,
            },
            safety: SafetyInfo {
                classification: safety,
                confidence: 0.9,
                reasoning: "test".to_string(),
            },
            confidence: ConfidenceScores {
                overall: 0.9,
                path: 0.9,
                path_params: 0.9,
                method: 0.99,
                input_schema: 0.9,
                response_schema: 0.9,
                auth: 0.5,
                safety: 0.9,
            },
            evidence: vec![Evidence {
                source: "har".to_string(),
                evidence_type: "observed_requests".to_string(),
                count: 1,
                confidence: 0.9,
                detail: None,
            }],
            warnings: vec![],
            idempotency: IdempotencyInfo {
                safe_to_retry: method == "GET",
                confidence: 0.9,
                reasoning: "test".to_string(),
            },
            pagination: None,
            rate_limit: None,
            approved,
        }
    }

    fn localization_tool() -> ToolDefinition {
        let mut tool = tool(
            "list_en.json",
            "GET",
            "/lang/en.json",
            true,
            SafetyClassification::Read,
        );
        tool.resource_kind = ResourceKind::LocalizationResource;
        tool.description = "Observed GET endpoint /lang/en.json".to_string();
        tool.response_schema = json!({
            "type": "object",
            "properties": {
                "PLAY": {"type":"string"},
                "SAVE": {"type":"string"}
            },
            "required": ["PLAY", "SAVE"]
        });
        tool.example_response = Some(json!({"PLAY": "Play", "SAVE": "Save"}));
        tool
    }

    fn wix_manifest_tool() -> ToolDefinition {
        let mut tool = tool(
            "list_rb_wixui.corvid.manifest.min.json",
            "GET",
            "/services/editor-elements/1.15085.0/rb_wixui.corvid.manifest.min.json",
            true,
            SafetyClassification::Read,
        );
        tool.resource_kind = ResourceKind::PlatformResource;
        tool.description = "Observed GET endpoint /services/editor-elements manifest".to_string();
        tool.response_schema = json!({
            "type": "object",
            "properties": {
                "components": {
                    "type": "object",
                    "properties": {
                        "ProductSpecification": {"type": "array"},
                        "SearchBox": {"type": "array"}
                    }
                }
            },
            "required": ["components"]
        });
        tool.example_response = Some(
            json!({"components":{"ProductSpecification":["bundle.js"],"SearchBox":["bundle.js"]}}),
        );
        tool
    }

    fn commerce_query_tool() -> ToolDefinition {
        let mut tool = tool(
            "list_query",
            "GET",
            "/_api/cloud-data/v2/items/query",
            true,
            SafetyClassification::Read,
        );
        tool.resource_kind = ResourceKind::CommerceApi;
        tool.description = "Observed commerce product query endpoint".to_string();
        tool.input_schema = json!({
            "type": "object",
            "properties": {
                "filter": {"type": "string"}
            },
            "required": []
        });
        tool.evidence[0].detail =
            Some("GET /_api/cloud-data/v2/items/query product items filter".to_string());
        tool
    }

    fn cart_tool() -> ToolDefinition {
        let mut tool = tool(
            "create_add-line-items",
            "POST",
            "/_api/cart-v2/v2/carts/current/add-line-items",
            false,
            SafetyClassification::Write,
        );
        tool.resource_kind = ResourceKind::CommerceApi;
        tool.description = "Observed commerce cart add line items endpoint".to_string();
        tool.input_schema = json!({
            "type": "object",
            "properties": {
                "lineItems": {"type": "array"}
            },
            "required": ["lineItems"]
        });
        tool.evidence[0].detail = Some(
            "POST /_api/cart-v2/v2/carts/current/add-line-items cart basket checkout".to_string(),
        );
        tool
    }

    #[derive(Clone)]
    struct MockResponse {
        status: u16,
        body: Value,
    }

    impl MockResponse {
        fn ok(body: Value) -> Self {
            Self { status: 200, body }
        }

        fn status(status: u16, body: Value) -> Self {
            Self { status, body }
        }
    }

    #[derive(Clone, Debug)]
    struct CapturedRequest {
        path: String,
        body: String,
    }

    struct MockServer {
        addr: std::net::SocketAddr,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl MockServer {
        fn new(responses: Vec<MockResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let captured = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                for response in responses {
                    let Ok((mut stream, _)) = listener.accept() else {
                        break;
                    };
                    handle_connection(&mut stream, response, &captured);
                }
            });
            Self {
                addr,
                requests,
                handle: Some(handle),
            }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            let _ = TcpStream::connect(self.addr);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn handle_connection(
        stream: &mut TcpStream,
        response: MockResponse,
        requests: &Arc<Mutex<Vec<CapturedRequest>>>,
    ) {
        let raw = read_http_request(stream);
        let mut lines = raw.lines();
        let first = lines.next().unwrap_or_default();
        let path = first
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_string();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
        requests
            .lock()
            .unwrap()
            .push(CapturedRequest { path, body });

        let body = response.body.to_string();
        let reason = if response.status == 200 { "OK" } else { "ERR" };
        let wire = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response.status,
            reason,
            body.len(),
            body
        );
        stream.write_all(wire.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let bytes = stream.read(&mut buffer).unwrap_or(0);
            if bytes == 0 {
                break;
            }
            data.extend_from_slice(&buffer[..bytes]);
            let raw = String::from_utf8_lossy(&data);
            let Some(header_end) = raw.find("\r\n\r\n") else {
                continue;
            };
            let content_length = raw
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            let body_start = header_end + 4;
            if data.len() >= body_start + content_length {
                break;
            }
        }
        String::from_utf8_lossy(&data).to_string()
    }
}
