use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::Duration,
};
use tapestry_core::{
    ResourceKind, RuntimeErrorResponse, SafetyClassification, ToolDefinition, ToolSpec,
};
use tracing::info;
use url::Url;

pub const DEFAULT_CONFIDENCE_THRESHOLD: f64 = 0.70;

/// Execution behavior for `call_tool_with_options` and friends: how much to
/// trust captured HAR responses vs. calling the network live, request
/// timeouts, pagination limits, and injected credentials.
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    /// Tools below this overall confidence require approval even if `Read`-safe.
    pub confidence_threshold: f64,
    /// Allow falling back to a captured HAR response when live execution fails.
    pub allow_har_replay: bool,
    /// Try HAR replay before attempting a live call (used for HAR-sourced/local sites).
    pub prefer_har_replay: bool,
    /// Never call the network; only ever replay captured HAR responses.
    pub offline_har_replay: bool,
    pub max_pages: usize,
    pub request_timeout_secs: u64,
    /// HTTP headers injected into every outgoing request (e.g. Authorization, Cookie).
    pub credentials: BTreeMap<String, String>,
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
            credentials: BTreeMap::new(),
        }
    }
}

/// One ranked match from `search_tools`. This is deliberately small (no
/// schema, no evidence) — the low-token summary an agent sees before
/// deciding whether to load the full schema via `get_tool_schema`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub safety: SafetyClassification,
    pub confidence: f64,
    pub score: usize,
    /// Tool warnings agents should see before calling (e.g. health drift).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Coarse guess at what a natural-language task is trying to do, used to
/// bias tool ranking in `search_tools`/agent selection (e.g. prefer a
/// `Read` tool for `SearchOrList`, allow `Write` tools for `CreateOrAdd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskIntent {
    SearchOrList,
    GetDetail,
    CreateOrAdd,
    UpdateOrEdit,
    DeleteOrRemove,
    CheckoutOrPurchase,
    Unknown,
}

impl TaskIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskIntent::SearchOrList => "search_or_list",
            TaskIntent::GetDetail => "get_detail",
            TaskIntent::CreateOrAdd => "create_or_add",
            TaskIntent::UpdateOrEdit => "update_or_edit",
            TaskIntent::DeleteOrRemove => "delete_or_remove",
            TaskIntent::CheckoutOrPurchase => "checkout_or_purchase",
            TaskIntent::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeRequest {
    method: String,
    path: String,
    query: Vec<(String, Value)>,
    body: Option<Value>,
}

/// Load a `ToolSpec` written by `tapestry generate` from disk.
pub fn load_toolspec(path: impl AsRef<Path>) -> Result<ToolSpec> {
    let raw = fs::read_to_string(path).context("failed to read ToolSpec")?;
    serde_json::from_str(&raw).context("failed to parse ToolSpec")
}

/// Load a site's stored credential headers (name -> value), or an empty map
/// if the file doesn't exist yet.
pub fn load_credentials(path: impl AsRef<Path>) -> Result<BTreeMap<String, String>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(path).context("failed to read credentials")?;
    let map: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&raw).context("failed to parse credentials JSON")?;
    Ok(map
        .into_iter()
        .filter_map(|(k, v)| {
            v.get("value")
                .and_then(serde_json::Value::as_str)
                .map(|s| (k, s.to_string()))
        })
        .collect())
}

/// One granted approval, stored per tool id in a site's `approvals.json`.
///
/// The fingerprint pins the approval to the request shape that was reviewed:
/// if `generate` later produces a tool with the same id but a different
/// method, path, or input schema, the approval no longer applies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub fingerprint: String,
    pub approved_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Fingerprint of the request shape an approval covers.
pub fn tool_fingerprint(tool: &ToolDefinition) -> String {
    let shape = json!({
        "method": tool.method,
        "path": tool.path,
        "input_schema": tool.input_schema,
    });
    let mut canonical = String::new();
    write_canonical_json(&shape, &mut canonical);
    format!("{:016x}", fnv1a64(canonical.as_bytes()))
}

fn write_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*key).clone()).to_string());
                out.push(':');
                write_canonical_json(&map[*key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Load a site's stored approvals (tool id -> `ApprovalRecord`), or an empty
/// map if `approvals.json` doesn't exist yet.
pub fn load_approvals(path: impl AsRef<Path>) -> Result<BTreeMap<String, ApprovalRecord>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(path).context("failed to read approvals")?;
    serde_json::from_str(&raw).context("failed to parse approvals JSON")
}

/// Outcome of overlaying stored approvals onto a freshly loaded ToolSpec.
#[derive(Debug, Clone, Default)]
pub struct ApprovalOverlay {
    /// Tool ids whose stored approval matched and was applied.
    pub applied: Vec<String>,
    /// Approvals whose tool changed shape since approval; not applied.
    pub stale: Vec<String>,
    /// Approvals whose tool id no longer exists in the ToolSpec.
    pub orphaned: Vec<String>,
}

/// Set `approved = true` on tools with a matching, still-valid approval.
///
/// An approval is applied only when the stored fingerprint equals the tool's
/// current fingerprint; otherwise it is reported as stale so callers can tell
/// the user to re-review the tool.
pub fn apply_approvals(
    spec: &mut ToolSpec,
    approvals: &BTreeMap<String, ApprovalRecord>,
) -> ApprovalOverlay {
    let mut overlay = ApprovalOverlay::default();
    for (tool_id, record) in approvals {
        let Some(tool) = spec.tools.iter_mut().find(|tool| tool.id == *tool_id) else {
            overlay.orphaned.push(tool_id.clone());
            continue;
        };
        if tool_fingerprint(tool) == record.fingerprint {
            tool.approved = true;
            overlay.applied.push(tool_id.clone());
        } else {
            overlay.stale.push(tool_id.clone());
        }
    }
    overlay
}

/// Meta-tool 1 of 4: rank a site's tools against a natural-language query
/// and return the top `limit` low-token summaries. This is the only thing an
/// agent sees before deciding which tool (if any) to load a schema for —
/// the whole point of the four-meta-tool design is that this list, not the
/// full ToolSpec, is what fits in context.
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
    let intent = classify_task_intent(query);
    let mut scored: Vec<(i32, &ToolDefinition)> = spec
        .tools
        .iter()
        .filter_map(|tool| {
            let score = search_score(tool, &tokens, intent);
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
            score: score.max(0) as usize,
            warnings: tool
                .warnings
                .iter()
                .filter(|warning| warning.starts_with("health:"))
                .cloned()
                .collect(),
        })
        .collect()
}

/// Meta-tool 2 of 4: the full call contract for one tool (input/response
/// schema, safety, confidence, an `arguments` calling convention hint, and
/// whether it's blocked pending approval), with the bulky example payload
/// and evidence trimmed out — call `get_evidence` separately for those.
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
        .map(|tool| {
            let mut value = serde_json::to_value(tool).expect("ToolDefinition serializes");
            compact_schema_response(&mut value);
            if let Some(map) = value.as_object_mut() {
                // The call-time envelope key is `arguments`, which nothing in
                // the tool's own schema would tell an agent (`input_schema`
                // invites guessing `input`). Say it here, before the mistake.
                map.insert(
                    "how_to_call".to_string(),
                    Value::String(format!(
                        "call_tool {{\"tool_id\": \"{}\", \"arguments\": {{...}}}} \
                         where arguments matches input_schema",
                        tool.id
                    )),
                );
                if !tool.approved {
                    let reasons = approval_pending_reasons(tool, DEFAULT_CONFIDENCE_THRESHOLD);
                    if !reasons.is_empty() {
                        map.insert(
                            "approval_pending".to_string(),
                            Value::String(format!(
                                "Calling this tool will fail until the user approves it: {}.",
                                reasons.join(", and ")
                            )),
                        );
                    }
                }
            }
            value
        })
}

/// Trim the parts of a schema response that don't help an agent make its
/// next call. Full example payloads dominate the serialized ToolDefinition
/// (often >80% of it) and evidence has its own meta-tool; leaving them here
/// would spend the token budget the meta-tool design exists to protect.
fn compact_schema_response(value: &mut Value) {
    let Some(map) = value.as_object_mut() else {
        return;
    };
    map.remove("evidence");
    if let Some(example) = map.get_mut("example_response") {
        if truncate_example_value(example) {
            map.insert("example_response_truncated".to_string(), Value::Bool(true));
        }
    }
}

/// Recursively shrink an example payload while preserving its shape: arrays
/// keep their first element, long strings are capped. Returns true if
/// anything was trimmed.
fn truncate_example_value(value: &mut Value) -> bool {
    const MAX_STRING_LEN: usize = 120;
    match value {
        Value::Array(items) => {
            let mut truncated = items.len() > 1;
            items.truncate(1);
            for item in items.iter_mut() {
                truncated |= truncate_example_value(item);
            }
            truncated
        }
        Value::Object(map) => {
            let mut truncated = false;
            for item in map.values_mut() {
                truncated |= truncate_example_value(item);
            }
            truncated
        }
        Value::String(text) if text.chars().count() > MAX_STRING_LEN => {
            let mut clipped: String = text.chars().take(MAX_STRING_LEN).collect();
            clipped.push('…');
            *text = clipped;
            true
        }
        _ => false,
    }
}

/// Meta-tool 4 of 4: the supporting evidence, warnings, and confidence
/// breakdown behind a tool's inferred shape — the detail `get_tool_schema`
/// deliberately omits, for when an agent or human needs to judge whether a
/// tool (especially one pending approval) is trustworthy.
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

/// `call_tool_with_options` with default `RuntimeOptions`.
pub fn call_tool(spec: &ToolSpec, tool_id: &str, arguments: Value) -> Value {
    call_tool_with_options(spec, tool_id, arguments, &RuntimeOptions::default())
}

/// Meta-tool 3 of 4: validate `arguments` against a tool's input schema,
/// enforce the safety gate (blocked until approved, unless read-safe above
/// the confidence threshold), then execute — live over HTTP or by replaying
/// a captured HAR response, per `options`. Always returns a structured JSON
/// value (see `RuntimeErrorResponse` for the error shape); never panics on
/// a bad call.
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

    if let Some(error) =
        enforce_approval(&spec.site.name, tool, tool_id, options.confidence_threshold)
    {
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

/// Validate and plan a call the same way `call_tool_with_options` does, but
/// always return the tool's captured example response instead of executing
/// — for previewing what a call would look like without touching the
/// network or requiring approval.
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
    if let Some(err) =
        enforce_approval(&spec.site.name, tool, tool_id, DEFAULT_CONFIDENCE_THRESHOLD)
    {
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

/// Why an unapproved tool will be blocked at execution time. Reports every
/// applicable reason, not just the first: a low-confidence write tool blocked
/// with only "confidence below threshold" reads as a tuning problem when the
/// real gate is the write classification.
fn approval_pending_reasons(tool: &ToolDefinition, threshold: f64) -> Vec<String> {
    let mut reasons = Vec::new();
    match tool.safety.classification {
        SafetyClassification::Write => reasons.push("it is classified as a write tool".to_string()),
        SafetyClassification::Unknown => {
            reasons.push("its safety classification is unknown".to_string())
        }
        SafetyClassification::Read => {}
    }
    if tool.confidence.overall < threshold {
        reasons.push(format!(
            "its confidence ({:.2}) is below the execution threshold ({:.2})",
            tool.confidence.overall, threshold
        ));
    }
    reasons
}

fn enforce_approval(
    site: &str,
    tool: &ToolDefinition,
    tool_id: &str,
    threshold: f64,
) -> Option<Value> {
    if tool.approved {
        return None;
    }

    let reasons = approval_pending_reasons(tool, threshold);
    if reasons.is_empty() {
        return None;
    }

    // Agents relay error text to the user, so the text must carry the fix.
    let message = format!(
        "Tool '{tool_id}' requires approval before it can execute: {}. \
         Ask the user to run `tapestry approve {site} {tool_id}` \
         (or `tapestry approve {site} --list` to review what is pending).",
        reasons.join(", and ")
    );
    Some(runtime_error(
        "approval_required",
        false,
        &message,
        json!({
            "tool_id": tool_id,
            "safety": tool.safety.classification,
            "confidence": tool.confidence.overall,
            "threshold": threshold,
            "fix": format!("tapestry approve {site} {tool_id}"),
        }),
        Some("approval_required"),
        None,
    ))
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
        body: method_is_body.then_some(Value::Object(body)),
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
    let mut req = agent.request(&request.method, url.as_str());
    for (name, value) in &options.credentials {
        req = req.set(name, value);
    }

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
    // Live payloads get the same secret-field masking as stored examples:
    // the capture pipeline redacts what it persists, and an agent's context
    // window is no safer a place for a session token than a JSON file.
    let data = tapestry_core::redact_sensitive_fields(parse_response_body(body)?);
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
    let mut response = json!({
        "status": "success",
        "data": data,
        "execution": { "mode": "live" }
    });
    if let Some(conformance) =
        response_field_compatibility(&response["data"], &tool.response_schema)
    {
        response["conformance"] = json!({
            "field_compatibility": conformance.compatibility,
            "missing_fields": conformance.missing_fields,
        });
    }
    Ok(response)
}

/// Field-level agreement between a live response and the inferred schema.
#[derive(Debug, Clone)]
pub struct FieldCompatibility {
    /// Fraction of inferred top-level fields present in the response (0..=1).
    pub compatibility: f64,
    pub missing_fields: Vec<String>,
}

/// Compare a response's fields against the inferred response schema.
///
/// Returns `None` when the schema carries no field information to compare
/// (opaque or empty schemas), so callers can distinguish "conforms" from
/// "nothing to check". Arrays are checked via their first element, matching
/// how the analyzer inferred the item schema.
pub fn response_field_compatibility(data: &Value, schema: &Value) -> Option<FieldCompatibility> {
    let (item_schema, item_data) = match schema.get("type").and_then(Value::as_str) {
        Some("array") => (schema.get("items")?, data.as_array()?.first()?),
        _ => (schema, data),
    };
    let properties = item_schema.get("properties").and_then(Value::as_object)?;
    if properties.is_empty() {
        return None;
    }
    let object = item_data.as_object()?;
    let missing_fields: Vec<String> = properties
        .keys()
        .filter(|field| !object.contains_key(*field))
        .cloned()
        .collect();
    Some(FieldCompatibility {
        compatibility: 1.0 - missing_fields.len() as f64 / properties.len() as f64,
        missing_fields,
    })
}

fn handle_error_status(status: u16, body: Option<String>, tool: &ToolDefinition) -> Value {
    match status {
        401 | 403 => runtime_error(
            "auth_expired",
            false,
            "Authentication expired or was rejected. Refresh stored credentials with `tapestry reauth <site>`.",
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
        _ => {
            // Error bodies can echo credentials back (e.g. "invalid token:
            // ..."); mask JSON fields, and token-shaped strings in non-JSON
            // bodies, before quoting the snippet.
            let body = body.unwrap_or_default();
            let snippet = match serde_json::from_str::<Value>(&body) {
                Ok(json) => tapestry_core::redact_sensitive_fields(json).to_string(),
                Err(_) => tapestry_core::mask_token_like(&body),
            };
            runtime_error(
                "endpoint_error",
                status >= 500,
                &format!("Endpoint returned HTTP {status}"),
                json!({
                    "tool_id": tool.id,
                    "status_code": status,
                    "body": snippet.chars().take(200).collect::<String>()
                }),
                None,
                Some(status),
            )
        }
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

/// Keyword-based guess at a natural-language task's `TaskIntent`, used to
/// bias tool ranking (e.g. a "list" task favors read tools; a "delete" task
/// won't be satisfied by a read-only tool no matter how well it scores).
pub fn classify_task_intent(task: &str) -> TaskIntent {
    let task_lower = task.to_ascii_lowercase();
    if contains_any_phrase(&task_lower, &["delete", "remove", "cancel"]) {
        TaskIntent::DeleteOrRemove
    } else if contains_any_phrase(&task_lower, &["update", "edit", "change", "modify"]) {
        TaskIntent::UpdateOrEdit
    } else if contains_any_phrase(
        &task_lower,
        &[
            "checkout", "buy", "purchase", "book", "pay", "basket", "cart",
        ],
    ) {
        TaskIntent::CheckoutOrPurchase
    } else if contains_any_phrase(&task_lower, &["create", "add", "insert", "new", "save"]) {
        TaskIntent::CreateOrAdd
    } else if contains_any_phrase(
        &task_lower,
        &["details", "detail", "open", "inspect", "by id", "specific"],
    ) {
        TaskIntent::GetDetail
    } else if contains_any_phrase(
        &task_lower,
        &[
            "search",
            "find",
            "list",
            "show",
            "browse",
            "look up",
            "view",
            "get products",
            "get flights",
            "get holidays",
        ],
    ) {
        TaskIntent::SearchOrList
    } else {
        TaskIntent::Unknown
    }
}

fn contains_any_phrase(text: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|phrase| text.contains(phrase))
}

fn search_score(tool: &ToolDefinition, tokens: &[String], intent: TaskIntent) -> i32 {
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
    // Whole-word matches must dominate: an exact resource-noun hit ("users"
    // -> list_users) is stronger evidence than any category or intent boost,
    // otherwise generic boosts push unrelated tools above the obvious match.
    let name_segments: Vec<&str> = name
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|seg| !seg.is_empty())
        .collect();
    let path_segments: Vec<String> = path
        .split('/')
        .filter(|seg| !seg.is_empty() && !seg.starts_with('{'))
        .map(str::to_ascii_lowercase)
        .collect();
    let term_match_score: i32 = tokens
        .iter()
        .map(|token| {
            if name_segments
                .iter()
                .any(|seg| token_matches_word(token, seg))
            {
                30
            } else if path_segments
                .iter()
                .any(|seg| token_matches_word(token, seg))
            {
                20
            } else if name.contains(token) {
                12
            } else if description.contains(token) {
                6
            } else if graphql.contains(token) {
                5
            } else if input_schema.contains(token) || evidence.contains(token) {
                4
            } else if path.contains(token) {
                3
            } else if warnings.contains(token) {
                1
            } else if resource_keywords.contains(&token.as_str()) {
                3
            } else {
                0
            }
        })
        .sum();

    let mut raw_score = term_match_score;

    raw_score += intent_search_adjustment(tool, intent);
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

    // Penalise low-confidence tools so high-quality tools always rank above them
    if tool.confidence.overall < 0.5 {
        raw_score -= 30;
    } else if tool.confidence.overall < 0.7 {
        raw_score -= 10;
    }

    // Penalise framework-generated versioned paths (Next.js, Nuxt, etc.)
    if is_framework_path(&tool.path) {
        raw_score -= 40;
    }

    // A tool that matched at least one query term is always included (ranked last).
    // Penalties demote rank but should not exclude genuinely relevant tools.
    if term_match_score > 0 && raw_score <= 0 {
        return 1;
    }

    raw_score
}

/// Whole-word token comparison with naive plural folding, so "users" matches
/// the `users` segment of `list_users` and "phone" matches "phones", without
/// substring false positives like "for" in "format".
fn token_matches_word(token: &str, word: &str) -> bool {
    if token == word {
        return true;
    }
    if token.len() < 3 || word.len() < 3 {
        return false;
    }
    let token_singular = token.strip_suffix('s').unwrap_or(token);
    let word_singular = word.strip_suffix('s').unwrap_or(word);
    token_singular == word_singular
}

fn is_framework_path(path: &str) -> bool {
    path.contains("/_next/")
        || path.contains("/_nuxt/")
        || path.contains("/_app/")
        || path.contains("/_astro/")
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
    tokens
        .iter()
        .any(|token| resource_search_keywords(kind).contains(&token.as_str()))
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

fn intent_search_adjustment(tool: &ToolDefinition, intent: TaskIntent) -> i32 {
    let mut score = 0;
    let name = tool.name.to_ascii_lowercase();
    let description = tool.description.to_ascii_lowercase();
    let path = tool.path.to_ascii_lowercase();
    let text = format!("{name} {description} {path}");
    let graphql_operation_type = tool
        .graphql
        .as_ref()
        .and_then(|graphql| graphql.operation_type.as_deref())
        .map(|value| value.to_ascii_lowercase());

    // Note: "list" is intentionally excluded — all GET non-detail tools are named list_*,
    // so it would trivially match every tool and provide no discriminating signal.
    // The Read safety boost (+20) and ApiAction boost (+8) already encode the preference for
    // GET tools on SearchOrList intent. has_query_list_terms is for domain-specific terms only.
    let has_query_list_terms = contains_any_phrase(
        &text,
        &[
            "search", "query", "products", "flights", "holidays", "items",
        ],
    );
    let has_write_terms = contains_any_phrase(
        &text,
        &["create", "update", "delete", "remove", "cancel", "submit"],
    );
    let has_detail_terms = contains_any_phrase(&text, &["detail", "details", "{id}", "by id"]);
    let has_cart_terms = contains_any_phrase(
        &text,
        &[
            "cart", "basket", "checkout", "book", "booking", "pay", "purchase", "add",
        ],
    );
    let has_add_terms = contains_any_phrase(&text, &["add", "create", "save", "insert", "new"]);

    match intent {
        TaskIntent::SearchOrList => {
            match tool.safety.classification {
                SafetyClassification::Read => score += 20,
                SafetyClassification::Unknown => score -= 10,
                SafetyClassification::Write => score -= 24,
            }
            if matches!(graphql_operation_type.as_deref(), Some("query")) {
                score += 12;
            }
            if matches!(graphql_operation_type.as_deref(), Some("mutation")) {
                score -= 18;
            }
            if tool.resource_kind == ResourceKind::CommerceApi {
                score += 14;
            }
            if tool.resource_kind == ResourceKind::ApiAction {
                score += 8;
            }
            if has_query_list_terms {
                score += 10;
            }
            if has_write_terms {
                score -= 18;
            }
            if is_static_resource_kind(&tool.resource_kind) {
                score -= 40;
            }
        }
        TaskIntent::GetDetail => {
            match tool.safety.classification {
                SafetyClassification::Read => score += 16,
                SafetyClassification::Unknown => score += 2,
                SafetyClassification::Write => score -= 10,
            }
            if !tool.path_params.is_empty() {
                score += 12;
            }
            if has_detail_terms {
                score += 10;
            }
        }
        TaskIntent::CreateOrAdd => {
            match tool.safety.classification {
                SafetyClassification::Write => score += 18,
                SafetyClassification::Unknown => score += 4,
                SafetyClassification::Read => score -= 8,
            }
            if tool.approved {
                score += 6;
            }
            if has_add_terms || has_cart_terms {
                score += 12;
            }
            if tool.resource_kind == ResourceKind::CommerceApi {
                score += 10;
            }
        }
        TaskIntent::UpdateOrEdit => {
            match tool.safety.classification {
                SafetyClassification::Write => score += 18,
                SafetyClassification::Unknown => score += 4,
                SafetyClassification::Read => score -= 8,
            }
            if contains_any_phrase(&text, &["update", "edit", "change", "modify"]) {
                score += 12;
            }
        }
        TaskIntent::DeleteOrRemove => {
            match tool.safety.classification {
                SafetyClassification::Write => score += 18,
                SafetyClassification::Unknown => score += 2,
                SafetyClassification::Read => score -= 12,
            }
            if contains_any_phrase(&text, &["delete", "remove", "cancel"]) {
                score += 12;
            }
        }
        TaskIntent::CheckoutOrPurchase => {
            match tool.safety.classification {
                SafetyClassification::Write => score += 16,
                SafetyClassification::Unknown => score += 6,
                SafetyClassification::Read => score += 4,
            }
            if tool.resource_kind == ResourceKind::CommerceApi {
                score += 16;
            }
            if has_cart_terms {
                score += 16;
            }
        }
        TaskIntent::Unknown => {}
    }

    score
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
    fn live_success_reports_field_compatibility_and_missing_fields() {
        let server = MockServer::new(vec![MockResponse::ok(json!({"id": 7}))]);
        let mut list = tool(
            "list_items",
            "GET",
            "/api/items",
            true,
            SafetyClassification::Read,
        );
        list.response_schema = json!({
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "title": {"type": "string"},
                "created_at": {"type": "string"},
                "owner": {"type": "string"}
            }
        });
        let spec = spec_with_base(&server.base_url(), vec![list]);

        let response = call_tool_with_options(&spec, "list_items", json!({}), &live_options());

        assert_eq!(response["status"], "success");
        assert_eq!(response["execution"]["mode"], "live");
        assert_eq!(response["conformance"]["field_compatibility"], 0.25);
        let missing = response["conformance"]["missing_fields"]
            .as_array()
            .expect("missing fields");
        assert_eq!(missing.len(), 3);
    }

    #[test]
    fn field_compatibility_checks_array_items_and_skips_opaque_schemas() {
        let array_schema = json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": { "id": {}, "name": {} }
            }
        });
        let full = response_field_compatibility(&json!([{"id":1,"name":"a"}]), &array_schema)
            .expect("comparable");
        assert_eq!(full.compatibility, 1.0);

        let half =
            response_field_compatibility(&json!([{"id":1}]), &array_schema).expect("comparable");
        assert_eq!(half.compatibility, 0.5);
        assert_eq!(half.missing_fields, vec!["name".to_string()]);

        assert!(response_field_compatibility(&json!({"a":1}), &json!({"type":"object"})).is_none());
        assert!(response_field_compatibility(&json!([]), &array_schema).is_none());
    }

    #[test]
    fn fingerprint_is_stable_and_ignores_key_order() {
        let read = tool(
            "list_items",
            "GET",
            "/api/items",
            false,
            SafetyClassification::Read,
        );
        let mut reordered = read.clone();
        reordered.input_schema = json!({
            "required": read.input_schema["required"],
            "properties": read.input_schema["properties"],
            "type": "object"
        });
        assert_eq!(tool_fingerprint(&read), tool_fingerprint(&reordered));
    }

    #[test]
    fn fingerprint_changes_when_request_shape_changes() {
        let base = tool(
            "create_item",
            "POST",
            "/api/items",
            false,
            SafetyClassification::Write,
        );
        let mut method_changed = base.clone();
        method_changed.method = "PUT".to_string();
        let mut path_changed = base.clone();
        path_changed.path = "/api/v2/items".to_string();
        let mut schema_changed = base.clone();
        schema_changed.input_schema = json!({"type":"object","properties":{}});
        let mut cosmetic_changed = base.clone();
        cosmetic_changed.description = "different description".to_string();

        assert_ne!(tool_fingerprint(&base), tool_fingerprint(&method_changed));
        assert_ne!(tool_fingerprint(&base), tool_fingerprint(&path_changed));
        assert_ne!(tool_fingerprint(&base), tool_fingerprint(&schema_changed));
        assert_eq!(tool_fingerprint(&base), tool_fingerprint(&cosmetic_changed));
    }

    #[test]
    fn apply_approvals_sets_approved_on_fingerprint_match() {
        let create = tool(
            "create_item",
            "POST",
            "/api/items",
            false,
            SafetyClassification::Write,
        );
        let fingerprint = tool_fingerprint(&create);
        let mut spec = spec_with_base("http://127.0.0.1:1", vec![create]);
        let approvals: BTreeMap<String, ApprovalRecord> = [(
            "create_item".to_string(),
            ApprovalRecord {
                fingerprint,
                approved_at: "2026-07-01T00:00:00Z".to_string(),
                note: None,
            },
        )]
        .into_iter()
        .collect();

        let overlay = apply_approvals(&mut spec, &approvals);

        assert!(spec.tools[0].approved);
        assert_eq!(overlay.applied, vec!["create_item".to_string()]);
        assert!(overlay.stale.is_empty());
        assert!(overlay.orphaned.is_empty());
    }

    #[test]
    fn apply_approvals_skips_stale_and_orphaned_entries() {
        let create = tool(
            "create_item",
            "POST",
            "/api/items",
            false,
            SafetyClassification::Write,
        );
        let mut spec = spec_with_base("http://127.0.0.1:1", vec![create]);
        let approvals: BTreeMap<String, ApprovalRecord> = [
            (
                "create_item".to_string(),
                ApprovalRecord {
                    fingerprint: "0000000000000000".to_string(),
                    approved_at: "2026-07-01T00:00:00Z".to_string(),
                    note: None,
                },
            ),
            (
                "removed_tool".to_string(),
                ApprovalRecord {
                    fingerprint: "0000000000000000".to_string(),
                    approved_at: "2026-07-01T00:00:00Z".to_string(),
                    note: None,
                },
            ),
        ]
        .into_iter()
        .collect();

        let overlay = apply_approvals(&mut spec, &approvals);

        assert!(!spec.tools[0].approved);
        assert!(overlay.applied.is_empty());
        assert_eq!(overlay.stale, vec!["create_item".to_string()]);
        assert_eq!(overlay.orphaned, vec!["removed_tool".to_string()]);
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
    fn approval_error_names_the_real_reason_and_the_fix() {
        // A low-confidence write tool must be reported as a write tool, not
        // as a confidence problem, and the message must carry the command
        // that unblocks it (agents relay error text to the user).
        let mut create = tool(
            "create_item",
            "POST",
            "/api/items",
            false,
            SafetyClassification::Write,
        );
        create.approved = false;
        create.confidence.overall = 0.3;
        let spec = spec_with_base("http://127.0.0.1:1", vec![create]);

        let response =
            call_tool_with_options(&spec, "create_item", json!({"name":"A"}), &live_options());

        assert_eq!(response["error_type"], "approval_required");
        let message = response["message"].as_str().expect("message");
        assert!(message.contains("write tool"), "names the safety gate");
        assert!(message.contains("confidence"), "names the confidence gate");
        assert!(
            message.contains("tapestry approve test create_item"),
            "message carries the fix command: {message}"
        );
        assert_eq!(
            response["details"]["fix"],
            json!("tapestry approve test create_item")
        );
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
                false,
                SafetyClassification::Unknown,
            )],
        );

        let response = call_tool_with_options(&spec, "unknown", json!({}), &live_options());

        assert_eq!(response["error_type"], "approval_required");
    }

    #[test]
    fn approved_unknown_safety_tool_is_allowed_to_execute() {
        // Per the execution policy: unknown -> blocked *unless approved*.
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

        // Execution proceeds past the approval gate and fails only on the
        // unreachable test endpoint.
        assert_eq!(response["error_type"], "network_error");
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
    fn non_json_error_snippets_mask_token_shapes() {
        let tool = tool(
            "list_items",
            "GET",
            "/api/items",
            true,
            SafetyClassification::Read,
        );
        let body =
            "invalid session eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345 please reauthenticate";

        let response = handle_error_status(500, Some(body.to_string()), &tool);
        let snippet = response["details"]["body"].as_str().unwrap();

        assert!(!snippet.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(snippet.contains("<redacted>"));
        assert!(snippet.contains("please reauthenticate"));
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
    fn live_response_masks_secret_fields() {
        // Stored examples are redacted at import; the live payload handed to
        // an agent must not disagree about what is sensitive.
        let server = MockServer::new(vec![MockResponse::ok(
            json!({"name":"Emily","password":"emilyspass","profile":{"api_key":"k-123"}}),
        )]);
        let read_tool = tool(
            "get_user",
            "GET",
            "/api/user",
            true,
            SafetyClassification::Read,
        );
        let spec = spec_with_base(&server.base_url(), vec![read_tool]);

        let response = call_tool_with_options(&spec, "get_user", json!({}), &live_options());

        assert_eq!(response["status"], "success");
        assert_eq!(response["data"]["name"], "Emily");
        assert_eq!(response["data"]["password"], "<redacted>");
        assert_eq!(response["data"]["profile"]["api_key"], "<redacted>");
    }

    #[test]
    fn schema_response_carries_call_shape_and_pending_approval() {
        let mut create = tool(
            "create_item",
            "POST",
            "/api/items",
            false,
            SafetyClassification::Write,
        );
        create.approved = false;
        let approved_read = tool(
            "list_items",
            "GET",
            "/api/items",
            true,
            SafetyClassification::Read,
        );
        let spec = spec_with_base("http://127.0.0.1:1", vec![create, approved_read]);

        let blocked = get_tool_schema(&spec, "create_item").unwrap();
        let how_to_call = blocked["how_to_call"].as_str().expect("how_to_call");
        assert!(how_to_call.contains("\"arguments\""));
        let pending = blocked["approval_pending"].as_str().expect("pending note");
        assert!(pending.contains("write tool"));

        // Approved tools carry the call shape but no approval warning.
        let ready = get_tool_schema(&spec, "list_items").unwrap();
        assert!(ready.get("how_to_call").is_some());
        assert!(ready.get("approval_pending").is_none());
    }

    #[test]
    fn get_tool_schema_compacts_example_and_strips_evidence() {
        let mut list = tool(
            "list_items",
            "GET",
            "/api/items",
            true,
            SafetyClassification::Read,
        );
        let long_text = "x".repeat(500);
        list.example_response = Some(json!({
            "items": [
                {"id": 1, "description": long_text},
                {"id": 2},
                {"id": 3}
            ],
            "total": 3
        }));
        let spec = spec_with_base("http://127.0.0.1:1", vec![list]);

        let schema = get_tool_schema(&spec, "list_items").unwrap();

        assert!(
            schema.get("evidence").is_none(),
            "evidence belongs in get_evidence"
        );
        assert_eq!(schema["example_response_truncated"], json!(true));
        let items = schema["example_response"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "arrays keep only the first element");
        let description = items[0]["description"].as_str().unwrap();
        assert!(
            description.chars().count() <= 121,
            "long strings are capped"
        );
        // Shape survives: scalar fields and the input schema are untouched.
        assert_eq!(schema["example_response"]["total"], json!(3));
        assert_eq!(schema["name"], json!("list_items"));
        assert!(schema.get("input_schema").is_some());
    }

    #[test]
    fn exact_resource_match_beats_category_boosts() {
        // Reproduces the dummyjson corpus failure: "list users" ranked
        // list_products/list_categories (CommerceApi boosts) above list_users,
        // because an exact name-token match scored below generic boosts.
        let mut products = tool(
            "list_products",
            "GET",
            "/products",
            true,
            SafetyClassification::Read,
        );
        products.resource_kind = ResourceKind::CommerceApi;
        products.description = "Observed GET endpoint /products".to_string();
        let mut categories = tool(
            "list_categories",
            "GET",
            "/products/categories",
            true,
            SafetyClassification::Read,
        );
        categories.resource_kind = ResourceKind::CommerceApi;
        let users = tool(
            "list_users",
            "GET",
            "/users",
            true,
            SafetyClassification::Read,
        );
        let spec = spec_with_base("http://127.0.0.1:1", vec![products, categories, users]);

        let results = search_tools(&spec, "list users", 3);

        assert_eq!(results[0].name, "list_users");
    }

    #[test]
    fn search_tool_named_after_resource_wins_search_query() {
        let mut products = tool(
            "list_products",
            "GET",
            "/products",
            true,
            SafetyClassification::Read,
        );
        products.resource_kind = ResourceKind::CommerceApi;
        let mut search = tool(
            "search_products",
            "GET",
            "/products/search",
            true,
            SafetyClassification::Read,
        );
        search.resource_kind = ResourceKind::CommerceApi;
        let categories = tool(
            "list_categories",
            "GET",
            "/products/categories",
            true,
            SafetyClassification::Read,
        );
        let spec = spec_with_base("http://127.0.0.1:1", vec![products, search, categories]);

        let results = search_tools(&spec, "search for phones", 3);

        assert_eq!(results[0].name, "search_products");
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
    fn task_intent_classifier_prefers_most_specific_category() {
        assert_eq!(
            classify_task_intent("Search for products"),
            TaskIntent::SearchOrList
        );
        assert_eq!(
            classify_task_intent("Add item to cart"),
            TaskIntent::CheckoutOrPurchase
        );
        assert_eq!(
            classify_task_intent("Delete booking"),
            TaskIntent::DeleteOrRemove
        );
    }

    #[test]
    fn search_penalizes_write_tools_for_search_intent() {
        let read = tool(
            "search_flights",
            "GET",
            "/api/flights/search",
            true,
            SafetyClassification::Read,
        );
        let mut write = tool(
            "create_clients.SearchResultsOption",
            "POST",
            "/api/search",
            false,
            SafetyClassification::Write,
        );
        write.description = "Search results option submission".to_string();
        let spec = spec_with_base("http://127.0.0.1:1", vec![write, read]);

        let results = search_tools(&spec, "Search for flights", 5);

        assert_eq!(results[0].name, "search_flights");
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
    fn checkout_intent_ranks_cart_write_tool() {
        let spec = spec_with_base(
            "http://127.0.0.1:1",
            vec![
                tool(
                    "list_items",
                    "GET",
                    "/api/items",
                    true,
                    SafetyClassification::Read,
                ),
                cart_tool(),
            ],
        );

        let results = search_tools(&spec, "Search for basket checkout", 5);

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
