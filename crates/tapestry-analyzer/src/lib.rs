use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use tapestry_core::*;
use tracing::{info, warn};

pub fn analyze(site_name: &str, observations: &[Observation]) -> ToolSpec {
    let mut clusters: BTreeMap<(String, String, String), Vec<&Observation>> = BTreeMap::new();
    let primary_host = infer_primary_host(observations);

    for obs in observations {
        let signal = classify_observation_signal(obs, primary_host.as_deref());
        if !signal.keep {
            info!(
                target: "tapestry::analyzer",
                phase = "signal_filtering",
                method = %obs.method,
                path = %obs.path,
                url = %obs.url,
                score = signal.score,
                reason = %signal.reason,
                "filtered observation"
            );
            continue;
        }

        info!(
            target: "tapestry::analyzer",
            phase = "signal_filtering",
            method = %obs.method,
            path = %obs.path,
            url = %obs.url,
            score = signal.score,
            reason = %signal.reason,
            "kept API-like observation"
        );

        let path_template = normalize_path_template(&obs.path);
        let operation_keys = operation_cluster_keys(obs);
        for operation_key in operation_keys {
            info!(
                target: "tapestry::analyzer",
                phase = "clustering",
                method = %obs.method,
                path = %obs.path,
                template = %path_template,
                operation = %operation_key,
                "clustered observation"
            );
            clusters
                .entry((obs.method.clone(), path_template.clone(), operation_key))
                .or_default()
                .push(obs);
        }
    }

    let tools = clusters
        .into_iter()
        .map(|((method, path, operation_key), obs)| {
            build_tool(&method, &path, operation_key.as_str(), &obs)
        })
        .collect();

    ToolSpec {
        site: SiteInfo {
            name: site_name.to_string(),
            base_url: observations.first().and_then(base_url_for),
            source: vec!["har".to_string()],
            generated_at: Some(current_timestamp()),
            spec_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        tools,
    }
}

#[derive(Debug)]
struct InferenceWarnings {
    items: Vec<String>,
    mixed_types: usize,
    low_sample: bool,
    non_json: usize,
    empty_body: bool,
    single_seen_params: usize,
    weak_path_params: usize,
}

impl InferenceWarnings {
    fn new(observation_count: usize) -> Self {
        let mut out = Self {
            items: Vec::new(),
            mixed_types: 0,
            low_sample: observation_count < 3,
            non_json: 0,
            empty_body: false,
            single_seen_params: 0,
            weak_path_params: 0,
        };
        if out.low_sample {
            out.push("low_sample_count");
        }
        out
    }

    fn push(&mut self, warning: impl Into<String>) {
        let warning = warning.into();
        if !self.items.contains(&warning) {
            self.items.push(warning);
        }
    }

    fn mixed(&mut self, field: &str) {
        self.mixed_types += 1;
        self.push(format!("mixed_types:{field}"));
    }

    fn seen_once(&mut self, field: &str) {
        self.single_seen_params += 1;
        self.push(format!("parameter_seen_once:{field}"));
    }
}

#[derive(Debug)]
struct SchemaMetrics {
    confidence: f64,
}

fn build_tool(
    method: &str,
    path: &str,
    operation_key: &str,
    observations: &[&Observation],
) -> ToolDefinition {
    let id = stable_tool_id(method, path, operation_key);
    let safety_class = classify_safety(method, observations);
    let approved = safety_class == SafetyClassification::Read;
    let base_confidence = confidence_for_count(observations.len());
    let mut warnings = InferenceWarnings::new(observations.len());
    let graphql = graphql_info_for(observations, operation_key);
    if let Some(info) = &graphql {
        warnings.push(if info.batched {
            "batched_graphql_detected"
        } else {
            "graphql_detected"
        });
        if info.operation_name.is_none() {
            warnings.push("operation_name_missing");
        }
    } else if is_opaque_root_post_json(observations) {
        warnings.push("opaque_root_post");
        warnings.push("operation_name_missing");
        warnings.push("low_semantic_confidence");
    } else if operation_key.starts_with("json:") {
        warnings.push("opaque_root_post");
    }
    let resource_kind = classify_resource_kind(method, path, observations);
    match resource_kind {
        ResourceKind::LocalizationResource => warnings.push("localization_resource"),
        ResourceKind::ConfigResource => warnings.push("config_resource"),
        ResourceKind::StaticJsonResource => warnings.push("static_json_resource"),
        ResourceKind::Telemetry => warnings.push("telemetry_resource"),
        ResourceKind::PlatformResource => warnings.push("platform_resource"),
        ResourceKind::CommerceApi => warnings.push("commerce_api"),
        ResourceKind::Unknown | ResourceKind::ApiAction => {}
    }
    let path_params = infer_path_params(path, observations, base_confidence, &mut warnings);
    let path_param_confidence = path_param_confidence(base_confidence, &warnings);
    let (input_schema, input_metrics) = infer_input_schema(
        observations,
        &path_params,
        method,
        operation_key,
        &mut warnings,
    );
    let (response_values, mapped_response_paths) =
        collect_response_values(observations, operation_key, &mut warnings);
    let (response_schema, response_metrics) = infer_response_schema(
        observations,
        &response_values,
        !mapped_response_paths.is_empty(),
        &mut warnings,
    );
    let auth = infer_auth(observations);
    let example_response = response_values
        .iter()
        .find_map(Clone::clone)
        .map(redact_value);
    let example_input = collect_example_input(observations, operation_key);

    if example_response.is_none() {
        warnings.push("no_example_response_available");
    }

    if let Some(info) = &graphql {
        info!(
            target: "tapestry::analyzer",
            phase = "schema",
            method = %method,
            path = %path,
            operation_name = %info.operation_name.as_deref().unwrap_or("unknown"),
            mapped_response_path = %mapped_response_paths.first().cloned().unwrap_or_else(|| "none".to_string()),
            schema_keys = %schema_key_summary(&response_schema),
            example_captured = example_response.is_some(),
            "mapped GraphQL response"
        );
    }

    for warning in &warnings.items {
        warn!(
            target: "tapestry::analyzer",
            phase = "schema",
            method = %method,
            path = %path,
            warning = %warning,
            "schema warning"
        );
    }

    info!(
        target: "tapestry::analyzer",
        phase = "confidence",
        method = %method,
        path = %path,
        confidence = base_confidence,
        input_schema_confidence = input_metrics.confidence,
        response_schema_confidence = response_metrics.confidence,
        path_param_confidence,
        "computed confidence score"
    );

    let mut overall = [
        base_confidence,
        input_metrics.confidence,
        response_metrics.confidence,
        path_param_confidence,
    ]
    .into_iter()
    .fold(1.0_f64, f64::min);

    if warnings
        .items
        .iter()
        .any(|warning| warning == "low_semantic_confidence")
    {
        overall = overall.min(0.55);
    }

    ToolDefinition {
        id,
        name: tool_name(method, path, operation_key, observations),
        description: describe_tool(method, path, operation_key, observations),
        method: method.to_string(),
        path: path.to_string(),
        resource_kind,
        graphql,
        path_params,
        input_schema,
        response_schema,
        example_response,
        example_input,
        auth,
        safety: SafetyInfo {
            classification: safety_class.clone(),
            confidence: base_confidence,
            reasoning: safety_reasoning(method, observations),
        },
        confidence: ConfidenceScores {
            overall,
            path: base_confidence,
            path_params: path_param_confidence,
            method: 0.99,
            input_schema: input_metrics.confidence,
            response_schema: response_metrics.confidence,
            auth: if observations.iter().any(|obs| has_auth_signal(obs)) { 0.85 } else { 0.50 },
            safety: base_confidence,
        },
        evidence: vec![Evidence {
            source: "har".to_string(),
            evidence_type: "observed_requests".to_string(),
            count: observations.len(),
            confidence: base_confidence,
            detail: Some(evidence_detail(method, path, operation_key, observations)),
        }],
        warnings: warnings.items,
        idempotency: IdempotencyInfo {
            safe_to_retry: safety_class == SafetyClassification::Read,
            confidence: base_confidence,
            reasoning: "Reads are retryable by default; writes are not retried unless approved and marked idempotent".to_string(),
        },
        pagination: infer_pagination(observations),
        rate_limit: Some(RateLimitInfo {
            recommended_delay_ms: 300,
            max_parallel: 2,
        }),
        approved,
    }
}

fn classify_resource_kind(method: &str, path: &str, observations: &[&Observation]) -> ResourceKind {
    let path_lower = path.to_ascii_lowercase();
    let host_lower = observations
        .first()
        .and_then(|obs| url::Url::parse(&obs.url).ok())
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
        .unwrap_or_default();

    if is_commerce_api_path(&path_lower) {
        return ResourceKind::CommerceApi;
    }
    if is_wix_telemetry_resource(&host_lower, &path_lower)
        || observations
            .iter()
            .any(|obs| body_contains_telemetry_key(obs.request_body.as_ref()))
    {
        return ResourceKind::Telemetry;
    }
    if is_wix_platform_resource(&host_lower, &path_lower) {
        return ResourceKind::PlatformResource;
    }
    if observations
        .iter()
        .any(|obs| body_contains_telemetry_key(obs.request_body.as_ref()))
    {
        return ResourceKind::Telemetry;
    }
    if method != "GET" || !path_lower.ends_with(".json") {
        return ResourceKind::ApiAction;
    }
    if is_localization_resource_path(&path_lower) {
        return ResourceKind::LocalizationResource;
    }
    if is_config_resource_path(&path_lower) {
        return ResourceKind::ConfigResource;
    }
    if is_static_json_resource_path(&path_lower) {
        return ResourceKind::StaticJsonResource;
    }
    ResourceKind::ApiAction
}

fn is_localization_resource_path(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    path.contains("/lang/")
        || path.contains("/locale/")
        || path.contains("/locales/")
        || path.contains("/i18n/")
        || path.contains("/translations/")
        || filename == "locales.json"
        || is_language_json_filename(filename)
}

fn is_language_json_filename(filename: &str) -> bool {
    let stem = filename.strip_suffix(".json").unwrap_or(filename);
    let parts = stem.split(['-', '_']).collect::<Vec<_>>();
    matches!(parts.as_slice(), [lang] if lang.len() == 2 && lang.chars().all(|ch| ch.is_ascii_lowercase()))
        || matches!(parts.as_slice(), [lang, region]
            if lang.len() == 2
                && region.len() == 2
                && lang.chars().all(|ch| ch.is_ascii_lowercase())
                && region.chars().all(|ch| ch.is_ascii_alphabetic()))
}

fn is_config_resource_path(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    path.contains("/config/")
        || path.contains("/settings/")
        || path.contains("/manifest")
        || path.contains("/metadata")
        || filename == "manifest.json"
        || filename == "config.json"
        || filename == "settings.json"
        || filename.ends_with("-manifest.json")
        || filename.ends_with(".webmanifest")
        || filename == "browserconfig.xml"
        || filename == "robots.txt"
        || filename == "sitemap.xml"
        || filename == "favicon.ico"
}

fn is_static_json_resource_path(path: &str) -> bool {
    path.contains("/dictionary") || path.rsplit('/').next().unwrap_or(path) == "dictionary.json"
}

fn is_wix_telemetry_resource(host: &str, path: &str) -> bool {
    host == "frog.wix.com"
        || path.contains("/monitoring")
        || path.contains("/monitor_browser/")
        || path.contains("/monitor_web/")
        || path.contains("/bulklog")
        || path.contains("/bolt-performance")
        || path.contains("/bi-event")
        || path.ends_with("/log")
        || path.contains("/log/")
}

fn is_wix_platform_resource(host: &str, path: &str) -> bool {
    let wix_host = host.contains("wix.com")
        || host.contains("wixstatic.com")
        || host.contains("parastorage.com");
    let explicit_platform_path = path.contains("/editor-elements/")
        || path.contains("/thunderbolt")
        || path.contains("/corvid")
        || path.contains("/manifest.min.json")
        || path.contains("/pages/pages/thunderbolt")
        || path.contains("/services/editor-elements");
    explicit_platform_path
        && (wix_host
            || path.contains("/pages/pages/thunderbolt")
            || path.contains("/services/editor-elements"))
}

fn is_commerce_api_path(path: &str) -> bool {
    path.contains("/_api/cart")
        || path.contains("/_api/cart-v2")
        || path.contains("/_api/cloud-data")
        || path.contains("/_api/wixstores")
        || path.contains("/_api/stores")
        || path.contains("/_api/catalog")
        || path.contains("/_api/checkout")
        || path.contains("/_api/ecom")
        || path.contains("/products")
        || path.contains("/product")
        || path.contains("/cart")
        || path.contains("/checkout")
        || path.contains("/basket")
}

#[derive(Debug)]
struct SignalDecision {
    keep: bool,
    score: i32,
    reason: String,
}

const KNOWN_NOISE_HOSTS: &[&str] = &[
    "maps.googleapis.com",
    "maps.google.com",
    "api.segment.io",
    "cdn.segment.com",
    "browser.sentry-dsn.com",
    "o1.ingest.sentry.io",
    "rum.datadoghq.com",
    "api.datadoghq.com",
    "analytics.google.com",
    "www.google-analytics.com",
    "www.googletagmanager.com",
    "px.ads.linkedin.com",
    "bat.bing.com",
    "connect.facebook.net",
    "www.facebook.com",
    "cdn.cookielaw.org",
    "geolocation.onetrust.com",
    "cdn.onetrust.com",
    "widget.trustpilot.com",
    "api.rollbar.com",
    "api.bugsnag.com",
    "app.launchdarkly.com",
    "events.launchdarkly.com",
    "app.split.io",
    "sdk.split.io",
    "amplitude.com",
    "api.amplitude.com",
    "api2.amplitude.com",
    "api.mixpanel.com",
    "api.intercom.io",
    "nexus-websocket-a.intercom.io",
];

fn classify_observation_signal(obs: &Observation, primary_host: Option<&str>) -> SignalDecision {
    let path = obs.path.to_ascii_lowercase();

    // Block known third-party analytics, telemetry, and tracking hosts unconditionally
    let host = url::Url::parse(&obs.url)
        .ok()
        .and_then(|url| url.host_str().map(|h| h.to_ascii_lowercase()));
    if let Some(h) = host.as_deref() {
        if KNOWN_NOISE_HOSTS.iter().any(|noise| *noise == h || h.ends_with(&format!(".{noise}"))) {
            return SignalDecision {
                keep: false,
                score: -100,
                reason: format!("known_noise_host:{h}"),
            };
        }
    }

    if is_consent_or_config_asset(obs, &path) {
        return SignalDecision {
            keep: false,
            score: -95,
            reason: "consent_or_config_asset".to_string(),
        };
    }

    if is_static_asset_path(&path) {
        return SignalDecision {
            keep: false,
            score: -100,
            reason: "static_asset_path".to_string(),
        };
    }

    if is_html_page(obs, &path) {
        return SignalDecision {
            keep: false,
            score: -80,
            reason: "html_page".to_string(),
        };
    }

    if is_bot_or_security_telemetry(obs, &path) {
        return SignalDecision {
            keep: false,
            score: -90,
            reason: "bot_or_security_telemetry".to_string(),
        };
    }

    if let (Some(primary), Some(h)) = (primary_host, host.as_deref()) {
        if h != primary && !has_json_signal(obs) && !is_api_path(&path) {
            return SignalDecision {
                keep: false,
                score: -70,
                reason: format!("third_party_non_api:{h}"),
            };
        }
    }

    // Penalise paths whose segments look like build hashes or encoded payloads.
    // Use the original path (not lowercased) — case-mix is part of the detection signal.
    if path_has_build_hash(&obs.path) {
        return SignalDecision {
            keep: false,
            score: -85,
            reason: "build_hash_path".to_string(),
        };
    }

    let mut score = 0;
    let mut reasons = Vec::new();

    if is_api_path(&path) {
        score += 50;
        reasons.push("api_path");
    }
    if has_json_signal(obs) {
        score += 45;
        reasons.push("json_signal");
    }
    if matches!(obs.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        score += 25;
        reasons.push("stateful_method");
    }
    if is_graphql_request(obs) {
        score += 70;
        reasons.push("graphql");
    } else if obs.method == "POST" && path == "/" && obs.request_body.is_some() {
        score += 35;
        reasons.push("root_post_json_api");
    }
    if obs.request_body.is_some() {
        score += 20;
        reasons.push("request_body");
    }
    if !obs.query.is_empty() {
        score += 8;
        reasons.push("query_params");
    }
    if is_likely_page_path(&path) && !has_json_signal(obs) {
        score -= 40;
        reasons.push("page_like_path");
    }

    let keep = score >= 40;
    SignalDecision {
        keep,
        score,
        reason: if reasons.is_empty() {
            "no_api_signal".to_string()
        } else {
            reasons.join("+")
        },
    }
}

fn infer_input_schema(
    observations: &[&Observation],
    path_params: &[PathParameter],
    method: &str,
    operation_key: &str,
    warnings: &mut InferenceWarnings,
) -> (Value, SchemaMetrics) {
    let total = observations.len();
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for param in path_params {
        properties.insert(param.name.clone(), param.schema.clone());
        required.push(Value::String(param.name.clone()));
    }

    let query_fields = collect_query_fields(observations);
    for (name, values) in query_fields {
        let schema =
            schema_for_optional_values(&format!("query.{name}"), &values, total, true, warnings);
        let present = values.iter().filter(|value| value.is_some()).count();
        if present == total {
            required.push(Value::String(name.clone()));
        } else if present == 1 {
            warnings.seen_once(&format!("query.{name}"));
        }
        log_field_schema(
            method,
            observations,
            "query",
            &name,
            &schema,
            present == total,
        );
        properties.insert(name, schema);
    }

    let body_observations = observations
        .iter()
        .filter(|obs| matches!(obs.method.as_str(), "POST" | "PUT" | "PATCH"))
        .count();
    if body_observations > 0 {
        let body_fields = if observations.iter().any(|obs| is_graphql_request(obs)) {
            collect_graphql_variable_fields(observations, operation_key, warnings)
        } else {
            collect_body_fields(observations, warnings)
        };
        if body_fields.is_empty() {
            warnings.empty_body = true;
            warnings.push("empty_body");
        }
        for (name, values) in body_fields {
            let schema =
                schema_for_optional_values(&format!("body.{name}"), &values, total, true, warnings);
            let present = values.iter().filter(|value| value.is_some()).count();
            if present == total {
                required.push(Value::String(name.clone()));
            }
            log_field_schema(
                method,
                observations,
                "body",
                &name,
                &schema,
                present == total,
            );
            properties.insert(name, schema);
        }
    }

    (
        json!({
            "type": "object",
            "properties": properties,
            "required": required
        }),
        SchemaMetrics {
            confidence: schema_confidence(0.95, total, warnings),
        },
    )
}

fn collect_query_fields(observations: &[&Observation]) -> BTreeMap<String, Vec<Option<Value>>> {
    let mut fields: BTreeMap<String, Vec<Option<Value>>> = BTreeMap::new();
    for (idx, obs) in observations.iter().enumerate() {
        for (name, value) in &obs.query {
            fields
                .entry(name.clone())
                .or_insert_with(|| vec![None; observations.len()])[idx] = Some(value.clone());
        }
    }
    fields
}

fn collect_body_fields(
    observations: &[&Observation],
    warnings: &mut InferenceWarnings,
) -> BTreeMap<String, Vec<Option<Value>>> {
    let mut fields: BTreeMap<String, Vec<Option<Value>>> = BTreeMap::new();
    for (idx, obs) in observations.iter().enumerate() {
        match &obs.request_body {
            Some(Value::Object(map)) => {
                for (name, value) in map {
                    fields
                        .entry(name.clone())
                        .or_insert_with(|| vec![None; observations.len()])[idx] =
                        Some(value.clone());
                }
            }
            Some(value) => {
                fields
                    .entry("body".to_string())
                    .or_insert_with(|| vec![None; observations.len()])[idx] = Some(value.clone());
            }
            None if matches!(obs.method.as_str(), "POST" | "PUT" | "PATCH") => {
                warnings.non_json += 1;
                if !header_contains(&obs.request_headers, "content-type", "json") {
                    warnings.push("non_json_body");
                }
            }
            None => {}
        }
    }
    fields
}

fn collect_graphql_variable_fields(
    observations: &[&Observation],
    operation_key: &str,
    warnings: &mut InferenceWarnings,
) -> BTreeMap<String, Vec<Option<Value>>> {
    let mut fields: BTreeMap<String, Vec<Option<Value>>> = BTreeMap::new();
    for (idx, obs) in observations.iter().enumerate() {
        let Some(variables) = graphql_variables_for_operation(obs, operation_key) else {
            warnings.push("operation_name_missing");
            continue;
        };
        if variables.is_empty() {
            continue;
        }
        for (name, value) in variables {
            fields
                .entry(name)
                .or_insert_with(|| vec![None; observations.len()])[idx] = Some(value);
        }
    }
    fields
}

fn graphql_variables_for_operation(
    obs: &Observation,
    operation_key: &str,
) -> Option<BTreeMap<String, Value>> {
    match obs.request_body.as_ref()? {
        Value::Object(map) => {
            let operation = graphql_operation_from_value(obs.request_body.as_ref()?, false)?;
            (operation.cluster_key() == operation_key)
                .then(|| object_variables(map.get("variables")).unwrap_or_default())
        }
        Value::Array(values) => {
            for value in values {
                let operation = graphql_operation_from_value(value, true)?;
                if operation.cluster_key() == operation_key {
                    let Value::Object(map) = value else {
                        return Some(BTreeMap::new());
                    };
                    return Some(object_variables(map.get("variables")).unwrap_or_default());
                }
            }
            None
        }
        _ => None,
    }
}

fn collect_response_values(
    observations: &[&Observation],
    operation_key: &str,
    warnings: &mut InferenceWarnings,
) -> (Vec<Option<Value>>, Vec<String>) {
    if !operation_key.starts_with("graphql:") {
        return (
            observations
                .iter()
                .map(|obs| obs.response_body.clone())
                .collect(),
            Vec::new(),
        );
    }

    let mut paths = Vec::new();
    let values = observations
        .iter()
        .map(|obs| {
            extract_graphql_response(obs, operation_key, warnings).map(|mapped| {
                paths.push(mapped.path);
                mapped.value
            })
        })
        .collect();
    (values, paths)
}

fn collect_example_input(observations: &[&Observation], operation_key: &str) -> Option<Value> {
    for obs in observations {
        if let Some(graphql_example) = graphql_example_input(obs, operation_key) {
            return Some(redact_value(graphql_example));
        }
        if let Some(body) = obs.request_body.as_ref() {
            if matches!(obs.method.as_str(), "POST" | "PUT" | "PATCH") {
                return Some(redact_value(body.clone()));
            }
        }
    }
    None
}

fn graphql_example_input(obs: &Observation, operation_key: &str) -> Option<Value> {
    if !operation_key.starts_with("graphql:") {
        return None;
    }

    let variables = graphql_variables_for_operation(obs, operation_key)?;
    if variables.is_empty() {
        return None;
    }
    Some(json!(variables))
}

#[derive(Debug)]
struct MappedGraphqlResponse {
    value: Value,
    path: String,
}

fn extract_graphql_response(
    obs: &Observation,
    operation_key: &str,
    warnings: &mut InferenceWarnings,
) -> Option<MappedGraphqlResponse> {
    let response = obs.response_body.as_ref()?;
    let operations = graphql_operations(obs);
    let operation_index = operations
        .iter()
        .position(|operation| operation.cluster_key() == operation_key);

    if let Some(mapped) = response_for_operation_index(response, operation_index, warnings) {
        return Some(mapped);
    }

    warnings.push("graphql_response_unmapped");
    None
}

fn response_for_operation_index(
    response: &Value,
    operation_index: Option<usize>,
    warnings: &mut InferenceWarnings,
) -> Option<MappedGraphqlResponse> {
    match response {
        Value::Array(items) => {
            let index = operation_index?;
            let item = items.get(index)?;
            graphql_data_from_response(item, &format!("$[{index}]"), warnings)
        }
        _ => graphql_data_from_response(response, "$", warnings),
    }
}

fn graphql_data_from_response(
    response: &Value,
    base_path: &str,
    warnings: &mut InferenceWarnings,
) -> Option<MappedGraphqlResponse> {
    if response.get("errors").is_some() {
        warnings.push("graphql_response_errors");
    }

    let data = response.get("data")?;
    if data.is_null() {
        warnings.push("response_schema_empty");
        return None;
    }

    if let Value::Object(map) = data {
        if map.len() == 1 {
            if let Some((field, value)) = map.iter().next() {
                return Some(MappedGraphqlResponse {
                    value: value.clone(),
                    path: format!("{base_path}.data.{field}"),
                });
            }
        }
    }

    Some(MappedGraphqlResponse {
        value: data.clone(),
        path: format!("{base_path}.data"),
    })
}

fn infer_response_schema(
    observations: &[&Observation],
    values: &[Option<Value>],
    graphql_mapping_succeeded: bool,
    warnings: &mut InferenceWarnings,
) -> (Value, SchemaMetrics) {
    let total = observations.len();
    for obs in observations {
        if obs.response_body.is_none()
            && !header_contains(&obs.response_headers, "content-type", "json")
        {
            warnings.non_json += 1;
            warnings.push("non_json_response");
        }
    }

    let present = values.iter().filter(|value| value.is_some()).count();
    if present == 0 {
        warnings.push("response_schema_empty");
        return (
            json!({"type":"object","properties":{}}),
            SchemaMetrics {
                confidence: schema_confidence(0.45, total, warnings),
            },
        );
    }

    let schema = schema_for_optional_values("response", &values, total, false, warnings);
    info!(
        target: "tapestry::analyzer",
        phase = "schema",
        method = %observations.first().map(|obs| obs.method.as_str()).unwrap_or(""),
        path = %observations.first().map(|obs| obs.path.as_str()).unwrap_or(""),
        schema = %schema,
        "inferred response schema"
    );

    (
        schema,
        SchemaMetrics {
            confidence: schema_confidence(
                if graphql_mapping_succeeded {
                    0.98
                } else {
                    0.95
                },
                total,
                warnings,
            ),
        },
    )
}

const MAX_SCHEMA_DEPTH: usize = 12;

fn schema_for_optional_values(
    field: &str,
    values: &[Option<Value>],
    total: usize,
    enum_candidates: bool,
    warnings: &mut InferenceWarnings,
) -> Value {
    schema_for_optional_values_depth(field, values, total, enum_candidates, warnings, 0)
}

fn schema_for_optional_values_depth(
    field: &str,
    values: &[Option<Value>],
    total: usize,
    enum_candidates: bool,
    warnings: &mut InferenceWarnings,
    depth: usize,
) -> Value {
    let present: Vec<Value> = values.iter().filter_map(Clone::clone).collect();
    let mut schema = schema_for_values_depth(field, &present, enum_candidates, warnings, depth);
    let present_count = present.len();
    if present_count < total {
        insert_bool(&mut schema, "optional", true);
    }
    schema
}

fn schema_for_values_depth(
    field: &str,
    values: &[Value],
    enum_candidates: bool,
    warnings: &mut InferenceWarnings,
    depth: usize,
) -> Value {
    if values.is_empty() {
        return json!({});
    }

    if depth >= MAX_SCHEMA_DEPTH {
        warnings.push("schema_depth_limit");
        return json!({"type": "object"});
    }

    let mut nullable = false;
    let mut concrete_types = BTreeSet::new();
    for value in values {
        if value.is_null() {
            nullable = true;
        } else {
            concrete_types.insert(type_name(value));
        }
    }

    let mut schema = if concrete_types.len() > 1 {
        warnings.mixed(field);
        json!({"type":"string","confidence":0.62})
    } else {
        match concrete_types.iter().next().copied().unwrap_or("null") {
            "array" => infer_array_schema_depth(field, values, warnings, depth + 1),
            "object" => infer_object_schema_depth(field, values, warnings, depth + 1),
            typ => json!({"type": typ}),
        }
    };

    if nullable {
        insert_bool(&mut schema, "nullable", true);
    }

    if enum_candidates {
        maybe_insert_default(&mut schema, values);
        maybe_insert_enum(&mut schema, values);
    }

    schema
}

fn infer_array_schema_depth(
    field: &str,
    values: &[Value],
    warnings: &mut InferenceWarnings,
    depth: usize,
) -> Value {
    let mut items = Vec::new();
    for value in values {
        if let Value::Array(values) = value {
            items.extend(values.clone());
        }
    }

    json!({
        "type": "array",
        "items": if items.is_empty() {
            json!({})
        } else {
            schema_for_values_depth(&format!("{field}[]"), &items, false, warnings, depth)
        }
    })
}

fn infer_object_schema_depth(
    field: &str,
    values: &[Value],
    warnings: &mut InferenceWarnings,
    depth: usize,
) -> Value {
    let mut fields: BTreeMap<String, Vec<Option<Value>>> = BTreeMap::new();
    let total = values.len();
    for (idx, value) in values.iter().enumerate() {
        if let Value::Object(map) = value {
            for (name, value) in map {
                fields
                    .entry(name.clone())
                    .or_insert_with(|| vec![None; total])[idx] = Some(value.clone());
            }
        }
    }

    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, values) in fields {
        let present = values.iter().filter(|value| value.is_some()).count();
        if present == total {
            required.push(Value::String(name.clone()));
        }
        properties.insert(
            name.clone(),
            schema_for_optional_values_depth(
                &format!("{field}.{name}"),
                &values,
                total,
                false,
                warnings,
                depth,
            ),
        );
    }

    json!({
        "type": "object",
        "properties": properties,
        "required": required
    })
}

fn maybe_insert_default(schema: &mut Value, values: &[Value]) {
    let non_null: Vec<&Value> = values.iter().filter(|value| !value.is_null()).collect();
    let Some(first) = non_null.first() else {
        return;
    };
    if non_null.iter().all(|value| *value == *first) && is_scalar(first) {
        if let Some(obj) = schema.as_object_mut() {
            obj.insert("default".to_string(), (*first).clone());
        }
    }
}

fn maybe_insert_enum(schema: &mut Value, values: &[Value]) {
    let strings: BTreeSet<String> = values
        .iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect();
    if (2..=8).contains(&strings.len()) {
        if let Some(obj) = schema.as_object_mut() {
            obj.insert(
                "enum".to_string(),
                Value::Array(strings.into_iter().map(Value::String).collect()),
            );
        }
    }
}

fn infer_path_params(
    path_template: &str,
    observations: &[&Observation],
    base_confidence: f64,
    warnings: &mut InferenceWarnings,
) -> Vec<PathParameter> {
    let template_segments: Vec<&str> = path_template.trim_matches('/').split('/').collect();
    let mut params = Vec::new();

    for (idx, segment) in template_segments.iter().enumerate() {
        if !segment.starts_with('{') {
            continue;
        }

        let name = segment.trim_matches(['{', '}']);
        let mut values = Vec::new();
        for obs in observations {
            if let Some(raw) = obs.path.trim_matches('/').split('/').nth(idx) {
                values.push(value_from_path_segment(raw));
            }
        }

        if values.len() < 2 {
            warnings.weak_path_params += 1;
            warnings.push(format!("path_param_low_evidence:{name}"));
        }

        let schema = schema_for_path_param(name, &values, warnings);
        let confidence = if values.len() < 2 {
            (base_confidence - 0.20).max(0.45)
        } else {
            base_confidence
        };
        info!(
            target: "tapestry::analyzer",
            phase = "schema",
            method = %observations.first().map(|obs| obs.method.as_str()).unwrap_or(""),
            path = %path_template,
            parameter = %name,
            schema = %schema,
            confidence,
            "[schema] path_param"
        );
        params.push(PathParameter {
            name: name.to_string(),
            schema,
            confidence,
            examples: unique_examples(values),
        });
    }

    params
}

fn schema_for_path_param(name: &str, values: &[Value], warnings: &mut InferenceWarnings) -> Value {
    let mut types = BTreeSet::new();
    let mut uuid = true;
    for value in values {
        types.insert(type_name(value));
        uuid &= value.as_str().map(looks_uuid).unwrap_or(false);
    }

    if types.len() > 1 {
        warnings.mixed(&format!("path.{name}"));
        json!({"type":"string"})
    } else if types.contains("integer") {
        json!({"type":"integer"})
    } else if uuid {
        json!({"type":"string","format":"uuid"})
    } else {
        json!({"type":"string"})
    }
}

fn normalize_path_template(path: &str) -> String {
    let parts: Vec<String> = path
        .trim_matches('/')
        .split('/')
        .filter(|seg| !seg.is_empty())
        .map(|seg| {
            if is_static_segment(seg) {
                seg.to_string()
            } else if typed_value(seg).is_some() {
                "{id}".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect();

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn path_param_confidence(base: f64, warnings: &InferenceWarnings) -> f64 {
    let mut confidence = base;
    confidence -= warnings.weak_path_params as f64 * 0.20;
    confidence -= warnings.mixed_types as f64 * 0.05;
    confidence.max(0.35)
}

fn schema_confidence(base: f64, observation_count: usize, warnings: &InferenceWarnings) -> f64 {
    let mut confidence = base;
    if observation_count == 1 {
        confidence -= 0.20;
    } else if observation_count == 2 {
        confidence -= 0.10;
    }
    confidence -= warnings.mixed_types as f64 * 0.08;
    confidence -= warnings.non_json as f64 * 0.10;
    if warnings.empty_body {
        confidence -= 0.15;
    }
    confidence.max(0.30)
}

fn log_field_schema(
    method: &str,
    observations: &[&Observation],
    source: &str,
    name: &str,
    schema: &Value,
    required: bool,
) {
    let type_name = schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    info!(
        target: "tapestry::analyzer",
        phase = "schema",
        method = %method,
        path = %observations.first().map(|obs| obs.path.as_str()).unwrap_or(""),
        field = %format!("{source}.{name}"),
        type_name,
        required,
        "[schema] inferred field"
    );
}

fn infer_auth(observations: &[&Observation]) -> AuthRequirement {
    let has_auth = observations.iter().any(|obs| has_auth_signal(obs));
    let method = if !has_auth {
        None
    } else if observations
        .iter()
        .any(|obs| has_header(&obs.request_headers, "authorization"))
    {
        Some("authorization_header".to_string())
    } else if observations
        .iter()
        .any(|obs| has_header(&obs.request_headers, "cookie"))
    {
        Some("cookie".to_string())
    } else {
        Some("csrf_or_session_header".to_string())
    };

    AuthRequirement {
        required: has_auth,
        method,
    }
}

fn infer_pagination(observations: &[&Observation]) -> Option<PaginationInfo> {
    let has_page = observations
        .iter()
        .any(|obs| obs.query.contains_key("page"));
    let has_limit = observations
        .iter()
        .any(|obs| obs.query.contains_key("limit"));
    if has_page || has_limit {
        Some(PaginationInfo {
            pagination_type: "page_limit".to_string(),
            auto: false,
            page_param: has_page.then(|| "page".to_string()),
            limit_param: has_limit.then(|| "limit".to_string()),
            total_path: Some("$.total".to_string()),
        })
    } else {
        None
    }
}

fn classify_safety(method: &str, observations: &[&Observation]) -> SafetyClassification {
    if observations
        .iter()
        .any(|obs| graphql_operation_type(obs) == Some("mutation"))
    {
        SafetyClassification::Write
    } else if observations
        .iter()
        .any(|obs| graphql_operation_type(obs) == Some("query"))
    {
        SafetyClassification::Read
    } else if is_opaque_root_post_json(observations) {
        SafetyClassification::Unknown
    } else {
        match method {
            "GET" | "HEAD" | "OPTIONS" => SafetyClassification::Read,
            "POST" | "PUT" | "PATCH" | "DELETE" => SafetyClassification::Write,
            _ => SafetyClassification::Unknown,
        }
    }
}

fn safety_reasoning(method: &str, observations: &[&Observation]) -> String {
    if observations
        .iter()
        .any(|obs| graphql_operation_type(obs) == Some("mutation"))
    {
        "GraphQL mutation observed in request body".to_string()
    } else if observations
        .iter()
        .any(|obs| graphql_operation_type(obs) == Some("query"))
    {
        "GraphQL query observed in request body".to_string()
    } else if is_opaque_root_post_json(observations) {
        "Opaque root POST JSON request; operation semantics were not inferred".to_string()
    } else {
        format!("Classified from HTTP method {method}")
    }
}

#[derive(Debug, Clone)]
struct GraphqlOperation {
    operation_name: Option<String>,
    operation_type: Option<String>,
    query: Option<String>,
    batched: bool,
}

impl GraphqlOperation {
    fn cluster_key(&self) -> String {
        let name = self.operation_name.as_deref().unwrap_or("unnamed_graphql");
        format!("graphql:{}", normalize_identifier(name))
    }
}

fn graphql_info_for(observations: &[&Observation], operation_key: &str) -> Option<GraphqlInfo> {
    let operation = observations.iter().find_map(|obs| {
        graphql_operations(obs)
            .into_iter()
            .find(|operation| operation.cluster_key() == operation_key)
    })?;
    Some(GraphqlInfo {
        operation_name: operation.operation_name,
        operation_type: operation.operation_type,
        query: operation.query,
        batched: operation.batched,
    })
}

fn operation_cluster_keys(obs: &Observation) -> Vec<String> {
    let graphql = graphql_operations(obs);
    if !graphql.is_empty() {
        return graphql
            .into_iter()
            .map(|operation| operation.cluster_key())
            .collect();
    }

    if obs.method == "POST" && obs.path == "/" && obs.request_body.is_some() {
        if let Some(name) = semantic_operation_name(&obs.request_body) {
            return vec![format!("json:{}", normalize_identifier(&name))];
        }
        return vec!["json:opaque_root_post".to_string()];
    }

    vec![String::new()]
}

fn graphql_operation_details(obs: &Observation) -> Option<GraphqlOperation> {
    graphql_operations(obs).into_iter().next()
}

fn graphql_operations(obs: &Observation) -> Vec<GraphqlOperation> {
    if obs.method != "POST" {
        return Vec::new();
    }
    graphql_operations_from_value(obs.request_body.as_ref(), false)
}

fn graphql_operations_from_value(value: Option<&Value>, batched: bool) -> Vec<GraphqlOperation> {
    match value {
        Some(Value::Array(values)) => values
            .iter()
            .flat_map(|value| graphql_operations_from_value(Some(value), true))
            .collect(),
        Some(value) => graphql_operation_from_value(value, batched)
            .into_iter()
            .collect(),
        None => Vec::new(),
    }
}

fn graphql_operation_from_value(value: &Value, batched: bool) -> Option<GraphqlOperation> {
    match value {
        Value::Object(map) => {
            let has_graphql_key = map.contains_key("operationName")
                || map.contains_key("query")
                || map.contains_key("variables");
            if !has_graphql_key {
                return None;
            }
            let query = map
                .get("query")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            Some(GraphqlOperation {
                operation_name: map
                    .get("operationName")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                operation_type: query.as_deref().and_then(graphql_query_type),
                query,
                batched,
            })
        }
        _ => None,
    }
}

fn graphql_query_type(query: &str) -> Option<String> {
    let trimmed = query.trim_start();
    if trimmed.starts_with("mutation") {
        Some("mutation".to_string())
    } else if trimmed.starts_with("query") || trimmed.starts_with('{') {
        Some("query".to_string())
    } else {
        None
    }
}

fn graphql_operation_type(obs: &Observation) -> Option<&'static str> {
    let query = graphql_operation_details(obs)?.operation_type?;
    match query.as_str() {
        "query" => Some("query"),
        "mutation" => Some("mutation"),
        _ => None,
    }
}

fn is_graphql_request(obs: &Observation) -> bool {
    graphql_operation_details(obs).is_some()
}

fn object_variables(value: Option<&Value>) -> Option<BTreeMap<String, Value>> {
    let Value::Object(map) = value? else {
        return Some(BTreeMap::new());
    };
    Some(
        map.iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

fn semantic_operation_name(body: &Option<Value>) -> Option<String> {
    let value = body.as_ref()?;
    match value {
        Value::Object(map) => [
            "operationName",
            "operation",
            "action",
            "type",
            "method",
            "query",
        ]
        .iter()
        .find_map(|key| map.get(*key).and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            map.get("requests")
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .and_then(|value| semantic_operation_name(&Some(value.clone())))
        }),
        Value::Array(values) => values
            .first()
            .and_then(|value| semantic_operation_name(&Some(value.clone()))),
        _ => None,
    }
}

fn is_opaque_root_post_json(observations: &[&Observation]) -> bool {
    observations.iter().any(|obs| {
        obs.method == "POST"
            && obs.path == "/"
            && obs.request_body.is_some()
            && !is_graphql_request(obs)
            && semantic_operation_name(&obs.request_body).is_none()
    })
}

fn has_auth_signal(obs: &Observation) -> bool {
    obs.request_headers.keys().any(|key| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "authorization" | "cookie" | "x-csrf-token" | "x-xsrf-token"
        )
    })
}

fn confidence_for_count(count: usize) -> f64 {
    if count >= 10 {
        0.95
    } else if count >= 3 {
        0.85
    } else {
        0.70
    }
}

fn stable_tool_id(method: &str, path: &str, operation_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "{}:{}:{}",
        method.to_uppercase(),
        path,
        operation_key
    ));
    let digest = hex::encode(hasher.finalize());
    format!("tool_{}", &digest[..12])
}

fn tool_name(
    method: &str,
    path: &str,
    operation_key: &str,
    observations: &[&Observation],
) -> String {
    if let Some(operation) = observations.iter().find_map(|obs| {
        graphql_operations(obs)
            .into_iter()
            .find(|operation| operation.cluster_key() == operation_key)
    }) {
        if let Some(name) = operation.operation_name {
            return normalize_identifier(&name);
        }
        return if operation.batched {
            "batched_graphql_request".to_string()
        } else {
            "graphql_request".to_string()
        };
    }

    if method == "POST" && path == "/" {
        if let Some(name) = observations
            .iter()
            .find_map(|obs| semantic_operation_name(&obs.request_body))
        {
            return normalize_identifier(&name);
        }
        return "opaque_root_post".to_string();
    }

    let resource = path
        .trim_matches('/')
        .split('/')
        .filter(|seg| !seg.starts_with('{') && !is_version(seg) && *seg != "api")
        .last()
        .unwrap_or("tool");
    let singular = resource.trim_end_matches('s');
    let prefix = match method {
        "GET" => {
            if path.contains("{id}") {
                "get"
            } else {
                "list"
            }
        }
        "POST" => "create",
        "PUT" | "PATCH" => "update",
        "DELETE" => "delete",
        _ => "call",
    };

    if path.contains("{id}") && method == "GET" {
        format!("{prefix}_{singular}_by_id")
    } else {
        format!("{prefix}_{resource}")
    }
}

fn describe_tool(
    method: &str,
    path: &str,
    operation_key: &str,
    observations: &[&Observation],
) -> String {
    if let Some(operation) = observations.iter().find_map(|obs| {
        graphql_operations(obs)
            .into_iter()
            .find(|operation| operation.cluster_key() == operation_key)
    }) {
        let name = operation
            .operation_name
            .unwrap_or_else(|| "unnamed".to_string());
        let typ = operation
            .operation_type
            .unwrap_or_else(|| "unknown".to_string());
        return format!("Observed GraphQL {typ} {name} at {method} {path}");
    }
    if method == "POST" && path == "/" {
        return "Observed root POST JSON API endpoint".to_string();
    }
    format!("Observed {method} endpoint {path}")
}

fn evidence_detail(
    method: &str,
    path: &str,
    operation_key: &str,
    observations: &[&Observation],
) -> String {
    if let Some(operation) = observations.iter().find_map(|obs| {
        graphql_operations(obs)
            .into_iter()
            .find(|operation| operation.cluster_key() == operation_key)
    }) {
        let name = operation
            .operation_name
            .unwrap_or_else(|| "unnamed".to_string());
        let query = operation
            .query
            .map(|query| {
                query
                    .split_whitespace()
                    .take(80)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        return format!("{method} {path} GraphQL {name} {query}");
    }
    if let Some(name) = observations
        .iter()
        .find_map(|obs| semantic_operation_name(&obs.request_body))
    {
        return format!("{method} {path} operation {name}");
    }
    format!("{method} {path}")
}

fn base_url_for(obs: &Observation) -> Option<String> {
    let url = url::Url::parse(&obs.url).ok()?;
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Some(format!("{}://{}{}", url.scheme(), url.host_str()?, port))
}

fn has_json_signal(obs: &Observation) -> bool {
    obs.request_body.is_some()
        || obs.response_body.is_some()
        || header_contains(&obs.request_headers, "content-type", "json")
        || header_contains(&obs.request_headers, "accept", "json")
        || header_contains(&obs.response_headers, "content-type", "json")
}

fn is_static_asset_path(path: &str) -> bool {
    let asset_extensions = [
        ".css", ".js", ".mjs", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".wav", ".pdf",
    ];
    asset_extensions
        .iter()
        .any(|extension| path.ends_with(extension))
}

fn is_consent_or_config_asset(obs: &Observation, path: &str) -> bool {
    let consent_markers = [
        "/assets/cmp/",
        "/cmp/",
        "/consent/",
        "/privacy/",
        "/cookie/",
        "/cookies/",
        "/onetrust/",
        "/trustarc/",
    ];
    if consent_markers.iter().any(|marker| path.contains(marker)) {
        return true;
    }

    obs.method == "GET"
        && obs.request_body.is_none()
        && path.contains("/assets/")
        && path.ends_with(".json")
        && response_looks_static_config(obs.response_body.as_ref())
}

fn response_looks_static_config(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let text = value.to_string().to_ascii_lowercase();
    [
        "consent", "cookie", "privacy", "onetrust", "trustarc", "cmp", "locale", "config",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn is_bot_or_security_telemetry(obs: &Observation, path: &str) -> bool {
    let path_markers = [
        "/akam/",
        "/akamai/",
        "/bot/",
        "/challenge/",
        "/captcha/",
        "/risk/",
        "/fingerprint/",
        "/telemetry/",
    ];
    if path_markers.iter().any(|marker| path.contains(marker)) {
        return true;
    }

    if body_contains_telemetry_key(obs.request_body.as_ref()) {
        return true;
    }

    obs.method == "POST"
        && has_opaque_path_segment(path)
        && !is_graphql_request(obs)
        && semantic_operation_name(&obs.request_body).is_none()
        && response_is_empty_or_opaque(obs.response_body.as_ref())
}

fn body_contains_telemetry_key(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "sensor_data"
                    | "_fingerprint"
                    | "fingerprint"
                    | "challenge"
                    | "captcha"
                    | "bot"
                    | "risk"
                    | "akamai"
            ) || body_contains_telemetry_key(Some(value))
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| body_contains_telemetry_key(Some(value))),
        Value::String(value) => {
            let value = value.to_ascii_lowercase();
            value.contains("sensor_data")
                || value.contains("fingerprint")
                || value.contains("akamai")
        }
        _ => false,
    }
}

fn has_opaque_path_segment(path: &str) -> bool {
    path.trim_matches('/').split('/').any(|segment| {
        segment.len() >= 16
            && segment
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .count()
                >= segment.len() * 3 / 4
            && !contains_semantic_word(segment)
    })
}

fn contains_semantic_word(segment: &str) -> bool {
    let segment = segment.to_ascii_lowercase();
    [
        "api", "search", "basket", "cart", "product", "item", "order", "user", "account", "list",
        "status", "graphql", "category", "grocer",
    ]
    .iter()
    .any(|word| segment.contains(word))
}

fn response_is_empty_or_opaque(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::Object(map)) => {
            map.is_empty() || map.keys().all(|key| !contains_semantic_word(key))
        }
        Some(Value::String(value)) => value.len() > 64 && !contains_semantic_word(value),
        _ => false,
    }
}

fn is_html_page(obs: &Observation, path: &str) -> bool {
    !is_api_path(path)
        && (header_contains(&obs.response_headers, "content-type", "text/html")
            || (obs.method == "GET" && obs.response_body.is_none() && is_likely_page_path(path)))
}

fn is_likely_page_path(path: &str) -> bool {
    path == "/"
        || path.ends_with('/')
        || !path
            .trim_matches('/')
            .split('/')
            .last()
            .unwrap_or_default()
            .contains('.')
}

fn is_api_path(path: &str) -> bool {
    let trimmed = path.trim_matches('/');
    trimmed == "graphql"
        || trimmed.starts_with("api/")
        || trimmed.starts_with("graphql/")
        || trimmed.starts_with("rest/")
        || trimmed.starts_with("rpc/")
        || trimmed.split('/').next().map(is_version).unwrap_or(false)
}

fn is_static_segment(seg: &str) -> bool {
    matches!(
        seg,
        "search"
            | "list"
            | "status"
            | "login"
            | "logout"
            | "export"
            | "bulk"
            | "me"
            | "current"
            | "api"
    ) || is_version(seg)
}

fn is_version(seg: &str) -> bool {
    seg.len() >= 2 && seg.starts_with('v') && seg[1..].chars().all(|c| c.is_ascii_digit())
}

fn typed_value(seg: &str) -> Option<Value> {
    if looks_uuid(seg) {
        Some(Value::String(seg.to_string()))
    } else if let Ok(i) = seg.parse::<i64>() {
        Some(Value::from(i))
    } else if looks_float_id(seg) {
        Some(Value::from(seg.parse::<f64>().unwrap()))
    } else {
        None
    }
}

/// Matches floating-point path segments like coordinates: `-4.308857`, `50.376705`.
/// Requires a decimal point to avoid matching plain integers twice.
fn looks_float_id(seg: &str) -> bool {
    seg.contains('.') && seg.parse::<f64>().is_ok()
}

fn path_has_build_hash(path: &str) -> bool {
    path.split('/').any(|seg| is_gibberish_path_segment(seg))
}

fn is_gibberish_path_segment(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    // Content hash (md5/sha): long hex with at least one letter. The letter
    // requirement excludes plain numeric IDs (snowflakes, sequential IDs), and
    // the >=25 threshold excludes 24-char Mongo ObjectIds and shorter IDs, all
    // of which are legitimate REST resource identifiers we must not drop.
    if seg.len() >= 25
        && seg.chars().all(|c| c.is_ascii_hexdigit())
        && seg.chars().any(|c| c.is_ascii_alphabetic())
    {
        return true;
    }
    // URL-percent-encoded binary payload baked into a path segment. Requires
    // the segment to be *dominated* by percent-escapes so that ordinary
    // encoded text (e.g. "New%20York%20Apartments") is not mistaken for one.
    if seg.len() >= 16 {
        let pct = seg.matches('%').count();
        if pct >= 4 && pct * 3 * 2 >= seg.len() {
            return true;
        }
    }
    // Base64url-encoded payload: long, mixed-case alphanumeric + '-'/'_'/'='
    // Requires both cases + digits to distinguish from regular slugs like "web-unified-search"
    if seg.len() >= 24 {
        let is_base64url = seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '='));
        if is_base64url {
            let upper = seg.chars().filter(|c| c.is_ascii_uppercase()).count();
            let lower = seg.chars().filter(|c| c.is_ascii_lowercase()).count();
            let digits = seg.chars().filter(|c| c.is_ascii_digit()).count();
            // True base64url tokens always have a dense mix of upper, lower, and digits
            return upper >= 3 && lower >= 3 && digits >= 2;
        }
    }
    false
}

fn value_from_path_segment(seg: &str) -> Value {
    typed_value(seg).unwrap_or_else(|| Value::String(seg.to_string()))
}

fn looks_uuid(seg: &str) -> bool {
    let parts: Vec<&str> = seg.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .into_iter()
            .zip(parts)
            .all(|(len, part)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) => {
            if number.is_i64() || number.is_u64() {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn unique_examples(values: Vec<Value>) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        let key = value.to_string();
        if seen.insert(key) {
            out.push(value);
        }
    }
    out
}

fn insert_bool(schema: &mut Value, key: &str, value: bool) {
    if let Some(obj) = schema.as_object_mut() {
        obj.insert(key.to_string(), Value::Bool(value));
    }
}

fn schema_key_summary(schema: &Value) -> String {
    let keys = schema_keys(schema);
    if keys.is_empty() {
        "none".to_string()
    } else {
        keys.join(",")
    }
}

fn schema_keys(schema: &Value) -> Vec<String> {
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        return properties.keys().cloned().collect();
    }
    schema
        .get("items")
        .map(schema_keys)
        .map(|keys| keys.into_iter().map(|key| format!("items.{key}")).collect())
        .unwrap_or_default()
}

fn is_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

fn header_contains(headers: &BTreeMap<String, String>, name: &str, needle: &str) -> bool {
    headers.iter().any(|(header_name, value)| {
        header_name.eq_ignore_ascii_case(name)
            && value
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
    })
}

fn has_header(headers: &BTreeMap<String, String>, name: &str) -> bool {
    headers
        .keys()
        .any(|header_name| header_name.eq_ignore_ascii_case(name))
}

fn infer_primary_host(observations: &[Observation]) -> Option<String> {
    // Track (count, first_seen_index) per host; ties broken by first-seen ordering.
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for (idx, obs) in observations.iter().enumerate() {
        let Some(host) = url::Url::parse(&obs.url)
            .ok()
            .and_then(|url| url.host_str().map(ToOwned::to_owned))
        else {
            continue;
        };
        let entry = counts.entry(host).or_insert((0, idx));
        entry.0 += 1;
    }

    counts
        .into_iter()
        .max_by(
            |(_, (left_count, left_first)), (_, (right_count, right_first))| {
                left_count
                    .cmp(right_count)
                    .then_with(|| right_first.cmp(left_first)) // lower first_seen wins on tie
            },
        )
        .map(|(host, _)| host)
}

fn redact_value(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    if is_secret_key(&key) {
                        (key, Value::String("<redacted>".to_string()))
                    } else {
                        (key, redact_value(value))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_value).collect()),
        other => other,
    }
}

fn is_secret_key(key: &str) -> bool {
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

fn current_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Days since 1970-01-01 → Gregorian date
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for md in &month_days {
        if days < *md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn normalize_identifier(value: &str) -> String {
    let mut out = String::new();
    let mut prev_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && prev_lower_or_digit && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
            prev_lower_or_digit = false;
        } else {
            prev_lower_or_digit = false;
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "operation".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tapestry_input::import_har;

    #[test]
    fn build_hash_filter_keeps_ids_but_drops_content_hashes() {
        // Legitimate resource identifiers must survive.
        assert!(!is_gibberish_path_segment("1234567890123456789")); // 19-digit snowflake
        assert!(!is_gibberish_path_segment("507f1f77bcf86cd799439011")); // 24-hex ObjectId
        assert!(!is_gibberish_path_segment("New%20York%20Apartments")); // encoded slug
        assert!(!is_gibberish_path_segment("web-unified-search"));
        // Real content hashes and dense percent-encoded payloads are noise.
        assert!(is_gibberish_path_segment(
            "d41d8cd98f00b204e9800998ecf8427e" // 32-char md5
        ));
        assert!(is_gibberish_path_segment("%00%01%02%ff%fe%fd%aa%bb"));
    }

    #[test]
    fn fixture_generates_vertical_slice_tools() {
        let observations = import_har("../../examples/fixtures/simple.har").unwrap();
        let spec = analyze("fixture", &observations);

        assert_eq!(spec.tools.len(), 3);
        assert!(spec.tools.iter().any(|tool| tool.name == "list_items"));
        assert!(spec.tools.iter().any(|tool| tool.name == "get_item_by_id"));
        assert!(spec.tools.iter().any(|tool| tool.name == "create_items"));

        let write_tool = spec
            .tools
            .iter()
            .find(|tool| tool.name == "create_items")
            .unwrap();
        assert_eq!(
            write_tool.safety.classification,
            SafetyClassification::Write
        );
        assert!(!write_tool.approved);
    }

    #[test]
    fn browser_docs_capture_does_not_generate_asset_or_page_tools() {
        let observations = import_har("../../examples/fixtures/dummyjson.com.har").unwrap();
        let spec = analyze("dummyjson", &observations);

        assert!(spec.tools.is_empty());
    }

    #[test]
    fn signal_filter_keeps_api_like_requests_and_drops_noise() {
        let observations = vec![
            observation(
                "GET",
                "https://app.test/api/items",
                None,
                Some(json!({"items": []})),
            ),
            observation(
                "POST",
                "https://app.test/api/items",
                Some(json!({"name": "A"})),
                Some(json!({"id": 1})),
            ),
            observation("GET", "https://app.test/public/app.js", None, None),
            observation("GET", "https://app.test/docs", None, None),
            observation(
                "GET",
                "https://analytics.example/gtag/js?id=abc",
                None,
                None,
            ),
        ];

        let spec = analyze("mixed", &observations);
        let paths: BTreeSet<_> = spec.tools.iter().map(|tool| tool.path.as_str()).collect();

        assert_eq!(spec.tools.len(), 2);
        assert!(paths.contains("/api/items"));
        assert!(spec.tools.iter().all(|tool| !tool.path.contains(".js")));
        assert!(spec.tools.iter().all(|tool| tool.path != "/docs"));
    }

    #[test]
    fn signal_filter_drops_consent_config_json() {
        let observations = vec![observation(
            "GET",
            "https://app.test/assets/cmp/en.json",
            None,
            Some(json!({"consent": {"cookies": true}, "config": {}})),
        )];

        let spec = analyze("consent", &observations);

        assert!(spec.tools.is_empty());
    }

    #[test]
    fn signal_filter_drops_sensor_data_and_opaque_security_paths() {
        let observations = vec![
            observation(
                "POST",
                "https://app.test/FA9knGUdK84kJD93kdla9P",
                Some(json!({"sensor_data": "opaque"})),
                Some(json!({})),
            ),
            observation(
                "POST",
                "https://app.test/AbCdEfGhIjKlMnOpQrSt",
                Some(json!({"payload": "opaque"})),
                None,
            ),
        ];

        let spec = analyze("telemetry", &observations);

        assert!(spec.tools.is_empty());
    }

    #[test]
    fn graphql_post_uses_operation_name_variables_and_read_safety() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!({
                "operationName": "SearchGroceries",
                "query": "query SearchGroceries($basketId: ID, $count: Int) { search(term: \"groceries\") { items { id title } } basket { id } }",
                "variables": {"basketId": "b1", "count": 5}
            })),
            Some(json!({"data": {"search": {"items": [{"id": 1, "title": "Bread"}]}}})),
        )];

        let spec = analyze("graphql", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.name, "search_groceries");
        assert_eq!(tool.path, "/");
        assert_eq!(
            tool.graphql.as_ref().unwrap().operation_name.as_deref(),
            Some("SearchGroceries")
        );
        assert_eq!(
            tool.graphql.as_ref().unwrap().operation_type.as_deref(),
            Some("query")
        );
        assert_eq!(tool.safety.classification, SafetyClassification::Read);
        assert_eq!(
            tool.input_schema["properties"]["basketId"]["type"],
            "string"
        );
        assert_eq!(tool.input_schema["properties"]["count"]["type"], "integer");
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "graphql_detected"));
    }

    #[test]
    fn graphql_post_preserves_redacted_example_input_from_variables() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!({
                "operationName": "Taxonomy",
                "query": "query Taxonomy($configs: ConfigInput!) { taxonomy(configs: $configs) { name } }",
                "variables": {
                    "configs": {
                        "access_token": "secret-token",
                        "mode": "delivery"
                    }
                }
            })),
            Some(json!({"data": {"taxonomy": []}})),
        )];

        let spec = analyze("graphql-example-input", &observations);
        let tool = &spec.tools[0];

        assert_eq!(
            tool.example_input.as_ref().unwrap()["configs"]["mode"],
            "delivery"
        );
        assert_eq!(
            tool.example_input.as_ref().unwrap()["configs"]["access_token"],
            "<redacted>"
        );
    }

    #[test]
    fn batched_graphql_sets_metadata_and_warning() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!([
                {
                    "operationName": "Taxonomy",
                    "query": "query Taxonomy { taxonomy { name } }",
                    "variables": {}
                }
            ])),
            Some(json!([{"data": {"taxonomy": []}}])),
        )];

        let spec = analyze("batched", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.name, "taxonomy");
        assert_eq!(tool.graphql.as_ref().unwrap().batched, true);
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "batched_graphql_detected"));
    }

    #[test]
    fn graphql_response_schema_uses_data_field_and_captures_example() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!({
                "operationName": "ProductDetails",
                "query": "query ProductDetails($id: ID!) { product(id: $id) { id title } }",
                "variables": {"id": "p1"}
            })),
            Some(json!({"data": {"product": {"id": "p1", "title": "Bread"}}})),
        )];

        let spec = analyze("graphql-response", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.name, "product_details");
        assert_eq!(tool.response_schema["properties"]["id"]["type"], "string");
        assert_eq!(
            tool.response_schema["properties"]["title"]["type"],
            "string"
        );
        assert_eq!(tool.example_response.as_ref().unwrap()["title"], "Bread");
        assert!(tool.confidence.response_schema >= 0.70);
    }

    #[test]
    fn graphql_response_errors_warn_but_data_still_maps() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!({
                "operationName": "ProductDetails",
                "query": "query ProductDetails { product { id } }",
                "variables": {}
            })),
            Some(json!({
                "data": {"product": {"id": "p1"}},
                "errors": [{"message": "partial"}]
            })),
        )];

        let spec = analyze("graphql-errors", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.response_schema["properties"]["id"]["type"], "string");
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "graphql_response_errors"));
    }

    #[test]
    fn batched_graphql_splits_responses_by_operation_index() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!([
                {
                    "operationName": "FirstOperation",
                    "query": "query FirstOperation($firstId: ID) { first { id } }",
                    "variables": {"firstId": "a"}
                },
                {
                    "operationName": "SecondOperation",
                    "query": "query SecondOperation($secondId: ID) { second { count } }",
                    "variables": {"secondId": "b"}
                }
            ])),
            Some(json!([
                {"data": {"first": {"id": "a"}}},
                {"data": {"second": {"count": 2}}}
            ])),
        )];

        let spec = analyze("batched-split", &observations);
        let first = spec
            .tools
            .iter()
            .find(|tool| tool.name == "first_operation")
            .unwrap();
        let second = spec
            .tools
            .iter()
            .find(|tool| tool.name == "second_operation")
            .unwrap();

        assert_eq!(spec.tools.len(), 2);
        assert_eq!(
            first.input_schema["properties"]["firstId"]["type"],
            "string"
        );
        assert!(first.input_schema["properties"].get("secondId").is_none());
        assert_eq!(first.response_schema["properties"]["id"]["type"], "string");
        assert_eq!(
            second.input_schema["properties"]["secondId"]["type"],
            "string"
        );
        assert_eq!(
            second.response_schema["properties"]["count"]["type"],
            "integer"
        );
        assert_eq!(second.example_response.as_ref().unwrap()["count"], 2);
    }

    #[test]
    fn graphql_example_input_preserves_nested_variables_for_required_object() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!({
                "operationName": "SearchGroceries",
                "query": "query SearchGroceries($configs: ConfigInput!) { taxonomy(configs: $configs) { name } }",
                "variables": {
                    "configs": {
                        "filter": {
                            "term": "groceries"
                        }
                    }
                }
            })),
            Some(json!({"data": {"taxonomy": []}})),
        )];

        let spec = analyze("graphql-required-object", &observations);
        let tool = &spec.tools[0];

        assert_eq!(
            tool.example_input.as_ref().unwrap()["configs"]["filter"]["term"],
            "groceries"
        );
    }

    #[test]
    fn graphql_nested_list_response_infers_array_items() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!({
                "operationName": "SearchGroceries",
                "query": "query SearchGroceries { search { items { id title } } }",
                "variables": {}
            })),
            Some(json!({
                "data": {
                    "search": {
                        "items": [
                            {"id": 1, "title": "Bread"},
                            {"id": 2, "title": "Milk"}
                        ]
                    }
                }
            })),
        )];

        let spec = analyze("nested-list", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.response_schema["properties"]["items"]["type"], "array");
        assert_eq!(
            tool.response_schema["properties"]["items"]["items"]["properties"]["title"]["type"],
            "string"
        );
    }

    #[test]
    fn graphql_example_response_is_redacted() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!({
                "operationName": "Session",
                "query": "query Session { session { access_token user { name } } }",
                "variables": {}
            })),
            Some(json!({
                "data": {
                    "session": {
                        "access_token": "secret-token",
                        "user": {"name": "Ada"}
                    }
                }
            })),
        )];

        let spec = analyze("graphql-redaction", &observations);
        let example = spec.tools[0].example_response.as_ref().unwrap();

        assert_eq!(example["access_token"], "<redacted>");
        assert_eq!(example["user"]["name"], "Ada");
    }

    #[test]
    fn opaque_root_post_json_is_included_unknown_and_warned() {
        let observations = vec![observation(
            "POST",
            "https://api.test/",
            Some(json!({"payload": {"id": 1}})),
            Some(json!({"ok": true})),
        )];

        let spec = analyze("opaque", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.name, "opaque_root_post");
        assert_eq!(tool.safety.classification, SafetyClassification::Unknown);
        assert!(!tool.approved);
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "opaque_root_post"));
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "low_semantic_confidence"));
    }

    #[test]
    fn query_params_are_typed_required_optional_and_warn_when_seen_once() {
        let observations = vec![
            observation(
                "GET",
                "https://app.test/api/items?page=1&limit=5",
                None,
                Some(json!({"items": []})),
            ),
            observation(
                "GET",
                "https://app.test/api/items?page=2",
                None,
                Some(json!({"items": []})),
            ),
        ];

        let spec = analyze("query", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.input_schema["properties"]["page"]["type"], "integer");
        assert_eq!(tool.input_schema["properties"]["limit"]["type"], "integer");
        assert!(tool.input_schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("page")));
        assert!(!tool.input_schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("limit")));
        assert_eq!(tool.input_schema["properties"]["limit"]["optional"], true);
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "parameter_seen_once:query.limit"));
    }

    #[test]
    fn path_params_are_inferred_as_integer() {
        let observations = vec![
            observation(
                "GET",
                "https://app.test/api/items/1",
                None,
                Some(json!({"id": 1, "name": "A"})),
            ),
            observation(
                "GET",
                "https://app.test/api/items/2",
                None,
                Some(json!({"id": 2, "name": "B"})),
            ),
        ];

        let spec = analyze("path", &observations);
        let tool = spec
            .tools
            .iter()
            .find(|tool| tool.path == "/api/items/{id}")
            .unwrap();

        assert_eq!(tool.path_params[0].name, "id");
        assert_eq!(tool.path_params[0].schema["type"], "integer");
        assert_eq!(tool.input_schema["properties"]["id"]["type"], "integer");
    }

    #[test]
    fn request_body_schema_marks_required_optional_nested_and_arrays() {
        let observations = vec![
            observation(
                "POST",
                "https://app.test/api/items",
                Some(json!({"name": "A", "active": true, "meta": {"rank": 1}, "tags": ["x"]})),
                Some(json!({"id": 1})),
            ),
            observation(
                "POST",
                "https://app.test/api/items",
                Some(
                    json!({"name": "B", "active": false, "meta": {}, "tags": ["y"], "note": "optional"}),
                ),
                Some(json!({"id": 2})),
            ),
        ];

        let spec = analyze("body", &observations);
        let tool = spec
            .tools
            .iter()
            .find(|tool| tool.method == "POST")
            .unwrap();

        assert_eq!(tool.input_schema["properties"]["name"]["type"], "string");
        assert_eq!(tool.input_schema["properties"]["active"]["type"], "boolean");
        assert_eq!(
            tool.input_schema["properties"]["meta"]["properties"]["rank"]["type"],
            "integer"
        );
        assert_eq!(
            tool.input_schema["properties"]["meta"]["properties"]["rank"]["optional"],
            true
        );
        assert_eq!(
            tool.input_schema["properties"]["tags"]["items"]["type"],
            "string"
        );
        assert!(tool.input_schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("name")));
        assert!(!tool.input_schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("note")));
    }

    #[test]
    fn response_schema_supports_arrays_objects_nullable_and_optional_fields() {
        let observations = vec![
            observation(
                "GET",
                "https://app.test/api/items/1",
                None,
                Some(json!({"id": 1, "name": "A", "description": null, "status": "draft"})),
            ),
            observation(
                "GET",
                "https://app.test/api/items/2",
                None,
                Some(json!({"id": 2, "name": "B", "description": "Ready"})),
            ),
            observation(
                "GET",
                "https://app.test/api/items/3",
                None,
                Some(json!({"id": 3, "name": "C", "description": null})),
            ),
        ];

        let spec = analyze("response", &observations);
        let tool = spec
            .tools
            .iter()
            .find(|tool| tool.path == "/api/items/{id}")
            .unwrap();

        assert_eq!(
            tool.response_schema["properties"]["description"]["type"],
            "string"
        );
        assert_eq!(
            tool.response_schema["properties"]["description"]["nullable"],
            true
        );
        assert_eq!(
            tool.response_schema["properties"]["status"]["optional"],
            true
        );
        assert!(!tool.response_schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("status")));
    }

    #[test]
    fn list_response_infers_array_item_schema() {
        let observations = vec![observation(
            "GET",
            "https://app.test/api/items",
            None,
            Some(json!({"items": [{"id": 1, "name": "A"}], "total": 1})),
        )];

        let spec = analyze("list", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.response_schema["properties"]["items"]["type"], "array");
        assert_eq!(
            tool.response_schema["properties"]["items"]["items"]["properties"]["id"]["type"],
            "integer"
        );
    }

    #[test]
    fn redacts_secret_fields_from_example_response() {
        let observations = vec![observation(
            "GET",
            "https://app.test/api/session",
            None,
            Some(json!({
                "access_token": "abc",
                "refresh_token": "def",
                "user": {"password": "secret", "name": "Ada"}
            })),
        )];

        let spec = analyze("redact", &observations);
        let example = spec.tools[0].example_response.as_ref().unwrap();

        assert_eq!(example["access_token"], "<redacted>");
        assert_eq!(example["refresh_token"], "<redacted>");
        assert_eq!(example["user"]["password"], "<redacted>");
        assert_eq!(example["user"]["name"], "Ada");
    }

    #[test]
    fn mixed_types_warn_and_lower_schema_confidence() {
        let observations = vec![
            observation(
                "GET",
                "https://app.test/api/items?page=1",
                None,
                Some(json!({"id": 1})),
            ),
            observation(
                "GET",
                "https://app.test/api/items?page=two",
                None,
                Some(json!({"id": "2"})),
            ),
        ];

        let spec = analyze("mixed-types", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.input_schema["properties"]["page"]["type"], "string");
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "mixed_types:query.page"));
        assert!(tool.confidence.input_schema < 0.95);
    }

    #[test]
    fn classifies_language_json_as_localization_resource() {
        let observations = vec![observation(
            "GET",
            "https://game.test/lang/en.json",
            None,
            Some(json!({"PLAY":"Play","SAVE":"Save"})),
        )];

        let spec = analyze("melvor-like", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.resource_kind, ResourceKind::LocalizationResource);
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "localization_resource"));
    }

    #[test]
    fn classifies_config_json_as_config_resource() {
        let observations = vec![observation(
            "GET",
            "https://app.test/config/app.json",
            None,
            Some(json!({"apiBase": "https://api.test", "version": "1"})),
        )];

        let spec = analyze("config", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.resource_kind, ResourceKind::ConfigResource);
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "config_resource"));
    }

    #[test]
    fn classifies_wix_editor_manifest_as_platform_resource() {
        let observations = vec![observation(
            "GET",
            "https://static.parastorage.com/services/editor-elements/1.15085.0/rb_wixui.thunderbolt.manifest.min.json",
            None,
            Some(json!({"components":{"ProductSpecification":["bundle.js"]}})),
        )];

        let spec = analyze("wix", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.resource_kind, ResourceKind::PlatformResource);
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "platform_resource"));
    }

    #[test]
    fn classifies_wix_thunderbolt_page_as_platform_resource() {
        let observations = vec![observation(
            "GET",
            "https://www.justkandy.co.uk/pages/pages/thunderbolt",
            None,
            Some(json!({"pageJsonFileName":"abc.json"})),
        )];

        let spec = analyze("wix", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.resource_kind, ResourceKind::PlatformResource);
    }

    #[test]
    fn classifies_frog_wix_log_endpoint_as_telemetry() {
        let observations = vec![observation(
            "POST",
            "https://frog.wix.com/api/v1/bulklog",
            Some(json!({"events":[{"evid": 1}]})),
            None,
        )];

        let spec = analyze("wix", &observations);
        let tool = &spec.tools[0];

        assert_eq!(tool.resource_kind, ResourceKind::Telemetry);
        assert!(tool
            .warnings
            .iter()
            .any(|warning| warning == "telemetry_resource"));
    }

    #[test]
    fn classifies_cart_and_cloud_data_as_commerce_api() {
        let observations = vec![
            observation(
                "POST",
                "https://www.justkandy.co.uk/_api/cart-v2/v2/carts/current/add-line-items",
                Some(json!({"lineItems":[{"catalogReference":{"catalogItemId":"1"}}]})),
                None,
            ),
            observation(
                "GET",
                "https://www.justkandy.co.uk/_api/cloud-data/v2/items/query?filter=sweets",
                None,
                Some(json!({"items":[{"name":"Sweets"}]})),
            ),
        ];

        let spec = analyze("wix", &observations);

        assert!(spec
            .tools
            .iter()
            .any(|tool| tool.path.contains("/_api/cart-v2")
                && tool.resource_kind == ResourceKind::CommerceApi
                && tool.safety.classification == SafetyClassification::Write));
        assert!(spec
            .tools
            .iter()
            .any(|tool| tool.path.contains("/_api/cloud-data")
                && tool.resource_kind == ResourceKind::CommerceApi
                && tool.safety.classification == SafetyClassification::Read));
    }

    fn observation(
        method: &str,
        url: &str,
        request_body: Option<Value>,
        response_body: Option<Value>,
    ) -> Observation {
        let parsed = url::Url::parse(url).unwrap();
        Observation {
            method: method.to_string(),
            url: url.to_string(),
            path: parsed.path().to_string(),
            query: parsed
                .query_pairs()
                .map(|(key, value)| (key.to_string(), infer_scalar(value.as_ref())))
                .collect(),
            request_headers: request_body
                .as_ref()
                .map(|_| {
                    BTreeMap::from([("content-type".to_string(), "application/json".to_string())])
                })
                .unwrap_or_default(),
            request_body,
            response_status: Some(200),
            response_headers: response_body
                .as_ref()
                .map(|_| {
                    BTreeMap::from([("content-type".to_string(), "application/json".to_string())])
                })
                .unwrap_or_default(),
            response_body,
            warnings: vec![],
        }
    }

    fn infer_scalar(value: &str) -> Value {
        if let Ok(value) = value.parse::<i64>() {
            Value::from(value)
        } else if let Ok(value) = value.parse::<f64>() {
            Value::from(value)
        } else if let Ok(value) = value.parse::<bool>() {
            Value::from(value)
        } else {
            Value::String(value.to_string())
        }
    }
}
