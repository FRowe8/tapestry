//! `tapestry diagnose` — assess whether a capture has enough evidence
//! (response bodies, GraphQL operation mapping, non-noise traffic) to
//! produce useful tools, and recommend concrete fixes.

use crate::commands::review::{is_static_resource_kind_label, resource_kind_label, schema_present};
use serde::Serialize;
use serde_json::{Map, Value};
use tapestry_core::signal;

#[derive(Debug, Serialize)]
pub(crate) struct DiagnoseReport {
    pub(crate) site: String,
    pub(crate) summary: DiagnoseSummary,
    pub(crate) filtered_counts: FilteredCounts,
    pub(crate) tools: Vec<ToolDiagnostics>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiagnoseSummary {
    pub(crate) total_observations: usize,
    pub(crate) candidate_api_observations: usize,
    pub(crate) generated_tools: usize,
    pub(crate) observations_with_response_bodies: usize,
    pub(crate) json_responses: usize,
    pub(crate) graphql_requests: usize,
    pub(crate) graphql_responses_mapped: usize,
    pub(crate) tools_missing_examples: usize,
    pub(crate) tools_with_empty_response_schemas: usize,
    pub(crate) static_resource_tools: usize,
    pub(crate) platform_resource_tools: usize,
    pub(crate) telemetry_tools: usize,
    pub(crate) commerce_api_tools: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct FilteredCounts {
    pub(crate) static_assets: usize,
    pub(crate) consent_or_config: usize,
    pub(crate) bot_or_security: usize,
    pub(crate) third_party_non_api: usize,
    pub(crate) html_fragments: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ToolDiagnostics {
    pub(crate) name: String,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) resource_kind: String,
    pub(crate) has_request_body: bool,
    pub(crate) has_response_body: bool,
    pub(crate) example_response_present: bool,
    pub(crate) response_schema_empty: bool,
    pub(crate) warnings: Vec<String>,
    pub(crate) problem: Option<String>,
    pub(crate) remediation: String,
}

pub(crate) fn diagnose_site(
    spec: &tapestry_core::ToolSpec,
    observations: &[tapestry_core::Observation],
) -> DiagnoseReport {
    let filtered_counts = filtered_counts(observations);
    let tools = spec
        .tools
        .iter()
        .map(|tool| diagnose_tool(tool, observations))
        .collect::<Vec<_>>();

    DiagnoseReport {
        site: spec.site.name.clone(),
        summary: DiagnoseSummary {
            total_observations: observations.len(),
            candidate_api_observations: observations
                .iter()
                .filter(|obs| is_candidate_api_observation(obs))
                .count(),
            generated_tools: spec.tools.len(),
            observations_with_response_bodies: observations
                .iter()
                .filter(|obs| obs.response_body.is_some())
                .count(),
            json_responses: observations
                .iter()
                .filter(|obs| signal::is_json_response(obs))
                .count(),
            graphql_requests: observations
                .iter()
                .filter(|obs| !graphql_operations_cli(obs).is_empty())
                .count(),
            graphql_responses_mapped: observations
                .iter()
                .filter(|obs| graphql_response_mapped_cli(obs))
                .count(),
            tools_missing_examples: tools
                .iter()
                .filter(|tool| !tool.example_response_present)
                .count(),
            tools_with_empty_response_schemas: tools
                .iter()
                .filter(|tool| tool.response_schema_empty)
                .count(),
            static_resource_tools: tools
                .iter()
                .filter(|tool| is_static_resource_kind_label(&tool.resource_kind))
                .count(),
            platform_resource_tools: tools
                .iter()
                .filter(|tool| tool.resource_kind == "platform_resource")
                .count(),
            telemetry_tools: tools
                .iter()
                .filter(|tool| tool.resource_kind == "telemetry")
                .count(),
            commerce_api_tools: tools
                .iter()
                .filter(|tool| tool.resource_kind == "commerce_api")
                .count(),
        },
        filtered_counts,
        tools,
    }
}

pub(crate) fn diagnose_tool(
    tool: &tapestry_core::ToolDefinition,
    observations: &[tapestry_core::Observation],
) -> ToolDiagnostics {
    let related = observations
        .iter()
        .filter(|obs| observation_matches_tool(obs, tool))
        .collect::<Vec<_>>();
    let has_request_body = related.iter().any(|obs| obs.request_body.is_some());
    let has_response_body = related.iter().any(|obs| obs.response_body.is_some());
    let response_schema_empty = !schema_present(&tool.response_schema);
    let example_response_present = tool.example_response.is_some();
    let (problem, remediation) = remediation_for_tool(
        tool,
        !related.is_empty(),
        has_response_body,
        example_response_present,
        response_schema_empty,
    );

    ToolDiagnostics {
        name: tool.name.clone(),
        method: tool.method.clone(),
        path: tool.path.clone(),
        resource_kind: resource_kind_label(&tool.resource_kind).to_string(),
        has_request_body,
        has_response_body,
        example_response_present,
        response_schema_empty,
        warnings: tool.warnings.clone(),
        problem,
        remediation,
    }
}

pub(crate) fn remediation_for_tool(
    tool: &tapestry_core::ToolDefinition,
    request_observed: bool,
    has_response_body: bool,
    example_response_present: bool,
    response_schema_empty: bool,
) -> (Option<String>, String) {
    if !request_observed {
        return (
            Some("tool has no matching persisted observation".to_string()),
            "Re-run import/generate from the same HAR, or inspect whether the ToolSpec is stale."
                .to_string(),
        );
    }
    if !has_response_body {
        return (
            Some("request observed, but no response body captured".to_string()),
            "Re-capture with Preserve log enabled and ensure response bodies are included in the HAR export.".to_string(),
        );
    }
    if !example_response_present {
        return (
            Some("response body exists, but no example response was captured for this tool".to_string()),
            "Inspect GraphQL batch ordering or response mapping; re-capture the specific operation if needed.".to_string(),
        );
    }
    if response_schema_empty {
        return (
            Some("example response exists, but response schema is empty or weak".to_string()),
            "Improve schema inference for this response shape or capture a response with non-empty data.".to_string(),
        );
    }
    if tool
        .warnings
        .iter()
        .any(|warning| warning == "graphql_response_unmapped")
    {
        return (
            Some("GraphQL response could not be mapped to the operation".to_string()),
            "Capture a HAR with complete batched GraphQL responses so request/response ordering is preserved.".to_string(),
        );
    }
    (
        None,
        "Capture appears sufficient for this tool; remaining quality issues are likely analyzer scoring or schema precision.".to_string(),
    )
}

pub(crate) fn format_diagnose_text(report: &DiagnoseReport) -> String {
    let s = &report.summary;
    let f = &report.filtered_counts;
    let mut out = vec![
        format!("Site: {}", report.site),
        format!("Observations: {}", s.total_observations),
        format!("Candidate API observations: {}", s.candidate_api_observations),
        format!("Generated tools: {}", s.generated_tools),
        format!("Observations with response bodies: {}", s.observations_with_response_bodies),
        format!("JSON responses: {}", s.json_responses),
        format!("GraphQL requests: {}", s.graphql_requests),
        format!("GraphQL responses mapped: {}", s.graphql_responses_mapped),
        format!("Tools missing examples: {}", s.tools_missing_examples),
        format!("Tools with empty response schemas: {}", s.tools_with_empty_response_schemas),
        format!("Static JSON/resource tools: {}", s.static_resource_tools),
        format!("Platform resource tools: {}", s.platform_resource_tools),
        format!("Telemetry tools: {}", s.telemetry_tools),
        format!("Commerce API tools: {}", s.commerce_api_tools),
        format!(
            "Filtered signals: static={}, consent/config={}, bot/security={}, third-party-non-api={}, html-fragments={}",
            f.static_assets, f.consent_or_config, f.bot_or_security, f.third_party_non_api, f.html_fragments
        ),
        String::new(),
    ];
    if f.html_fragments > 0 {
        out.push(format!(
            "{} request(s) fetched server-rendered HTML fragments instead of JSON.",
            f.html_fragments
        ));
        out.push(
            "Tapestry cannot turn HTML fragment endpoints into tools yet (see docs/LIMITATIONS.md)."
                .to_string(),
        );
        out.push(
            "If this site's listing/search flow uses them, the main workflow will not produce tools."
                .to_string(),
        );
        out.push(String::new());
    }
    if s.generated_tools > 0 && s.generated_tools == s.static_resource_tools {
        out.push("Only static JSON/config/localization resources were captured.".to_string());
        out.push("Try interacting with app features that trigger account, save, search, or data API calls.".to_string());
        out.push(String::new());
    }
    if s.commerce_api_tools > 0 && s.tools_missing_examples > 0 {
        out.push(
            "Commerce API requests were captured, but many response bodies are missing."
                .to_string(),
        );
        out.push(
            "Re-capture with response bodies enabled and perform product search/cart actions again."
                .to_string(),
        );
        out.push(String::new());
    }
    if s.platform_resource_tools > 0 && s.platform_resource_tools >= s.commerce_api_tools.max(1) {
        out.push(
            "Many Wix platform/config resources were captured. These are deprioritized for agent use."
                .to_string(),
        );
        out.push(String::new());
    }

    out.push("Tools:".to_string());
    for tool in &report.tools {
        out.push(format!("{}:", tool.name));
        out.push(format!("  Endpoint: {} {}", tool.method, tool.path));
        out.push(format!("  Resource kind: {}", tool.resource_kind));
        out.push(format!("  Has request body: {}", tool.has_request_body));
        out.push(format!("  Has response body: {}", tool.has_response_body));
        out.push(format!(
            "  Example response present: {}",
            tool.example_response_present
        ));
        out.push(format!(
            "  Response schema empty: {}",
            tool.response_schema_empty
        ));
        out.push(format!(
            "  Warnings: {}",
            if tool.warnings.is_empty() {
                "none".to_string()
            } else {
                tool.warnings.join(", ")
            }
        ));
        if let Some(problem) = &tool.problem {
            out.push(format!("  Problem: {problem}."));
        }
        out.push(format!("  Try: {}", tool.remediation));
    }

    out.join("\n")
}

pub(crate) fn filtered_counts(observations: &[tapestry_core::Observation]) -> FilteredCounts {
    let primary = signal::infer_primary_host(observations);
    FilteredCounts {
        static_assets: observations
            .iter()
            .filter(|obs| signal::is_static_asset_path(&obs.path))
            .count(),
        consent_or_config: observations
            .iter()
            .filter(|obs| signal::is_consent_or_config_asset(obs))
            .count(),
        bot_or_security: observations
            .iter()
            .filter(|obs| signal::is_bot_or_security_telemetry(obs))
            .count(),
        third_party_non_api: observations
            .iter()
            .filter(|obs| {
                primary
                    .as_deref()
                    .zip(signal::host_for(&obs.url).as_deref())
                    .map(|(primary, host)| {
                        host != primary
                            && !signal::has_json_signal(obs)
                            && !signal::is_api_path(&obs.path)
                    })
                    .unwrap_or(false)
            })
            .count(),
        html_fragments: observations
            .iter()
            .filter(|obs| obs.is_html_fragment())
            .count(),
    }
}

pub(crate) fn is_candidate_api_observation(obs: &tapestry_core::Observation) -> bool {
    signal::is_candidate_api_observation(obs)
}

pub(crate) fn observation_matches_tool(
    obs: &tapestry_core::Observation,
    tool: &tapestry_core::ToolDefinition,
) -> bool {
    if obs.method != tool.method {
        return false;
    }
    if let Some(graphql) = &tool.graphql {
        return graphql_operations_cli(obs).iter().any(|operation| {
            operation.operation_name.as_deref() == graphql.operation_name.as_deref()
        });
    }
    normalize_tool_path_match(&obs.path, &tool.path)
}

pub(crate) fn normalize_tool_path_match(path: &str, template: &str) -> bool {
    if path == template {
        return true;
    }
    let left = path.trim_matches('/').split('/').collect::<Vec<_>>();
    let right = template.trim_matches('/').split('/').collect::<Vec<_>>();
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(segment, template)| template.starts_with('{') || segment == template)
}

#[derive(Clone)]
pub(crate) struct GraphqlOperationCli {
    pub(crate) operation_name: Option<String>,
}

pub(crate) fn graphql_operations_cli(obs: &tapestry_core::Observation) -> Vec<GraphqlOperationCli> {
    if obs.method != "POST" {
        return Vec::new();
    }
    match obs.request_body.as_ref() {
        Some(Value::Object(map)) => graphql_operation_cli(map).into_iter().collect(),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_object())
            .filter_map(graphql_operation_cli)
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn graphql_operation_cli(map: &Map<String, Value>) -> Option<GraphqlOperationCli> {
    let has_graphql = map.contains_key("operationName")
        || map.contains_key("query")
        || map.contains_key("variables");
    has_graphql.then(|| GraphqlOperationCli {
        operation_name: map
            .get("operationName")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

pub(crate) fn graphql_response_mapped_cli(obs: &tapestry_core::Observation) -> bool {
    let operations = graphql_operations_cli(obs);
    if operations.is_empty() {
        return false;
    }
    let Some(response) = &obs.response_body else {
        return false;
    };
    match response {
        Value::Array(items) => operations
            .iter()
            .enumerate()
            .any(|(idx, _)| items.get(idx).and_then(|item| item.get("data")).is_some()),
        Value::Object(map) => map.get("data").is_some(),
        _ => false,
    }
}

pub(crate) fn contains_any_cli(text: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|phrase| text.contains(phrase))
}
