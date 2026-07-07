//! `tapestry review` — grade generated tools for agent usefulness
//! (schema completeness, examples, confidence, safety) and format the
//! text/JSON report.

use crate::support::round2;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub(crate) struct ReviewReport {
    pub(crate) site: String,
    pub(crate) summary: ReviewSummary,
    pub(crate) tools: Vec<ToolReview>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReviewSummary {
    pub(crate) total_tools: usize,
    pub(crate) read_tools: usize,
    pub(crate) write_tools: usize,
    pub(crate) unknown_tools: usize,
    pub(crate) graphql_tools: usize,
    pub(crate) opaque_root_post_tools: usize,
    pub(crate) average_confidence: f64,
    pub(crate) tools_with_warnings: usize,
    pub(crate) tools_missing_response_schema: usize,
    pub(crate) tools_missing_examples: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ToolReview {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) resource_kind: String,
    pub(crate) safety: String,
    pub(crate) confidence: f64,
    pub(crate) confidence_breakdown: ConfidenceReview,
    pub(crate) warnings: Vec<String>,
    pub(crate) usefulness_grade: String,
    pub(crate) usefulness_score: i32,
    pub(crate) reasons: Vec<String>,
    pub(crate) positive_signals: Vec<String>,
    pub(crate) negative_signals: Vec<String>,
    pub(crate) missing_fields: Vec<String>,
    pub(crate) graphql: Option<GraphqlReview>,
    pub(crate) input_schema_keys: Vec<String>,
    pub(crate) response_schema_keys: Vec<String>,
    pub(crate) evidence: EvidenceReview,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConfidenceReview {
    pub(crate) overall: f64,
    pub(crate) path: f64,
    pub(crate) path_params: f64,
    pub(crate) method: f64,
    pub(crate) input_schema: f64,
    pub(crate) response_schema: f64,
    pub(crate) auth: f64,
    pub(crate) safety: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct GraphqlReview {
    pub(crate) operation_name: Option<String>,
    pub(crate) operation_type: Option<String>,
    pub(crate) batched: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceReview {
    pub(crate) count: usize,
    pub(crate) details: Vec<String>,
}

pub(crate) fn review_toolspec(
    spec: &tapestry_core::ToolSpec,
    only_grade: Option<&str>,
) -> ReviewReport {
    let grade_filter = only_grade.map(|grade| grade.to_ascii_uppercase());
    let tools = spec
        .tools
        .iter()
        .map(review_tool)
        .filter(|tool| {
            grade_filter
                .as_deref()
                .map(|grade| tool.usefulness_grade == grade)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    let total_tools = tools.len();
    let read_tools = tools.iter().filter(|tool| tool.safety == "read").count();
    let write_tools = tools.iter().filter(|tool| tool.safety == "write").count();
    let unknown_tools = tools.iter().filter(|tool| tool.safety == "unknown").count();
    let average_confidence = if total_tools == 0 {
        0.0
    } else {
        tools.iter().map(|tool| tool.confidence).sum::<f64>() / total_tools as f64
    };

    ReviewReport {
        site: spec.site.name.clone(),
        summary: ReviewSummary {
            total_tools,
            read_tools,
            write_tools,
            unknown_tools,
            graphql_tools: tools.iter().filter(|tool| tool.graphql.is_some()).count(),
            opaque_root_post_tools: tools
                .iter()
                .filter(|tool| {
                    tool.name == "opaque_root_post"
                        || tool
                            .warnings
                            .iter()
                            .any(|warning| warning == "opaque_root_post")
                })
                .count(),
            average_confidence: round2(average_confidence),
            tools_with_warnings: tools
                .iter()
                .filter(|tool| !tool.warnings.is_empty())
                .count(),
            tools_missing_response_schema: tools
                .iter()
                .filter(|tool| {
                    tool.missing_fields
                        .iter()
                        .any(|field| field == "response_schema")
                })
                .count(),
            tools_missing_examples: tools
                .iter()
                .filter(|tool| {
                    tool.missing_fields
                        .iter()
                        .any(|field| field == "example_response")
                })
                .count(),
        },
        tools,
    }
}

pub(crate) fn review_tool(tool: &tapestry_core::ToolDefinition) -> ToolReview {
    let (score, positive_signals, negative_signals, missing_fields) = usefulness_score(tool);
    let usefulness_grade = usefulness_grade(score).to_string();
    let reasons = positive_signals
        .iter()
        .chain(negative_signals.iter())
        .chain(missing_fields.iter())
        .cloned()
        .collect();
    ToolReview {
        id: tool.id.clone(),
        name: tool.name.clone(),
        method: tool.method.clone(),
        path: tool.path.clone(),
        resource_kind: resource_kind_label(&tool.resource_kind).to_string(),
        safety: format!("{:?}", tool.safety.classification).to_ascii_lowercase(),
        confidence: round2(tool.confidence.overall),
        confidence_breakdown: ConfidenceReview {
            overall: round2(tool.confidence.overall),
            path: round2(tool.confidence.path),
            path_params: round2(tool.confidence.path_params),
            method: round2(tool.confidence.method),
            input_schema: round2(tool.confidence.input_schema),
            response_schema: round2(tool.confidence.response_schema),
            auth: round2(tool.confidence.auth),
            safety: round2(tool.confidence.safety),
        },
        warnings: tool.warnings.clone(),
        usefulness_grade,
        usefulness_score: score,
        reasons,
        positive_signals,
        negative_signals,
        missing_fields,
        graphql: tool.graphql.as_ref().map(|graphql| GraphqlReview {
            operation_name: graphql.operation_name.clone(),
            operation_type: graphql.operation_type.clone(),
            batched: graphql.batched,
        }),
        input_schema_keys: schema_keys(&tool.input_schema),
        response_schema_keys: schema_keys(&tool.response_schema),
        evidence: EvidenceReview {
            count: tool.evidence.iter().map(|evidence| evidence.count).sum(),
            details: tool
                .evidence
                .iter()
                .filter_map(|evidence| evidence.detail.clone())
                .collect(),
        },
    }
}

pub(crate) fn usefulness_score(
    tool: &tapestry_core::ToolDefinition,
) -> (i32, Vec<String>, Vec<String>, Vec<String>) {
    let mut score = 0;
    let mut positive = Vec::new();
    let mut negative = Vec::new();
    let mut missing = Vec::new();

    if meaningful_name(&tool.name) {
        score += 18;
        positive.push("Meaningful tool name".to_string());
    }
    if tool
        .graphql
        .as_ref()
        .and_then(|graphql| graphql.operation_name.as_deref())
        .is_some()
    {
        score += 16;
        positive.push("GraphQL operation detected".to_string());
    }
    if schema_present(&tool.input_schema) {
        score += 12;
        positive.push("Input schema inferred".to_string());
    } else {
        missing.push("input_schema".to_string());
    }
    if schema_present(&tool.response_schema) {
        score += 14;
        positive.push("Response schema inferred".to_string());
    } else {
        score -= 16;
        missing.push("response_schema".to_string());
        negative.push("Response schema weak or empty".to_string());
    }
    if tool.example_response.is_some() {
        score += 10;
        positive.push("Example response captured".to_string());
    } else {
        score -= 8;
        missing.push("example_response".to_string());
        negative.push("Missing example response".to_string());
    }
    if tool.safety.classification == tapestry_core::SafetyClassification::Read || tool.approved {
        score += 14;
        positive.push("Read-safe query or approved tool".to_string());
    }
    if tool.confidence.overall >= 0.80 {
        score += 14;
        positive.push("High overall confidence".to_string());
    } else if tool.confidence.overall < 0.50 {
        score -= 18;
        negative.push("Low overall confidence".to_string());
    }

    if tool.safety.classification == tapestry_core::SafetyClassification::Unknown {
        score -= 18;
        negative.push("Unknown safety classification".to_string());
    }
    match tool.resource_kind {
        tapestry_core::ResourceKind::LocalizationResource => {
            score -= 35;
            negative.push("Static localization JSON; not likely an agent action".to_string());
        }
        tapestry_core::ResourceKind::ConfigResource => {
            score -= 30;
            negative.push("Static config JSON; not likely an agent action".to_string());
        }
        tapestry_core::ResourceKind::StaticJsonResource => {
            score -= 25;
            negative.push("Static JSON resource; not likely an agent action".to_string());
        }
        tapestry_core::ResourceKind::Telemetry => {
            score -= 35;
            negative.push("Telemetry resource; not likely an agent action".to_string());
        }
        tapestry_core::ResourceKind::PlatformResource => {
            score -= 35;
            negative.push("Wix platform/config resource; not likely an agent action".to_string());
        }
        tapestry_core::ResourceKind::CommerceApi => {
            score += 18;
            positive.push("Commerce API detected".to_string());
        }
        tapestry_core::ResourceKind::ApiAction | tapestry_core::ResourceKind::Unknown => {}
    }
    for warning in &tool.warnings {
        match warning.as_str() {
            "opaque_root_post" => {
                score -= 18;
                negative.push("Opaque root POST".to_string());
            }
            "operation_name_missing" => {
                score -= 10;
                negative.push("Operation name missing".to_string());
            }
            "low_semantic_confidence" => {
                score -= 14;
                negative.push("Low semantic confidence".to_string());
            }
            _ => {
                score -= 3;
                negative.push(format!("Warning: {warning}"));
            }
        }
    }

    if tool.graphql.is_some()
        && tool.safety.classification == tapestry_core::SafetyClassification::Read
        && schema_present(&tool.input_schema)
        && !is_opaque_tool(tool)
    {
        score = score.max(30);
    }

    (score.clamp(0, 100), positive, negative, missing)
}

pub(crate) fn usefulness_grade(score: i32) -> &'static str {
    match score {
        80..=100 => "A",
        60..=79 => "B",
        25..=59 => "C",
        _ => "D",
    }
}

pub(crate) fn usefulness_grade_value(grade: &str) -> i32 {
    match grade {
        "A" => 4,
        "B" => 3,
        "C" => 2,
        _ => 1,
    }
}

pub(crate) fn format_review_text(report: &ReviewReport, verbose: bool) -> String {
    let summary = &report.summary;
    let mut out = vec![
        format!("Site: {}", report.site),
        format!("Tools: {} total", summary.total_tools),
        format!(
            "Safety: {} read, {} write, {} unknown",
            summary.read_tools, summary.write_tools, summary.unknown_tools
        ),
        format!("GraphQL: {}", summary.graphql_tools),
        format!("Opaque root POST: {}", summary.opaque_root_post_tools),
        format!("Average confidence: {:.2}", summary.average_confidence),
        format!(
            "Warnings: {} tool(s) have warnings",
            summary.tools_with_warnings
        ),
        format!(
            "Missing response schema: {}",
            summary.tools_missing_response_schema
        ),
        format!("Missing examples: {}", summary.tools_missing_examples),
        String::new(),
        "Tools:".to_string(),
    ];

    for tool in &report.tools {
        let warnings = if tool.warnings.is_empty() {
            "none".to_string()
        } else {
            tool.warnings
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push(format!("- {}  {}", tool.name, tool.usefulness_grade));
        out.push(format!(
            "  {} {} resource_kind={} safety={} confidence={:.2} warnings={}",
            tool.method, tool.path, tool.resource_kind, tool.safety, tool.confidence, warnings
        ));
        for signal in &tool.positive_signals {
            out.push(format!("  + {signal}"));
        }
        for signal in &tool.negative_signals {
            out.push(format!("  - {signal}"));
        }
        for field in &tool.missing_fields {
            out.push(format!("  - Missing {field}"));
        }
        out.push(format!(
            "  Confidence: overall={:.2}, input={:.2}, response={:.2}, path={:.2}, safety={:.2}",
            tool.confidence_breakdown.overall,
            tool.confidence_breakdown.input_schema,
            tool.confidence_breakdown.response_schema,
            tool.confidence_breakdown.path,
            tool.confidence_breakdown.safety
        ));
        if verbose {
            if let Some(graphql) = &tool.graphql {
                out.push(format!(
                    "  GraphQL: operation={} type={} batched={}",
                    graphql.operation_name.as_deref().unwrap_or("unknown"),
                    graphql.operation_type.as_deref().unwrap_or("unknown"),
                    graphql.batched
                ));
            }
            out.push(format!(
                "  Input keys: {}",
                list_or_none(&tool.input_schema_keys)
            ));
            out.push(format!(
                "  Response keys: {}",
                list_or_none(&tool.response_schema_keys)
            ));
            out.push(format!("  Evidence count: {}", tool.evidence.count));
            if !tool.evidence.details.is_empty() {
                out.push(format!(
                    "  Evidence details: {}",
                    tool.evidence.details.join(" | ")
                ));
            }
        }
    }

    out.join("\n")
}

pub(crate) fn meaningful_name(name: &str) -> bool {
    !matches!(
        name,
        "tool"
            | "create_tool"
            | "call_tool"
            | "graphql_request"
            | "batched_graphql_request"
            | "opaque_root_post"
    ) && name.len() >= 4
}

pub(crate) fn is_opaque_tool(tool: &tapestry_core::ToolDefinition) -> bool {
    tool.name == "opaque_root_post"
        || tool
            .warnings
            .iter()
            .any(|warning| warning == "opaque_root_post")
}

pub(crate) fn resource_kind_label(kind: &tapestry_core::ResourceKind) -> &'static str {
    match kind {
        tapestry_core::ResourceKind::ApiAction => "api_action",
        tapestry_core::ResourceKind::StaticJsonResource => "static_json_resource",
        tapestry_core::ResourceKind::ConfigResource => "config_resource",
        tapestry_core::ResourceKind::LocalizationResource => "localization_resource",
        tapestry_core::ResourceKind::Telemetry => "telemetry",
        tapestry_core::ResourceKind::PlatformResource => "platform_resource",
        tapestry_core::ResourceKind::CommerceApi => "commerce_api",
        tapestry_core::ResourceKind::Unknown => "unknown",
    }
}

pub(crate) fn is_static_resource_kind(kind: &tapestry_core::ResourceKind) -> bool {
    matches!(
        kind,
        tapestry_core::ResourceKind::StaticJsonResource
            | tapestry_core::ResourceKind::ConfigResource
            | tapestry_core::ResourceKind::LocalizationResource
            | tapestry_core::ResourceKind::PlatformResource
    )
}

pub(crate) fn is_static_resource_kind_label(label: &str) -> bool {
    matches!(
        label,
        "static_json_resource" | "config_resource" | "localization_resource" | "platform_resource"
    )
}

pub(crate) fn schema_present(schema: &Value) -> bool {
    let Some(schema_type) = schema.get("type").and_then(Value::as_str) else {
        return false;
    };
    match schema_type {
        "object" => schema
            .get("properties")
            .and_then(Value::as_object)
            .map(|properties| !properties.is_empty())
            .unwrap_or(false),
        "array" => true,
        _ => true,
    }
}

pub(crate) fn schema_keys(schema: &Value) -> Vec<String> {
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        return properties.keys().cloned().collect();
    }

    schema
        .get("items")
        .map(schema_keys)
        .map(|keys| keys.into_iter().map(|key| format!("items.{key}")).collect())
        .unwrap_or_default()
}

pub(crate) fn list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}
