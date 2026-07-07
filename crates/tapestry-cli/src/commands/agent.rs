//! `tapestry agent-task` — the deterministic agent loop: search-rank
//! candidate tools for a natural-language task, plan call arguments from
//! observed evidence, execute, and summarize the result the way a real
//! MCP-driven agent would.

use crate::commands::diagnose::contains_any_cli;
use crate::commands::review::{
    is_static_resource_kind, resource_kind_label, review_tool, schema_present,
    usefulness_grade_value,
};
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

pub(crate) fn run_agent_task(
    spec: &tapestry_core::ToolSpec,
    observations: &[tapestry_core::Observation],
    task: &str,
    trace: bool,
    options: &tapestry_runtime::RuntimeOptions,
) -> String {
    let mut out = Vec::new();
    if trace {
        out.push(format!("[agent] search_tools query=\"{task}\""));
        out.push(format!(
            "[agent] intent={}",
            tapestry_runtime::classify_task_intent(task).as_str()
        ));
        out.push(format!(
            "[agent] execution_mode={}",
            agent_execution_mode(options)
        ));
    }

    let candidates = select_agent_candidates(spec, observations, task, options);
    if candidates.is_empty() {
        out.push("No matching tool found. Try a task that mentions an observed endpoint or import a richer HAR.".to_string());
        return out.join("\n");
    }

    // Try candidates in rank order; retry on recoverable tool-selection failures
    let mut tried: Vec<String> = Vec::new();
    let mut final_response: Option<Value> = None;

    for selection in &candidates {
        if tried.contains(&selection.result.id) {
            continue;
        }
        tried.push(selection.result.id.clone());

        if trace {
            out.extend(selection.ranking_notes.iter().cloned());
            out.push(format!(
                "[agent] selected tool={} score={}",
                selection.result.name, selection.result.score
            ));
            out.push("[agent] schema loaded".to_string());
            out.push(format!("[agent] arguments={}", selection.plan.arguments));
            for provenance in &selection.plan.provenance {
                out.push(format!(
                    "[agent] arg {} inferred from {}",
                    provenance.name, provenance.source
                ));
            }
        }

        if selection.result.safety == tapestry_core::SafetyClassification::Read
            && !selection.plan.missing.is_empty()
        {
            out.push(format_missing_argument_guidance(spec, selection));
            return out.join("\n");
        }

        let response = tapestry_runtime::call_tool_with_options(
            spec,
            &selection.result.id,
            selection.plan.arguments.clone(),
            options,
        );

        if response.get("status").and_then(Value::as_str) == Some("success") {
            if trace {
                out.push("[agent] call_tool success".to_string());
            }
            final_response = Some(response);
            break;
        }

        let error_type = response
            .get("error_type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");

        if trace {
            out.push(format!("[agent] call_tool error={error_type}"));
        }

        // Auth failures and approval gates affect all tools — stop immediately
        if matches!(error_type, "auth_expired" | "approval_required") {
            final_response = Some(response);
            break;
        }

        // endpoint_error (wrong tool, 404, 5xx) or schema_mismatch — try next candidate
        if tried.len() < 3 && candidates.len() > tried.len() {
            if trace {
                out.push(format!(
                    "[agent] retrying with next ranked tool (attempt {})",
                    tried.len() + 1
                ));
            }
            final_response = Some(response);
            continue;
        }

        final_response = Some(response);
        break;
    }

    let response = final_response.unwrap_or_else(|| {
        serde_json::json!({"status":"error","error_type":"no_tool_succeeded","message":"All ranked tools failed"})
    });

    if response.get("status").and_then(Value::as_str) == Some("success") {
        out.push(summarize_success(
            candidates
                .iter()
                .find(|s| tried.last() == Some(&s.result.id))
                .map(|s| s.result.name.as_str())
                .unwrap_or("tool"),
            &response,
        ));
    } else {
        out.push(summarize_error(&response));
    }

    out.join("\n")
}

#[derive(Clone)]
pub(crate) struct RankingScore {
    pub(crate) score: i32,
    pub(crate) notes: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct AgentToolSelection {
    pub(crate) result: tapestry_runtime::SearchResult,
    pub(crate) plan: ArgumentPlan,
    pub(crate) replayable: bool,
    pub(crate) intent: tapestry_runtime::TaskIntent,
    pub(crate) ranking_notes: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct ArgumentPlan {
    pub(crate) arguments: Value,
    pub(crate) provenance: Vec<ArgumentProvenance>,
    pub(crate) missing: Vec<MissingArgument>,
}

#[derive(Clone)]
pub(crate) struct ArgumentProvenance {
    pub(crate) name: String,
    pub(crate) source: &'static str,
}

#[derive(Clone)]
pub(crate) struct MissingArgument {
    pub(crate) name: String,
    pub(crate) type_name: String,
    pub(crate) examples: Vec<String>,
    pub(crate) default_value: Option<String>,
    pub(crate) reason: String,
}

pub(crate) fn select_agent_tool(
    spec: &tapestry_core::ToolSpec,
    observations: &[tapestry_core::Observation],
    task: &str,
    options: &tapestry_runtime::RuntimeOptions,
) -> Option<AgentToolSelection> {
    select_agent_candidates(spec, observations, task, options)
        .into_iter()
        .next()
}

pub(crate) fn select_agent_candidates(
    spec: &tapestry_core::ToolSpec,
    observations: &[tapestry_core::Observation],
    task: &str,
    options: &tapestry_runtime::RuntimeOptions,
) -> Vec<AgentToolSelection> {
    let intent = tapestry_runtime::classify_task_intent(task);
    let limit = spec.tools.len().max(5);
    let mut candidates = tapestry_runtime::search_tools(spec, task, limit)
        .into_iter()
        .filter_map(|result| {
            let schema = tapestry_runtime::get_tool_schema(spec, &result.id)?;
            let tool = spec
                .tools
                .iter()
                .find(|tool| tool.id == result.id || tool.name == result.id)?;
            let plan = plan_agent_arguments(task, Some(tool), observations, &schema);
            let replayable = options.offline_har_replay && is_replayable(tool, observations);
            let ranking =
                agent_selection_score(&result, tool, &schema, &plan, replayable, intent, options);
            Some((ranking.score, result, plan, replayable, ranking.notes))
        })
        .collect::<Vec<_>>();

    candidates.sort_by(
        |(left_score, left, _, _, _), (right_score, right, _, _, _)| {
            right_score
                .cmp(left_score)
                .then_with(|| right.confidence.total_cmp(&left.confidence))
        },
    );

    candidates
        .into_iter()
        .map(
            |(_, result, plan, replayable, ranking_notes)| AgentToolSelection {
                result,
                plan,
                replayable,
                intent,
                ranking_notes,
            },
        )
        .collect()
}

pub(crate) fn agent_selection_score(
    result: &tapestry_runtime::SearchResult,
    tool: &tapestry_core::ToolDefinition,
    schema: &Value,
    plan: &ArgumentPlan,
    replayable: bool,
    intent: tapestry_runtime::TaskIntent,
    options: &tapestry_runtime::RuntimeOptions,
) -> RankingScore {
    let mut score = result.score as i32 * 3;
    let mut notes = Vec::new();
    let intent_adjustment = intent_ranking_adjustment(result, tool, intent);
    score += intent_adjustment.score;
    notes.extend(intent_adjustment.notes);
    let required_count = required_fields(schema).len() as i32;
    score -= plan.missing.len() as i32 * 30;
    if required_count > 0 && plan.missing.is_empty() {
        score += 8;
    }
    if required_count == 0 {
        score += 8;
    }
    if schema
        .get("example_response")
        .is_some_and(|value| !value.is_null())
    {
        score += 5;
    }
    if schema_present(schema.get("response_schema").unwrap_or(&Value::Null)) {
        score += 5;
    }
    if options.offline_har_replay {
        score += match usefulness_grade_value(&review_tool(tool).usefulness_grade) {
            4 => 24,
            3 => 18,
            2 => 10,
            _ => -4,
        };
        if replayable {
            score += 80;
            notes.push(format!(
                "[agent] rerank offline: {} boosted replayable",
                result.name
            ));
        } else {
            score -= 45;
            notes.push(format!(
                "[agent] rerank offline: {} penalized no_example_response",
                result.name
            ));
        }
        if tool.example_response.is_some() {
            score += 15;
        }
        if schema_present(&tool.response_schema) {
            score += 10;
        } else {
            score -= 20;
        }
        if matches!(
            tool.resource_kind,
            tapestry_core::ResourceKind::CommerceApi | tapestry_core::ResourceKind::ApiAction
        ) {
            score += 10;
        }
        if is_static_resource_kind(&tool.resource_kind) {
            score -= 35;
            notes.push(format!(
                "[agent] rerank offline: {} penalized {}",
                result.name,
                resource_kind_label(&tool.resource_kind)
            ));
        }
    }
    // Penalise framework-generated versioned paths regardless of mode
    if is_framework_path_cli(&tool.path) {
        score -= 40;
        notes.push(format!(
            "[agent] rank penalty framework_path {}",
            result.name
        ));
    }

    // Penalise low-confidence tools so high-quality tools rank above them
    if result.confidence < 0.5 {
        score -= 30;
        notes.push(format!(
            "[agent] rank penalty low_confidence {}",
            result.name
        ));
    } else if result.confidence < 0.7 {
        score -= 10;
        notes.push(format!(
            "[agent] rank penalty below_threshold_confidence {}",
            result.name
        ));
    }

    RankingScore { score, notes }
}

pub(crate) fn is_framework_path_cli(path: &str) -> bool {
    path.contains("/_next/")
        || path.contains("/_nuxt/")
        || path.contains("/_app/")
        || path.contains("/_astro/")
}

pub(crate) fn intent_ranking_adjustment(
    result: &tapestry_runtime::SearchResult,
    tool: &tapestry_core::ToolDefinition,
    intent: tapestry_runtime::TaskIntent,
) -> RankingScore {
    let mut score = 0;
    let mut notes = Vec::new();
    let name = result.name.to_ascii_lowercase();
    let path = tool.path.to_ascii_lowercase();
    let description = tool.description.to_ascii_lowercase();
    let text = format!("{name} {path} {description}");
    // "list" excluded — all GET non-detail tools are named list_* by convention;
    // matching on it would give equal boosts to manifests, configs, and real list endpoints.
    let has_search_terms = contains_any_cli(
        &text,
        &[
            "search", "query", "products", "flights", "holidays", "items",
        ],
    );
    let has_write_terms = contains_any_cli(
        &text,
        &["create", "update", "delete", "remove", "cancel", "submit"],
    );
    let has_detail_terms = contains_any_cli(&text, &["detail", "details", "{id}", "by id"]);
    let has_cart_terms = contains_any_cli(
        &text,
        &[
            "cart", "basket", "checkout", "book", "booking", "pay", "purchase", "add",
        ],
    );
    let has_add_terms = contains_any_cli(&text, &["add", "create", "save", "insert", "new"]);
    let graphql_operation_type = tool
        .graphql
        .as_ref()
        .and_then(|graphql| graphql.operation_type.as_deref())
        .map(|value| value.to_ascii_lowercase());

    match intent {
        tapestry_runtime::TaskIntent::SearchOrList => {
            match tool.safety.classification {
                tapestry_core::SafetyClassification::Read => {
                    score += 24;
                    notes.push(format!(
                        "[agent] rank boost read_search_tool {}",
                        result.name
                    ));
                }
                tapestry_core::SafetyClassification::Unknown => {
                    score -= 10;
                    notes.push(format!(
                        "[agent] rank penalty unknown_safety_for_search {}",
                        result.name
                    ));
                }
                tapestry_core::SafetyClassification::Write => {
                    score -= 24;
                    notes.push(format!(
                        "[agent] rank penalty write_tool_for_search {}",
                        result.name
                    ));
                }
            }
            if matches!(graphql_operation_type.as_deref(), Some("query")) {
                score += 12;
                notes.push(format!(
                    "[agent] rank boost graphql_query_tool {}",
                    result.name
                ));
            }
            if matches!(graphql_operation_type.as_deref(), Some("mutation")) {
                score -= 18;
                notes.push(format!(
                    "[agent] rank penalty graphql_mutation_for_search {}",
                    result.name
                ));
            }
            if tool.resource_kind == tapestry_core::ResourceKind::CommerceApi {
                score += 14;
                notes.push(format!(
                    "[agent] rank boost commerce_api_search_tool {}",
                    result.name
                ));
            }
            if tool.resource_kind == tapestry_core::ResourceKind::ApiAction {
                score += 8;
                notes.push(format!(
                    "[agent] rank boost api_action_search_candidate {}",
                    result.name
                ));
            }
            if has_search_terms {
                score += 10;
                notes.push(format!(
                    "[agent] rank boost search_semantics {}",
                    result.name
                ));
            }
            if has_write_terms {
                score -= 18;
                notes.push(format!(
                    "[agent] rank penalty write_semantics_for_search {}",
                    result.name
                ));
            }
            if is_static_resource_kind(&tool.resource_kind) {
                score -= 40;
                notes.push(format!(
                    "[agent] rank penalty {}_for_search {}",
                    resource_kind_label(&tool.resource_kind),
                    result.name
                ));
            }
        }
        tapestry_runtime::TaskIntent::GetDetail => {
            match tool.safety.classification {
                tapestry_core::SafetyClassification::Read => {
                    score += 16;
                    notes.push(format!(
                        "[agent] rank boost read_detail_tool {}",
                        result.name
                    ));
                }
                tapestry_core::SafetyClassification::Unknown => {
                    score += 2;
                }
                tapestry_core::SafetyClassification::Write => {
                    score -= 10;
                    notes.push(format!(
                        "[agent] rank penalty write_tool_for_detail {}",
                        result.name
                    ));
                }
            }
            if !tool.path_params.is_empty() {
                score += 12;
                notes.push(format!(
                    "[agent] rank boost path_params_for_detail {}",
                    result.name
                ));
            }
            if has_detail_terms {
                score += 10;
                notes.push(format!(
                    "[agent] rank boost detail_semantics {}",
                    result.name
                ));
            }
        }
        tapestry_runtime::TaskIntent::CreateOrAdd => {
            match tool.safety.classification {
                tapestry_core::SafetyClassification::Write => {
                    score += 18;
                    notes.push(format!(
                        "[agent] rank boost write_create_tool {}",
                        result.name
                    ));
                }
                tapestry_core::SafetyClassification::Unknown => {
                    score += 4;
                }
                tapestry_core::SafetyClassification::Read => {
                    score -= 8;
                    notes.push(format!(
                        "[agent] rank penalty read_tool_for_create {}",
                        result.name
                    ));
                }
            }
            if tool.approved {
                score += 6;
                notes.push(format!(
                    "[agent] rank boost approved_write_tool {}",
                    result.name
                ));
            }
            if has_add_terms || has_cart_terms {
                score += 12;
                notes.push(format!(
                    "[agent] rank boost add_or_cart_semantics {}",
                    result.name
                ));
            }
            if tool.resource_kind == tapestry_core::ResourceKind::CommerceApi {
                score += 10;
                notes.push(format!(
                    "[agent] rank boost commerce_api_create_tool {}",
                    result.name
                ));
            }
        }
        tapestry_runtime::TaskIntent::UpdateOrEdit => {
            match tool.safety.classification {
                tapestry_core::SafetyClassification::Write => {
                    score += 18;
                    notes.push(format!(
                        "[agent] rank boost write_update_tool {}",
                        result.name
                    ));
                }
                tapestry_core::SafetyClassification::Unknown => {
                    score += 4;
                }
                tapestry_core::SafetyClassification::Read => {
                    score -= 8;
                    notes.push(format!(
                        "[agent] rank penalty read_tool_for_update {}",
                        result.name
                    ));
                }
            }
            if contains_any_cli(&text, &["update", "edit", "change", "modify"]) {
                score += 12;
                notes.push(format!(
                    "[agent] rank boost update_semantics {}",
                    result.name
                ));
            }
        }
        tapestry_runtime::TaskIntent::DeleteOrRemove => {
            match tool.safety.classification {
                tapestry_core::SafetyClassification::Write => {
                    score += 18;
                    notes.push(format!(
                        "[agent] rank boost write_delete_tool {}",
                        result.name
                    ));
                }
                tapestry_core::SafetyClassification::Unknown => {
                    score += 2;
                }
                tapestry_core::SafetyClassification::Read => {
                    score -= 12;
                    notes.push(format!(
                        "[agent] rank penalty read_tool_for_delete {}",
                        result.name
                    ));
                }
            }
            if contains_any_cli(&text, &["delete", "remove", "cancel"]) {
                score += 12;
                notes.push(format!(
                    "[agent] rank boost delete_semantics {}",
                    result.name
                ));
            }
        }
        tapestry_runtime::TaskIntent::CheckoutOrPurchase => {
            match tool.safety.classification {
                tapestry_core::SafetyClassification::Write => {
                    score += 16;
                    notes.push(format!(
                        "[agent] rank boost write_checkout_tool {}",
                        result.name
                    ));
                }
                tapestry_core::SafetyClassification::Unknown => {
                    score += 6;
                }
                tapestry_core::SafetyClassification::Read => {
                    score += 4;
                }
            }
            if tool.resource_kind == tapestry_core::ResourceKind::CommerceApi {
                score += 16;
                notes.push(format!(
                    "[agent] rank boost commerce_api_checkout_tool {}",
                    result.name
                ));
            }
            if has_cart_terms {
                score += 16;
                notes.push(format!(
                    "[agent] rank boost cart_or_checkout_semantics {}",
                    result.name
                ));
            }
        }
        tapestry_runtime::TaskIntent::Unknown => {}
    }

    RankingScore { score, notes }
}

pub(crate) fn is_replayable(
    tool: &tapestry_core::ToolDefinition,
    observations: &[tapestry_core::Observation],
) -> bool {
    tool.example_response.is_some() || matching_replay_observation(tool, observations).is_some()
}

pub(crate) fn matching_replay_observation<'a>(
    tool: &tapestry_core::ToolDefinition,
    observations: &'a [tapestry_core::Observation],
) -> Option<&'a tapestry_core::Observation> {
    observations
        .iter()
        .find(|obs| replayable_observation_matches_tool(tool, obs))
}

pub(crate) fn replayable_observation_matches_tool(
    tool: &tapestry_core::ToolDefinition,
    obs: &tapestry_core::Observation,
) -> bool {
    if obs.method != tool.method {
        return false;
    }
    if !path_matches_tool_path(&tool.path, &obs.path) {
        return false;
    }
    if obs.response_body.is_none() {
        return false;
    }

    if let Some(graphql) = &tool.graphql {
        return graphql_observation_matches(graphql, obs);
    }

    required_input_keys(&tool.input_schema)
        .into_iter()
        .all(|key| {
            obs.query.contains_key(&key)
                || request_body_contains_key(obs.request_body.as_ref(), &key)
                || tool.path.contains(&format!("{{{key}}}"))
        })
}

pub(crate) fn graphql_observation_matches(
    graphql: &tapestry_core::GraphqlInfo,
    obs: &tapestry_core::Observation,
) -> bool {
    let Some(operation_name) = graphql.operation_name.as_deref() else {
        return true;
    };

    match obs.request_body.as_ref() {
        Some(Value::Object(body)) => body
            .get("operationName")
            .and_then(Value::as_str)
            .map(|value| value == operation_name)
            .unwrap_or(false),
        Some(Value::Array(items)) => items.iter().any(|item| {
            matches!(
                item,
                Value::Object(body)
                    if body
                        .get("operationName")
                        .and_then(Value::as_str)
                        .map(|value| value == operation_name)
                        .unwrap_or(false)
            )
        }),
        _ => false,
    }
}

pub(crate) fn request_body_contains_key(body: Option<&Value>, key: &str) -> bool {
    match body {
        Some(Value::Object(map)) => {
            map.contains_key(key)
                || map
                    .get("variables")
                    .and_then(Value::as_object)
                    .is_some_and(|vars| vars.contains_key(key))
        }
        Some(Value::Array(items)) => items
            .iter()
            .any(|item| request_body_contains_key(Some(item), key)),
        _ => false,
    }
}

pub(crate) fn required_input_keys(schema: &Value) -> Vec<String> {
    schema
        .get("input_schema")
        .and_then(|input| input.get("required"))
        .and_then(Value::as_array)
        .map(|required| {
            required
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn path_matches_tool_path(tool_path: &str, obs_path: &str) -> bool {
    let tool_segments = tool_path.trim_matches('/').split('/').collect::<Vec<_>>();
    let obs_segments = obs_path.trim_matches('/').split('/').collect::<Vec<_>>();
    if tool_segments.len() != obs_segments.len() {
        return false;
    }

    tool_segments
        .iter()
        .zip(obs_segments.iter())
        .all(|(tool_segment, obs_segment)| {
            if tool_segment.starts_with('{') && tool_segment.ends_with('}') {
                !obs_segment.is_empty()
            } else {
                tool_segment.eq_ignore_ascii_case(obs_segment)
            }
        })
}

pub(crate) fn plan_agent_arguments(
    task: &str,
    tool: Option<&tapestry_core::ToolDefinition>,
    observations: &[tapestry_core::Observation],
    schema: &Value,
) -> ArgumentPlan {
    let mut args = Map::new();
    let mut provenance = Vec::new();
    let Some(properties) = schema
        .get("input_schema")
        .and_then(|input| input.get("properties"))
        .and_then(Value::as_object)
    else {
        return ArgumentPlan {
            arguments: Value::Object(args),
            provenance,
            missing: Vec::new(),
        };
    };

    let task_lower = task.to_ascii_lowercase();
    for (name, schema) in properties {
        if let Some((value, source)) = example_input_planned_value(tool, name) {
            insert_planned_arg(&mut args, &mut provenance, name, value, source);
            continue;
        }

        if let Some((value, source)) = observed_request_input_value(tool, observations, name) {
            insert_planned_arg(&mut args, &mut provenance, name, value, source);
            continue;
        }

        if name == "limit" {
            if let Some(limit) = first_number(&task_lower) {
                insert_planned_arg(
                    &mut args,
                    &mut provenance,
                    name,
                    json!(limit),
                    "number_from_task",
                );
                continue;
            }
        }

        if name == "page" {
            if let Some(page) = number_after_word(&task_lower, "page") {
                insert_planned_arg(
                    &mut args,
                    &mut provenance,
                    name,
                    json!(page),
                    "page_from_task",
                );
                continue;
            }
        }

        if name == "status" {
            if let Some(status) = infer_status(&task_lower, Some(schema)) {
                insert_planned_arg(
                    &mut args,
                    &mut provenance,
                    name,
                    json!(status),
                    "status_from_task",
                );
                continue;
            }
        }

        if is_search_like_arg(name) && primitive_type(schema) == "string" {
            if let Some(value) = search_term_from_task(&task_lower) {
                insert_planned_arg(
                    &mut args,
                    &mut provenance,
                    name,
                    json!(value),
                    "search_term_from_task",
                );
                continue;
            }
        }

        if let Some(value) = schema.get("default") {
            insert_planned_arg(
                &mut args,
                &mut provenance,
                name,
                value.clone(),
                "observed_default",
            );
            continue;
        }

        if let Some(value) = first_schema_example(schema) {
            insert_planned_arg(&mut args, &mut provenance, name, value, "example_value");
        }
    }

    let missing = required_fields(schema)
        .into_iter()
        .filter(|name| !args.contains_key(name.as_str()))
        .map(|name| missing_argument(&name, properties.get(&name)))
        .collect::<Vec<_>>();

    ArgumentPlan {
        arguments: Value::Object(args),
        provenance,
        missing,
    }
}

pub(crate) fn example_input_planned_value(
    tool: Option<&tapestry_core::ToolDefinition>,
    name: &str,
) -> Option<(Value, &'static str)> {
    let tool = tool?;
    let example_input = tool.example_input.as_ref()?;

    example_input
        .as_object()
        .and_then(|object| object.get(name))
        .cloned()
        .map(|value| (value, "example_input"))
}

pub(crate) fn observed_request_input_value(
    tool: Option<&tapestry_core::ToolDefinition>,
    observations: &[tapestry_core::Observation],
    name: &str,
) -> Option<(Value, &'static str)> {
    let tool = tool?;

    if let Some(graphql) = &tool.graphql {
        if let Some(operation_name) = graphql.operation_name.as_deref() {
            for obs in observations {
                if let Some(value) = observed_graphql_variable_value(obs, operation_name, name) {
                    return Some((value, "observed_graphql_variables"));
                }
            }
        }
    }

    for obs in observations {
        if let Some(value) = observed_request_body_value(obs, name) {
            return Some((value, "observed_request_body"));
        }
    }

    None
}

pub(crate) fn observed_graphql_variable_value(
    obs: &tapestry_core::Observation,
    operation_name: &str,
    name: &str,
) -> Option<Value> {
    let request_body = obs.request_body.as_ref()?;
    match request_body {
        Value::Object(map) => {
            if map
                .get("operationName")
                .and_then(Value::as_str)
                .map(|value| value == operation_name)
                .unwrap_or(false)
            {
                return map
                    .get("variables")
                    .and_then(Value::as_object)
                    .and_then(|variables| variables.get(name))
                    .cloned();
            }
            None
        }
        Value::Array(items) => items.iter().find_map(|item| {
            let Value::Object(map) = item else {
                return None;
            };
            if map
                .get("operationName")
                .and_then(Value::as_str)
                .map(|value| value == operation_name)
                .unwrap_or(false)
            {
                return map
                    .get("variables")
                    .and_then(Value::as_object)
                    .and_then(|variables| variables.get(name))
                    .cloned();
            }
            None
        }),
        _ => None,
    }
}

pub(crate) fn observed_request_body_value(
    obs: &tapestry_core::Observation,
    name: &str,
) -> Option<Value> {
    let request_body = obs.request_body.as_ref()?;
    match request_body {
        Value::Object(map) => map.get(name).cloned(),
        Value::Array(items) => items.iter().find_map(|item| {
            if let Value::Object(map) = item {
                map.get(name).cloned()
            } else {
                None
            }
        }),
        _ => None,
    }
}

pub(crate) fn insert_planned_arg(
    args: &mut Map<String, Value>,
    provenance: &mut Vec<ArgumentProvenance>,
    name: &str,
    value: Value,
    source: &'static str,
) {
    args.insert(name.to_string(), value);
    provenance.push(ArgumentProvenance {
        name: name.to_string(),
        source,
    });
}

pub(crate) fn required_fields(schema: &Value) -> Vec<String> {
    schema
        .get("input_schema")
        .and_then(|input| input.get("required"))
        .and_then(Value::as_array)
        .map(|required| {
            required
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn primitive_type(schema: &Value) -> &str {
    schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("string")
}

pub(crate) fn is_search_like_arg(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "q" | "query" | "search" | "term" | "keyword" | "filter"
    )
}

pub(crate) fn first_schema_example(schema: &Value) -> Option<Value> {
    schema
        .get("examples")
        .and_then(Value::as_array)
        .and_then(|values| values.first().cloned())
        .or_else(|| {
            schema
                .get("enum")
                .and_then(Value::as_array)
                .and_then(|values| values.first().cloned())
        })
}

pub(crate) fn missing_argument(name: &str, schema: Option<&Value>) -> MissingArgument {
    let schema = schema.unwrap_or(&Value::Null);
    MissingArgument {
        name: name.to_string(),
        type_name: primitive_type(schema).to_string(),
        examples: schema_examples(schema),
        default_value: schema.get("default").map(compact_value),
        reason: "no default/example was available and no value could be derived from the task text"
            .to_string(),
    }
}

pub(crate) fn schema_examples(schema: &Value) -> Vec<String> {
    schema
        .get("examples")
        .or_else(|| schema.get("enum"))
        .and_then(Value::as_array)
        .map(|values| values.iter().take(3).map(compact_value).collect())
        .unwrap_or_default()
}

pub(crate) fn search_term_from_task(task_lower: &str) -> Option<String> {
    let stop_words = [
        "search", "find", "list", "show", "get", "fetch", "for", "the", "a", "an", "and", "to",
        "me", "recent", "most", "latest", "products", "items", "product", "item",
    ];
    let mut tokens = task_lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    if let Some(position) = tokens.iter().position(|token| {
        matches!(
            *token,
            "q" | "query" | "search" | "term" | "keyword" | "filter"
        )
    }) {
        let nearby = tokens
            .iter()
            .skip(position + 1)
            .find(|token| !stop_words.contains(token));
        if let Some(value) = nearby {
            return Some((*value).to_string());
        }
    }

    let meaningful = tokens
        .drain(..)
        .filter(|token| !stop_words.contains(token))
        .collect::<Vec<_>>();
    if !meaningful.is_empty() {
        return Some(meaningful.join(" "));
    }

    task_lower
        .split_whitespace()
        .last()
        .map(|value| {
            value
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                .to_string()
        })
        .filter(|value| !value.is_empty())
}

pub(crate) fn format_missing_argument_guidance(
    spec: &tapestry_core::ToolSpec,
    selection: &AgentToolSelection,
) -> String {
    let Some(missing) = selection.plan.missing.first() else {
        return "Missing required argument.".to_string();
    };
    let tool = spec
        .tools
        .iter()
        .find(|tool| tool.id == selection.result.id || tool.name == selection.result.name);
    if let Some(tool) = tool {
        if tool.graphql.is_some() {
            return format!(
                "Missing required GraphQL variable: {}.\nType: {}.\nExamples/defaults: examples={}, default={}.\nReason: no captured example value was available and the GraphQL request payload did not provide it.\nTry re-capturing the workflow with request payloads included.\nOr run: tapestry tools schema {} {}",
                missing.name,
                missing.type_name,
                if missing.examples.is_empty() {
                    "none".to_string()
                } else {
                    missing.examples.join(", ")
                },
                missing.default_value.as_deref().unwrap_or("none"),
                spec.site.name,
                selection.result.name
            );
        }
    }
    let examples = if missing.examples.is_empty() {
        "none".to_string()
    } else {
        missing.examples.join(", ")
    };
    let default_value = missing.default_value.as_deref().unwrap_or("none");
    format!(
        "Missing required argument: {}.\nType: {}.\nExamples/defaults: examples={}, default={}.\nReason: {}.\nTry: tapestry agent-task {} \"Search for sofas\"\nOr run: tapestry tools schema {} {}",
        missing.name,
        missing.type_name,
        examples,
        default_value,
        missing.reason,
        spec.site.name,
        spec.site.name,
        selection.result.name
    )
}

pub(crate) fn first_number(text: &str) -> Option<i64> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| token.parse::<i64>().ok())
        .next()
}

pub(crate) fn number_after_word(text: &str, word: &str) -> Option<i64> {
    let mut previous = "";
    for token in text.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        if previous == word {
            if let Ok(value) = token.parse::<i64>() {
                return Some(value);
            }
        }
        previous = token;
    }
    None
}

pub(crate) fn infer_status(task_lower: &str, status_schema: Option<&Value>) -> Option<String> {
    if let Some(values) = status_schema
        .and_then(|schema| schema.get("enum"))
        .and_then(Value::as_array)
    {
        for value in values {
            let Some(status) = value.as_str() else {
                continue;
            };
            if task_lower.contains(&status.to_ascii_lowercase()) {
                return Some(status.to_string());
            }
        }
    }

    [
        "draft",
        "published",
        "active",
        "inactive",
        "open",
        "closed",
        "pending",
        "shipped",
    ]
    .into_iter()
    .find(|status| task_lower.contains(status))
    .map(ToOwned::to_owned)
}

pub(crate) fn summarize_success(tool_name: &str, response: &Value) -> String {
    let data = response.get("data").unwrap_or(&Value::Null);
    if let Some(items) = data.get("items").and_then(Value::as_array) {
        return summarize_items(items);
    }
    if let Some(items) = data.as_array() {
        return summarize_items(items);
    }
    if let Some(obj) = data.as_object() {
        let fields = obj
            .iter()
            .take(5)
            .map(|(key, value)| format!("{key}={}", compact_value(value)))
            .collect::<Vec<_>>()
            .join(", ");
        return format!("Summary from {tool_name}: {fields}");
    }
    format!("Summary from {tool_name}: {}", compact_value(data))
}

pub(crate) fn summarize_items(items: &[Value]) -> String {
    if items.is_empty() {
        return "Summary: no items returned.".to_string();
    }

    let previews = items
        .iter()
        .take(5)
        .map(|item| {
            item.get("title")
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| compact_value(item))
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("Summary: {} item(s) returned. {}", items.len(), previews)
}

pub(crate) fn summarize_error(response: &Value) -> String {
    let error_type = response
        .get("error_type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let message = response
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("Runtime call failed");

    match error_type {
        "approval_required" => {
            format!("{message}. Next step: approve the tool or choose a read-only task.")
        }
        "missing_required_argument" => {
            format!("{message}. Next step: include the missing value in the task.")
        }
        "auth_expired" => {
            format!("{message}. Next step: re-import the HAR or refresh credentials.")
        }
        "rate_limited" => format!("{message}. Next step: retry later or lower request volume."),
        "endpoint_error" => {
            format!("{message}. Next step: inspect get_evidence and endpoint status.")
        }
        "replay_not_found" => {
            format!("{message}. Next step: re-capture this action with response bodies included or run with --live.")
        }
        _ => format!("{message}. Error type: {error_type}."),
    }
}

pub(crate) fn compact_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn agent_execution_mode(options: &tapestry_runtime::RuntimeOptions) -> &'static str {
    if options.offline_har_replay {
        "offline_har_replay"
    } else {
        "live_http"
    }
}

pub(crate) fn parse_args(args: &str) -> Result<serde_json::Value> {
    match serde_json::from_str(args) {
        Ok(value) => Ok(value),
        Err(json_error) => parse_relaxed_object(args).with_context(|| {
            format!(
                "failed to parse --args as JSON ({json_error}); relaxed object parsing also failed"
            )
        }),
    }
}

pub(crate) fn parse_relaxed_object(args: &str) -> Result<serde_json::Value> {
    let trimmed = args.trim();
    let body = trimmed
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .context("relaxed arguments must look like {key:value}")?;
    let mut map = serde_json::Map::new();

    if body.trim().is_empty() {
        return Ok(serde_json::Value::Object(map));
    }

    for pair in body.split(',') {
        let (key, raw_value) = pair
            .split_once(':')
            .with_context(|| format!("invalid relaxed argument pair '{pair}'"))?;
        let key = key.trim().trim_matches('"').trim_matches('\'').to_string();
        let raw_value = raw_value.trim();
        let value = serde_json::from_str(raw_value).unwrap_or_else(|_| {
            serde_json::Value::String(raw_value.trim_matches('"').trim_matches('\'').to_string())
        });
        map.insert(key, value);
    }

    Ok(serde_json::Value::Object(map))
}
