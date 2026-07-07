//! `tapestry validate` — run one agent task end-to-end against a site and
//! combine the result with review/diagnose summaries into a single
//! recommended next action.
//!
//! NOTE: still depends on agent-selection types/functions (AgentToolSelection,
//! select_agent_tool, format_missing_argument_guidance, summarize_success,
//! summarize_error) that live in main.rs until the agent-task command is
//! extracted in a later commit; `use crate::*` bridges that temporarily.

use crate::commands::diagnose::diagnose_site;
use crate::commands::review::review_toolspec;
use crate::*;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub(crate) struct ValidateReport {
    pub(crate) site: String,
    pub(crate) agent_task: AgentValidation,
    pub(crate) review_summary: ReviewSummary,
    pub(crate) diagnose_summary: DiagnoseSummary,
    pub(crate) recommended_next_action: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentValidation {
    pub(crate) task: String,
    pub(crate) success: bool,
    pub(crate) top_tool_used: Option<String>,
    pub(crate) top_tool_id: Option<String>,
    pub(crate) top_tool_score: Option<usize>,
    pub(crate) ranking_note: Option<String>,
    pub(crate) failure_type: Option<String>,
    pub(crate) result: String,
}

pub(crate) fn validate_site(
    spec: &tapestry_core::ToolSpec,
    observations: &[tapestry_core::Observation],
    task: &str,
    options: &tapestry_runtime::RuntimeOptions,
) -> ValidateReport {
    let agent_task = run_agent_validation(spec, observations, task, options);
    let review = review_toolspec(spec, None);
    let diagnose = diagnose_site(spec, observations);
    let recommended_next_action = recommended_next_action(&agent_task, &review, &diagnose);

    ValidateReport {
        site: spec.site.name.clone(),
        agent_task,
        review_summary: review.summary,
        diagnose_summary: diagnose.summary,
        recommended_next_action,
    }
}
pub(crate) fn run_agent_validation(
    spec: &tapestry_core::ToolSpec,
    observations: &[tapestry_core::Observation],
    task: &str,
    options: &tapestry_runtime::RuntimeOptions,
) -> AgentValidation {
    let ranking_note = |selection: &AgentToolSelection| {
        let mut notes = vec![format!("Intent: {}", selection.intent.as_str())];
        notes.extend(selection.ranking_notes.iter().cloned());
        if options.offline_har_replay {
            notes.push(format!(
                "Offline ranking considered replayability. Selected replayable tool: {}.",
                selection.result.name
            ));
        }
        Some(notes.join(" "))
    };

    let Some(selection) = select_agent_tool(spec, observations, task, options) else {
        return AgentValidation {
            task: task.to_string(),
            success: false,
            top_tool_used: None,
            top_tool_id: None,
            top_tool_score: None,
            ranking_note: if options.offline_har_replay {
                Some(
                    "Offline ranking considered replayability. No replayable tool matched task."
                        .to_string(),
                )
            } else {
                None
            },
            failure_type: Some("no_matching_tool".to_string()),
            result: "No matching tool found. Try a task that mentions an observed endpoint or import a richer HAR.".to_string(),
        };
    };

    if options.offline_har_replay && !selection.replayable {
        return AgentValidation {
            task: task.to_string(),
            success: false,
            top_tool_used: Some(selection.result.name.clone()),
            top_tool_id: Some(selection.result.id.clone()),
            top_tool_score: Some(selection.result.score),
            ranking_note: Some(format!(
                "Offline ranking considered replayability. No replayable tool matched task. Selected lexical fallback: {}.",
                selection.result.name
            )),
            failure_type: Some("no_replayable_tool".to_string()),
            result: "No replayable tool matched this task in offline mode. Re-capture the action with response bodies or try a more direct replayable endpoint.".to_string(),
        };
    }

    if selection.result.safety == tapestry_core::SafetyClassification::Read
        && !selection.plan.missing.is_empty()
    {
        return AgentValidation {
            task: task.to_string(),
            success: false,
            top_tool_used: Some(selection.result.name.clone()),
            top_tool_id: Some(selection.result.id.clone()),
            top_tool_score: Some(selection.result.score),
            ranking_note: ranking_note(&selection),
            failure_type: Some("missing_required_argument".to_string()),
            result: format_missing_argument_guidance(spec, &selection),
        };
    }

    let selection_ranking_note = ranking_note(&selection);
    let response = tapestry_runtime::call_tool_with_options(
        spec,
        &selection.result.id,
        selection.plan.arguments,
        options,
    );
    if response.get("status").and_then(Value::as_str) == Some("success") {
        return AgentValidation {
            task: task.to_string(),
            success: true,
            top_tool_used: Some(selection.result.name.clone()),
            top_tool_id: Some(selection.result.id.clone()),
            top_tool_score: Some(selection.result.score),
            ranking_note: selection_ranking_note.clone(),
            failure_type: None,
            result: if let Some(note) = selection_ranking_note {
                format!(
                    "{note} {}",
                    summarize_success(&selection.result.name, &response)
                )
            } else {
                summarize_success(&selection.result.name, &response)
            },
        };
    }

    AgentValidation {
        task: task.to_string(),
        success: false,
        top_tool_used: Some(selection.result.name),
        top_tool_id: Some(selection.result.id),
        top_tool_score: Some(selection.result.score),
        ranking_note: selection_ranking_note,
        failure_type: response
            .get("error_type")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| Some("unknown".to_string())),
        result: summarize_error(&response),
    }
}

pub(crate) fn recommended_next_action(
    agent: &AgentValidation,
    review: &ReviewReport,
    diagnose: &DiagnoseReport,
) -> String {
    if diagnose.summary.generated_tools == 0
        || agent.failure_type.as_deref() == Some("no_matching_tool")
    {
        return "Capture a richer task flow that performs real search/list/detail actions, then regenerate tools.".to_string();
    }
    if diagnose.summary.observations_with_response_bodies == 0
        || diagnose.summary.tools_missing_examples > 0
    {
        return "Re-capture the HAR with Preserve log enabled and response bodies included, then run import/generate again.".to_string();
    }
    if matches!(
        agent.failure_type.as_deref(),
        Some("approval_required") | Some("auth_expired")
    ) {
        return "Inspect runtime safety/auth details; use approved read tools or configure a live authenticated runtime before retrying.".to_string();
    }
    if matches!(
        agent.failure_type.as_deref(),
        Some("missing_required_argument") | Some("invalid_argument_type")
    ) {
        return "Improve task-to-argument mapping or provide a validation task that includes required identifiers and filters.".to_string();
    }
    if diagnose.summary.tools_with_empty_response_schemas > 0 {
        return "Improve response capture/schema inference for weak tools before validating agent usefulness.".to_string();
    }
    if review.summary.average_confidence < 0.7 || review.summary.tools_with_warnings > 0 {
        return "Review low-confidence tools and warnings; prioritize analyzer quality before adding integrations.".to_string();
    }
    if agent.success {
        return "Validation passed. Run the same command against additional real-world HAR captures and compare reports.".to_string();
    }
    "Inspect the failure type and top tool evidence, then re-run `tapestry review` and `tapestry diagnose` for detail.".to_string()
}

pub(crate) fn format_validate_text(report: &ValidateReport) -> String {
    let agent = &report.agent_task;
    let review = &report.review_summary;
    let diagnose = &report.diagnose_summary;
    vec![
        format!("Site: {}", report.site),
        format!("Agent task: {}", agent.task),
        format!(
            "Agent result: {}",
            if agent.success { "success" } else { "fail" }
        ),
        format!(
            "Top tool used: {}",
            agent.top_tool_used.as_deref().unwrap_or("none")
        ),
        format!(
            "Ranking note: {}",
            agent.ranking_note.as_deref().unwrap_or("none")
        ),
        format!(
            "Failure type: {}",
            agent.failure_type.as_deref().unwrap_or("none")
        ),
        format!("Result: {}", agent.result),
        String::new(),
        "Review summary:".to_string(),
        format!("  Tools: {}", review.total_tools),
        format!(
            "  Safety: {} read, {} write, {} unknown",
            review.read_tools, review.write_tools, review.unknown_tools
        ),
        format!("  GraphQL tools: {}", review.graphql_tools),
        format!("  Average confidence: {:.2}", review.average_confidence),
        format!("  Tools with warnings: {}", review.tools_with_warnings),
        format!(
            "  Missing response schema: {}",
            review.tools_missing_response_schema
        ),
        format!("  Missing examples: {}", review.tools_missing_examples),
        String::new(),
        "Diagnose summary:".to_string(),
        format!("  Observations: {}", diagnose.total_observations),
        format!(
            "  Candidate API observations: {}",
            diagnose.candidate_api_observations
        ),
        format!("  Generated tools: {}", diagnose.generated_tools),
        format!(
            "  Observations with response bodies: {}",
            diagnose.observations_with_response_bodies
        ),
        format!("  JSON responses: {}", diagnose.json_responses),
        format!("  GraphQL requests: {}", diagnose.graphql_requests),
        format!(
            "  GraphQL responses mapped: {}",
            diagnose.graphql_responses_mapped
        ),
        format!(
            "  Tools missing examples: {}",
            diagnose.tools_missing_examples
        ),
        format!(
            "  Tools with empty response schemas: {}",
            diagnose.tools_with_empty_response_schemas
        ),
        String::new(),
        format!(
            "Recommended next action: {}",
            report.recommended_next_action
        ),
    ]
    .join("\n")
}
