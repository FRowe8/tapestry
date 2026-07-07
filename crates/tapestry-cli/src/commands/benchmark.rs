//! `tapestry benchmark` — run the frozen benchmark suite (benchmark_cases.json)
//! across tracked sites: agent-task success, review grade, and HAR/CDP
//! capture-parity metrics.

use crate::commands::diagnose::DiagnoseSummary;
use crate::commands::review::{review_toolspec, ReviewReport};
use crate::commands::validate::{validate_site, ValidateReport};
use crate::mcp;
use crate::support::*;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(crate) struct BenchmarkReport {
    pub(crate) total_sites: usize,
    pub(crate) success_count: usize,
    pub(crate) failure_count: usize,
    pub(crate) expected_match_count: usize,
    pub(crate) drift_count: usize,
    pub(crate) cases: Vec<BenchmarkCaseReport>,
    /// HAR-vs-CDP comparison for sites captured both ways. The release gate
    /// for recommending live recording is: CDP meets HAR on every pair.
    pub(crate) capture_parity: Vec<CaptureParityReport>,
    /// Token cost of the meta-tool interface vs stuffing every generated
    /// tool schema into agent context. Measures the PRD's context-reduction
    /// claim instead of asserting it.
    pub(crate) context_reduction: ContextReductionReport,
}

#[derive(Debug, Serialize)]
pub(crate) struct ContextReductionReport {
    /// Estimated tokens of the four meta-tool definitions an MCP agent sees,
    /// regardless of how many tools a site has.
    pub(crate) meta_tool_tokens: usize,
    pub(crate) sites: Vec<SiteContextCost>,
    /// Mean reduction across sites with at least one generated tool.
    pub(crate) mean_reduction: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SiteContextCost {
    pub(crate) site: String,
    pub(crate) tools: usize,
    /// Estimated tokens if every generated tool schema sat in agent context.
    pub(crate) full_toolspec_tokens: usize,
    /// 1 - meta/full; `None` when the site has no tools to compare against.
    pub(crate) reduction: Option<f64>,
}

/// Rough token estimate (chars / 4) — good enough for order-of-magnitude
/// context comparisons, not billing.
pub(crate) fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

pub(crate) fn build_context_reduction(
    site_specs: &[(String, tapestry_core::ToolSpec)],
) -> ContextReductionReport {
    let meta_config = mcp::McpServerConfig {
        default_site: Some("site".to_string()),
        live: false,
        offline: false,
        max_pages: 1,
    };
    let meta_tool_tokens = estimate_tokens(&mcp::tool_definitions(&meta_config).to_string());

    let mut sites = Vec::new();
    for (site, spec) in site_specs {
        let full = serde_json::to_string(&spec.tools).unwrap_or_default();
        let full_toolspec_tokens = estimate_tokens(&full);
        let reduction = (!spec.tools.is_empty())
            .then(|| 1.0 - meta_tool_tokens as f64 / full_toolspec_tokens as f64);
        sites.push(SiteContextCost {
            site: site.clone(),
            tools: spec.tools.len(),
            full_toolspec_tokens,
            reduction,
        });
    }

    let reductions: Vec<f64> = sites.iter().filter_map(|site| site.reduction).collect();
    let mean_reduction =
        (!reductions.is_empty()).then(|| reductions.iter().sum::<f64>() / reductions.len() as f64);

    ContextReductionReport {
        meta_tool_tokens,
        sites,
        mean_reduction,
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct BenchmarkCaseReport {
    pub(crate) site: String,
    pub(crate) capture_variant: Option<String>,
    pub(crate) parity_group: Option<String>,
    pub(crate) task: String,
    pub(crate) expected_outcome: String,
    pub(crate) expected_tool: Option<String>,
    pub(crate) selected_tool: Option<String>,
    pub(crate) success: bool,
    pub(crate) failure_type: Option<String>,
    pub(crate) failure_bucket: String,
    pub(crate) outcome_matches_expected: bool,
    pub(crate) tool_matches_expected: Option<bool>,
    pub(crate) review_grade: Option<String>,
    pub(crate) diagnose_summary: DiagnoseSummary,
    /// Fraction of the case's expected endpoints observed in the capture.
    /// `None` when the case defines no ground-truth endpoint list.
    pub(crate) endpoint_coverage: Option<f64>,
    pub(crate) ranking_note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct BenchmarkCase {
    pub(crate) site: String,
    #[serde(default)]
    pub(crate) capture_variant: Option<String>,
    /// Cases sharing a group name are captures of the same app via different
    /// methods and get compared in the capture-parity report.
    #[serde(default)]
    pub(crate) parity_group: Option<String>,
    pub(crate) task: String,
    pub(crate) expected_outcome: String,
    pub(crate) expected_tool: Option<String>,
    /// Ground-truth endpoints the app is known to expose. Comparing capture
    /// methods only against each other can't detect when both miss the same
    /// traffic; this can.
    #[serde(default)]
    pub(crate) expected_endpoints: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CaptureParityReport {
    pub(crate) group: String,
    pub(crate) har_site: String,
    pub(crate) cdp_site: String,
    pub(crate) har: CaptureVariantMetrics,
    pub(crate) cdp: CaptureVariantMetrics,
    pub(crate) cdp_meets_har: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CaptureVariantMetrics {
    pub(crate) observations: usize,
    pub(crate) api_observations: usize,
    pub(crate) response_bodies: usize,
    pub(crate) tools: usize,
    pub(crate) replayable_tools: usize,
    pub(crate) endpoint_coverage: Option<f64>,
    pub(crate) agent_success: bool,
    pub(crate) failure_type: Option<String>,
}

impl CaptureVariantMetrics {
    fn from_case(case: &BenchmarkCaseReport) -> Self {
        Self {
            observations: case.diagnose_summary.total_observations,
            api_observations: case.diagnose_summary.candidate_api_observations,
            response_bodies: case.diagnose_summary.observations_with_response_bodies,
            tools: case.diagnose_summary.generated_tools,
            replayable_tools: case
                .diagnose_summary
                .generated_tools
                .saturating_sub(case.diagnose_summary.tools_missing_examples),
            endpoint_coverage: case.endpoint_coverage,
            agent_success: case.success,
            failure_type: case.failure_type.clone(),
        }
    }
}

/// Pair har/cdp case reports that share a parity group.
pub(crate) fn build_capture_parity(cases: &[BenchmarkCaseReport]) -> Vec<CaptureParityReport> {
    let mut groups: Vec<String> = cases
        .iter()
        .filter_map(|case| case.parity_group.clone())
        .collect();
    groups.sort();
    groups.dedup();

    let mut reports = Vec::new();
    for group in groups {
        let of_variant = |want_cdp: bool| {
            cases.iter().find(|case| {
                case.parity_group.as_deref() == Some(group.as_str())
                    && (case.capture_variant.as_deref() == Some("cdp")) == want_cdp
            })
        };
        let (Some(har_case), Some(cdp_case)) = (of_variant(false), of_variant(true)) else {
            continue;
        };
        let har = CaptureVariantMetrics::from_case(har_case);
        let cdp = CaptureVariantMetrics::from_case(cdp_case);
        let coverage_ok = match (har.endpoint_coverage, cdp.endpoint_coverage) {
            (Some(har_cov), Some(cdp_cov)) => cdp_cov >= har_cov,
            _ => true,
        };
        let cdp_meets_har = (cdp.agent_success || !har.agent_success)
            && cdp.api_observations >= har.api_observations
            && cdp.replayable_tools >= har.replayable_tools
            && coverage_ok;
        reports.push(CaptureParityReport {
            group,
            har_site: har_case.site.clone(),
            cdp_site: cdp_case.site.clone(),
            har,
            cdp,
            cdp_meets_har,
        });
    }
    reports
}

/// Coverage of ground-truth endpoints in a capture's observations.
/// `{param}` segments in the expected pattern match any single path segment.
pub(crate) fn endpoint_coverage(
    expected_endpoints: &[String],
    observations: &[tapestry_core::Observation],
) -> Option<f64> {
    if expected_endpoints.is_empty() {
        return None;
    }
    let observed = expected_endpoints
        .iter()
        .filter(|pattern| {
            observations
                .iter()
                .any(|obs| endpoint_pattern_matches(pattern, &obs.path))
        })
        .count();
    Some(observed as f64 / expected_endpoints.len() as f64)
}

pub(crate) fn endpoint_pattern_matches(pattern: &str, path: &str) -> bool {
    let pattern_segments: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let path_segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    // Require the same segment count: an expected `/api/items` must not be
    // counted as covered by a deeper `/api/items/42/reviews`, which would
    // inflate endpoint coverage in the capture-parity gate.
    if path_segments.len() != pattern_segments.len() {
        return false;
    }
    pattern_segments
        .iter()
        .zip(path_segments.iter())
        .all(|(expected, actual)| {
            (expected.starts_with('{') && expected.ends_with('}')) || expected == actual
        })
}
pub(crate) fn run_benchmark_suite() -> Result<BenchmarkReport> {
    let mut cases = Vec::new();
    let mut site_specs: Vec<(String, tapestry_core::ToolSpec)> = Vec::new();
    for case in benchmark_cases() {
        let spec = load_site_spec(&case.site)?;
        let observations = load_site_observations(&case.site)?;
        if !site_specs.iter().any(|(site, _)| site == &case.site) {
            site_specs.push((case.site.clone(), spec.clone()));
        }
        let options = tapestry_runtime::RuntimeOptions {
            max_pages: 1,
            allow_har_replay: true,
            prefer_har_replay: true,
            offline_har_replay: true,
            ..tapestry_runtime::RuntimeOptions::default()
        };
        let report = validate_site(&spec, &observations, &case.task, &options);
        let review = review_toolspec(&spec, None);
        let selected_tool_grade = selected_tool_grade(&report, &review);
        let failure_bucket = failure_bucket_for_benchmark(&report);
        let outcome_matches_expected = benchmark_outcome_matches(&case.expected_outcome, &report);
        let tool_matches_expected = case.expected_tool.as_ref().map(|expected_tool| {
            report
                .agent_task
                .top_tool_used
                .as_deref()
                .map(|actual_tool| actual_tool == expected_tool.as_str())
                .unwrap_or(false)
        });
        cases.push(BenchmarkCaseReport {
            site: report.site.clone(),
            capture_variant: case.capture_variant,
            parity_group: case.parity_group,
            task: report.agent_task.task.clone(),
            expected_outcome: case.expected_outcome,
            expected_tool: case.expected_tool,
            selected_tool: report.agent_task.top_tool_used.clone(),
            success: report.agent_task.success,
            failure_type: report.agent_task.failure_type.clone(),
            failure_bucket,
            outcome_matches_expected,
            tool_matches_expected,
            review_grade: selected_tool_grade,
            diagnose_summary: report.diagnose_summary.clone(),
            endpoint_coverage: endpoint_coverage(&case.expected_endpoints, &observations),
            ranking_note: report.agent_task.ranking_note.clone(),
        });
    }

    let success_count = cases.iter().filter(|case| case.success).count();
    let failure_count = cases.len().saturating_sub(success_count);
    let expected_match_count = cases
        .iter()
        .filter(|case| case.outcome_matches_expected)
        .count();
    let drift_count = cases.len().saturating_sub(expected_match_count);
    let capture_parity = build_capture_parity(&cases);
    let context_reduction = build_context_reduction(&site_specs);

    Ok(BenchmarkReport {
        total_sites: cases.len(),
        success_count,
        failure_count,
        expected_match_count,
        drift_count,
        cases,
        capture_parity,
        context_reduction,
    })
}

pub(crate) fn benchmark_cases() -> Vec<BenchmarkCase> {
    serde_json::from_str(include_str!("../../benchmark_cases.json"))
        .expect("benchmark_cases.json must contain a valid benchmark case array")
}

pub(crate) fn benchmark_outcome_matches(expected: &str, report: &ValidateReport) -> bool {
    for expected in expected.split('|').map(str::trim) {
        if expected.is_empty() {
            continue;
        }
        if expected == "success" && report.agent_task.success {
            return true;
        }

        if !report.agent_task.success && report.agent_task.failure_type.as_deref() == Some(expected)
        {
            return true;
        }
    }

    false
}

pub(crate) fn selected_tool_grade(
    report: &ValidateReport,
    review: &ReviewReport,
) -> Option<String> {
    let selected = report.agent_task.top_tool_used.as_ref()?;
    let selected_id = report.agent_task.top_tool_id.as_deref();
    review
        .tools
        .iter()
        .find(|tool| &tool.name == selected || Some(tool.id.as_str()) == selected_id)
        .map(|tool| tool.usefulness_grade.clone())
}

pub(crate) fn failure_bucket_for_benchmark(report: &ValidateReport) -> String {
    if report.agent_task.success {
        return "success".to_string();
    }

    match report.agent_task.failure_type.as_deref() {
        Some("no_replayable_tool") => "no_replayable_tool".to_string(),
        Some("missing_required_argument") => "missing_required_argument".to_string(),
        Some("approval_required") => "approval_required".to_string(),
        Some("capture_quality") => "capture_quality".to_string(),
        Some("auth_expired") => "auth_expired".to_string(),
        Some("rate_limited") => "rate_limited".to_string(),
        Some("endpoint_error") => "endpoint_error".to_string(),
        Some("schema_mismatch") => "schema_mismatch".to_string(),
        Some("network_error") => "network_error".to_string(),
        Some("static_resource_only") => "static_resource_only".to_string(),
        _ if report.diagnose_summary.static_resource_tools > 0
            && report.diagnose_summary.static_resource_tools
                == report.review_summary.total_tools =>
        {
            "static_resource_only".to_string()
        }
        _ if report.diagnose_summary.observations_with_response_bodies == 0
            || report.diagnose_summary.tools_missing_examples > 0
            || report.diagnose_summary.tools_with_empty_response_schemas > 0 =>
        {
            "capture_quality".to_string()
        }
        _ => "unknown".to_string(),
    }
}

pub(crate) fn format_benchmark_text(report: &BenchmarkReport) -> String {
    let mut out = vec![
        format!("Benchmark suite: {} site(s)", report.total_sites),
        format!(
            "Result counts: {} success, {} failure",
            report.success_count, report.failure_count
        ),
        format!(
            "Expected matches: {} drift: {}",
            report.expected_match_count, report.drift_count
        ),
    ];

    if !report.capture_parity.is_empty() {
        out.push(String::new());
        out.push("Capture parity (HAR vs CDP):".to_string());
        for parity in &report.capture_parity {
            let verdict = if parity.cdp_meets_har {
                "CDP meets HAR"
            } else {
                "CDP BELOW HAR — re-record or investigate"
            };
            out.push(format!("- group={} : {}", parity.group, verdict));
            for (label, metrics) in [("har", &parity.har), ("cdp", &parity.cdp)] {
                let coverage = metrics
                    .endpoint_coverage
                    .map(|value| format!("{:.0}%", value * 100.0))
                    .unwrap_or_else(|| "n/a".to_string());
                out.push(format!(
                    "  {label}: obs={} api={} bodies={} tools={} replayable={} endpoint_coverage={} agent_success={}{}",
                    metrics.observations,
                    metrics.api_observations,
                    metrics.response_bodies,
                    metrics.tools,
                    metrics.replayable_tools,
                    coverage,
                    metrics.agent_success,
                    metrics
                        .failure_type
                        .as_deref()
                        .map(|failure| format!(" failure={failure}"))
                        .unwrap_or_default(),
                ));
            }
        }
    }

    out.push(String::new());
    out.push(format!(
        "Context reduction (token estimate): meta-tool surface = {} tokens{}",
        report.context_reduction.meta_tool_tokens,
        report
            .context_reduction
            .mean_reduction
            .map(|mean| format!(", mean reduction {:.1}%", mean * 100.0))
            .unwrap_or_default()
    ));
    for site in &report.context_reduction.sites {
        if let Some(reduction) = site.reduction {
            out.push(format!(
                "  {}: {} tool(s), full toolspec ~{} tokens -> {:.1}% reduction",
                site.site,
                site.tools,
                site.full_toolspec_tokens,
                reduction * 100.0
            ));
        }
    }

    out.push(String::new());
    out.push("Cases:".to_string());

    for case in &report.cases {
        let review_grade = case.review_grade.as_deref().unwrap_or("none");
        let selected_tool = case.selected_tool.as_deref().unwrap_or("none");
        let failure_type = case.failure_type.as_deref().unwrap_or("none");
        let expected_tool = case.expected_tool.as_deref().unwrap_or("none");
        let outcome_match = case.outcome_matches_expected;
        let tool_match = case
            .tool_matches_expected
            .map_or("n/a".to_string(), |value| value.to_string());
        out.push(format!(
            "- site={}{} task=\"{}\" expected={} selected_tool={} success={} failure_type={} failure_bucket={} outcome_match={} review_grade={}",
            case.site,
            case.capture_variant.as_deref().map(|variant| format!(" variant={variant}")).unwrap_or_default(),
            case.task,
            case.expected_outcome,
            selected_tool,
            case.success,
            failure_type,
            case.failure_bucket,
            outcome_match,
            review_grade
        ));
        out.push(format!(
            "  expected_tool={} tool_match={}",
            expected_tool, tool_match
        ));
        out.push(format!(
            "  diagnose: obs={} api={} tools={} response_bodies={} json={} graphql={} mapped={}",
            case.diagnose_summary.total_observations,
            case.diagnose_summary.candidate_api_observations,
            case.diagnose_summary.generated_tools,
            case.diagnose_summary.observations_with_response_bodies,
            case.diagnose_summary.json_responses,
            case.diagnose_summary.graphql_requests,
            case.diagnose_summary.graphql_responses_mapped
        ));
        out.push(format!("  review_grade: {}", review_grade));
        if let Some(note) = &case.ranking_note {
            out.push(format!("  ranking_note: {note}"));
        }
    }

    out.join("\n")
}
