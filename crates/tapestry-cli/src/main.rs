use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{fs, path::PathBuf};
use tracing::info;

#[derive(Parser)]
#[command(name = "tapestry")]
#[command(about = "Turn captured web app traffic into low-token agent tools")]
#[command(
    after_help = "Examples:\n  tapestry import examples/fixtures/simple.har --site demo\n  tapestry generate demo\n  tapestry record https://example.com --site demo\n  tapestry agent-task demo \"List the most recent 5 items\"\n  tapestry review demo\n  tapestry diagnose demo\n  tapestry benchmark"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(
        about = "Import a HAR file into a local Tapestry site",
        after_help = "Example:\n  tapestry import examples/fixtures/simple.har --site demo"
    )]
    Import {
        #[arg(help = "Path to the HAR file exported from browser DevTools")]
        har: PathBuf,
        #[arg(
            long,
            help = "Local site name used for generated observations and tools"
        )]
        site: String,
    },
    #[command(
        about = "Record network traffic from a browser session using CDP",
        after_help = "Examples:\n  tapestry record https://example.com --site demo\n  tapestry record http://localhost:3000 --site demo --headless"
    )]
    Record {
        #[arg(help = "URL to open in the browser for manual interaction")]
        url: String,
        #[arg(
            long,
            help = "Local site name used for generated observations and tools"
        )]
        site: String,
        #[arg(long, help = "Explicit browser executable path")]
        browser: Option<PathBuf>,
        #[arg(long, help = "Launch the browser in headless mode")]
        headless: bool,
        #[arg(long, default_value_t = 120, help = "Capture timeout in seconds")]
        timeout_secs: u64,
        #[arg(
            long,
            default_value_t = 10 * 1024 * 1024,
            help = "Maximum response body size in bytes"
        )]
        max_body_bytes: usize,
        #[arg(long, help = "Include third-party network traffic")]
        include_third_party: bool,
        #[arg(long, help = "Print redacted observations JSON after capture")]
        output_observations: bool,
        #[arg(long, help = "Keep the temporary browser profile directory")]
        keep_profile: bool,
    },
    #[command(
        about = "Generate a ToolSpec from imported observations",
        after_help = "Example:\n  tapestry generate demo"
    )]
    Generate {
        #[arg(help = "Local site name previously imported with `tapestry import`")]
        site: String,
    },
    #[command(about = "Print a redacted view of a HAR file")]
    Redact { har: PathBuf },
    #[command(
        about = "Purge local stored data for a site",
        after_help = "Examples:\n  tapestry purge demo --secrets\n  tapestry purge demo --observations\n  tapestry purge demo --all"
    )]
    Purge {
        site: String,
        #[arg(long, help = "Remove stored credentials")]
        secrets: bool,
        #[arg(long, help = "Remove imported observations")]
        observations: bool,
        #[arg(long, help = "Remove all data for the site")]
        all: bool,
    },
    #[command(about = "Search, inspect, and view evidence for generated tools")]
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },
    #[command(
        about = "Run a deterministic agent loop over generated tools",
        after_help = "Examples:\n  tapestry agent-task demo \"List the most recent 5 items\"\n  tapestry agent-task demo \"List 5 items\" --trace"
    )]
    AgentTask {
        #[arg(help = "Local site name with a generated ToolSpec")]
        site: String,
        #[arg(help = "Natural-language task to satisfy using native Tapestry tools")]
        task: String,
        #[arg(long, help = "Print search, schema, argument, and call stages")]
        trace: bool,
        #[arg(
            long,
            default_value_t = 1,
            help = "Maximum pages for simple runtime pagination"
        )]
        max_pages: usize,
        #[arg(long, help = "Force live HTTP execution instead of HAR replay")]
        live: bool,
        #[arg(long, help = "Use captured HAR responses only; never call the network")]
        offline: bool,
    },
    #[command(
        about = "Review whether a generated ToolSpec is useful for agents",
        after_help = "Examples:\n  tapestry review demo\n  tapestry review demo --verbose\n  tapestry review demo --only-grade C\n  tapestry review demo --format json"
    )]
    Review {
        #[arg(help = "Local site name with a generated ToolSpec")]
        site: String,
        #[arg(long, default_value = "text", help = "Output format: text or json")]
        format: ReviewFormat,
        #[arg(
            long,
            help = "Include GraphQL metadata, schema keys, and evidence details"
        )]
        verbose: bool,
        #[arg(
            long,
            help = "Show only tools with a specific usefulness grade: A, B, C, or D"
        )]
        only_grade: Option<String>,
    },
    #[command(
        about = "Diagnose whether a HAR capture has enough evidence for useful tools",
        after_help = "Examples:\n  tapestry diagnose demo\n  tapestry diagnose demo --format json"
    )]
    Diagnose {
        #[arg(help = "Local site name with imported observations and generated tools")]
        site: String,
        #[arg(long, default_value = "text", help = "Output format: text or json")]
        format: ReviewFormat,
    },
    #[command(
        about = "Validate a site end-to-end and recommend the next action",
        after_help = "Examples:\n  tapestry validate demo\n  tapestry validate demo --task \"List the most recent 5 items\"\n  tapestry validate demo --format json"
    )]
    Validate {
        #[arg(help = "Local site name with imported observations and generated tools")]
        site: String,
        #[arg(
            long,
            default_value = "List the most recent 5 items",
            help = "Agent task used for validation"
        )]
        task: String,
        #[arg(long, default_value = "text", help = "Output format: text or json")]
        format: ReviewFormat,
        #[arg(
            long,
            default_value_t = 1,
            help = "Maximum pages for simple runtime pagination"
        )]
        max_pages: usize,
        #[arg(long, help = "Force live HTTP execution instead of HAR replay")]
        live: bool,
        #[arg(long, help = "Use captured HAR responses only; never call the network")]
        offline: bool,
    },
    #[command(
        about = "Run a frozen benchmark suite across tracked sites",
        after_help = "Examples:\n  tapestry benchmark\n  tapestry benchmark --format json"
    )]
    Benchmark {
        #[arg(long, default_value = "text", help = "Output format: text or json")]
        format: ReviewFormat,
    },
    #[command(
        about = "Call a generated tool directly through the native runtime",
        after_help = "Examples:\n  tapestry run demo list_items --args '{\"limit\":5}'\n  tapestry run demo list_items --args '{limit:5}'\n  tapestry run demo list_items --args '{\"limit\":5}' --live"
    )]
    Run {
        site: String,
        tool_id: String,
        #[arg(long, default_value = "{}")]
        args: String,
        #[arg(long, default_value_t = 1)]
        max_pages: usize,
        #[arg(long, help = "Force live HTTP execution instead of HAR replay")]
        live: bool,
        #[arg(long, help = "Use captured HAR responses only; never call the network")]
        offline: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ToolsCommand {
    #[command(about = "Search generated tools by name, description, path, schema, or evidence")]
    Search {
        site: String,
        query: String,
        #[arg(long, default_value_t = 5)]
        limit: usize,
    },
    #[command(about = "Print one generated tool schema")]
    Schema { site: String, tool_id: String },
    #[command(about = "Print evidence and warnings for one generated tool")]
    Evidence { site: String, tool_id: String },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Import { har, site } => {
            validate_site_name(&site)?;
            eprintln!(
                "Warning: HAR files may contain credentials and personal data. Tapestry will persist redacted observations, not the raw HAR."
            );
            info!(command = "import", site, har = %har.display(), "starting HAR import");
            let observations = tapestry_input::import_har(&har)?;
            let dir = site_dir(&site);
            fs::create_dir_all(&dir)?;
            write_protected(
                &dir.join("observations.json"),
                &serde_json::to_string_pretty(&observations)?,
            )?;
            println!(
                "Imported {} observations for site '{}'",
                observations.len(),
                site
            );
        }
        Command::Record {
            url,
            site,
            browser,
            headless,
            timeout_secs,
            max_body_bytes,
            include_third_party,
            output_observations,
            keep_profile,
        } => {
            validate_site_name(&site)?;
            info!(command = "record", site, url = %url, "starting CDP capture");
            print_record_guidance();
            let record = tapestry_input::record(
                &url,
                &tapestry_input::RecordOptions {
                    browser,
                    headless,
                    timeout_secs,
                    max_body_bytes,
                    include_third_party,
                    output_observations,
                    keep_profile,
                },
            )?;
            let observations = record.observations;
            let dir = site_dir(&site);
            fs::create_dir_all(&dir)?;
            write_protected(
                &dir.join("observations.json"),
                &serde_json::to_string_pretty(&observations)?,
            )?;
            if output_observations {
                println!("{}", serde_json::to_string_pretty(&observations)?);
            }
            println!("{}", format_record_summary(&site, &observations));
        }
        Command::Generate { site } => {
            validate_site_name(&site)?;
            info!(command = "generate", site, "starting ToolSpec generation");
            let dir = site_dir(&site);
            let raw =
                fs::read_to_string(dir.join("observations.json")).context("run import first")?;
            let observations: Vec<tapestry_core::Observation> = serde_json::from_str(&raw)?;
            let spec = tapestry_analyzer::analyze(&site, &observations);
            write_protected(
                &dir.join("toolspec.json"),
                &serde_json::to_string_pretty(&spec)?,
            )?;
            println!("Generated {} tools for site '{}'", spec.tools.len(), site);
        }
        Command::Redact { har } => {
            info!(command = "redact", har = %har.display(), "redacting HAR");
            let redacted = tapestry_input::redact_har(&har)?;
            println!("{}", serde_json::to_string_pretty(&redacted)?);
        }
        Command::Purge {
            site,
            secrets,
            observations,
            all,
        } => {
            validate_site_name(&site)?;
            info!(
                command = "purge",
                site, secrets, observations, all, "purging site data"
            );
            let dir = site_dir(&site);
            if all {
                if dir.exists() {
                    fs::remove_dir_all(&dir)?;
                    println!("Purged all data for site '{}'", site);
                } else {
                    println!("No data found for site '{}'", site);
                }
            } else {
                let mut purged = false;
                if secrets {
                    let credentials = dir.join("credentials.json");
                    if credentials.exists() {
                        fs::remove_file(&credentials)?;
                        println!("Purged secrets for site '{}'", site);
                        purged = true;
                    } else {
                        println!("No secrets found for site '{}'", site);
                    }
                }
                if observations {
                    let obs_path = dir.join("observations.json");
                    if obs_path.exists() {
                        fs::remove_file(&obs_path)?;
                        println!("Purged observations for site '{}'", site);
                        purged = true;
                    } else {
                        println!("No observations found for site '{}'", site);
                    }
                }
                if !purged && !secrets && !observations {
                    println!("Nothing purged. Pass --secrets, --observations, or --all.");
                }
            }
        }
        Command::Tools { command } => match command {
            ToolsCommand::Search { site, query, limit } => {
                validate_site_name(&site)?;
                let spec = load_site_spec(&site)?;
                let results = tapestry_runtime::search_tools(&spec, &query, limit);
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
            ToolsCommand::Schema { site, tool_id } => {
                validate_site_name(&site)?;
                let spec = load_site_spec(&site)?;
                let schema =
                    tapestry_runtime::get_tool_schema(&spec, &tool_id).context("tool not found")?;
                println!("{}", serde_json::to_string_pretty(&schema)?);
            }
            ToolsCommand::Evidence { site, tool_id } => {
                validate_site_name(&site)?;
                let spec = load_site_spec(&site)?;
                let evidence = tapestry_runtime::get_evidence(&spec, &tool_id);
                println!("{}", serde_json::to_string_pretty(&evidence)?);
            }
        },
        Command::AgentTask {
            site,
            task,
            trace,
            max_pages,
            live,
            offline,
        } => {
            validate_site_name(&site)?;
            let spec = load_site_spec(&site)?;
            let observations = if offline {
                load_site_observations(&site)?
            } else {
                Vec::new()
            };
            let options = runtime_options_for(&spec, max_pages, live, offline);
            let out = run_agent_task(&spec, &observations, &task, trace, &options);
            println!("{out}");
        }
        Command::Review {
            site,
            format,
            verbose,
            only_grade,
        } => {
            validate_site_name(&site)?;
            let spec = load_site_spec(&site)?;
            let report = review_toolspec(&spec, only_grade.as_deref());
            match format {
                ReviewFormat::Text => println!("{}", format_review_text(&report, verbose)),
                ReviewFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
            }
        }
        Command::Diagnose { site, format } => {
            validate_site_name(&site)?;
            let observations = load_site_observations(&site)?;
            let spec = load_site_spec(&site)?;
            let report = diagnose_site(&spec, &observations);
            match format {
                ReviewFormat::Text => println!("{}", format_diagnose_text(&report)),
                ReviewFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
            }
        }
        Command::Validate {
            site,
            task,
            format,
            max_pages,
            live,
            offline,
        } => {
            validate_site_name(&site)?;
            let observations = load_site_observations(&site)?;
            let spec = load_site_spec(&site)?;
            let options = runtime_options_for(&spec, max_pages, live, offline);
            let report = validate_site(&spec, &observations, &task, &options);
            match format {
                ReviewFormat::Text => println!("{}", format_validate_text(&report)),
                ReviewFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
            }
        }
        Command::Benchmark { format } => {
            let report = run_benchmark_suite()?;
            match format {
                ReviewFormat::Text => println!("{}", format_benchmark_text(&report)),
                ReviewFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
            }
        }
        Command::Run {
            site,
            tool_id,
            args,
            max_pages,
            live,
            offline,
        } => {
            validate_site_name(&site)?;
            let spec = load_site_spec(&site)?;
            let args_json = parse_args(&args)?;
            let options = runtime_options_for(&spec, max_pages, live, offline);
            let out =
                tapestry_runtime::call_tool_with_options(&spec, &tool_id, args_json, &options);
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ReviewFormat {
    Text,
    Json,
}

fn site_dir(site: &str) -> PathBuf {
    PathBuf::from(".tapestry-dev").join("sites").join(site)
}

fn validate_site_name(site: &str) -> Result<()> {
    if site.is_empty() || site.len() > 64 {
        anyhow::bail!("Site name must be 1–64 characters");
    }
    if !site
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "Site name '{}' is invalid — use only letters, digits, hyphens, and underscores",
            site
        );
    }
    Ok(())
}

fn write_protected(path: &std::path::Path, content: &str) -> Result<()> {
    fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_site_spec(site: &str) -> Result<tapestry_core::ToolSpec> {
    tapestry_runtime::load_toolspec(site_dir(site).join("toolspec.json"))
}

fn load_site_observations(site: &str) -> Result<Vec<tapestry_core::Observation>> {
    let raw =
        fs::read_to_string(site_dir(site).join("observations.json")).context("run import first")?;
    Ok(serde_json::from_str(&raw)?)
}

fn format_record_summary(site: &str, observations: &[tapestry_core::Observation]) -> String {
    let summary = tapestry_input::CaptureSummary::from_observations(observations);
    let coverage = round2(summary.response_body_coverage() * 100.0);

    format!(
        "Recorded {} observations\nCapture quality: {}\nAPI observations: {}\nResponse body coverage: {:.0}%\nReplayable tools (estimate): {}\nMissing response bodies: {}\nJSON responses: {}\nGraphQL requests: {}\nRecommended next action: {}\nSaved to {}\nNext: tapestry generate {}",
        summary.total_observations,
        summary.quality_grade(),
        summary.candidate_api_observations,
        coverage,
        summary.replayable_tool_hint(),
        summary
            .total_observations
            .saturating_sub(summary.observations_with_response_bodies),
        summary.json_responses,
        summary.graphql_requests,
        summary.recommended_next_action(),
        site_dir(site).join("observations.json").display(),
        site
    )
}

fn print_record_guidance() {
    eprintln!("{}", record_guidance_text());
}

fn record_guidance_text() -> &'static str {
    "Now perform:\n- search\n- open detail\n- add to basket\n- view basket\nPress Enter when done."
}

fn runtime_options_for(
    spec: &tapestry_core::ToolSpec,
    max_pages: usize,
    live: bool,
    offline: bool,
) -> tapestry_runtime::RuntimeOptions {
    if live {
        return tapestry_runtime::RuntimeOptions {
            max_pages,
            allow_har_replay: false,
            prefer_har_replay: false,
            offline_har_replay: false,
            ..tapestry_runtime::RuntimeOptions::default()
        };
    }

    if offline {
        return tapestry_runtime::RuntimeOptions {
            max_pages,
            allow_har_replay: true,
            prefer_har_replay: true,
            offline_har_replay: true,
            ..tapestry_runtime::RuntimeOptions::default()
        };
    }

    tapestry_runtime::RuntimeOptions {
        max_pages,
        prefer_har_replay: should_prefer_har_replay(spec),
        ..tapestry_runtime::RuntimeOptions::default()
    }
}

fn should_prefer_har_replay(spec: &tapestry_core::ToolSpec) -> bool {
    let har_only =
        spec.site.source.len() == 1 && spec.site.source.iter().any(|source| source == "har");
    if !har_only {
        return false;
    }

    let fixture_site = {
        let name = spec.site.name.to_ascii_lowercase();
        name == "demo" || name == "fixture" || name.contains("fixture")
    };

    fixture_site || has_localhost_base_url(spec.site.base_url.as_deref())
}

fn has_localhost_base_url(base_url: Option<&str>) -> bool {
    let Some(base_url) = base_url else {
        return false;
    };
    let Ok(parsed) = url::Url::parse(base_url) else {
        return false;
    };
    matches!(
        parsed.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("::1")
    )
}

#[derive(Debug, Serialize)]
struct ReviewReport {
    site: String,
    summary: ReviewSummary,
    tools: Vec<ToolReview>,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewSummary {
    total_tools: usize,
    read_tools: usize,
    write_tools: usize,
    unknown_tools: usize,
    graphql_tools: usize,
    opaque_root_post_tools: usize,
    average_confidence: f64,
    tools_with_warnings: usize,
    tools_missing_response_schema: usize,
    tools_missing_examples: usize,
}

#[derive(Debug, Serialize)]
struct ToolReview {
    id: String,
    name: String,
    method: String,
    path: String,
    resource_kind: String,
    safety: String,
    confidence: f64,
    confidence_breakdown: ConfidenceReview,
    warnings: Vec<String>,
    usefulness_grade: String,
    usefulness_score: i32,
    reasons: Vec<String>,
    positive_signals: Vec<String>,
    negative_signals: Vec<String>,
    missing_fields: Vec<String>,
    graphql: Option<GraphqlReview>,
    input_schema_keys: Vec<String>,
    response_schema_keys: Vec<String>,
    evidence: EvidenceReview,
}

#[derive(Debug, Serialize)]
struct ConfidenceReview {
    overall: f64,
    path: f64,
    path_params: f64,
    method: f64,
    input_schema: f64,
    response_schema: f64,
    auth: f64,
    safety: f64,
}

#[derive(Debug, Serialize)]
struct GraphqlReview {
    operation_name: Option<String>,
    operation_type: Option<String>,
    batched: bool,
}

#[derive(Debug, Serialize)]
struct EvidenceReview {
    count: usize,
    details: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DiagnoseReport {
    site: String,
    summary: DiagnoseSummary,
    filtered_counts: FilteredCounts,
    tools: Vec<ToolDiagnostics>,
}

#[derive(Debug, Clone, Serialize)]
struct DiagnoseSummary {
    total_observations: usize,
    candidate_api_observations: usize,
    generated_tools: usize,
    observations_with_response_bodies: usize,
    json_responses: usize,
    graphql_requests: usize,
    graphql_responses_mapped: usize,
    tools_missing_examples: usize,
    tools_with_empty_response_schemas: usize,
    static_resource_tools: usize,
    platform_resource_tools: usize,
    telemetry_tools: usize,
    commerce_api_tools: usize,
}

#[derive(Debug, Serialize)]
struct FilteredCounts {
    static_assets: usize,
    consent_or_config: usize,
    bot_or_security: usize,
    third_party_non_api: usize,
}

#[derive(Debug, Serialize)]
struct ToolDiagnostics {
    name: String,
    method: String,
    path: String,
    resource_kind: String,
    has_request_body: bool,
    has_response_body: bool,
    example_response_present: bool,
    response_schema_empty: bool,
    warnings: Vec<String>,
    problem: Option<String>,
    remediation: String,
}

#[derive(Debug, Serialize)]
struct ValidateReport {
    site: String,
    agent_task: AgentValidation,
    review_summary: ReviewSummary,
    diagnose_summary: DiagnoseSummary,
    recommended_next_action: String,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    total_sites: usize,
    success_count: usize,
    failure_count: usize,
    expected_match_count: usize,
    drift_count: usize,
    cases: Vec<BenchmarkCaseReport>,
}

#[derive(Debug, Serialize)]
struct BenchmarkCaseReport {
    site: String,
    capture_variant: Option<String>,
    task: String,
    expected_outcome: String,
    expected_tool: Option<String>,
    selected_tool: Option<String>,
    success: bool,
    failure_type: Option<String>,
    failure_bucket: String,
    outcome_matches_expected: bool,
    tool_matches_expected: Option<bool>,
    review_grade: Option<String>,
    diagnose_summary: DiagnoseSummary,
    ranking_note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BenchmarkCase {
    site: String,
    #[serde(default)]
    capture_variant: Option<String>,
    task: String,
    expected_outcome: String,
    expected_tool: Option<String>,
}

#[derive(Debug, Serialize)]
struct AgentValidation {
    task: String,
    success: bool,
    top_tool_used: Option<String>,
    top_tool_id: Option<String>,
    top_tool_score: Option<usize>,
    ranking_note: Option<String>,
    failure_type: Option<String>,
    result: String,
}

fn validate_site(
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

fn run_benchmark_suite() -> Result<BenchmarkReport> {
    let mut cases = Vec::new();
    for case in benchmark_cases() {
        let spec = load_site_spec(&case.site)?;
        let observations = load_site_observations(&case.site)?;
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

    Ok(BenchmarkReport {
        total_sites: cases.len(),
        success_count,
        failure_count,
        expected_match_count,
        drift_count,
        cases,
    })
}

fn benchmark_cases() -> Vec<BenchmarkCase> {
    serde_json::from_str(include_str!("../benchmark_cases.json"))
        .expect("benchmark_cases.json must contain a valid benchmark case array")
}

fn benchmark_outcome_matches(expected: &str, report: &ValidateReport) -> bool {
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

fn selected_tool_grade(report: &ValidateReport, review: &ReviewReport) -> Option<String> {
    let selected = report.agent_task.top_tool_used.as_ref()?;
    let selected_id = report.agent_task.top_tool_id.as_deref();
    review
        .tools
        .iter()
        .find(|tool| &tool.name == selected || Some(tool.id.as_str()) == selected_id)
        .map(|tool| tool.usefulness_grade.clone())
}

fn failure_bucket_for_benchmark(report: &ValidateReport) -> String {
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

fn format_benchmark_text(report: &BenchmarkReport) -> String {
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
        String::new(),
        "Cases:".to_string(),
    ];

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

fn run_agent_validation(
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

fn recommended_next_action(
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

fn format_validate_text(report: &ValidateReport) -> String {
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

fn diagnose_site(
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
                .filter(|obs| {
                    obs.response_body.is_some()
                        || header_contains_cli(&obs.response_headers, "content-type", "json")
                })
                .count(),
            graphql_requests: observations
                .iter()
                .filter(|obs| graphql_operations_cli(obs).len() > 0)
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

fn diagnose_tool(
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

fn remediation_for_tool(
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

fn format_diagnose_text(report: &DiagnoseReport) -> String {
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
            "Filtered signals: static={}, consent/config={}, bot/security={}, third-party-non-api={}",
            f.static_assets, f.consent_or_config, f.bot_or_security, f.third_party_non_api
        ),
        String::new(),
        "Tools:".to_string(),
    ];
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

fn review_toolspec(spec: &tapestry_core::ToolSpec, only_grade: Option<&str>) -> ReviewReport {
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

fn review_tool(tool: &tapestry_core::ToolDefinition) -> ToolReview {
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

fn usefulness_score(
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

fn usefulness_grade(score: i32) -> &'static str {
    match score {
        80..=100 => "A",
        60..=79 => "B",
        25..=59 => "C",
        _ => "D",
    }
}

fn usefulness_grade_value(grade: &str) -> i32 {
    match grade {
        "A" => 4,
        "B" => 3,
        "C" => 2,
        _ => 1,
    }
}

fn format_review_text(report: &ReviewReport, verbose: bool) -> String {
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

fn meaningful_name(name: &str) -> bool {
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

fn is_opaque_tool(tool: &tapestry_core::ToolDefinition) -> bool {
    tool.name == "opaque_root_post"
        || tool
            .warnings
            .iter()
            .any(|warning| warning == "opaque_root_post")
}

fn resource_kind_label(kind: &tapestry_core::ResourceKind) -> &'static str {
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

fn is_static_resource_kind(kind: &tapestry_core::ResourceKind) -> bool {
    matches!(
        kind,
        tapestry_core::ResourceKind::StaticJsonResource
            | tapestry_core::ResourceKind::ConfigResource
            | tapestry_core::ResourceKind::LocalizationResource
            | tapestry_core::ResourceKind::PlatformResource
    )
}

fn is_static_resource_kind_label(label: &str) -> bool {
    matches!(
        label,
        "static_json_resource" | "config_resource" | "localization_resource" | "platform_resource"
    )
}

fn schema_present(schema: &Value) -> bool {
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

fn list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn filtered_counts(observations: &[tapestry_core::Observation]) -> FilteredCounts {
    let primary = primary_host_cli(observations);
    FilteredCounts {
        static_assets: observations
            .iter()
            .filter(|obs| is_static_asset_path_cli(&obs.path))
            .count(),
        consent_or_config: observations
            .iter()
            .filter(|obs| is_consent_or_config_cli(obs))
            .count(),
        bot_or_security: observations
            .iter()
            .filter(|obs| is_bot_or_security_cli(obs))
            .count(),
        third_party_non_api: observations
            .iter()
            .filter(|obs| {
                primary
                    .as_deref()
                    .zip(host_for(&obs.url).as_deref())
                    .map(|(primary, host)| {
                        host != primary && !has_json_signal_cli(obs) && !is_api_path_cli(&obs.path)
                    })
                    .unwrap_or(false)
            })
            .count(),
    }
}

fn is_candidate_api_observation(obs: &tapestry_core::Observation) -> bool {
    !is_static_asset_path_cli(&obs.path)
        && !is_consent_or_config_cli(obs)
        && !is_bot_or_security_cli(obs)
        && (is_api_path_cli(&obs.path)
            || has_json_signal_cli(obs)
            || obs.request_body.is_some()
            || matches!(obs.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE"))
}

fn observation_matches_tool(
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

fn normalize_tool_path_match(path: &str, template: &str) -> bool {
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
struct GraphqlOperationCli {
    operation_name: Option<String>,
}

fn graphql_operations_cli(obs: &tapestry_core::Observation) -> Vec<GraphqlOperationCli> {
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

fn graphql_operation_cli(map: &Map<String, Value>) -> Option<GraphqlOperationCli> {
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

fn graphql_response_mapped_cli(obs: &tapestry_core::Observation) -> bool {
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

fn header_contains_cli(
    headers: &std::collections::BTreeMap<String, String>,
    name: &str,
    needle: &str,
) -> bool {
    headers.iter().any(|(header_name, value)| {
        header_name.eq_ignore_ascii_case(name)
            && value
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
    })
}

fn has_json_signal_cli(obs: &tapestry_core::Observation) -> bool {
    obs.request_body.is_some()
        || obs.response_body.is_some()
        || header_contains_cli(&obs.request_headers, "content-type", "json")
        || header_contains_cli(&obs.request_headers, "accept", "json")
        || header_contains_cli(&obs.response_headers, "content-type", "json")
}

fn is_static_asset_path_cli(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        ".css", ".js", ".mjs", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".wav", ".pdf",
    ]
    .iter()
    .any(|extension| path.ends_with(extension))
}

fn is_consent_or_config_cli(obs: &tapestry_core::Observation) -> bool {
    let path = obs.path.to_ascii_lowercase();
    [
        "/assets/cmp/",
        "/cmp/",
        "/consent/",
        "/privacy/",
        "/cookie/",
        "/cookies/",
        "/onetrust/",
        "/trustarc/",
    ]
    .iter()
    .any(|marker| path.contains(marker))
        || (obs.method == "GET"
            && obs.request_body.is_none()
            && path.contains("/assets/")
            && path.ends_with(".json"))
}

fn is_bot_or_security_cli(obs: &tapestry_core::Observation) -> bool {
    let path = obs.path.to_ascii_lowercase();
    [
        "/akam/",
        "/akamai/",
        "/bot/",
        "/challenge/",
        "/captcha/",
        "/risk/",
        "/fingerprint/",
        "/telemetry/",
    ]
    .iter()
    .any(|marker| path.contains(marker))
        || body_contains_telemetry_key_cli(obs.request_body.as_ref())
        || (obs.method == "POST"
            && !is_static_asset_path_cli(&path)
            && path
                .trim_matches('/')
                .split('/')
                .any(|segment| segment.len() >= 16 && !contains_semantic_word_cli(segment)))
}

fn body_contains_telemetry_key_cli(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Object(map)) => map.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "sensor_data"
                    | "_fingerprint"
                    | "fingerprint"
                    | "challenge"
                    | "captcha"
                    | "bot"
                    | "risk"
                    | "akamai"
            ) || body_contains_telemetry_key_cli(Some(value))
        }),
        Some(Value::Array(values)) => values
            .iter()
            .any(|value| body_contains_telemetry_key_cli(Some(value))),
        Some(Value::String(value)) => value.to_ascii_lowercase().contains("sensor_data"),
        _ => false,
    }
}

fn contains_any_cli(text: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|phrase| text.contains(phrase))
}

fn contains_semantic_word_cli(segment: &str) -> bool {
    let segment = segment.to_ascii_lowercase();
    [
        "api", "search", "basket", "cart", "product", "item", "order", "user", "account", "list",
        "status", "graphql", "category", "grocer",
    ]
    .iter()
    .any(|word| segment.contains(word))
}

fn is_api_path_cli(path: &str) -> bool {
    let trimmed = path.trim_matches('/').to_ascii_lowercase();
    trimmed == "graphql"
        || trimmed.starts_with("api/")
        || trimmed.starts_with("graphql/")
        || trimmed.starts_with("rest/")
        || trimmed.starts_with("rpc/")
        || trimmed
            .split('/')
            .next()
            .map(|seg| {
                seg.len() >= 2
                    && seg.starts_with('v')
                    && seg[1..].chars().all(|ch| ch.is_ascii_digit())
            })
            .unwrap_or(false)
}

fn primary_host_cli(observations: &[tapestry_core::Observation]) -> Option<String> {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for obs in observations {
        if let Some(host) = host_for(&obs.url) {
            *counts.entry(host).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(host, _)| host)
}

fn host_for(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn run_agent_task(
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

    let Some(selection) = select_agent_tool(spec, observations, task, options) else {
        out.push("No matching tool found. Try a task that mentions an observed endpoint or import a richer HAR.".to_string());
        return out.join("\n");
    };

    if trace {
        out.extend(selection.ranking_notes.iter().cloned());
    }

    if trace {
        out.push(format!(
            "[agent] selected tool={} score={}",
            selection.result.name, selection.result.score
        ));
    }

    if trace {
        out.push("[agent] schema loaded".to_string());
    }

    if trace {
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
        out.push(format_missing_argument_guidance(spec, &selection));
        return out.join("\n");
    }

    let response = tapestry_runtime::call_tool_with_options(
        spec,
        &selection.result.id,
        selection.plan.arguments,
        options,
    );
    if response.get("status").and_then(Value::as_str) == Some("success") {
        if trace {
            out.push("[agent] call_tool success".to_string());
        }
        out.push(summarize_success(&selection.result.name, &response));
    } else {
        if trace {
            out.push(format!(
                "[agent] call_tool error={}",
                response
                    .get("error_type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ));
        }
        out.push(summarize_error(&response));
    }

    out.join("\n")
}

#[derive(Clone)]
struct RankingScore {
    score: i32,
    notes: Vec<String>,
}

#[derive(Clone)]
struct AgentToolSelection {
    result: tapestry_runtime::SearchResult,
    plan: ArgumentPlan,
    replayable: bool,
    intent: tapestry_runtime::TaskIntent,
    ranking_notes: Vec<String>,
}

#[derive(Clone)]
struct ArgumentPlan {
    arguments: Value,
    provenance: Vec<ArgumentProvenance>,
    missing: Vec<MissingArgument>,
}

#[derive(Clone)]
struct ArgumentProvenance {
    name: String,
    source: &'static str,
}

#[derive(Clone)]
struct MissingArgument {
    name: String,
    type_name: String,
    examples: Vec<String>,
    default_value: Option<String>,
    reason: String,
}

fn select_agent_tool(
    spec: &tapestry_core::ToolSpec,
    observations: &[tapestry_core::Observation],
    task: &str,
    options: &tapestry_runtime::RuntimeOptions,
) -> Option<AgentToolSelection> {
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
        .next()
        .map(
            |(_, result, plan, replayable, ranking_notes)| AgentToolSelection {
                result,
                plan,
                replayable,
                intent,
                ranking_notes,
            },
        )
}

fn agent_selection_score(
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
    RankingScore { score, notes }
}

fn intent_ranking_adjustment(
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
    let has_search_terms = contains_any_cli(
        &text,
        &[
            "search", "query", "list", "products", "flights", "holidays", "items",
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

fn is_replayable(
    tool: &tapestry_core::ToolDefinition,
    observations: &[tapestry_core::Observation],
) -> bool {
    tool.example_response.is_some() || matching_replay_observation(tool, observations).is_some()
}

fn matching_replay_observation<'a>(
    tool: &tapestry_core::ToolDefinition,
    observations: &'a [tapestry_core::Observation],
) -> Option<&'a tapestry_core::Observation> {
    observations
        .iter()
        .find(|obs| replayable_observation_matches_tool(tool, obs))
}

fn replayable_observation_matches_tool(
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

fn graphql_observation_matches(
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

fn request_body_contains_key(body: Option<&Value>, key: &str) -> bool {
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

fn required_input_keys(schema: &Value) -> Vec<String> {
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

fn path_matches_tool_path(tool_path: &str, obs_path: &str) -> bool {
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

fn plan_agent_arguments(
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

fn example_input_planned_value(
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

fn observed_request_input_value(
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

fn observed_graphql_variable_value(
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

fn observed_request_body_value(obs: &tapestry_core::Observation, name: &str) -> Option<Value> {
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

fn insert_planned_arg(
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

fn required_fields(schema: &Value) -> Vec<String> {
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

fn primitive_type(schema: &Value) -> &str {
    schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("string")
}

fn is_search_like_arg(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "q" | "query" | "search" | "term" | "keyword" | "filter"
    )
}

fn first_schema_example(schema: &Value) -> Option<Value> {
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

fn missing_argument(name: &str, schema: Option<&Value>) -> MissingArgument {
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

fn schema_examples(schema: &Value) -> Vec<String> {
    schema
        .get("examples")
        .or_else(|| schema.get("enum"))
        .and_then(Value::as_array)
        .map(|values| values.iter().take(3).map(compact_value).collect())
        .unwrap_or_default()
}

fn search_term_from_task(task_lower: &str) -> Option<String> {
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

fn format_missing_argument_guidance(
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

fn first_number(text: &str) -> Option<i64> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| token.parse::<i64>().ok())
        .next()
}

fn number_after_word(text: &str, word: &str) -> Option<i64> {
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

fn infer_status(task_lower: &str, status_schema: Option<&Value>) -> Option<String> {
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

fn summarize_success(tool_name: &str, response: &Value) -> String {
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

fn summarize_items(items: &[Value]) -> String {
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

fn summarize_error(response: &Value) -> String {
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

fn compact_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

fn agent_execution_mode(options: &tapestry_runtime::RuntimeOptions) -> &'static str {
    if options.offline_har_replay {
        "offline_har_replay"
    } else {
        "live_http"
    }
}

fn parse_args(args: &str) -> Result<serde_json::Value> {
    match serde_json::from_str(args) {
        Ok(value) => Ok(value),
        Err(json_error) => parse_relaxed_object(args).with_context(|| {
            format!(
                "failed to parse --args as JSON ({json_error}); relaxed object parsing also failed"
            )
        }),
    }
}

fn parse_relaxed_object(args: &str) -> Result<serde_json::Value> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tapestry_core::*;

    #[test]
    fn agent_task_successfully_lists_and_summarizes_items() {
        let spec = spec(vec![list_tool()]);
        let output = run_agent_task(
            &spec,
            &[],
            "List the most recent 5 items and summarize them",
            false,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("Summary: 1 item(s) returned"));
        assert!(output.contains("One"));
    }

    #[test]
    fn agent_task_reports_no_matching_tool() {
        let spec = spec(vec![]);
        let output = run_agent_task(
            &spec,
            &[],
            "List items",
            false,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("No matching tool found"));
    }

    #[test]
    fn agent_task_surfaces_approval_required_for_write_tool() {
        let spec = spec(vec![create_tool(false)]);
        let output = run_agent_task(
            &spec,
            &[],
            "Create item named A",
            false,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("approve the tool"));
    }

    #[test]
    fn agent_task_surfaces_missing_required_argument() {
        let spec = spec(vec![get_tool()]);
        let output = run_agent_task(
            &spec,
            &[],
            "Get item",
            false,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("Missing required argument: id"));
        assert!(output.contains("Type: integer"));
        assert!(output.contains("tapestry tools schema fixture get_item"));
    }

    #[test]
    fn agent_task_trace_includes_each_stage() {
        let spec = spec(vec![list_tool()]);
        let output = run_agent_task(
            &spec,
            &[],
            "List 5 items",
            true,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("[agent] search_tools query=\"List 5 items\""));
        assert!(output.contains("[agent] intent=search_or_list"));
        assert!(output.contains("[agent] execution_mode=live_http"));
        assert!(output.contains("[agent] selected tool=list_items score="));
        assert!(output.contains("[agent] rank boost read_search_tool list_items"));
        assert!(output.contains("[agent] schema loaded"));
        assert!(output.contains("\"limit\":5"));
        assert!(output.contains("[agent] arg limit inferred from number_from_task"));
        assert!(output.contains("[agent] call_tool success"));
    }

    #[test]
    fn agent_task_trace_reports_offline_execution_mode() {
        let spec = spec(vec![list_tool()]);
        let options = tapestry_runtime::RuntimeOptions {
            offline_har_replay: true,
            ..tapestry_runtime::RuntimeOptions::default()
        };
        let output = run_agent_task(&spec, &[], "List 5 items", true, &options);

        assert!(output.contains("[agent] execution_mode=offline_har_replay"));
        assert!(output.contains("[agent] call_tool success"));
    }

    #[test]
    fn record_guidance_text_is_actionable() {
        let guidance = record_guidance_text();

        assert!(guidance.contains("search"));
        assert!(guidance.contains("open detail"));
        assert!(guidance.contains("add to basket"));
        assert!(guidance.contains("Press Enter when done."));
    }

    #[test]
    fn record_summary_includes_capture_quality_metrics() {
        let observations = vec![
            Observation {
                method: "GET".to_string(),
                url: "https://example.com/api/items".to_string(),
                path: "/api/items".to_string(),
                query: Default::default(),
                request_headers: Default::default(),
                request_body: None,
                response_status: Some(200),
                response_headers: Default::default(),
                response_body: Some(json!({"items":[{"id":1}]})),
                warnings: vec![],
            },
            Observation {
                method: "POST".to_string(),
                url: "https://example.com/api/items".to_string(),
                path: "/api/items".to_string(),
                query: Default::default(),
                request_headers: Default::default(),
                request_body: Some(json!({"name":"Item"})),
                response_status: Some(200),
                response_headers: Default::default(),
                response_body: None,
                warnings: vec![],
            },
        ];
        let summary = format_record_summary("fixture", &observations);

        assert!(summary.contains("Capture quality:"));
        assert!(summary.contains("API observations: 2"));
        assert!(summary.contains("Response body coverage: 50%"));
        assert!(summary.contains("Replayable tools (estimate): 1"));
        assert!(summary.contains("Missing response bodies: 1"));
        assert!(summary.contains("Recommended next action:"));
    }

    #[test]
    fn agent_task_trace_includes_write_tool_penalty_for_search_intent() {
        let mut write_tool = create_tool(false);
        write_tool.name = "create_clients.SearchResultsOption".to_string();
        write_tool.id = write_tool.name.clone();
        write_tool.description = "Search flights results option".to_string();
        write_tool.path = "/api/flights/search".to_string();
        let spec = spec(vec![write_tool]);
        let output = run_agent_task(
            &spec,
            &[],
            "Search for flights",
            true,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("[agent] intent=search_or_list"));
        assert!(output.contains("[agent] rank penalty write_tool_for_search"));
        assert!(output.contains("SearchResultsOption"));
    }

    #[test]
    fn checkout_intent_trace_prefers_cart_write_tool() {
        let mut cart = create_tool(true);
        cart.name = "create_add-line-items".to_string();
        cart.id = cart.name.clone();
        cart.path = "/checkout/cart".to_string();
        let spec = spec(vec![list_tool(), cart]);
        let output = run_agent_task(
            &spec,
            &[],
            "Add item to cart",
            true,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("[agent] intent=checkout_or_purchase"));
        assert!(output.contains("[agent] rank boost write_checkout_tool create_add-line-items"));
    }

    #[test]
    fn agent_task_offline_reports_replay_not_found() {
        let spec = spec(vec![list_tool_without_example()]);
        let options = tapestry_runtime::RuntimeOptions {
            offline_har_replay: true,
            ..tapestry_runtime::RuntimeOptions::default()
        };
        let output = run_agent_task(&spec, &[], "List 5 items", true, &options);

        assert!(output.contains("[agent] execution_mode=offline_har_replay"));
        assert!(output.contains("[agent] call_tool error=replay_not_found"));
        assert!(output.contains("No captured HAR response matched this request"));
    }

    #[test]
    fn agent_task_infers_filter_from_search_products() {
        let spec = spec(vec![search_filter_tool("filter")]);
        let output = run_agent_task(
            &spec,
            &[],
            "Search for products",
            true,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("[agent] arguments={\"filter\":\"products\"}"));
        assert!(output.contains("[agent] arg filter inferred from search_term_from_task"));
        assert!(output.contains("Summary: 1 item(s) returned"));
    }

    #[test]
    fn agent_task_infers_filter_from_search_sofas() {
        let plan = plan_agent_arguments(
            "Search for sofas",
            None,
            &[],
            &serde_json::to_value(search_filter_tool("filter")).unwrap(),
        );

        assert_eq!(plan.arguments["filter"], "sofas");
        assert!(plan.missing.is_empty());
    }

    #[test]
    fn agent_task_infers_q_query_and_search_args_from_task() {
        for name in ["q", "query", "search"] {
            let plan = plan_agent_arguments(
                "Search for sofas",
                None,
                &[],
                &serde_json::to_value(search_filter_tool(name)).unwrap(),
            );

            assert_eq!(plan.arguments[name], "sofas");
            assert!(plan.missing.is_empty());
        }
    }

    #[test]
    fn agent_task_recovers_graphql_required_object_from_example_input() {
        let mut tool = graphql_tool();
        tool.input_schema = json!({
            "type": "object",
            "properties": {
                "configs": {
                    "type": "object",
                    "properties": {
                        "term": {"type":"string"}
                    },
                    "required": ["term"]
                }
            },
            "required": ["configs"]
        });
        tool.example_input = Some(json!({
            "configs": {
                "term": "groceries"
            }
        }));
        let spec = spec(vec![tool]);

        let output = run_agent_task(
            &spec,
            &[],
            "Search groceries",
            true,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("[agent] arguments={\"configs\":{\"term\":\"groceries\"}}"));
        assert!(output.contains("[agent] arg configs inferred from example_input"));
    }

    #[test]
    fn agent_task_recovers_graphql_required_object_from_captured_variables() {
        let mut tool = graphql_tool();
        tool.input_schema = json!({
            "type": "object",
            "properties": {
                "configs": {
                    "type": "object",
                    "properties": {
                        "term": {"type":"string"}
                    },
                    "required": ["term"]
                }
            },
            "required": ["configs"]
        });
        tool.example_input = None;
        let spec = spec(vec![tool]);
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(json!({
                "operationName": "SearchGroceries",
                "query": "query SearchGroceries($configs: ConfigInput!) { taxonomy(configs: $configs) { name } }",
                "variables": {
                    "configs": {
                        "term": "groceries"
                    }
                }
            })),
            Some(json!({"data": {"taxonomy": []}})),
        )];

        let selected = select_agent_tool(
            &spec,
            &observations,
            "Search groceries",
            &tapestry_runtime::RuntimeOptions::default(),
        )
        .unwrap();

        assert_eq!(selected.plan.arguments["configs"]["term"], "groceries");
        assert!(selected
            .plan
            .provenance
            .iter()
            .any(|item| item.source == "observed_graphql_variables"));
    }

    #[test]
    fn missing_required_arg_guidance_includes_type_examples_and_schema_command() {
        let spec = spec(vec![required_category_tool()]);
        let output = run_agent_task(
            &spec,
            &[],
            "List items",
            false,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("Missing required argument: category"));
        assert!(output.contains("Type: string"));
        assert!(output.contains("Examples/defaults: examples=none, default=none"));
        assert!(output.contains("Reason: no default/example was available"));
        assert!(output.contains("Or run: tapestry tools schema fixture list_by_category"));
    }

    #[test]
    fn missing_graphql_variable_guidance_is_specific() {
        let mut tool = graphql_tool();
        tool.input_schema = json!({
            "type": "object",
            "properties": {
                "configs": {
                    "type": "object"
                }
            },
            "required": ["configs"]
        });
        tool.example_input = None;
        tool.response_schema = json!({
            "type": "object",
            "properties": {},
            "required": []
        });
        let spec = spec(vec![tool]);

        let output = run_agent_task(
            &spec,
            &[],
            "Search groceries",
            false,
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(output.contains("Missing required GraphQL variable: configs"));
        assert!(output.contains("request payloads included"));
    }

    #[test]
    fn agent_selection_penalizes_uninferable_required_args() {
        let mut bad = required_category_tool();
        bad.name = "list_products_by_category".to_string();
        bad.id = bad.name.clone();
        bad.description = "GET /api/products/category".to_string();
        let good = search_filter_tool("filter");
        let spec = spec(vec![bad, good]);

        let selected = select_agent_tool(
            &spec,
            &[],
            "Search for products",
            &tapestry_runtime::RuntimeOptions::default(),
        )
        .unwrap();

        assert_eq!(selected.result.name, "search_products");
        assert!(selected.plan.missing.is_empty());
    }

    #[test]
    fn agent_selection_offline_prefers_replayable_over_lexical_match() {
        let mut lexical = search_filter_tool("filter");
        lexical.name = "list_products.json".to_string();
        lexical.id = lexical.name.clone();
        lexical.description = "GET /api/products/search".to_string();
        lexical.example_response = None;
        lexical.response_schema = json!({"type":"object","properties":{},"required":[]});
        lexical.warnings = vec![
            "no_example_response_available".to_string(),
            "response_schema_empty".to_string(),
        ];

        let mut replayable = base_tool(
            "list_index.json",
            "GET",
            "/api/products/index",
            json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            json!({"items":[{"id":1,"title":"One"}]}),
            SafetyClassification::Read,
            true,
        );
        replayable.response_schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type":"object"}
                }
            },
            "required": ["items"]
        });

        let observations = vec![observation(
            "GET",
            "https://next.test/api/products/index",
            None,
            Some(json!({"items":[{"id":1,"title":"One"}]})),
        )];
        let options = tapestry_runtime::RuntimeOptions {
            offline_har_replay: true,
            ..tapestry_runtime::RuntimeOptions::default()
        };
        let spec = spec(vec![lexical, replayable]);

        let selected =
            select_agent_tool(&spec, &observations, "Search for products", &options).unwrap();

        assert_eq!(selected.result.name, "list_index.json");
        assert!(selected.replayable);
        assert!(selected
            .ranking_notes
            .iter()
            .any(|note| note.contains("boosted replayable")));
    }

    #[test]
    fn agent_selection_live_keeps_lexical_best_match() {
        let mut lexical = search_filter_tool("filter");
        lexical.name = "list_products.json".to_string();
        lexical.id = lexical.name.clone();
        lexical.description = "GET /api/products/search".to_string();
        lexical.example_response = None;

        let mut replayable = base_tool(
            "list_index.json",
            "GET",
            "/api/products/index",
            json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            json!({"items":[{"id":1,"title":"One"}]}),
            SafetyClassification::Read,
            true,
        );
        replayable.response_schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type":"object"}
                }
            },
            "required": ["items"]
        });

        let observations = vec![observation(
            "GET",
            "https://next.test/api/products/index",
            None,
            Some(json!({"items":[{"id":1,"title":"One"}]})),
        )];
        let spec = spec(vec![lexical, replayable]);

        let selected = select_agent_tool(
            &spec,
            &observations,
            "Search for products",
            &tapestry_runtime::RuntimeOptions::default(),
        )
        .unwrap();

        assert_eq!(selected.result.name, "list_products.json");
        assert!(!selected.replayable);
    }

    #[test]
    fn review_summary_counts_tool_quality_signals() {
        let spec = spec(vec![graphql_tool(), opaque_root_post_tool()]);
        let report = review_toolspec(&spec, None);

        assert_eq!(report.summary.total_tools, 2);
        assert_eq!(report.summary.read_tools, 1);
        assert_eq!(report.summary.unknown_tools, 1);
        assert_eq!(report.summary.graphql_tools, 1);
        assert_eq!(report.summary.opaque_root_post_tools, 1);
        assert_eq!(report.summary.tools_with_warnings, 1);
        assert_eq!(report.summary.tools_missing_examples, 1);
    }

    #[test]
    fn usefulness_grade_calculation_separates_good_and_bad_tools() {
        let good = review_tool(&graphql_tool());
        let bad = review_tool(&opaque_root_post_tool());

        assert!(matches!(good.usefulness_grade.as_str(), "A" | "B"));
        assert_eq!(bad.usefulness_grade, "D");
        assert!(good.usefulness_score > bad.usefulness_score);
    }

    #[test]
    fn review_json_output_has_expected_shape() {
        let report = review_toolspec(&spec(vec![graphql_tool()]), None);
        let value = serde_json::to_value(&report).unwrap();

        assert_eq!(value["site"], "fixture");
        assert_eq!(value["summary"]["total_tools"], 1);
        assert_eq!(value["tools"][0]["name"], "search_groceries");
        assert!(value["tools"][0]["usefulness_grade"].is_string());
    }

    #[test]
    fn graphql_tool_gets_higher_grade_than_opaque_root_post() {
        let report = review_toolspec(&spec(vec![opaque_root_post_tool(), graphql_tool()]), None);
        let graphql = report
            .tools
            .iter()
            .find(|tool| tool.name == "search_groceries")
            .unwrap();
        let opaque = report
            .tools
            .iter()
            .find(|tool| tool.name == "opaque_root_post")
            .unwrap();

        assert!(graphql.usefulness_score > opaque.usefulness_score);
    }

    #[test]
    fn warnings_reduce_usefulness_grade() {
        let mut clean = graphql_tool();
        clean.confidence.overall = 0.95;
        let mut noisy = graphql_tool();
        noisy.confidence.overall = 0.95;
        noisy.warnings = vec![
            "low_sample_count".to_string(),
            "operation_name_missing".to_string(),
            "low_semantic_confidence".to_string(),
        ];

        let clean_review = review_tool(&clean);
        let noisy_review = review_tool(&noisy);

        assert!(clean_review.usefulness_score > noisy_review.usefulness_score);
        assert!(clean_review.usefulness_grade <= noisy_review.usefulness_grade);
    }

    #[test]
    fn localization_resource_receives_lower_usefulness_grade() {
        let localization = review_tool(&localization_tool());
        let api = review_tool(&list_tool());

        assert!(api.usefulness_score > localization.usefulness_score);
        assert!(matches!(localization.usefulness_grade.as_str(), "C" | "D"));
        assert!(localization
            .negative_signals
            .iter()
            .any(|signal| signal.contains("Static localization JSON")));
    }

    #[test]
    fn platform_resource_receives_lower_usefulness_grade() {
        let platform = review_tool(&wix_manifest_tool());
        let commerce = review_tool(&commerce_query_tool());

        assert!(commerce.usefulness_score > platform.usefulness_score);
        assert!(matches!(platform.usefulness_grade.as_str(), "C" | "D"));
        assert!(platform
            .negative_signals
            .iter()
            .any(|signal| signal.contains("platform/config resource")));
    }

    #[test]
    fn commerce_api_gets_positive_review_signal() {
        let review = review_tool(&commerce_query_tool());

        assert!(review
            .positive_signals
            .iter()
            .any(|signal| signal == "Commerce API detected"));
    }

    #[test]
    fn review_text_includes_positive_negative_reasons() {
        let report = review_toolspec(&spec(vec![opaque_root_post_tool()]), None);
        let output = format_review_text(&report, false);

        assert!(output.contains("- opaque_root_post  D"));
        assert!(output.contains("+ Input schema inferred"));
        assert!(output.contains("- Missing example response"));
        assert!(output.contains("- Low semantic confidence"));
    }

    #[test]
    fn review_verbose_includes_graphql_metadata_and_schema_keys() {
        let report = review_toolspec(&spec(vec![graphql_tool()]), None);
        let output = format_review_text(&report, true);

        assert!(output.contains("GraphQL: operation=SearchGroceries type=query batched=false"));
        assert!(output.contains("Input keys: basketId, count"));
        assert!(output.contains("Response keys: data"));
        assert!(output.contains("Evidence count: 1"));
    }

    #[test]
    fn review_only_grade_filters_report_tools() {
        let report = review_toolspec(
            &spec(vec![graphql_tool(), opaque_root_post_tool()]),
            Some("D"),
        );

        assert_eq!(report.summary.total_tools, 1);
        assert_eq!(report.tools[0].name, "opaque_root_post");
        assert_eq!(report.tools[0].usefulness_grade, "D");
    }

    #[test]
    fn review_text_includes_confidence_breakdown() {
        let report = review_toolspec(&spec(vec![graphql_tool()]), None);
        let output = format_review_text(&report, false);

        assert!(output.contains("Confidence: overall=0.90, input=0.90, response=0.90"));
    }

    #[test]
    fn diagnose_reports_request_with_missing_response_body() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(
                json!({"operationName":"SearchGroceries","query":"query SearchGroceries { search { items { id } } }","variables":{}}),
            ),
            None,
        )];
        let mut tool = graphql_tool();
        tool.example_response = None;
        tool.response_schema = json!({"type":"object","properties":{},"required":[]});
        tool.warnings = vec![
            "response_schema_empty".to_string(),
            "no_example_response_available".to_string(),
        ];
        let report = diagnose_site(&spec(vec![tool]), &observations);
        let output = format_diagnose_text(&report);

        assert_eq!(report.summary.total_observations, 1);
        assert_eq!(report.summary.observations_with_response_bodies, 0);
        assert!(output.contains("Problem: request observed, but no response body captured."));
        assert!(output.contains("Preserve log"));
    }

    #[test]
    fn diagnose_counts_json_response_body() {
        let observations = vec![observation(
            "GET",
            "https://app.test/api/items",
            None,
            Some(json!({"items": []})),
        )];
        let mut tool = list_tool();
        tool.response_schema = json!({
            "type": "object",
            "properties": {
                "items": {"type":"array","items":{}}
            },
            "required": ["items"]
        });
        let report = diagnose_site(&spec(vec![tool]), &observations);

        assert_eq!(report.summary.json_responses, 1);
        assert_eq!(report.summary.observations_with_response_bodies, 1);
        assert!(!report.tools[0].response_schema_empty);
    }

    #[test]
    fn diagnose_counts_graphql_mapped_and_unmapped_responses() {
        let mapped = observation(
            "POST",
            "https://xapi.test/",
            Some(
                json!({"operationName":"SearchGroceries","query":"query SearchGroceries { search { items { id } } }","variables":{}}),
            ),
            Some(json!({"data":{"search":{"items":[]}}})),
        );
        let unmapped = observation(
            "POST",
            "https://xapi.test/",
            Some(
                json!({"operationName":"Other","query":"query Other { other { id } }","variables":{}}),
            ),
            Some(json!({"errors":[{"message":"no data"}]})),
        );
        let report = diagnose_site(&spec(vec![graphql_tool()]), &[mapped, unmapped]);

        assert_eq!(report.summary.graphql_requests, 2);
        assert_eq!(report.summary.graphql_responses_mapped, 1);
    }

    #[test]
    fn diagnose_json_output_has_expected_shape() {
        let observations = vec![observation(
            "POST",
            "https://xapi.test/",
            Some(
                json!({"operationName":"SearchGroceries","query":"query SearchGroceries { search { items { id } } }","variables":{}}),
            ),
            Some(json!({"data":{"search":{"items":[]}}})),
        )];
        let report = diagnose_site(&spec(vec![graphql_tool()]), &observations);
        let value = serde_json::to_value(&report).unwrap();

        assert_eq!(value["site"], "fixture");
        assert_eq!(value["summary"]["generated_tools"], 1);
        assert_eq!(value["tools"][0]["name"], "search_groceries");
        assert!(value["tools"][0]["remediation"].is_string());
    }

    #[test]
    fn diagnose_reports_static_resource_only_capture() {
        let observations = vec![observation(
            "GET",
            "https://game.test/lang/en.json",
            None,
            Some(json!({"PLAY":"Play","SAVE":"Save"})),
        )];
        let report = diagnose_site(&spec(vec![localization_tool()]), &observations);
        let output = format_diagnose_text(&report);

        assert_eq!(report.summary.generated_tools, 1);
        assert_eq!(report.summary.static_resource_tools, 1);
        assert!(output.contains("Only static JSON/config/localization resources were captured."));
        assert!(output.contains("account, save, search, or data API calls"));
    }

    #[test]
    fn diagnose_reports_commerce_apis_with_missing_response_bodies() {
        let observations = vec![observation(
            "POST",
            "https://www.justkandy.co.uk/_api/cart-v2/v2/carts/current/add-line-items",
            Some(json!({"lineItems":[{"id":"1"}]})),
            None,
        )];
        let mut tool = cart_tool();
        tool.response_schema = json!({"type":"object","properties":{},"required":[]});
        tool.example_response = None;

        let report = diagnose_site(&spec(vec![tool, wix_manifest_tool()]), &observations);
        let output = format_diagnose_text(&report);

        assert_eq!(report.summary.commerce_api_tools, 1);
        assert_eq!(report.summary.platform_resource_tools, 1);
        assert!(output.contains(
            "Commerce API requests were captured, but many response bodies are missing."
        ));
        assert!(output.contains("Many Wix platform/config resources were captured."));
    }

    #[test]
    fn validate_reports_success_top_tool_and_summaries() {
        let spec = spec(vec![list_tool()]);
        let observations = vec![observation(
            "GET",
            "https://app.test/api/items",
            None,
            Some(json!({"items":[{"id":1,"title":"One"}],"total":1})),
        )];

        let report = validate_site(
            &spec,
            &observations,
            "List the most recent 5 items",
            &tapestry_runtime::RuntimeOptions::default(),
        );
        let text = format_validate_text(&report);

        assert!(report.agent_task.success);
        assert_eq!(
            report.agent_task.top_tool_used.as_deref(),
            Some("list_items")
        );
        assert_eq!(report.review_summary.total_tools, 1);
        assert_eq!(report.diagnose_summary.generated_tools, 1);
        assert!(text.contains("Agent result: success"));
        assert!(text.contains("Recommended next action:"));
    }

    #[test]
    fn validate_reports_no_matching_tool_failure() {
        let report = validate_site(
            &spec(vec![]),
            &[],
            "Find baskets",
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(!report.agent_task.success);
        assert_eq!(
            report.agent_task.failure_type.as_deref(),
            Some("no_matching_tool")
        );
        assert_eq!(report.agent_task.top_tool_used, None);
        assert!(report
            .recommended_next_action
            .contains("Capture a richer task flow"));
    }

    #[test]
    fn validate_recommends_recapture_when_response_bodies_missing() {
        let observations = vec![observation("GET", "https://app.test/api/items", None, None)];
        let mut tool = list_tool();
        tool.example_response = None;
        let report = validate_site(
            &spec(vec![tool]),
            &observations,
            "List the most recent 5 items",
            &tapestry_runtime::RuntimeOptions::default(),
        );

        assert!(report.diagnose_summary.tools_missing_examples > 0);
        assert!(report
            .recommended_next_action
            .contains("Re-capture the HAR"));
    }

    #[test]
    fn validate_offline_reports_replayability_aware_selection() {
        let mut lexical = search_filter_tool("filter");
        lexical.name = "list_products.json".to_string();
        lexical.id = lexical.name.clone();
        lexical.description = "GET /api/products/search".to_string();
        lexical.example_response = None;
        lexical.response_schema = json!({"type":"object","properties":{},"required":[]});

        let mut replayable = base_tool(
            "list_index.json",
            "GET",
            "/api/products/index",
            json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            json!({"items":[{"id":1,"title":"One"}]}),
            SafetyClassification::Read,
            true,
        );
        replayable.response_schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type":"object"}
                }
            },
            "required": ["items"]
        });

        let observations = vec![observation(
            "GET",
            "https://next.test/api/products/index",
            None,
            Some(json!({"items":[{"id":1,"title":"One"}]})),
        )];
        let options = tapestry_runtime::RuntimeOptions {
            offline_har_replay: true,
            ..tapestry_runtime::RuntimeOptions::default()
        };
        let report = validate_site(
            &spec(vec![lexical, replayable]),
            &observations,
            "Search for products",
            &options,
        );

        assert!(report.agent_task.success);
        assert_eq!(
            report.agent_task.top_tool_used.as_deref(),
            Some("list_index.json")
        );
        assert!(report
            .agent_task
            .ranking_note
            .as_deref()
            .unwrap_or_default()
            .contains("Offline ranking considered replayability."));
    }

    #[test]
    fn validate_passes_offline_mode_to_runtime() {
        let options = tapestry_runtime::RuntimeOptions {
            offline_har_replay: true,
            ..tapestry_runtime::RuntimeOptions::default()
        };
        let report = validate_site(
            &spec(vec![list_tool_without_example()]),
            &[],
            "List the most recent 5 items",
            &options,
        );

        assert!(!report.agent_task.success);
        assert_eq!(
            report.agent_task.failure_type.as_deref(),
            Some("no_replayable_tool")
        );
    }

    #[test]
    fn validate_json_output_has_expected_shape() {
        let report = validate_site(
            &spec(vec![list_tool()]),
            &[],
            "List the most recent 5 items",
            &tapestry_runtime::RuntimeOptions::default(),
        );
        let value = serde_json::to_value(&report).unwrap();

        assert_eq!(value["site"], "fixture");
        assert_eq!(value["agent_task"]["top_tool_used"], "list_items");
        assert!(value["review_summary"]["total_tools"].is_number());
        assert!(value["diagnose_summary"]["generated_tools"].is_number());
        assert!(value["recommended_next_action"].is_string());
    }

    #[test]
    fn benchmark_suite_freezes_expected_sites_and_tasks() {
        let cases = benchmark_cases();
        let sites = cases
            .iter()
            .map(|case| case.site.as_str())
            .collect::<Vec<_>>();

        assert_eq!(cases.len(), 11);
        assert!(sites.contains(&"tesco"));
        assert!(sites.contains(&"next"));
        assert!(sites.contains(&"next-cdp"));
        assert!(sites.contains(&"justkandy"));
        assert!(sites.contains(&"justkandy-cdp"));
        assert!(sites.contains(&"melvor"));
        assert!(sites.contains(&"argos"));
        assert!(sites.contains(&"amazon"));
        assert!(sites.contains(&"wowhead"));
        assert!(sites.contains(&"skyscanner"));
        assert!(sites.contains(&"onthebeach"));
    }

    #[test]
    fn benchmark_report_serializes_expected_shape() {
        let report = BenchmarkReport {
            total_sites: 1,
            success_count: 1,
            failure_count: 0,
            expected_match_count: 1,
            drift_count: 0,
            cases: vec![BenchmarkCaseReport {
                site: "fixture".to_string(),
                capture_variant: Some("har".to_string()),
                task: "Search for products".to_string(),
                expected_outcome: "success".to_string(),
                expected_tool: Some("list_items".to_string()),
                selected_tool: Some("list_items".to_string()),
                success: true,
                failure_type: None,
                failure_bucket: "success".to_string(),
                outcome_matches_expected: true,
                tool_matches_expected: Some(true),
                review_grade: Some("A".to_string()),
                diagnose_summary: DiagnoseSummary {
                    total_observations: 1,
                    candidate_api_observations: 1,
                    generated_tools: 1,
                    observations_with_response_bodies: 1,
                    json_responses: 1,
                    graphql_requests: 0,
                    graphql_responses_mapped: 0,
                    tools_missing_examples: 0,
                    tools_with_empty_response_schemas: 0,
                    static_resource_tools: 0,
                    platform_resource_tools: 0,
                    telemetry_tools: 0,
                    commerce_api_tools: 1,
                },
                ranking_note: Some("Offline ranking considered replayability.".to_string()),
            }],
        };
        let value = serde_json::to_value(&report).unwrap();
        let text = format_benchmark_text(&report);

        assert_eq!(value["total_sites"], 1);
        assert_eq!(value["cases"][0]["site"], "fixture");
        assert_eq!(value["cases"][0]["expected_outcome"], "success");
        assert_eq!(value["cases"][0]["failure_bucket"], "success");
        assert!(text.contains("Benchmark suite: 1 site(s)"));
        assert!(text.contains("Expected matches: 1 drift: 0"));
        assert!(text.contains("expected=success"));
        assert!(text.contains("failure_bucket=success"));
        assert!(text.contains("review_grade=A"));
    }

    #[test]
    fn cli_parses_record_command_arguments() {
        let cli = Cli::parse_from([
            "tapestry",
            "record",
            "https://example.com",
            "--site",
            "demo",
            "--browser",
            "chrome.exe",
            "--headless",
            "--timeout-secs",
            "30",
            "--max-body-bytes",
            "1024",
            "--include-third-party",
            "--output-observations",
            "--keep-profile",
        ]);

        match cli.command {
            Command::Record {
                url,
                site,
                browser,
                headless,
                timeout_secs,
                max_body_bytes,
                include_third_party,
                output_observations,
                keep_profile,
            } => {
                assert_eq!(url, "https://example.com");
                assert_eq!(site, "demo");
                assert_eq!(browser.as_deref(), Some(std::path::Path::new("chrome.exe")));
                assert!(headless);
                assert_eq!(timeout_secs, 30);
                assert_eq!(max_body_bytes, 1024);
                assert!(include_third_party);
                assert!(output_observations);
                assert!(keep_profile);
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn runtime_options_prefer_har_replay_for_fixture_har_site() {
        let mut spec = spec(vec![list_tool()]);
        spec.site.source = vec!["har".to_string()];
        spec.site.base_url = Some("http://localhost:3000".to_string());

        let options = runtime_options_for(&spec, 1, false, false);

        assert!(options.allow_har_replay);
        assert!(options.prefer_har_replay);
    }

    #[test]
    fn runtime_options_live_forces_live_http() {
        let mut spec = spec(vec![list_tool()]);
        spec.site.source = vec!["har".to_string()];
        spec.site.base_url = Some("http://localhost:3000".to_string());

        let options = runtime_options_for(&spec, 3, true, false);

        assert_eq!(options.max_pages, 3);
        assert!(!options.allow_har_replay);
        assert!(!options.prefer_har_replay);
    }

    #[test]
    fn runtime_options_do_not_prefer_replay_for_normal_live_site() {
        let mut spec = spec(vec![list_tool()]);
        spec.site.name = "production".to_string();
        spec.site.source = vec!["har".to_string()];
        spec.site.base_url = Some("https://api.example.com".to_string());

        let options = runtime_options_for(&spec, 1, false, false);

        assert!(options.allow_har_replay);
        assert!(!options.prefer_har_replay);
    }

    #[test]
    fn runtime_options_offline_forces_har_replay_only() {
        let spec = spec(vec![list_tool()]);

        let options = runtime_options_for(&spec, 2, false, true);

        assert_eq!(options.max_pages, 2);
        assert!(options.allow_har_replay);
        assert!(options.prefer_har_replay);
        assert!(options.offline_har_replay);
    }

    fn spec(tools: Vec<ToolDefinition>) -> ToolSpec {
        ToolSpec {
            site: SiteInfo {
                name: "fixture".to_string(),
                base_url: None,
                source: vec!["test".to_string()],
                generated_at: None,
                spec_version: "0.1.0".to_string(),
            },
            tools,
        }
    }

    fn list_tool() -> ToolDefinition {
        base_tool(
            "list_items",
            "GET",
            "/api/items",
            json!({
                "type": "object",
                "properties": {
                    "limit": {"type":"integer"},
                    "page": {"type":"integer", "default": 1}
                },
                "required": []
            }),
            json!({"items":[{"id":1,"title":"One"}],"total":1}),
            SafetyClassification::Read,
            true,
        )
    }

    fn list_tool_without_example() -> ToolDefinition {
        let mut tool = list_tool();
        tool.example_response = None;
        tool
    }

    fn get_tool() -> ToolDefinition {
        let mut tool = base_tool(
            "get_item",
            "GET",
            "/api/items/{id}",
            json!({
                "type": "object",
                "properties": {
                    "id": {"type":"integer"}
                },
                "required": ["id"]
            }),
            json!({"id":1,"title":"One"}),
            SafetyClassification::Read,
            true,
        );
        tool.path_params = vec![PathParameter {
            name: "id".to_string(),
            schema: json!({"type":"integer"}),
            confidence: 0.9,
            examples: vec![json!(1)],
        }];
        tool
    }

    fn create_tool(approved: bool) -> ToolDefinition {
        base_tool(
            "create_item",
            "POST",
            "/api/items",
            json!({
                "type": "object",
                "properties": {
                    "name": {"type":"string"}
                },
                "required": ["name"]
            }),
            json!({"id":1,"name":"A"}),
            SafetyClassification::Write,
            approved,
        )
    }

    fn search_filter_tool(arg_name: &str) -> ToolDefinition {
        base_tool(
            "search_products",
            "GET",
            "/api/products/search",
            json!({
                "type": "object",
                "properties": {
                    arg_name: {"type":"string"}
                },
                "required": [arg_name]
            }),
            json!({"items":[{"id":1,"title":"Sofa"}]}),
            SafetyClassification::Read,
            true,
        )
    }

    fn required_category_tool() -> ToolDefinition {
        base_tool(
            "list_by_category",
            "GET",
            "/api/products/category",
            json!({
                "type": "object",
                "properties": {
                    "category": {"type":"string"}
                },
                "required": ["category"]
            }),
            json!({"items":[{"id":1,"title":"Chair"}]}),
            SafetyClassification::Read,
            true,
        )
    }

    fn graphql_tool() -> ToolDefinition {
        let mut tool = base_tool(
            "search_groceries",
            "POST",
            "/",
            json!({
                "type": "object",
                "properties": {
                    "basketId": {"type":"string"},
                    "count": {"type":"integer"}
                },
                "required": []
            }),
            json!({"data":{"search":{"items":[{"id":1,"title":"Bread"}]}}}),
            SafetyClassification::Read,
            true,
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
        tool.response_schema = json!({
            "type": "object",
            "properties": {
                "data": {"type":"object","properties":{"search":{"type":"object"}}}
            },
            "required": ["data"]
        });
        tool
    }

    fn opaque_root_post_tool() -> ToolDefinition {
        let mut tool = base_tool(
            "opaque_root_post",
            "POST",
            "/",
            json!({"type":"object","properties":{"payload":{"type":"object"}},"required":[]}),
            json!({"ok": true}),
            SafetyClassification::Unknown,
            false,
        );
        tool.response_schema = json!({"type":"object","properties":{},"required":[]});
        tool.example_response = None;
        tool.confidence.overall = 0.35;
        tool.warnings = vec![
            "opaque_root_post".to_string(),
            "operation_name_missing".to_string(),
            "low_semantic_confidence".to_string(),
        ];
        tool
    }

    fn localization_tool() -> ToolDefinition {
        let mut tool = base_tool(
            "list_en.json",
            "GET",
            "/lang/en.json",
            json!({"type":"object","properties":{},"required":[]}),
            json!({"PLAY":"Play","SAVE":"Save"}),
            SafetyClassification::Read,
            true,
        );
        tool.resource_kind = ResourceKind::LocalizationResource;
        tool.response_schema = json!({
            "type": "object",
            "properties": {
                "PLAY": {"type":"string"},
                "SAVE": {"type":"string"}
            },
            "required": ["PLAY", "SAVE"]
        });
        tool.warnings = vec!["localization_resource".to_string()];
        tool
    }

    fn wix_manifest_tool() -> ToolDefinition {
        let mut tool = base_tool(
            "list_rb_wixui.corvid.manifest.min.json",
            "GET",
            "/services/editor-elements/1.15085.0/rb_wixui.corvid.manifest.min.json",
            json!({"type":"object","properties":{},"required":[]}),
            json!({"components":{"ProductSpecification":["bundle.js"],"SearchBox":["bundle.js"]}}),
            SafetyClassification::Read,
            true,
        );
        tool.resource_kind = ResourceKind::PlatformResource;
        tool.response_schema = json!({
            "type":"object",
            "properties":{"components":{"type":"object"}},
            "required":["components"]
        });
        tool.warnings = vec!["platform_resource".to_string()];
        tool
    }

    fn commerce_query_tool() -> ToolDefinition {
        let mut tool = base_tool(
            "list_query",
            "GET",
            "/_api/cloud-data/v2/items/query",
            json!({
                "type":"object",
                "properties":{"filter":{"type":"string"}},
                "required":[]
            }),
            json!({"items":[{"name":"Sweets"}]}),
            SafetyClassification::Read,
            true,
        );
        tool.resource_kind = ResourceKind::CommerceApi;
        tool.warnings = vec!["commerce_api".to_string()];
        tool
    }

    fn cart_tool() -> ToolDefinition {
        let mut tool = base_tool(
            "create_add-line-items",
            "POST",
            "/_api/cart-v2/v2/carts/current/add-line-items",
            json!({
                "type":"object",
                "properties":{"lineItems":{"type":"array"}},
                "required":["lineItems"]
            }),
            json!({"cart":{"lineItems":[]}}),
            SafetyClassification::Write,
            false,
        );
        tool.resource_kind = ResourceKind::CommerceApi;
        tool.warnings = vec!["commerce_api".to_string()];
        tool
    }

    fn base_tool(
        name: &str,
        method: &str,
        path: &str,
        input_schema: Value,
        example_response: Value,
        safety: SafetyClassification,
        approved: bool,
    ) -> ToolDefinition {
        ToolDefinition {
            id: name.to_string(),
            name: name.to_string(),
            description: format!("{method} {path}"),
            method: method.to_string(),
            path: path.to_string(),
            resource_kind: ResourceKind::ApiAction,
            graphql: None,
            path_params: vec![],
            input_schema,
            response_schema: json!({"type":"object","properties":{},"required":[]}),
            example_response: Some(example_response),
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
                .map(|(key, value)| (key.to_string(), Value::String(value.to_string())))
                .collect(),
            request_headers: request_body
                .as_ref()
                .map(|_| {
                    std::collections::BTreeMap::from([(
                        "content-type".to_string(),
                        "application/json".to_string(),
                    )])
                })
                .unwrap_or_default(),
            request_body,
            response_status: Some(200),
            response_headers: response_body
                .as_ref()
                .map(|_| {
                    std::collections::BTreeMap::from([(
                        "content-type".to_string(),
                        "application/json".to_string(),
                    )])
                })
                .unwrap_or_default(),
            response_body,
            warnings: vec![],
        }
    }
}
