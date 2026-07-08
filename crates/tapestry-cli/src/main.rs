use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use tracing::info;

mod commands;
mod mcp;
mod support;

use commands::agent::*;
use commands::approve::*;
use commands::benchmark::*;
use commands::capture::*;
use commands::diagnose::*;
use commands::doctor::*;
use commands::review::*;
use commands::validate::*;
use support::*;

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
        #[arg(
            long,
            help = "Replace existing observations instead of merging into them"
        )]
        replace: bool,
        #[arg(long, help = "Immediately run `generate` after a successful import")]
        generate: bool,
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
        #[arg(
            long,
            default_value_t = 1,
            help = "Minimum number of candidate API observations required before failing"
        )]
        min_api_observations: usize,
        #[arg(
            long,
            help = "Allow low-signal captures to be saved instead of exiting non-zero"
        )]
        allow_low_signal: bool,
        #[arg(
            long,
            help = "Replace existing observations instead of merging into them"
        )]
        replace: bool,
        #[arg(
            long,
            help = "Use a throwaway browser profile instead of the site's persistent one"
        )]
        ephemeral_profile: bool,
        #[arg(long, help = "Immediately run `generate` after a successful recording")]
        generate: bool,
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
        about = "Manage stored credentials for a site",
        after_help = "Examples:\n  tapestry credentials demo list\n  tapestry credentials demo set Authorization \"Bearer eyJ...\"\n  tapestry credentials demo set Cookie \"session=abc\"\n  tapestry credentials demo from-har capture.har\n  tapestry credentials demo purge"
    )]
    Credentials {
        site: String,
        #[command(subcommand)]
        command: CredentialsCommand,
    },
    #[command(
        about = "Approve tools that are blocked pending review, or list approval status",
        after_help = "Examples:\n  tapestry approve demo --list\n  tapestry approve demo create_items\n  tapestry approve demo create_items --note \"reviewed evidence, safe test env\"\n  tapestry approve demo create_items --revoke"
    )]
    Approve {
        #[arg(help = "Local site name with a generated ToolSpec")]
        site: String,
        #[arg(help = "Tool id or name to approve (omit to list approval status)")]
        tool_id: Option<String>,
        #[arg(long, help = "List approval status for all tools")]
        list: bool,
        #[arg(long, help = "Revoke a previously granted approval")]
        revoke: bool,
        #[arg(long, help = "Optional note stored with the approval")]
        note: Option<String>,
    },
    #[command(
        about = "Refresh stored credentials by logging in through a real browser",
        after_help = "Examples:\n  tapestry reauth demo\n  tapestry reauth demo --url https://app.example.com/login\n\nA browser window opens; log in and perform one authenticated action, then press Enter in this terminal. Tapestry harvests the fresh auth headers from first-party traffic and updates the site's stored credentials. Your login keystrokes are never captured — only the resulting request headers."
    )]
    Reauth {
        #[arg(help = "Local site name whose credentials should be refreshed")]
        site: String,
        #[arg(long, help = "Login URL to open (defaults to the site's base URL)")]
        url: Option<String>,
        #[arg(long, help = "Explicit browser executable path")]
        browser: Option<PathBuf>,
        #[arg(long, default_value_t = 300, help = "Timeout in seconds")]
        timeout_secs: u64,
        #[arg(
            long,
            help = "Use a throwaway browser profile instead of the site's persistent one"
        )]
        ephemeral_profile: bool,
    },
    #[command(
        about = "Check the local environment and site data for common problems",
        after_help = "Example:\n  tapestry doctor"
    )]
    Doctor,
    #[command(
        about = "Serve the native runtime as an MCP stdio server for agents",
        after_help = "Examples:\n  tapestry serve --site demo\n  tapestry serve\n\nAdd to an MCP client config (e.g. .mcp.json):\n  {\n    \"mcpServers\": {\n      \"tapestry\": { \"command\": \"tapestry\", \"args\": [\"serve\", \"--site\", \"demo\"] }\n    }\n  }"
    )]
    Serve {
        #[arg(
            long,
            help = "Default site for tool calls; without it, agents pass `site` per call"
        )]
        site: Option<String>,
        #[arg(long, help = "Force live HTTP execution instead of HAR replay")]
        live: bool,
        #[arg(long, help = "Use captured HAR responses only; never call the network")]
        offline: bool,
        #[arg(
            long,
            default_value_t = 1,
            help = "Maximum pages for simple runtime pagination"
        )]
        max_pages: usize,
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

#[derive(Debug, Subcommand)]
enum CredentialsCommand {
    #[command(about = "List stored credential header names (values are not shown)")]
    List,
    #[command(about = "Store a credential header value")]
    Set {
        #[arg(help = "HTTP header name, e.g. Authorization or Cookie")]
        header: String,
        #[arg(help = "Header value to store")]
        value: String,
    },
    #[command(about = "Remove a stored credential header")]
    Remove {
        #[arg(help = "HTTP header name to remove")]
        header: String,
    },
    #[command(about = "Remove all credentials for this site")]
    Purge,
    #[command(about = "Extract auth headers from a raw HAR file and store them")]
    FromHar {
        #[arg(help = "Path to the HAR file to extract credentials from")]
        har: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Import {
            har,
            site,
            replace,
            generate,
        } => {
            validate_site_name(&site)?;
            eprintln!(
                "Warning: HAR files may contain credentials and personal data. Tapestry will persist redacted observations, not the raw HAR."
            );
            info!(command = "import", site, har = %har.display(), "starting HAR import");
            let observations = tapestry_input::import_har(&har)?;
            // Same early feedback `record` gives: fragment endpoints, missing
            // bodies, and no-API-traffic captures should be visible at import
            // time, not discovered after generate.
            let summary = tapestry_input::CaptureSummary::from_observations(&observations);
            for warning in summary.capture_warnings() {
                eprintln!("Warning: {warning}");
            }
            let source = format!("har:{}", har.display());
            let outcome = store_capture(&site, &source, observations, replace)?;
            println!("{}", format_capture_message(&site, &outcome, "Imported"));
            if generate {
                run_generate(&site)?;
            } else {
                print_generate_nudge(&site);
            }
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
            min_api_observations,
            allow_low_signal,
            replace,
            ephemeral_profile,
            generate,
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
                    profile_dir: site_profile_dir(&site, ephemeral_profile),
                },
            )?;
            let observations = record.observations;
            let summary = tapestry_input::CaptureSummary::from_observations(&observations);
            let warnings = summary.capture_warnings();
            for warning in &warnings {
                eprintln!("Warning: {warning}");
            }
            // Reject a low-signal capture before persisting anything, so a
            // failed re-record never overwrites (or, with --replace, destroys)
            // an existing good capture.
            if let Some(message) =
                record_low_signal_failure(&summary, min_api_observations, allow_low_signal)
            {
                anyhow::bail!(
                    "{} Nothing was saved. Use --allow-low-signal to keep this capture anyway.",
                    message
                );
            }
            if output_observations {
                println!("{}", serde_json::to_string_pretty(&observations)?);
            }
            let summary_text = format_record_summary(&site, &observations);
            let outcome = store_capture(&site, &format!("cdp:{url}"), observations, replace)?;
            if outcome.merged_into_existing {
                println!("{}", format_capture_message(&site, &outcome, "Recorded"));
            }
            println!("{summary_text}");
            if generate {
                run_generate(&site)?;
            } else {
                print_generate_nudge(&site);
            }
        }
        Command::Generate { site } => {
            run_generate(&site)?;
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
                    let mut removed_any = false;
                    let credentials = dir.join("credentials.json");
                    if credentials.exists() {
                        fs::remove_file(&credentials)?;
                        removed_any = true;
                    }
                    let profile = dir.join("browser-profile");
                    if profile.exists() {
                        fs::remove_dir_all(&profile)?;
                        removed_any = true;
                    }
                    if removed_any {
                        println!(
                            "Purged secrets for site '{}' (credentials and browser profile)",
                            site
                        );
                        purged = true;
                    } else {
                        println!("No secrets found for site '{}'", site);
                    }
                }
                if observations {
                    let obs_path = dir.join("observations.json");
                    if obs_path.exists() {
                        fs::remove_file(&obs_path)?;
                        let mut meta = load_site_meta(&site);
                        if !meta.capture_sessions.is_empty() {
                            meta.capture_sessions.clear();
                            save_site_meta(&site, &meta)?;
                        }
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
            let mut options = runtime_options_for(&spec, max_pages, live, offline);
            options.credentials = load_site_credentials(&site)?;
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
        Command::Credentials { site, command } => {
            validate_site_name(&site)?;
            let dir = site_dir(&site);
            fs::create_dir_all(&dir)?;
            let creds_path = dir.join("credentials.json");
            match command {
                CredentialsCommand::List => {
                    let creds = load_credentials_raw(&creds_path)?;
                    if creds.is_empty() {
                        println!("No credentials stored for site '{}'.", site);
                    } else {
                        println!("Stored credentials for site '{}':", site);
                        for (name, entry) in &creds {
                            let captured_at = entry
                                .get("captured_at")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown");
                            println!("  {name}  (captured {captured_at})");
                        }
                    }
                }
                CredentialsCommand::Set { header, value } => {
                    let mut creds = load_credentials_raw(&creds_path)?;
                    creds.insert(
                        header.clone(),
                        json!({
                            "value": value,
                            "captured_at": current_timestamp_cli()
                        }),
                    );
                    write_secret(&creds_path, &serde_json::to_string_pretty(&creds)?)?;
                    println!("Stored credential '{header}' for site '{site}'.");
                }
                CredentialsCommand::Remove { header } => {
                    let mut creds = load_credentials_raw(&creds_path)?;
                    if creds.remove(&header).is_some() {
                        write_secret(&creds_path, &serde_json::to_string_pretty(&creds)?)?;
                        println!("Removed credential '{header}' for site '{site}'.");
                    } else {
                        println!("No credential '{header}' found for site '{site}'.");
                    }
                }
                CredentialsCommand::Purge => {
                    if creds_path.exists() {
                        fs::remove_file(&creds_path)?;
                        println!("Purged all credentials for site '{site}'.");
                    } else {
                        println!("No credentials found for site '{site}'.");
                    }
                }
                CredentialsCommand::FromHar { har } => {
                    let raw = fs::read_to_string(&har).context("failed to read HAR file")?;
                    let json: Value =
                        serde_json::from_str(&raw).context("failed to parse HAR JSON")?;
                    let entries = json
                        .get("log")
                        .and_then(|v| v.get("entries"))
                        .and_then(|v| v.as_array())
                        .context("HAR missing log.entries")?;

                    let secret_headers = [
                        "authorization",
                        "cookie",
                        "x-api-key",
                        "x-auth-token",
                        "x-access-token",
                        "x-session-token",
                    ];
                    let mut extracted: std::collections::BTreeMap<String, Value> =
                        std::collections::BTreeMap::new();
                    for entry in entries {
                        if let Some(headers) = entry
                            .get("request")
                            .and_then(|r| r.get("headers"))
                            .and_then(|h| h.as_array())
                        {
                            for h in headers {
                                let name = h
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string();
                                let value = h
                                    .get("value")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string();
                                if secret_headers.contains(&name.to_ascii_lowercase().as_str())
                                    && !value.is_empty()
                                    && !extracted.contains_key(&name)
                                {
                                    extracted.insert(
                                        name,
                                        json!({
                                            "value": value,
                                            "captured_at": current_timestamp_cli()
                                        }),
                                    );
                                }
                            }
                        }
                    }

                    if extracted.is_empty() {
                        println!("No auth headers found in HAR.");
                    } else {
                        let mut existing = load_credentials_raw(&creds_path)?;
                        for (name, entry) in &extracted {
                            existing.insert(name.clone(), entry.clone());
                        }
                        write_secret(&creds_path, &serde_json::to_string_pretty(&existing)?)?;
                        println!(
                            "Extracted {} credential(s) from HAR for site '{site}':",
                            extracted.len()
                        );
                        for name in extracted.keys() {
                            println!("  {name}");
                        }
                    }
                }
            }
        }
        Command::Reauth {
            site,
            url,
            browser,
            timeout_secs,
            ephemeral_profile,
        } => {
            validate_site_name(&site)?;
            let target_url = match url {
                Some(url) => url,
                None => load_site_spec(&site)
                    .ok()
                    .and_then(|spec| spec.site.base_url)
                    .context("site has no base URL; pass the login page with --url <url>")?,
            };
            info!(command = "reauth", site, url = %target_url, "starting credential refresh");
            eprintln!(
                "A browser window will open at {target_url}.\n\
                 1. Log in as usual.\n\
                 2. Perform one authenticated action (open a list, view a record).\n\
                 3. Press Enter here to finish.\n\
                 Tapestry only harvests the resulting auth headers; keystrokes are not captured."
            );
            let harvested = tapestry_input::reauth(
                &target_url,
                &tapestry_input::ReauthOptions {
                    browser,
                    timeout_secs,
                    profile_dir: site_profile_dir(&site, ephemeral_profile),
                },
            )?;
            if harvested.is_empty() {
                anyhow::bail!(
                    "No credential headers were observed. Make sure you logged in and triggered at least one API request, then try again."
                );
            }
            let dir = site_dir(&site);
            fs::create_dir_all(&dir)?;
            let creds_path = dir.join("credentials.json");
            let mut creds = load_credentials_raw(&creds_path)?;
            let mut names: Vec<String> = Vec::new();
            for (name, value) in harvested {
                creds.insert(
                    name.clone(),
                    json!({
                        "value": value,
                        "captured_at": current_timestamp_cli()
                    }),
                );
                names.push(name);
            }
            write_secret(&creds_path, &serde_json::to_string_pretty(&creds)?)?;
            println!(
                "Refreshed {} credential header(s) for site '{}': {}",
                names.len(),
                site,
                names.join(", ")
            );
        }
        Command::Approve {
            site,
            tool_id,
            list,
            revoke,
            note,
        } => {
            validate_site_name(&site)?;
            run_approve(&site, tool_id.as_deref(), list, revoke, note)?;
        }
        Command::Doctor => {
            println!("{}", run_doctor());
        }
        Command::Serve {
            site,
            live,
            offline,
            max_pages,
        } => {
            if let Some(site) = &site {
                validate_site_name(site)?;
            }
            info!(command = "serve", site = ?site, "starting MCP stdio server");
            mcp::serve(mcp::McpServerConfig {
                default_site: site,
                live,
                offline,
                max_pages,
            })?;
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
            let mut options = runtime_options_for(&spec, max_pages, live, offline);
            options.credentials = load_site_credentials(&site)?;
            let out =
                tapestry_runtime::call_tool_with_options(&spec, &tool_id, args_json, &options);
            record_tool_health(&site, &spec, &tool_id, &out);
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
