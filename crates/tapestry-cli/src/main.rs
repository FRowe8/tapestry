use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Map, Value};
use std::{fs, path::PathBuf};
use tracing::info;

mod commands;
mod mcp;
mod support;

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
    select_agent_candidates(spec, observations, task, options)
        .into_iter()
        .next()
}

fn select_agent_candidates(
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

fn is_framework_path_cli(path: &str) -> bool {
    path.contains("/_next/")
        || path.contains("/_nuxt/")
        || path.contains("/_app/")
        || path.contains("/_astro/")
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
    fn merge_skips_exact_duplicates_and_keeps_new_evidence() {
        let existing = vec![observation(
            "GET",
            "http://x.test/api/items",
            None,
            Some(json!({"items":[1]})),
        )];
        let incoming = vec![
            // Exact duplicate: dropped.
            observation(
                "GET",
                "http://x.test/api/items",
                None,
                Some(json!({"items":[1]})),
            ),
            // Same endpoint, different response: kept as new evidence.
            observation(
                "GET",
                "http://x.test/api/items",
                None,
                Some(json!({"items":[2]})),
            ),
            // New endpoint: kept.
            observation(
                "GET",
                "http://x.test/api/users",
                None,
                Some(json!({"users":[]})),
            ),
        ];

        let outcome = merge_observations(existing, incoming);

        assert!(outcome.merged_into_existing);
        assert_eq!(outcome.added, 2);
        assert_eq!(outcome.duplicates, 1);
        assert_eq!(outcome.observations.len(), 3);
    }

    #[test]
    fn merge_into_empty_site_reports_fresh_import() {
        let incoming = vec![observation("GET", "http://x.test/api/items", None, None)];
        let outcome = merge_observations(Vec::new(), incoming);
        assert!(!outcome.merged_into_existing);
        assert_eq!(outcome.added, 1);
        assert_eq!(
            format_capture_message("demo", &outcome, "Imported"),
            "Imported 1 observations for site 'demo'"
        );
    }

    #[test]
    fn merged_capture_message_reports_new_duplicates_and_total() {
        let existing = vec![observation("GET", "http://x.test/api/items", None, None)];
        let incoming = vec![
            observation("GET", "http://x.test/api/items", None, None),
            observation("GET", "http://x.test/api/users", None, None),
        ];
        let outcome = merge_observations(existing, incoming);
        let message = format_capture_message("demo", &outcome, "Imported");
        assert!(message.contains("1 new"));
        assert!(message.contains("1 duplicate(s) skipped"));
        assert!(message.contains("2 total"));
    }

    #[test]
    fn health_classifies_conformant_live_success_as_healthy() {
        let response = json!({
            "status": "success",
            "data": {},
            "execution": { "mode": "live" },
            "conformance": { "field_compatibility": 1.0, "missing_fields": [] }
        });
        let update = classify_tool_health(&response, "live", "T0", None);
        let health = update.tool_health.expect("health recorded");
        assert_eq!(health.status, "healthy");
        assert_eq!(health.last_success.as_deref(), Some("T0"));
        assert!(update.auth_success);
        assert!(!update.auth_failure);
    }

    #[test]
    fn health_classifies_low_conformance_as_degraded_with_detail() {
        let response = json!({
            "status": "success",
            "data": {},
            "execution": { "mode": "live" },
            "conformance": { "field_compatibility": 0.25, "missing_fields": ["title", "owner"] }
        });
        let update = classify_tool_health(&response, "live", "T0", None);
        let health = update.tool_health.expect("health recorded");
        assert_eq!(health.status, "degraded");
        let detail = health.detail.expect("detail");
        assert!(detail.contains("25%"));
        assert!(detail.contains("title, owner"));
    }

    #[test]
    fn health_auth_expired_updates_auth_state_not_tool_health() {
        let response = json!({
            "status": "error",
            "error_type": "auth_expired",
            "http_status": 401
        });
        let update = classify_tool_health(&response, "live", "T0", None);
        assert!(update.tool_health.is_none());
        assert!(update.auth_failure);
    }

    #[test]
    fn health_endpoint_error_is_broken_and_keeps_previous_success() {
        let response = json!({
            "status": "error",
            "error_type": "endpoint_error",
            "http_status": 500
        });
        let update = classify_tool_health(&response, "live", "T1", Some("T0".to_string()));
        let health = update.tool_health.expect("health recorded");
        assert_eq!(health.status, "broken");
        assert_eq!(health.http_status, Some(500));
        assert_eq!(health.last_success.as_deref(), Some("T0"));
    }

    #[test]
    fn health_ignores_approval_and_argument_errors() {
        for response in [
            json!({ "status": "error", "error_type": "approval_required" }),
            json!({ "status": "error", "error_type": "schema_mismatch" }),
            json!({ "status": "error", "error_type": "rate_limited", "http_status": 429 }),
        ] {
            let update = classify_tool_health(&response, "live", "T0", None);
            assert!(update.tool_health.is_none(), "no health for {response}");
            assert!(!update.auth_failure || response["error_type"] == "auth_expired");
        }
    }

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

        assert!(guidance.contains("Recording started."));
        assert!(guidance.contains("search/list something"));
        assert!(guidance.contains("open a detail page"));
        assert!(guidance.contains("Press Enter when finished."));
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
    fn record_low_signal_failure_respects_allow_low_signal() {
        let summary = tapestry_input::CaptureSummary::from_observations(&[]);

        assert!(record_low_signal_failure(&summary, 1, false).is_some());
        assert!(record_low_signal_failure(&summary, 1, true).is_none());
    }

    #[test]
    fn record_low_signal_failure_requires_minimum_api_observations() {
        let observations = vec![Observation {
            method: "GET".to_string(),
            url: "https://example.com/page".to_string(),
            path: "/page".to_string(),
            query: Default::default(),
            request_headers: Default::default(),
            request_body: None,
            response_status: Some(200),
            response_headers: Default::default(),
            response_body: None,
            warnings: vec![],
        }];
        let summary = tapestry_input::CaptureSummary::from_observations(&observations);

        assert!(record_low_signal_failure(&summary, 2, false).is_some());
        assert!(record_low_signal_failure(&summary, 0, false).is_none());
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

        assert_eq!(cases.len(), 15);
        assert!(sites.contains(&"tesco"));
        assert!(sites.contains(&"localapp"));
        assert!(sites.contains(&"localapp-cdp"));
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
        assert!(sites.contains(&"fixture"));
        assert!(sites.contains(&"rightmove"));
    }

    #[test]
    fn benchmark_report_serializes_expected_shape() {
        let report = BenchmarkReport {
            total_sites: 1,
            success_count: 1,
            failure_count: 0,
            expected_match_count: 1,
            drift_count: 0,
            capture_parity: Vec::new(),
            context_reduction: ContextReductionReport {
                meta_tool_tokens: 900,
                sites: Vec::new(),
                mean_reduction: None,
            },
            cases: vec![BenchmarkCaseReport {
                site: "fixture".to_string(),
                capture_variant: Some("har".to_string()),
                parity_group: None,
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
                endpoint_coverage: Some(1.0),
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
    fn no_seeded_secret_survives_the_full_pipeline() {
        // Import the seeded fixture, run the analyzer, and check every
        // artifact an agent or log could ever see.
        let observations =
            tapestry_input::import_har("../../examples/fixtures/redaction.har").unwrap();
        let spec = tapestry_analyzer::analyze("redaction-test", &observations);

        let observations_json = serde_json::to_string(&observations).unwrap();
        let toolspec_json = serde_json::to_string(&spec).unwrap();
        assert!(
            !observations_json.contains("FAKESECRET"),
            "observations leaked"
        );
        assert!(!toolspec_json.contains("FAKESECRET"), "toolspec leaked");

        // Review and diagnose reports are printed to stdout; they must be
        // clean too.
        let review = review_toolspec(&spec, None);
        let review_json = serde_json::to_string(&review).unwrap();
        assert!(!review_json.contains("FAKESECRET"), "review leaked");
        let diagnose = diagnose_site(&spec, &observations);
        let diagnose_json = serde_json::to_string(&diagnose).unwrap();
        assert!(!diagnose_json.contains("FAKESECRET"), "diagnose leaked");

        // Agent trace output (the noisiest path) must be clean as well.
        let options = tapestry_runtime::RuntimeOptions {
            offline_har_replay: true,
            prefer_har_replay: true,
            ..tapestry_runtime::RuntimeOptions::default()
        };
        let trace = run_agent_task(&spec, &observations, "list items", true, &options);
        assert!(!trace.contains("FAKESECRET"), "agent trace leaked");
    }

    #[test]
    fn endpoint_patterns_match_paths_with_params() {
        assert!(endpoint_pattern_matches("/api/items", "/api/items"));
        assert!(endpoint_pattern_matches("/api/items/{id}", "/api/items/42"));
        // A shorter pattern must NOT be covered by a deeper path.
        assert!(!endpoint_pattern_matches("/api/items", "/api/items/42"));
        assert!(!endpoint_pattern_matches("/api/items/{id}", "/api/items"));
        assert!(!endpoint_pattern_matches("/api/users", "/api/items"));
    }

    #[test]
    fn endpoint_coverage_scores_against_ground_truth() {
        let observations = vec![
            observation("GET", "http://x.test/api/items?page=1", None, None),
            observation("GET", "http://x.test/api/items/7", None, None),
        ];
        let expected = vec![
            "/api/items".to_string(),
            "/api/items/{id}".to_string(),
            "/api/config".to_string(),
        ];
        let coverage = endpoint_coverage(&expected, &observations).expect("coverage");
        assert!((coverage - 2.0 / 3.0).abs() < 1e-9);
        assert!(endpoint_coverage(&[], &observations).is_none());
    }

    fn parity_case(
        site: &str,
        group: &str,
        cdp: bool,
        api_observations: usize,
        success: bool,
    ) -> BenchmarkCaseReport {
        BenchmarkCaseReport {
            site: site.to_string(),
            capture_variant: cdp.then(|| "cdp".to_string()),
            parity_group: Some(group.to_string()),
            task: "task".to_string(),
            expected_outcome: "success".to_string(),
            expected_tool: None,
            selected_tool: None,
            success,
            failure_type: (!success).then(|| "no_matching_tool".to_string()),
            failure_bucket: "unknown".to_string(),
            outcome_matches_expected: true,
            tool_matches_expected: None,
            review_grade: None,
            diagnose_summary: DiagnoseSummary {
                total_observations: api_observations + 1,
                candidate_api_observations: api_observations,
                generated_tools: api_observations,
                observations_with_response_bodies: api_observations,
                json_responses: api_observations,
                graphql_requests: 0,
                graphql_responses_mapped: 0,
                tools_missing_examples: 0,
                tools_with_empty_response_schemas: 0,
                static_resource_tools: 0,
                platform_resource_tools: 0,
                telemetry_tools: 0,
                commerce_api_tools: 0,
            },
            endpoint_coverage: None,
            ranking_note: None,
        }
    }

    #[test]
    fn context_reduction_compares_meta_surface_against_full_toolspec() {
        let spec = tapestry_analyzer::analyze(
            "ctx",
            &tapestry_input::import_har("../../examples/fixtures/simple.har").unwrap(),
        );
        assert!(!spec.tools.is_empty());

        let report = build_context_reduction(&[
            ("ctx".to_string(), spec),
            (
                "empty".to_string(),
                ToolSpec {
                    site: SiteInfo {
                        name: "empty".to_string(),
                        base_url: None,
                        source: vec![],
                        generated_at: None,
                        spec_version: "0.1.0".to_string(),
                    },
                    tools: vec![],
                },
            ),
        ]);

        assert!(report.meta_tool_tokens > 0);
        assert_eq!(report.sites.len(), 2);
        let ctx = &report.sites[0];
        assert!(ctx.full_toolspec_tokens > 0);
        // Sites with no tools are excluded from the mean instead of skewing it.
        assert!(report.sites[1].reduction.is_none());
        assert_eq!(report.mean_reduction, ctx.reduction);
    }

    #[test]
    fn capture_parity_pairs_variants_and_flags_regressions() {
        let cases = vec![
            parity_case("app", "app", false, 4, true),
            parity_case("app-cdp", "app", true, 4, true),
            parity_case("shop", "shop", false, 5, true),
            parity_case("shop-cdp", "shop", true, 0, false),
            // Unpaired case: no parity entry.
            parity_case("solo", "solo", false, 2, true),
        ];

        let parity = build_capture_parity(&cases);

        assert_eq!(parity.len(), 2);
        let app = parity.iter().find(|p| p.group == "app").expect("app pair");
        assert!(app.cdp_meets_har);
        let shop = parity
            .iter()
            .find(|p| p.group == "shop")
            .expect("shop pair");
        assert!(!shop.cdp_meets_har);
        assert_eq!(shop.har.api_observations, 5);
        assert_eq!(shop.cdp.api_observations, 0);
    }

    #[test]
    fn capture_parity_accepts_cdp_success_when_har_failed() {
        let cases = vec![
            parity_case("app", "app", false, 2, false),
            parity_case("app-cdp", "app", true, 3, true),
        ];
        let parity = build_capture_parity(&cases);
        assert!(parity[0].cdp_meets_har);
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
            "--min-api-observations",
            "3",
            "--allow-low-signal",
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
                min_api_observations,
                allow_low_signal,
                replace,
                ephemeral_profile,
                generate,
            } => {
                assert!(!replace);
                assert!(!ephemeral_profile);
                assert!(!generate);
                assert_eq!(url, "https://example.com");
                assert_eq!(site, "demo");
                assert_eq!(browser.as_deref(), Some(std::path::Path::new("chrome.exe")));
                assert!(headless);
                assert_eq!(timeout_secs, 30);
                assert_eq!(max_body_bytes, 1024);
                assert!(include_third_party);
                assert!(output_observations);
                assert!(keep_profile);
                assert_eq!(min_api_observations, 3);
                assert!(allow_low_signal);
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
