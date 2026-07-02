use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{fs, path::PathBuf};
use tracing::info;

mod mcp;

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
        Command::Import { har, site, replace } => {
            validate_site_name(&site)?;
            eprintln!(
                "Warning: HAR files may contain credentials and personal data. Tapestry will persist redacted observations, not the raw HAR."
            );
            info!(command = "import", site, har = %har.display(), "starting HAR import");
            let observations = tapestry_input::import_har(&har)?;
            let source = format!("har:{}", har.display());
            let outcome = store_capture(&site, &source, observations, replace)?;
            println!("{}", format_capture_message(&site, &outcome, "Imported"));
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
            prune_stale_approvals(&site, &spec)?;
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
                    write_secret(
                        &creds_path,
                        &serde_json::to_string_pretty(&creds)?,
                    )?;
                    println!("Stored credential '{header}' for site '{site}'.");
                }
                CredentialsCommand::Remove { header } => {
                    let mut creds = load_credentials_raw(&creds_path)?;
                    if creds.remove(&header).is_some() {
                        write_secret(
                            &creds_path,
                            &serde_json::to_string_pretty(&creds)?,
                        )?;
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
                    let raw = fs::read_to_string(&har)
                        .context("failed to read HAR file")?;
                    let json: Value = serde_json::from_str(&raw)
                        .context("failed to parse HAR JSON")?;
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
                        write_secret(
                            &creds_path,
                            &serde_json::to_string_pretty(&existing)?,
                        )?;
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
                    .context(
                        "site has no base URL; pass the login page with --url <url>",
                    )?,
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

fn run_approve(
    site: &str,
    tool_id: Option<&str>,
    list: bool,
    revoke: bool,
    note: Option<String>,
) -> Result<()> {
    let approvals_path = site_dir(site).join("approvals.json");
    let spec = load_site_spec(site)?;
    let mut approvals = tapestry_runtime::load_approvals(&approvals_path)?;

    if list || tool_id.is_none() {
        if revoke {
            anyhow::bail!("--revoke requires a tool id: tapestry approve {site} <tool_id> --revoke");
        }
        println!("{}", format_approval_status(site, &spec, &approvals));
        return Ok(());
    }

    let tool_id = tool_id.expect("checked above");
    let Some(tool) = spec
        .tools
        .iter()
        .find(|tool| tool.id == tool_id || tool.name == tool_id)
    else {
        anyhow::bail!(
            "Tool '{}' not found for site '{}'. Run `tapestry approve {} --list` to see tools.",
            tool_id,
            site,
            site
        );
    };

    if revoke {
        if approvals.remove(&tool.id).is_some() {
            write_protected(&approvals_path, &serde_json::to_string_pretty(&approvals)?)?;
            println!("Revoked approval for '{}' on site '{}'.", tool.id, site);
        } else {
            println!("No stored approval for '{}' on site '{}'.", tool.id, site);
        }
        return Ok(());
    }

    let required = approval_requirement(tool);
    approvals.insert(
        tool.id.clone(),
        tapestry_runtime::ApprovalRecord {
            fingerprint: tapestry_runtime::tool_fingerprint(tool),
            approved_at: current_timestamp_cli(),
            note,
        },
    );
    write_protected(&approvals_path, &serde_json::to_string_pretty(&approvals)?)?;
    println!(
        "Approved '{}' ({} {}, safety {}, confidence {:.2}) for site '{}'.",
        tool.id,
        tool.method,
        tool.path,
        safety_label(&tool.safety.classification),
        tool.confidence.overall,
        site
    );
    if required.is_none() {
        println!("Note: this tool is read-safe above the confidence threshold and did not require approval.");
    }
    println!("The approval is pinned to the tool's current request shape; if `generate` changes the tool, re-approve it.");
    Ok(())
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SiteMeta {
    #[serde(default)]
    tool_health: std::collections::BTreeMap<String, ToolHealth>,
    #[serde(default)]
    auth: AuthMeta,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    capture_sessions: Vec<CaptureSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CaptureSession {
    source: String,
    imported_at: String,
    observations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolHealth {
    /// healthy | degraded | broken | unreachable
    status: String,
    last_checked: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_success: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    field_compatibility: Option<f64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AuthMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_success: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_auth_failure: Option<String>,
}

fn load_site_meta(site: &str) -> SiteMeta {
    let path = site_dir(site).join("meta.json");
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_site_meta(site: &str, meta: &SiteMeta) -> Result<()> {
    let dir = site_dir(site);
    fs::create_dir_all(&dir)?;
    write_protected(&dir.join("meta.json"), &serde_json::to_string_pretty(meta)?)
}

/// Record per-tool health from a live execution result.
///
/// Replay and dry-run results carry no drift signal and are ignored. Auth
/// failures update site-level auth state rather than tool health: stale
/// credentials say nothing about whether the endpoint drifted. Failures to
/// persist are reported but never fail the call itself.
fn record_tool_health(site: &str, spec: &tapestry_core::ToolSpec, tool_id: &str, response: &Value) {
    let mode = response
        .pointer("/execution/mode")
        .and_then(Value::as_str)
        .unwrap_or("");
    if mode == "har_replay" || response["status"] == "dry_run" {
        return;
    }
    let Some(tool) = spec
        .tools
        .iter()
        .find(|tool| tool.id == tool_id || tool.name == tool_id)
    else {
        return;
    };

    let now = current_timestamp_cli();
    let mut meta = load_site_meta(site);
    let previous_success = meta
        .tool_health
        .get(&tool.id)
        .and_then(|health| health.last_success.clone());
    let update = classify_tool_health(response, mode, &now, previous_success);

    if update.auth_success {
        meta.auth.last_success = Some(now.clone());
    }
    if update.auth_failure {
        meta.auth.last_auth_failure = Some(now);
    }
    if let Some(health) = update.tool_health {
        meta.tool_health.insert(tool.id.clone(), health);
    } else if !update.auth_success && !update.auth_failure {
        return;
    }
    if let Err(error) = save_site_meta(site, &meta) {
        eprintln!("Warning: failed to persist tool health for site '{site}': {error}");
    }
}

/// Outcome of merging a new capture into a site's stored observations.
struct MergeOutcome {
    observations: Vec<tapestry_core::Observation>,
    added: usize,
    duplicates: usize,
    merged_into_existing: bool,
}

/// Append new observations to the stored ones, skipping exact duplicates.
///
/// Multiple sessions of the same app legitimately repeat requests; identical
/// request/response pairs add no evidence, but the same endpoint with a
/// different response is new evidence and is kept.
fn merge_observations(
    existing: Vec<tapestry_core::Observation>,
    incoming: Vec<tapestry_core::Observation>,
) -> MergeOutcome {
    let merged_into_existing = !existing.is_empty();
    let mut seen: std::collections::BTreeSet<String> =
        existing.iter().map(observation_key).collect();
    let mut observations = existing;
    let mut added = 0;
    let mut duplicates = 0;
    for observation in incoming {
        if seen.insert(observation_key(&observation)) {
            observations.push(observation);
            added += 1;
        } else {
            duplicates += 1;
        }
    }
    MergeOutcome {
        observations,
        added,
        duplicates,
        merged_into_existing,
    }
}

fn observation_key(observation: &tapestry_core::Observation) -> String {
    serde_json::to_string(&json!({
        "method": observation.method,
        "url": observation.url,
        "request_body": observation.request_body,
        "response_status": observation.response_status,
        "response_body": observation.response_body,
    }))
    .unwrap_or_default()
}

/// Load stored observations for merging; a missing file is an empty site.
fn load_existing_observations(site: &str) -> Vec<tapestry_core::Observation> {
    fs::read_to_string(site_dir(site).join("observations.json"))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Persist a capture: merge (or replace), write observations, track the session.
fn store_capture(
    site: &str,
    source: &str,
    incoming: Vec<tapestry_core::Observation>,
    replace: bool,
) -> Result<MergeOutcome> {
    let incoming_count = incoming.len();
    let existing = if replace {
        Vec::new()
    } else {
        load_existing_observations(site)
    };
    let outcome = merge_observations(existing, incoming);
    let dir = site_dir(site);
    fs::create_dir_all(&dir)?;
    write_protected(
        &dir.join("observations.json"),
        &serde_json::to_string_pretty(&outcome.observations)?,
    )?;
    let mut meta = load_site_meta(site);
    if replace {
        meta.capture_sessions.clear();
    }
    meta.capture_sessions.push(CaptureSession {
        source: source.to_string(),
        imported_at: current_timestamp_cli(),
        observations: incoming_count,
    });
    save_site_meta(site, &meta)?;
    Ok(outcome)
}

fn format_capture_message(site: &str, outcome: &MergeOutcome, verb: &str) -> String {
    if outcome.merged_into_existing {
        format!(
            "{verb} {} observation(s) for site '{}' ({} new, {} duplicate(s) skipped; {} total). Use --replace to start fresh.",
            outcome.added + outcome.duplicates,
            site,
            outcome.added,
            outcome.duplicates,
            outcome.observations.len()
        )
    } else {
        format!(
            "{verb} {} observations for site '{}'",
            outcome.observations.len(),
            site
        )
    }
}

#[derive(Debug, Default)]
struct HealthUpdate {
    tool_health: Option<ToolHealth>,
    auth_success: bool,
    auth_failure: bool,
}

fn classify_tool_health(
    response: &Value,
    mode: &str,
    now: &str,
    previous_success: Option<String>,
) -> HealthUpdate {
    let http_status = response
        .get("http_status")
        .and_then(Value::as_u64)
        .map(|status| status as u16);

    match response["status"].as_str() {
        Some("success") if mode == "live" => {
            let compatibility = response
                .pointer("/conformance/field_compatibility")
                .and_then(Value::as_f64);
            let missing = response
                .pointer("/conformance/missing_fields")
                .and_then(Value::as_array)
                .map(|fields| {
                    fields
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let health = match compatibility {
                Some(value) if value < 0.8 => ToolHealth {
                    status: "degraded".to_string(),
                    last_checked: now.to_string(),
                    last_success: Some(now.to_string()),
                    detail: Some(format!(
                        "response matched {:.0}% of inferred fields; missing: {missing}",
                        value * 100.0
                    )),
                    http_status: None,
                    field_compatibility: Some(value),
                },
                other => ToolHealth {
                    status: "healthy".to_string(),
                    last_checked: now.to_string(),
                    last_success: Some(now.to_string()),
                    detail: None,
                    http_status: None,
                    field_compatibility: other,
                },
            };
            HealthUpdate {
                tool_health: Some(health),
                auth_success: true,
                auth_failure: false,
            }
        }
        Some("error") => match response["error_type"].as_str() {
            Some("auth_expired") => HealthUpdate {
                tool_health: None,
                auth_success: false,
                auth_failure: true,
            },
            Some("schema_mismatch") if http_status.is_some() => HealthUpdate {
                tool_health: Some(ToolHealth {
                    status: "degraded".to_string(),
                    last_checked: now.to_string(),
                    last_success: previous_success,
                    detail: Some(
                        "live response no longer matches the inferred schema".to_string(),
                    ),
                    http_status,
                    field_compatibility: None,
                }),
                ..HealthUpdate::default()
            },
            Some("endpoint_error") => HealthUpdate {
                tool_health: Some(ToolHealth {
                    status: "broken".to_string(),
                    last_checked: now.to_string(),
                    last_success: previous_success,
                    detail: Some(format!(
                        "endpoint returned HTTP {}",
                        http_status.map(|s| s.to_string()).unwrap_or_default()
                    )),
                    http_status,
                    field_compatibility: None,
                }),
                ..HealthUpdate::default()
            },
            Some("network_error") => HealthUpdate {
                tool_health: Some(ToolHealth {
                    status: "unreachable".to_string(),
                    last_checked: now.to_string(),
                    last_success: previous_success,
                    detail: Some("network request failed".to_string()),
                    http_status: None,
                    field_compatibility: None,
                }),
                ..HealthUpdate::default()
            },
            _ => HealthUpdate::default(),
        },
        _ => HealthUpdate::default(),
    }
}

/// Attach non-healthy health states as tool warnings so review, tools search,
/// and MCP search_tools all surface drift without extra plumbing.
fn apply_health_warnings(site: &str, spec: &mut tapestry_core::ToolSpec) {
    let meta = load_site_meta(site);
    if meta.tool_health.is_empty() {
        return;
    }
    for tool in &mut spec.tools {
        let Some(health) = meta.tool_health.get(&tool.id) else {
            continue;
        };
        if health.status == "healthy" {
            continue;
        }
        let detail = health.detail.clone().unwrap_or_default();
        tool.warnings.push(format!(
            "health:{} — {} (last checked {}). Re-capture and regenerate if this persists.",
            health.status, detail, health.last_checked
        ));
    }
}

/// Environment and site-data checks for `tapestry doctor`.
fn run_doctor() -> String {
    let mut out = vec!["Tapestry doctor".to_string(), String::new()];

    match tapestry_input::resolve_browser(None) {
        Ok(path) => out.push(format!("[ok]   browser: {}", path.display())),
        Err(error) => out.push(format!(
            "[FAIL] browser: {error}\n       Live recording and reauth need Chrome/Chromium/Edge. HAR import still works."
        )),
    }

    let root = sites_root();
    match fs::create_dir_all(&root).and_then(|_| {
        let probe = root.join(".doctor-probe");
        fs::write(&probe, "probe")?;
        fs::remove_file(&probe)
    }) {
        Ok(()) => out.push(format!("[ok]   storage: {} is writable", root.display())),
        Err(error) => out.push(format!(
            "[FAIL] storage: cannot write {} — {error}",
            root.display()
        )),
    }

    let mut site_lines = Vec::new();
    let mut total = 0usize;
    let mut ready = 0usize;
    if let Ok(entries) = fs::read_dir(&root) {
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        for name in names {
            total += 1;
            let dir = site_dir(&name);
            let observations = load_existing_observations(&name).len();
            let has_spec = dir.join("toolspec.json").exists();
            if observations == 0 {
                site_lines.push(format!(
                    "[warn] site '{name}': no observations — record or import a capture"
                ));
            } else if !has_spec {
                site_lines.push(format!(
                    "[warn] site '{name}': {observations} observation(s) but no ToolSpec — run `tapestry generate {name}`"
                ));
            } else {
                ready += 1;
            }
            let meta = load_site_meta(&name);
            if let (Some(failure), success) =
                (&meta.auth.last_auth_failure, &meta.auth.last_success)
            {
                let stale = success
                    .as_ref()
                    .map(|success| failure.as_str() > success.as_str())
                    .unwrap_or(true);
                if stale {
                    site_lines.push(format!(
                        "[warn] site '{name}': credentials look stale (last auth failure {failure}) — run `tapestry reauth {name}`"
                    ));
                }
            }
            let unhealthy: Vec<&String> = meta
                .tool_health
                .iter()
                .filter(|(_, health)| health.status != "healthy")
                .map(|(tool_id, _)| tool_id)
                .collect();
            if !unhealthy.is_empty() {
                site_lines.push(format!(
                    "[warn] site '{name}': {} tool(s) degraded/broken — run `tapestry review {name}`",
                    unhealthy.len()
                ));
            }
        }
    }
    out.push(format!(
        "[ok]   sites: {total} total, {ready} ready (observations + ToolSpec)"
    ));
    out.extend(site_lines);

    out.push(String::new());
    out.push("Done. [FAIL] items block core workflows; [warn] items affect one site.".to_string());
    out.join("\n")
}

/// Drop approvals whose tool disappeared or changed request shape during `generate`.
fn prune_stale_approvals(site: &str, spec: &tapestry_core::ToolSpec) -> Result<()> {
    let approvals_path = site_dir(site).join("approvals.json");
    let approvals = tapestry_runtime::load_approvals(&approvals_path)?;
    if approvals.is_empty() {
        return Ok(());
    }
    let mut kept = std::collections::BTreeMap::new();
    let mut dropped: Vec<(String, &'static str)> = Vec::new();
    for (tool_id, record) in approvals {
        match spec.tools.iter().find(|tool| tool.id == tool_id) {
            Some(tool) if tapestry_runtime::tool_fingerprint(tool) == record.fingerprint => {
                kept.insert(tool_id, record);
            }
            Some(_) => dropped.push((tool_id, "request shape changed")),
            None => dropped.push((tool_id, "tool no longer exists")),
        }
    }
    if dropped.is_empty() {
        return Ok(());
    }
    write_protected(&approvals_path, &serde_json::to_string_pretty(&kept)?)?;
    for (tool_id, reason) in &dropped {
        println!(
            "Dropped approval for '{tool_id}' ({reason}). Re-review with `tapestry approve {site} {tool_id}` if still wanted."
        );
    }
    Ok(())
}

/// Why a tool needs approval before `call_tool` will execute it, if it does.
fn approval_requirement(tool: &tapestry_core::ToolDefinition) -> Option<&'static str> {
    if tool.safety.classification == tapestry_core::SafetyClassification::Unknown {
        return Some("unknown safety");
    }
    if tool.safety.classification != tapestry_core::SafetyClassification::Read {
        return Some("write tool");
    }
    if tool.confidence.overall < tapestry_runtime::DEFAULT_CONFIDENCE_THRESHOLD {
        return Some("low confidence");
    }
    None
}

fn safety_label(classification: &tapestry_core::SafetyClassification) -> &'static str {
    match classification {
        tapestry_core::SafetyClassification::Read => "read",
        tapestry_core::SafetyClassification::Write => "write",
        tapestry_core::SafetyClassification::Unknown => "unknown",
    }
}

fn format_approval_status(
    site: &str,
    spec: &tapestry_core::ToolSpec,
    approvals: &std::collections::BTreeMap<String, tapestry_runtime::ApprovalRecord>,
) -> String {
    let mut out = format!(
        "Approval status for site '{}' ({} tools):\n\n",
        site,
        spec.tools.len()
    );
    let mut pending = 0usize;
    for tool in &spec.tools {
        let requirement = approval_requirement(tool);
        let (status, reason) = match (requirement, tool.approved) {
            (None, _) => ("-", "  no approval needed".to_string()),
            (Some(_), true) => ("approved", String::new()),
            (Some(reason), false) => {
                pending += 1;
                ("PENDING", format!("  needs approval: {reason}"))
            }
        };
        let evidence_count: usize = tool.evidence.iter().map(|e| e.count).sum();
        out.push_str(&format!(
            "  {:<9} {:<28} {:<7} confidence {:.2}  {} {}  ({} observation{}){}\n",
            status,
            tool.id,
            safety_label(&tool.safety.classification),
            tool.confidence.overall,
            tool.method,
            tool.path,
            evidence_count,
            if evidence_count == 1 { "" } else { "s" },
            reason
        ));
    }
    for (tool_id, record) in approvals {
        if !spec.tools.iter().any(|tool| tool.id == *tool_id) {
            out.push_str(&format!(
                "  orphaned  {:<28} approval stored {} but tool no longer exists\n",
                tool_id, record.approved_at
            ));
        }
    }
    if pending > 0 {
        out.push_str(&format!(
            "\nApprove with: tapestry approve {site} <tool_id>\nInspect first: tapestry tools evidence {site} <tool_id>"
        ));
    } else {
        out.push_str("\nNo tools are pending approval.");
    }
    out
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ReviewFormat {
    Text,
    Json,
}

fn sites_root() -> PathBuf {
    PathBuf::from(".tapestry-dev").join("sites")
}

fn site_dir(site: &str) -> PathBuf {
    sites_root().join(site)
}

/// Persistent browser profile for a site (logins survive across record and
/// reauth sessions). Contains session cookies — purged with `--secrets`.
fn site_profile_dir(site: &str, ephemeral: bool) -> Option<PathBuf> {
    (!ephemeral).then(|| site_dir(site).join("browser-profile"))
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

/// Write a file containing secrets, restricting access to the current user.
///
/// On Unix this is mode 0600. On Windows, where Unix modes are a no-op, the
/// ACL is rewritten via `icacls`: inheritance removed, current user granted
/// full control, everyone else implicitly denied. Failure to restrict is
/// reported but does not lose the write.
fn write_secret(path: &std::path::Path, content: &str) -> Result<()> {
    write_protected(path, content)?;
    restrict_to_current_user(path);
    Ok(())
}

#[cfg(windows)]
fn restrict_to_current_user(path: &std::path::Path) {
    let Ok(user) = std::env::var("USERNAME") else {
        eprintln!(
            "Warning: USERNAME not set; could not restrict permissions on {}",
            path.display()
        );
        return;
    };
    let restricted = std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:F"))
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !restricted {
        eprintln!(
            "Warning: could not restrict permissions on {} — it may be readable by other local users.",
            path.display()
        );
    }
}

#[cfg(not(windows))]
fn restrict_to_current_user(_path: &std::path::Path) {}

fn load_site_spec(site: &str) -> Result<tapestry_core::ToolSpec> {
    let dir = site_dir(site);
    let mut spec = tapestry_runtime::load_toolspec(dir.join("toolspec.json"))?;
    let approvals = tapestry_runtime::load_approvals(dir.join("approvals.json"))?;
    let overlay = tapestry_runtime::apply_approvals(&mut spec, &approvals);
    for tool_id in &overlay.stale {
        eprintln!(
            "Warning: approval for '{tool_id}' no longer applies because the tool's request shape changed; re-approve with `tapestry approve {site} {tool_id}`."
        );
    }
    for tool_id in &overlay.orphaned {
        eprintln!(
            "Warning: stored approval for '{tool_id}' refers to a tool that no longer exists on site '{site}'."
        );
    }
    apply_health_warnings(site, &mut spec);
    let meta = load_site_meta(site);
    if let Some(failure) = &meta.auth.last_auth_failure {
        let stale = match &meta.auth.last_success {
            Some(success) => failure.as_str() > success.as_str(),
            None => true,
        };
        if stale {
            eprintln!(
                "Warning: credentials for site '{site}' look stale (last auth failure {failure}). Refresh with `tapestry reauth {site}`."
            );
        }
    }
    Ok(spec)
}

fn load_site_credentials(site: &str) -> Result<std::collections::BTreeMap<String, String>> {
    tapestry_runtime::load_credentials(site_dir(site).join("credentials.json"))
}

fn load_credentials_raw(
    path: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, Value>> {
    if !path.exists() {
        return Ok(std::collections::BTreeMap::new());
    }
    let raw = fs::read_to_string(path).context("failed to read credentials")?;
    Ok(serde_json::from_str(&raw).context("failed to parse credentials JSON")?)
}

fn current_timestamp_cli() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    let mut rem = days;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if rem < dy {
            break;
        }
        rem -= dy;
        y += 1;
    }
    let months = if is_leap(y) {
        [31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo = 1u64;
    for dm in months {
        if rem < dm {
            break;
        }
        rem -= dm;
        mo += 1;
    }
    (y, mo, rem + 1)
}

fn is_leap(y: u64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
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
    "Recording started.\n\nNow interact with the site:\n- search/list something\n- open a detail page\n- perform a relevant workflow step\n- wait for results to load\n\nPress Enter when finished."
}

fn record_low_signal_failure(
    summary: &tapestry_input::CaptureSummary,
    min_api_observations: usize,
    allow_low_signal: bool,
) -> Option<String> {
    if allow_low_signal {
        return None;
    }

    summary.minimum_api_failure_message(min_api_observations)
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
    /// HAR-vs-CDP comparison for sites captured both ways. The release gate
    /// for recommending live recording is: CDP meets HAR on every pair.
    capture_parity: Vec<CaptureParityReport>,
    /// Token cost of the meta-tool interface vs stuffing every generated
    /// tool schema into agent context. Measures the PRD's context-reduction
    /// claim instead of asserting it.
    context_reduction: ContextReductionReport,
}

#[derive(Debug, Serialize)]
struct ContextReductionReport {
    /// Estimated tokens of the four meta-tool definitions an MCP agent sees,
    /// regardless of how many tools a site has.
    meta_tool_tokens: usize,
    sites: Vec<SiteContextCost>,
    /// Mean reduction across sites with at least one generated tool.
    mean_reduction: Option<f64>,
}

#[derive(Debug, Serialize)]
struct SiteContextCost {
    site: String,
    tools: usize,
    /// Estimated tokens if every generated tool schema sat in agent context.
    full_toolspec_tokens: usize,
    /// 1 - meta/full; `None` when the site has no tools to compare against.
    reduction: Option<f64>,
}

/// Rough token estimate (chars / 4) — good enough for order-of-magnitude
/// context comparisons, not billing.
fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

fn build_context_reduction(
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
    let mean_reduction = (!reductions.is_empty())
        .then(|| reductions.iter().sum::<f64>() / reductions.len() as f64);

    ContextReductionReport {
        meta_tool_tokens,
        sites,
        mean_reduction,
    }
}

#[derive(Debug, Serialize)]
struct BenchmarkCaseReport {
    site: String,
    capture_variant: Option<String>,
    parity_group: Option<String>,
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
    /// Fraction of the case's expected endpoints observed in the capture.
    /// `None` when the case defines no ground-truth endpoint list.
    endpoint_coverage: Option<f64>,
    ranking_note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BenchmarkCase {
    site: String,
    #[serde(default)]
    capture_variant: Option<String>,
    /// Cases sharing a group name are captures of the same app via different
    /// methods and get compared in the capture-parity report.
    #[serde(default)]
    parity_group: Option<String>,
    task: String,
    expected_outcome: String,
    expected_tool: Option<String>,
    /// Ground-truth endpoints the app is known to expose. Comparing capture
    /// methods only against each other can't detect when both miss the same
    /// traffic; this can.
    #[serde(default)]
    expected_endpoints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CaptureParityReport {
    group: String,
    har_site: String,
    cdp_site: String,
    har: CaptureVariantMetrics,
    cdp: CaptureVariantMetrics,
    cdp_meets_har: bool,
}

#[derive(Debug, Clone, Serialize)]
struct CaptureVariantMetrics {
    observations: usize,
    api_observations: usize,
    response_bodies: usize,
    tools: usize,
    replayable_tools: usize,
    endpoint_coverage: Option<f64>,
    agent_success: bool,
    failure_type: Option<String>,
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
fn build_capture_parity(cases: &[BenchmarkCaseReport]) -> Vec<CaptureParityReport> {
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
fn endpoint_coverage(
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

fn endpoint_pattern_matches(pattern: &str, path: &str) -> bool {
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
                site.site, site.tools, site.full_toolspec_tokens, reduction * 100.0
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
            out.push(format_missing_argument_guidance(spec, &selection));
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
            &candidates
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
        .map(|(_, result, plan, replayable, ranking_notes)| AgentToolSelection {
            result,
            plan,
            replayable,
            intent,
            ranking_notes,
        })
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
        notes.push(format!("[agent] rank penalty framework_path {}", result.name));
    }

    // Penalise low-confidence tools so high-quality tools rank above them
    if result.confidence < 0.5 {
        score -= 30;
        notes.push(format!("[agent] rank penalty low_confidence {}", result.name));
    } else if result.confidence < 0.7 {
        score -= 10;
        notes.push(format!("[agent] rank penalty below_threshold_confidence {}", result.name));
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
        let update =
            classify_tool_health(&response, "live", "T1", Some("T0".to_string()));
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
        assert!(!observations_json.contains("FAKESECRET"), "observations leaked");
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
        let shop = parity.iter().find(|p| p.group == "shop").expect("shop pair");
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
            } => {
                assert!(!replace);
                assert!(!ephemeral_profile);
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
