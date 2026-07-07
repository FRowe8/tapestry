//! Cross-cutting infrastructure shared by every CLI command: on-disk site
//! storage layout (`sites_root`/`site_dir`), site metadata and tool-health
//! tracking, observation merging on import/record, credential and ToolSpec
//! loading, and small formatting/date utilities. Nothing here is specific to
//! a single `tapestry` subcommand.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct SiteMeta {
    #[serde(default)]
    pub(crate) tool_health: std::collections::BTreeMap<String, ToolHealth>,
    #[serde(default)]
    pub(crate) auth: AuthMeta,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) capture_sessions: Vec<CaptureSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CaptureSession {
    pub(crate) source: String,
    pub(crate) imported_at: String,
    pub(crate) observations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ToolHealth {
    /// healthy | degraded | broken | unreachable
    pub(crate) status: String,
    pub(crate) last_checked: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_success: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) field_compatibility: Option<f64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct AuthMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_success: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_auth_failure: Option<String>,
}

pub(crate) fn load_site_meta(site: &str) -> SiteMeta {
    let path = site_dir(site).join("meta.json");
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub(crate) fn save_site_meta(site: &str, meta: &SiteMeta) -> Result<()> {
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
pub(crate) fn record_tool_health(
    site: &str,
    spec: &tapestry_core::ToolSpec,
    tool_id: &str,
    response: &Value,
) {
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
pub(crate) struct MergeOutcome {
    pub(crate) observations: Vec<tapestry_core::Observation>,
    pub(crate) added: usize,
    pub(crate) duplicates: usize,
    pub(crate) merged_into_existing: bool,
}

/// Append new observations to the stored ones, skipping exact duplicates.
///
/// Multiple sessions of the same app legitimately repeat requests; identical
/// request/response pairs add no evidence, but the same endpoint with a
/// different response is new evidence and is kept.
pub(crate) fn merge_observations(
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

pub(crate) fn observation_key(observation: &tapestry_core::Observation) -> String {
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
pub(crate) fn load_existing_observations(site: &str) -> Vec<tapestry_core::Observation> {
    fs::read_to_string(site_dir(site).join("observations.json"))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Persist a capture: merge (or replace), write observations, track the session.
pub(crate) fn store_capture(
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

pub(crate) fn format_capture_message(site: &str, outcome: &MergeOutcome, verb: &str) -> String {
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
pub(crate) struct HealthUpdate {
    pub(crate) tool_health: Option<ToolHealth>,
    pub(crate) auth_success: bool,
    pub(crate) auth_failure: bool,
}

pub(crate) fn classify_tool_health(
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
                    detail: Some("live response no longer matches the inferred schema".to_string()),
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
pub(crate) fn apply_health_warnings(site: &str, spec: &mut tapestry_core::ToolSpec) {
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

/// Drop approvals whose tool disappeared or changed request shape during `generate`.
pub(crate) fn prune_stale_approvals(site: &str, spec: &tapestry_core::ToolSpec) -> Result<()> {
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

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum ReviewFormat {
    Text,
    Json,
}

pub(crate) fn sites_root() -> PathBuf {
    PathBuf::from(".tapestry-dev").join("sites")
}

pub(crate) fn site_dir(site: &str) -> PathBuf {
    sites_root().join(site)
}

/// Persistent browser profile for a site (logins survive across record and
/// reauth sessions). Contains session cookies — purged with `--secrets`.
pub(crate) fn site_profile_dir(site: &str, ephemeral: bool) -> Option<PathBuf> {
    (!ephemeral).then(|| site_dir(site).join("browser-profile"))
}

pub(crate) fn validate_site_name(site: &str) -> Result<()> {
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

pub(crate) fn write_protected(path: &std::path::Path, content: &str) -> Result<()> {
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
pub(crate) fn write_secret(path: &std::path::Path, content: &str) -> Result<()> {
    write_protected(path, content)?;
    restrict_to_current_user(path);
    Ok(())
}

#[cfg(windows)]
pub(crate) fn restrict_to_current_user(path: &std::path::Path) {
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
pub(crate) fn restrict_to_current_user(_path: &std::path::Path) {}

pub(crate) fn load_site_spec(site: &str) -> Result<tapestry_core::ToolSpec> {
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

pub(crate) fn load_site_credentials(
    site: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    tapestry_runtime::load_credentials(site_dir(site).join("credentials.json"))
}

pub(crate) fn load_credentials_raw(
    path: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, Value>> {
    if !path.exists() {
        return Ok(std::collections::BTreeMap::new());
    }
    let raw = fs::read_to_string(path).context("failed to read credentials")?;
    serde_json::from_str(&raw).context("failed to parse credentials JSON")
}

pub(crate) fn current_timestamp_cli() -> String {
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

pub(crate) fn days_to_ymd(days: u64) -> (u64, u64, u64) {
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

pub(crate) fn is_leap(y: u64) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

pub(crate) fn load_site_observations(site: &str) -> Result<Vec<tapestry_core::Observation>> {
    let raw =
        fs::read_to_string(site_dir(site).join("observations.json")).context("run import first")?;
    Ok(serde_json::from_str(&raw)?)
}

pub(crate) fn runtime_options_for(
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

pub(crate) fn should_prefer_har_replay(spec: &tapestry_core::ToolSpec) -> bool {
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

pub(crate) fn has_localhost_base_url(base_url: Option<&str>) -> bool {
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

pub(crate) fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}
