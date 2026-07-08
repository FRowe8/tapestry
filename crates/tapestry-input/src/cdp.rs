use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tapestry_core::Observation;
use url::Url;

const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RecordOptions {
    pub browser: Option<PathBuf>,
    pub headless: bool,
    pub timeout_secs: u64,
    pub max_body_bytes: usize,
    pub include_third_party: bool,
    pub output_observations: bool,
    pub keep_profile: bool,
    /// Persistent browser profile directory. When set, logins and consent
    /// choices survive across sessions and the directory is never deleted.
    /// When `None`, a throwaway temp profile is used (deleted unless
    /// `keep_profile`). Persistent profiles contain session cookies — treat
    /// them with the same secrecy as stored credentials.
    pub profile_dir: Option<PathBuf>,
}

impl Default for RecordOptions {
    fn default() -> Self {
        Self {
            browser: None,
            headless: false,
            timeout_secs: 120,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            include_third_party: false,
            output_observations: false,
            keep_profile: false,
            profile_dir: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureOptions {
    pub include_third_party: bool,
    pub max_body_bytes: usize,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            include_third_party: false,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordResult {
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone)]
pub struct CaptureSummary {
    pub total_observations: usize,
    pub candidate_api_observations: usize,
    pub observations_with_response_bodies: usize,
    pub json_responses: usize,
    pub graphql_requests: usize,
    pub html_fragment_endpoints: usize,
}

impl CaptureSummary {
    pub fn from_observations(observations: &[Observation]) -> Self {
        Self {
            total_observations: observations.len(),
            candidate_api_observations: observations
                .iter()
                .filter(|obs| is_candidate_api_observation(obs))
                .count(),
            observations_with_response_bodies: observations
                .iter()
                .filter(|obs| obs.response_body.is_some())
                .count(),
            json_responses: observations
                .iter()
                .filter(|obs| has_json_signal(obs))
                .count(),
            graphql_requests: observations
                .iter()
                .filter(|obs| !graphql_operations(obs).is_empty())
                .count(),
            html_fragment_endpoints: observations
                .iter()
                .filter(|obs| obs.is_html_fragment())
                .count(),
        }
    }

    pub fn response_body_coverage(&self) -> f64 {
        if self.total_observations == 0 {
            0.0
        } else {
            self.observations_with_response_bodies as f64 / self.total_observations as f64
        }
    }

    pub fn replayable_tool_hint(&self) -> usize {
        self.candidate_api_observations
            .min(self.observations_with_response_bodies)
    }

    pub fn quality_grade(&self) -> &'static str {
        let coverage = self.response_body_coverage();
        let score = coverage * 100.0
            + (self.candidate_api_observations as f64 * 0.8)
            + (self.json_responses as f64 * 0.5)
            + (self.graphql_requests as f64 * 1.5);
        if score >= 180.0 {
            "A"
        } else if score >= 120.0 {
            "B"
        } else if score >= 60.0 {
            "C"
        } else {
            "D"
        }
    }

    pub fn recommended_next_action(&self) -> &'static str {
        if self.total_observations == 0 {
            "record real app actions that trigger API traffic"
        } else if self.observations_with_response_bodies == 0 {
            "re-capture with response bodies included"
        } else if self.response_body_coverage() < 0.5 {
            "capture more response bodies before generating tools"
        } else {
            "good enough to generate"
        }
    }

    pub fn capture_warnings(&self) -> Vec<String> {
        if self.total_observations == 0 {
            return vec![empty_capture_warning()];
        }

        let mut warnings = Vec::new();
        if self.candidate_api_observations == 0 {
            warnings.push(no_api_traffic_warning());
        } else {
            if self.response_body_coverage() < 0.30 {
                warnings.push(format!(
                    "Low response-body coverage: {:.0}%. Capture more requests with responses.",
                    self.response_body_coverage() * 100.0
                ));
            }
            if self.json_responses == 0 {
                warnings.push(
                    "No JSON responses were captured. Re-capture with a focused API workflow."
                        .to_string(),
                );
            }
            if self.replayable_tool_hint() == 0 {
                warnings.push(
                    "No replayable tools were captured. Capture requests and their responses."
                        .to_string(),
                );
            }
        }
        if self.html_fragment_endpoints > 0 {
            warnings.push(html_fragment_warning(self.html_fragment_endpoints));
        }
        warnings
    }

    pub fn needs_more_api_observations(&self, min_api_observations: usize) -> bool {
        self.candidate_api_observations < min_api_observations
    }

    pub fn minimum_api_failure_message(&self, min_api_observations: usize) -> Option<String> {
        if !self.needs_more_api_observations(min_api_observations) {
            return None;
        }

        if self.total_observations == 0 {
            return Some(empty_capture_warning());
        }

        if self.candidate_api_observations == 0 {
            return Some(no_api_traffic_warning());
        }

        Some(format!(
            "Captured {} candidate API observation(s), below --min-api-observations {}. Capture a focused workflow with real API traffic.",
            self.candidate_api_observations, min_api_observations
        ))
    }
}

fn empty_capture_warning() -> String {
    "No useful API traffic was captured. This usually means no interaction occurred, the browser failed to launch, or requests were served from cache/service worker. Try again and perform a focused workflow while recording.".to_string()
}

fn no_api_traffic_warning() -> String {
    "No useful API traffic was captured. This usually means no interaction occurred, the browser failed to launch, or requests were served from cache/service worker. Try again and perform a focused workflow while recording.".to_string()
}

fn html_fragment_warning(count: usize) -> String {
    format!(
        "{count} request(s) fetched server-rendered HTML fragments instead of JSON. Tapestry cannot turn HTML fragment endpoints into tools yet (see docs/LIMITATIONS.md); if this site's listing/search flow uses them, expect only secondary config/read tools."
    )
}

#[derive(Debug, Clone)]
pub struct CdpObservationBuilder {
    options: CaptureOptions,
    origin_host: Option<String>,
    next_sequence: usize,
    pending: BTreeMap<String, PendingObservation>,
}

impl CdpObservationBuilder {
    pub fn new(options: CaptureOptions, origin_url: &str) -> Self {
        Self {
            origin_host: host_from_url(origin_url).map(|host| host.to_ascii_lowercase()),
            options,
            next_sequence: 0,
            pending: BTreeMap::new(),
        }
    }

    pub fn ingest_message(&mut self, message: &Value) {
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return;
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        match method {
            "Network.requestWillBeSent" => self.ingest_request_will_be_sent(&params),
            "Network.requestWillBeSentExtraInfo" => self.ingest_request_extra_info(&params),
            "Network.responseReceived" => self.ingest_response_received(&params),
            "Network.responseReceivedExtraInfo" => self.ingest_response_extra_info(&params),
            "Network.loadingFinished" => self.ingest_loading_finished(&params),
            "Network.loadingFailed" => self.ingest_loading_failed(&params),
            _ => {}
        }
    }

    pub fn mark_response_body(&mut self, request_id: &str, body: &str, base64_encoded: bool) {
        let Some(pending) = self.pending.get_mut(request_id) else {
            return;
        };
        pending.body_attempted = true;
        if response_body_should_skip(pending.response_mime_type.as_deref(), &pending.path) {
            pending
                .warnings
                .push("cdp_response_body_skipped_static_resource".to_string());
            return;
        }
        let decoded = if base64_encoded {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(body) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => text,
                    Err(_) => {
                        pending
                            .warnings
                            .push("cdp_response_body_decode_failed".to_string());
                        return;
                    }
                },
                Err(_) => {
                    pending
                        .warnings
                        .push("cdp_response_body_decode_failed".to_string());
                    return;
                }
            }
        } else {
            body.to_string()
        };
        if decoded.len() > self.options.max_body_bytes {
            pending
                .warnings
                .push("cdp_response_body_too_large".to_string());
            return;
        }
        if let Some(json) = parse_json_maybe(&decoded) {
            pending.response_body = Some(redact_value(json));
        }
    }

    pub fn response_body_present(&self, request_id: &str) -> bool {
        self.pending
            .get(request_id)
            .map(|pending| pending.response_body.is_some())
            .unwrap_or(false)
    }

    pub fn mark_response_body_unavailable(&mut self, request_id: &str) {
        if let Some(pending) = self.pending.get_mut(request_id) {
            pending.body_attempted = true;
            pending
                .warnings
                .push("cdp_response_body_unavailable".to_string());
        }
    }

    pub fn finalize(self) -> Vec<Observation> {
        let include_third_party = self.options.include_third_party;
        let origin_host = self.origin_host.clone();
        let mut pending = self
            .pending
            .into_values()
            .filter(|item| include_third_party || item.same_site(&origin_host))
            .collect::<Vec<_>>();
        pending.sort_by_key(|item| item.sequence);
        pending
            .into_iter()
            .map(|item| item.into_observation())
            .collect()
    }

    fn ingest_request_will_be_sent(&mut self, params: &Value) {
        let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
            return;
        };
        let request = params.get("request").cloned().unwrap_or(Value::Null);
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .or_else(|| params.get("documentURL").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string();
        let Some(parsed_url) = Url::parse(&url).ok() else {
            return;
        };
        if !matches!(parsed_url.scheme(), "http" | "https") {
            return;
        }
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let path = parsed_url.path().to_string();
        let query = crate::redacted_query_map(&parsed_url);
        let url = crate::redact_url_query(&parsed_url);
        let request_headers = headers_from_value(request.get("headers"));
        let request_body = request
            .get("postData")
            .and_then(|post_data| post_data.get("text"))
            .and_then(Value::as_str)
            .and_then(parse_json_maybe)
            .map(redact_value);

        self.pending.insert(
            request_id.to_string(),
            PendingObservation {
                sequence: self.next_sequence,
                method,
                url,
                path,
                query,
                request_headers,
                request_body,
                response_status: None,
                response_headers: BTreeMap::new(),
                response_body: None,
                response_mime_type: None,
                resource_type: params
                    .get("type")
                    .and_then(Value::as_str)
                    .map(|kind| kind.to_ascii_lowercase()),
                warnings: Vec::new(),
                body_attempted: false,
                request_finished: false,
            },
        );
        self.next_sequence += 1;
    }

    fn ingest_request_extra_info(&mut self, params: &Value) {
        let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
            return;
        };
        let Some(pending) = self.pending.get_mut(request_id) else {
            return;
        };
        pending
            .request_headers
            .extend(headers_from_value(params.get("headers")));
    }

    fn ingest_response_received(&mut self, params: &Value) {
        let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
            return;
        };
        let Some(pending) = self.pending.get_mut(request_id) else {
            return;
        };
        let response = params.get("response").cloned().unwrap_or(Value::Null);
        pending.response_status = response
            .get("status")
            .and_then(Value::as_u64)
            .map(|status| status as u16);
        pending.response_mime_type = response
            .get("mimeType")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        // responseReceived carries the final resource type; prefer it over
        // the one guessed at request time.
        if let Some(kind) = params.get("type").and_then(Value::as_str) {
            pending.resource_type = Some(kind.to_ascii_lowercase());
        }
        pending
            .response_headers
            .extend(headers_from_value(response.get("headers")));
    }

    fn ingest_response_extra_info(&mut self, params: &Value) {
        let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
            return;
        };
        let Some(pending) = self.pending.get_mut(request_id) else {
            return;
        };
        pending
            .response_headers
            .extend(headers_from_value(params.get("headers")));
    }

    fn ingest_loading_finished(&mut self, params: &Value) {
        let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
            return;
        };
        let Some(pending) = self.pending.get_mut(request_id) else {
            return;
        };
        pending.body_attempted = true;
        pending.request_finished = true;
    }

    fn ingest_loading_failed(&mut self, params: &Value) {
        let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
            return;
        };
        if let Some(pending) = self.pending.get_mut(request_id) {
            pending.warnings.push("cdp_loading_failed".to_string());
            pending.request_finished = true;
        }
    }
}

/// Resolve the profile directory for a browser session: persistent when
/// configured (created with restricted permissions), throwaway otherwise.
///
/// The path is always absolutized: Chrome resolves a relative
/// `--user-data-dir` against its own working directory and can silently fall
/// back to the default profile — where recent Chrome disables remote
/// debugging entirely, so the DevTools port never opens.
fn resolve_profile_dir(persistent: Option<&Path>) -> Result<(PathBuf, bool)> {
    match persistent {
        Some(dir) => {
            let dir = if dir.is_absolute() {
                dir.to_path_buf()
            } else {
                std::env::current_dir()
                    .context("failed to resolve current directory")?
                    .join(dir)
            };
            fs::create_dir_all(&dir).context("failed to create browser profile directory")?;
            restrict_dir_to_current_user(&dir);
            Ok((dir, false))
        }
        None => Ok((make_profile_dir()?, true)),
    }
}

/// The profile holds session cookies; keep it private to the current user.
fn restrict_dir_to_current_user(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    #[cfg(windows)]
    {
        let restricted = std::env::var("USERNAME")
            .ok()
            .and_then(|user| {
                Command::new("icacls")
                    .arg(dir)
                    .arg("/inheritance:r")
                    .arg("/grant:r")
                    .arg(format!("{user}:(OI)(CI)F"))
                    .output()
                    .ok()
            })
            .map(|output| output.status.success())
            .unwrap_or(false);
        if !restricted {
            eprintln!(
                "Warning: could not restrict permissions on browser profile {} — it may be readable by other local users.",
                dir.display()
            );
        }
    }
}

/// Connect to the page target, enable capture domains, auto-attach to child
/// targets (service workers, popups, OOPIFs), and only then navigate.
///
/// The navigation must come last: enabling Network after the page starts
/// loading loses the initial burst of API traffic, which is usually the
/// richest part of the session.
fn attach_and_navigate(port: u16, timeout: Duration, url: &str) -> Result<WsClient> {
    wait_for_devtools_ready(port, timeout)?;
    // Network.enable only works on page-level targets, not the browser-level
    // target returned by /json/version.
    let page_ws_url = wait_for_page_target(port, timeout)?;
    let mut client = WsClient::connect(&page_ws_url)?;
    client.send_command("Network.enable", json!({}))?;
    client.send_command("Page.enable", json!({}))?;
    client.send_command("Network.setCacheDisabled", json!({ "cacheDisabled": true }))?;
    client.send_command(
        "Target.setAutoAttach",
        json!({ "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true }),
    )?;
    client.send_command("Page.navigate", json!({ "url": url }))?;
    Ok(client)
}

/// Handle a `Target.attachedToTarget` event: enable Network capture in the
/// new session and release it if it was paused waiting for the debugger.
/// Returns the child session id when the event was an attachment.
fn handle_target_attachment(client: &mut WsClient, message: &Value) -> Option<String> {
    if message.get("method").and_then(Value::as_str) != Some("Target.attachedToTarget") {
        return None;
    }
    let session_id = message
        .pointer("/params/sessionId")
        .and_then(Value::as_str)?
        .to_string();
    let _ = client.send_command_in_session("Network.enable", json!({}), Some(&session_id));
    let _ = client.send_command_in_session(
        "Target.setAutoAttach",
        json!({ "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true }),
        Some(&session_id),
    );
    let _ = client.send_command_in_session(
        "Runtime.runIfWaitingForDebugger",
        json!({}),
        Some(&session_id),
    );
    Some(session_id)
}

/// Namespace `params.requestId` with the session id so request ids from
/// different targets can never collide inside the observation builder.
/// Returns the (possibly rewritten) message plus the raw request id needed
/// for `Network.getResponseBody`, which expects the un-namespaced id.
fn namespace_session_request(message: &Value) -> (Value, Option<String>, Option<String>) {
    let session_id = message
        .get("sessionId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let raw_request_id = message
        .pointer("/params/requestId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    match (&session_id, &raw_request_id) {
        (Some(session), Some(raw)) => {
            let mut rewritten = message.clone();
            rewritten["params"]["requestId"] = json!(format!("{session}:{raw}"));
            (rewritten, raw_request_id, session_id)
        }
        _ => (message.clone(), raw_request_id, session_id),
    }
}

pub fn record(url: &str, options: &RecordOptions) -> Result<RecordResult> {
    let browser = resolve_browser(options.browser.as_deref())?;
    let port = reserve_port()?;
    let (profile_dir, ephemeral) = resolve_profile_dir(options.profile_dir.as_deref())?;
    let mut child = launch_browser(
        &browser,
        port,
        &profile_dir,
        options.headless,
        "about:blank",
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let mut client = attach_and_navigate(port, timeout, url)?;
    let capture_options = CaptureOptions {
        include_third_party: options.include_third_party,
        max_body_bytes: options.max_body_bytes,
    };
    let mut builder = CdpObservationBuilder::new(capture_options, url);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    thread::spawn(move || {
        let mut input = String::new();
        // Only stop on a real keypress (n > 0). EOF (n == 0) means stdin is not a
        // terminal — let the timeout handle termination instead.
        if std::io::stdin().read_line(&mut input).unwrap_or(0) > 0 {
            stop_clone.store(true, Ordering::SeqCst);
        }
    });

    let deadline = Instant::now() + Duration::from_secs(options.timeout_secs.max(1));
    let mut pending_body_commands = HashMap::<u64, PendingBodyFetch>::new();

    while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        if let Some(message) = client.read_message_timeout(Duration::from_millis(250))? {
            handle_cdp_message(
                &mut client,
                &mut builder,
                &mut pending_body_commands,
                message,
            )?;
        }
    }

    let _ = client.send_command("Page.stopLoading", json!({}));
    let observations = builder.finalize();
    drop(client);
    let _ = child.kill();
    let _ = child.wait();
    if ephemeral && !options.keep_profile {
        let _ = fs::remove_dir_all(&profile_dir);
    }

    Ok(RecordResult { observations })
}

#[derive(Debug, Clone)]
pub struct ReauthOptions {
    pub browser: Option<PathBuf>,
    pub timeout_secs: u64,
    /// Persistent browser profile directory shared with `record`, so a login
    /// performed during reauth carries over to later capture sessions.
    pub profile_dir: Option<PathBuf>,
}

impl Default for ReauthOptions {
    fn default() -> Self {
        Self {
            browser: None,
            timeout_secs: 300,
            profile_dir: None,
        }
    }
}

/// Collects credential headers from live CDP traffic.
///
/// This deliberately runs on the raw event stream, before the redaction that
/// `CdpObservationBuilder` applies: harvested values are returned to the
/// caller for storage in a site's credentials file and must never be written
/// into observations or logs. Only first-party requests are inspected.
#[derive(Debug, Clone)]
pub struct CredentialHarvester {
    origin_host: Option<String>,
    first_party_requests: HashMap<String, bool>,
    credentials: BTreeMap<String, String>,
}

impl CredentialHarvester {
    pub fn new(origin_url: &str) -> Self {
        Self {
            origin_host: host_from_url(origin_url).map(|host| host.to_ascii_lowercase()),
            first_party_requests: HashMap::new(),
            credentials: BTreeMap::new(),
        }
    }

    pub fn ingest_message(&mut self, message: &Value) {
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return;
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        match method {
            "Network.requestWillBeSent" => {
                let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
                    return;
                };
                let request = params.get("request").cloned().unwrap_or(Value::Null);
                let url = request
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let first_party = self.is_first_party(url);
                self.first_party_requests
                    .insert(request_id.to_string(), first_party);
                if first_party {
                    self.harvest_headers(request.get("headers"));
                }
            }
            "Network.requestWillBeSentExtraInfo" => {
                let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
                    return;
                };
                // ExtraInfo events carry no URL; correlate through the id. An
                // ExtraInfo arriving before its requestWillBeSent is dropped
                // rather than trusted blindly.
                if self
                    .first_party_requests
                    .get(request_id)
                    .copied()
                    .unwrap_or(false)
                {
                    self.harvest_headers(params.get("headers"));
                }
            }
            _ => {}
        }
    }

    fn is_first_party(&self, url: &str) -> bool {
        match (&self.origin_host, host_from_url(url)) {
            (Some(origin), Some(current)) => same_site_host(origin, &current),
            _ => false,
        }
    }

    fn harvest_headers(&mut self, headers: Option<&Value>) {
        let Some(object) = headers.and_then(Value::as_object) else {
            return;
        };
        for (name, raw_value) in object {
            if name.starts_with(':') || !is_secret_header(name) {
                continue;
            }
            // Set-Cookie is a response header; harvesting it as a request
            // credential would replay stale values.
            if name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let Some(value) = raw_value.as_str() else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            // Later requests overwrite earlier ones so we keep the freshest
            // value the session produced.
            self.credentials
                .insert(canonical_header_name(name), value.to_string());
        }
    }

    pub fn into_credentials(self) -> BTreeMap<String, String> {
        self.credentials
    }
}

fn canonical_header_name(name: &str) -> String {
    name.split('-')
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => {
                    first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Opens a browser for a manual login and harvests fresh credential headers.
///
/// The human performs the login; Tapestry only observes the resulting request
/// headers. Always headed — a headless login makes no sense here.
pub fn reauth(url: &str, options: &ReauthOptions) -> Result<BTreeMap<String, String>> {
    let browser = resolve_browser(options.browser.as_deref())?;
    let port = reserve_port()?;
    let (profile_dir, ephemeral) = resolve_profile_dir(options.profile_dir.as_deref())?;
    let mut child = launch_browser(&browser, port, &profile_dir, false, "about:blank")?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let mut client = attach_and_navigate(port, timeout, url)?;
    let mut harvester = CredentialHarvester::new(url);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    thread::spawn(move || {
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).unwrap_or(0) > 0 {
            stop_clone.store(true, Ordering::SeqCst);
        }
    });

    let deadline = Instant::now() + Duration::from_secs(options.timeout_secs.max(1));
    while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        if let Some(message) = client.read_message_timeout(Duration::from_millis(250))? {
            if handle_target_attachment(&mut client, &message).is_some() {
                continue;
            }
            let (message, _, _) = namespace_session_request(&message);
            harvester.ingest_message(&message);
        }
    }

    drop(client);
    let _ = child.kill();
    let _ = child.wait();
    if ephemeral {
        let _ = fs::remove_dir_all(&profile_dir);
    }

    Ok(harvester.into_credentials())
}

/// One in-flight `Network.getResponseBody` command.
///
/// Eager fetches (at `responseReceived`) are opportunistic: their failures
/// are silent because the body may simply not be complete yet. The fetch at
/// `loadingFinished` is authoritative — its failure marks the body
/// unavailable.
struct PendingBodyFetch {
    request_key: String,
    final_attempt: bool,
}

fn handle_cdp_message(
    client: &mut WsClient,
    builder: &mut CdpObservationBuilder,
    pending_body_commands: &mut HashMap<u64, PendingBodyFetch>,
    message: Value,
) -> Result<()> {
    if let Some(id) = message.get("id").and_then(Value::as_u64) {
        if let Some(fetch) = pending_body_commands.remove(&id) {
            if message.get("error").is_some() {
                if fetch.final_attempt {
                    builder.mark_response_body_unavailable(&fetch.request_key);
                }
                return Ok(());
            }
            let result = message.get("result").cloned().unwrap_or(Value::Null);
            let body = result
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let base64_encoded = result
                .get("base64Encoded")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            builder.mark_response_body(&fetch.request_key, body, base64_encoded);
        }
        return Ok(());
    }

    if handle_target_attachment(client, &message).is_some() {
        return Ok(());
    }

    let Some(method) = message
        .get("method")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return Ok(());
    };
    let (message, raw_request_id, session_id) = namespace_session_request(&message);
    let request_key = message
        .pointer("/params/requestId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    match method.as_str() {
        "Network.responseReceived" => {
            builder.ingest_message(&message);
            // Eager body fetch for JSON responses: if the page navigates away
            // before loadingFinished, the body is unrecoverable later.
            let mime = message
                .pointer("/params/response/mimeType")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if mime.contains("json") {
                if let Some(raw_id) = &raw_request_id {
                    let command_id = client.send_command_in_session(
                        "Network.getResponseBody",
                        json!({ "requestId": raw_id }),
                        session_id.as_deref(),
                    )?;
                    pending_body_commands.insert(
                        command_id,
                        PendingBodyFetch {
                            request_key: request_key.clone(),
                            final_attempt: false,
                        },
                    );
                }
            }
        }
        "Network.loadingFinished" => {
            builder.ingest_message(&message);
            if let Some(raw_id) = &raw_request_id {
                if !builder.response_body_present(&request_key) {
                    let command_id = client.send_command_in_session(
                        "Network.getResponseBody",
                        json!({ "requestId": raw_id }),
                        session_id.as_deref(),
                    )?;
                    pending_body_commands.insert(
                        command_id,
                        PendingBodyFetch {
                            request_key,
                            final_attempt: true,
                        },
                    );
                }
            }
        }
        _ => builder.ingest_message(&message),
    }
    Ok(())
}

/// Waits until Chrome's DevTools HTTP endpoint is responding.
fn wait_for_devtools_ready(port: u16, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let version_url = format!("http://127.0.0.1:{port}/json/version");
    loop {
        if ureq::get(&version_url).call().is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "Timed out waiting for browser DevTools on port {port}. Try again with --browser <path>."
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}

/// Returns the WebSocket URL for the first page target from /json/list.
///
/// Network.enable and Page.navigate are page-level CDP commands — they only work
/// when connected to a page target, not the browser-level target from /json/version.
fn wait_for_page_target(port: u16, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    let list_url = format!("http://127.0.0.1:{port}/json/list");
    loop {
        if let Ok(response) = ureq::get(&list_url).call() {
            if let Ok(targets) =
                serde_json::from_reader::<_, Vec<DevToolsTarget>>(response.into_reader())
            {
                if let Some(ws_url) = targets
                    .into_iter()
                    .filter(|t| t.target_type.as_deref() == Some("page"))
                    .find_map(|t| t.web_socket_debugger_url)
                {
                    return Ok(ws_url);
                }
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("Timed out waiting for a page target on DevTools port {port}.");
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct DevToolsTarget {
    #[serde(rename = "type")]
    target_type: Option<String>,
    #[serde(rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: Option<String>,
}

fn launch_browser(
    browser: &Path,
    port: u16,
    profile_dir: &Path,
    headless: bool,
    url: &str,
) -> Result<Child> {
    let mut command = Command::new(browser);
    command
        .arg(format!("--remote-debugging-port={port}"))
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-cache")
        .arg("--disable-background-networking")
        .arg("--disable-sync")
        .arg("--disable-extensions")
        .arg("--new-window")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if headless {
        command.arg("--headless=new");
    }
    command.spawn().with_context(|| {
        format!(
            "failed to launch browser '{}' with remote debugging",
            browser.display()
        )
    })
}

pub fn resolve_browser(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        anyhow::bail!("browser path '{}' does not exist", path.display());
    }

    let candidates = [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "chrome",
        "chromium",
        "chromium-browser",
        "google-chrome",
        "msedge",
    ];
    for candidate in candidates {
        if let Some(path) = locate_executable(candidate) {
            return Ok(path);
        }
    }
    anyhow::bail!("could not locate a Chrome/Chromium browser. Try `--browser <path>`.")
}

fn locate_executable(candidate: &str) -> Option<PathBuf> {
    let candidate_path = PathBuf::from(candidate);
    if candidate_path.exists() {
        return Some(candidate_path);
    }
    if candidate.contains('\\') {
        return None;
    }
    let extensions = ["", ".exe", ".cmd", ".bat"];
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        for ext in extensions {
            let path = dir.join(format!("{candidate}{ext}"));
            if path.exists() {
                return Some(path);
            }
        }
    }
    None
}

fn reserve_port() -> Result<u16> {
    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to reserve a debugging port")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn make_profile_dir() -> Result<PathBuf> {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let dir = std::env::temp_dir().join(format!("tapestry-record-{suffix}"));
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

#[derive(Debug, Clone)]
struct PendingObservation {
    sequence: usize,
    method: String,
    url: String,
    path: String,
    query: BTreeMap<String, Value>,
    request_headers: BTreeMap<String, String>,
    request_body: Option<Value>,
    response_status: Option<u16>,
    response_headers: BTreeMap<String, String>,
    response_body: Option<Value>,
    response_mime_type: Option<String>,
    resource_type: Option<String>,
    warnings: Vec<String>,
    body_attempted: bool,
    request_finished: bool,
}

impl PendingObservation {
    fn same_site(&self, origin_host: &Option<String>) -> bool {
        match (origin_host, host_from_url(&self.url)) {
            (Some(origin), Some(current)) => same_site_host(origin, &current),
            // Unknown origin: keep, so a capture is never silently emptied.
            _ => true,
        }
    }

    fn into_observation(mut self) -> Observation {
        if self.request_finished
            && self.body_attempted
            && self.response_body.is_none()
            && !self
                .warnings
                .iter()
                .any(|warning| warning == "cdp_response_body_unavailable")
        {
            self.warnings
                .push("cdp_response_body_unavailable".to_string());
        }
        Observation {
            method: self.method,
            url: self.url,
            path: self.path,
            query: self.query,
            request_headers: self.request_headers,
            request_body: self.request_body,
            response_status: self.response_status,
            response_headers: self.response_headers,
            response_body: self.response_body,
            resource_type: self.resource_type,
            warnings: self.warnings,
        }
    }
}

fn headers_from_value(value: Option<&Value>) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    let Some(object) = value.and_then(Value::as_object) else {
        return headers;
    };
    for (name, raw_value) in object {
        let value = raw_value
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| raw_value.to_string());
        headers.insert(name.clone(), redact_header(name, &value));
    }
    headers
}

fn redact_header(name: &str, value: &str) -> String {
    if is_secret_header(name) {
        "<redacted>".to_string()
    } else {
        value.to_string()
    }
}

fn is_secret_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "x-csrf-token"
            | "x-xsrf-token"
            | "x-api-key"
            | "x-auth-token"
            | "x-access-token"
            | "x-session-token"
            | "proxy-authorization"
    ) || (lower.starts_with("x-") && lower.contains("token"))
}

fn redact_value(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    if is_secret_body_key(&key) {
                        (key, Value::String("<redacted>".to_string()))
                    } else {
                        (key, redact_value(value))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_value).collect()),
        other => other,
    }
}

fn is_secret_body_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "password",
        "secret",
        "api_key",
    ]
    .iter()
    .any(|secret| key == *secret || key.contains(secret))
}

fn parse_json_maybe(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok()
}

fn host_from_url(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
}

/// Returns the registrable domain (eTLD+1) for a host string.
///
/// Uses a heuristic for multi-part TLDs: if the TLD is a 2-letter country code
/// and the second-level label is a short generic word (co, com, org, net, gov,
/// me, ac, edu ≤ 3 chars), treat the last three labels as the registrable domain.
/// Otherwise use the last two labels. This correctly handles .co.uk, .com.au,
/// .co.jp etc. without requiring a full public-suffix-list dependency.
fn registrable_domain(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let tld = parts[parts.len() - 1];
    let sld = parts[parts.len() - 2];
    let n = if tld.len() == 2
        && sld.len() <= 3
        && sld.chars().all(|c| c.is_ascii_alphabetic())
        && parts.len() >= 3
    {
        // country-code TLD with short second-level label: take last 3 parts
        3
    } else {
        2
    };
    Some(
        parts[parts.len().saturating_sub(n)..]
            .join(".")
            .to_ascii_lowercase(),
    )
}

/// Whether two hosts belong to the same site for first-party filtering.
///
/// IP literals and single-label hosts (localhost, intranet names) have no
/// meaningful registrable domain, so they are compared exactly; everything
/// else is compared by registrable domain so subdomains count as same-site.
fn same_site_host(origin_host: &str, other_host: &str) -> bool {
    let origin = origin_host.to_ascii_lowercase();
    let other = other_host.to_ascii_lowercase();
    match (registrable_domain(&origin), registrable_domain(&other)) {
        (Some(a), Some(b)) if !is_ip_literal(&origin) && !is_ip_literal(&other) => a == b,
        _ => origin == other,
    }
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

fn response_body_should_skip(mime_type: Option<&str>, path: &str) -> bool {
    let mime = mime_type.unwrap_or_default().to_ascii_lowercase();
    let path = path.to_ascii_lowercase();
    mime.starts_with("image/")
        || mime.starts_with("font/")
        || mime.starts_with("audio/")
        || mime.starts_with("video/")
        || mime.contains("javascript")
        || mime.contains("css")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".gif")
        || path.ends_with(".webp")
        || path.ends_with(".ico")
        || path.ends_with(".svg")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
        || path.ends_with(".ttf")
        || path.ends_with(".otf")
        || path.ends_with(".css")
        || path.ends_with(".js")
}

pub(crate) fn is_candidate_api_observation(obs: &Observation) -> bool {
    let path = obs.path.to_ascii_lowercase();
    let method = obs.method.to_ascii_uppercase();
    method != "GET"
        || path.contains("api")
        || path.contains("graphql")
        || obs.request_body.is_some()
}

pub(crate) fn has_json_signal(obs: &Observation) -> bool {
    obs.response_body.is_some()
}

pub(crate) fn graphql_operations(obs: &Observation) -> Vec<String> {
    match &obs.request_body {
        Some(Value::Object(body)) => body
            .get("operationName")
            .and_then(Value::as_str)
            .map(|value| vec![value.to_string()])
            .unwrap_or_default(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                item.as_object()
                    .and_then(|body| body.get("operationName"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect(),
        _ => Vec::new(),
    }
}

struct WsClient {
    stream: TcpStream,
    next_id: u64,
}

impl WsClient {
    fn connect(url: &str) -> Result<Self> {
        let parsed = Url::parse(url).context("invalid DevTools websocket URL")?;
        let host = parsed
            .host_str()
            .context("websocket URL missing host")?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .context("websocket URL missing port")?;
        let addr = format!("{host}:{port}");
        let mut stream =
            TcpStream::connect(addr).context("failed to connect to DevTools websocket")?;
        let key = websocket_key();
        let path = if parsed.path().is_empty() {
            "/"
        } else {
            parsed.path()
        };
        let path = match parsed.query() {
            Some(query) => format!("{path}?{query}"),
            None => path.to_string(),
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .context("failed to send websocket handshake")?;
        stream.flush().ok();
        let _ = read_http_response_headers(&mut stream)?;
        stream
            .set_read_timeout(Some(Duration::from_millis(250)))
            .ok();
        Ok(Self { stream, next_id: 1 })
    }

    fn send_command(&mut self, method: &str, params: Value) -> Result<u64> {
        self.send_command_in_session(method, params, None)
    }

    /// Send a command scoped to a flattened target session (child frames,
    /// service workers, popups). `None` targets the root page session.
    fn send_command_in_session(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let mut payload = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        if let Some(session_id) = session_id {
            payload["sessionId"] = json!(session_id);
        }
        self.send_text(&payload.to_string())?;
        Ok(id)
    }

    fn read_message_timeout(&mut self, timeout: Duration) -> Result<Option<Value>> {
        self.stream
            .set_read_timeout(Some(timeout))
            .context("failed to configure websocket read timeout")?;
        match self.read_text_frame() {
            Ok(Some(text)) => Ok(serde_json::from_str(&text).ok()),
            Ok(None) => Ok(None),
            Err(error) if is_timeout_error(&error) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn send_text(&mut self, text: &str) -> Result<()> {
        let mut frame = Vec::new();
        frame.push(0x81);
        let payload = text.as_bytes();
        let mask = websocket_mask();
        let masked_len = payload.len();
        if masked_len < 126 {
            frame.push(0x80 | masked_len as u8);
        } else if masked_len <= 0xffff {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(masked_len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(masked_len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        self.stream
            .write_all(&frame)
            .context("failed to send websocket frame")?;
        self.stream.flush().ok();
        Ok(())
    }

    fn read_text_frame(&mut self) -> std::io::Result<Option<String>> {
        let mut header = [0u8; 2];
        match self.stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if is_timeout_error(&error) => return Ok(None),
            Err(error) => return Err(error),
        }
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let mut length = (header[1] & 0x7f) as u64;
        if length == 126 {
            let mut buf = [0u8; 2];
            self.stream.read_exact(&mut buf)?;
            length = u16::from_be_bytes(buf) as u64;
        } else if length == 127 {
            let mut buf = [0u8; 8];
            self.stream.read_exact(&mut buf)?;
            length = u64::from_be_bytes(buf);
        }
        let mut mask = [0u8; 4];
        if masked {
            self.stream.read_exact(&mut mask)?;
        }
        let mut payload = vec![0u8; length as usize];
        self.stream.read_exact(&mut payload)?;
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        match opcode {
            0x1 => Ok(Some(String::from_utf8_lossy(&payload).to_string())),
            0x8 => Ok(None),
            0x9 => {
                let _ = self.send_pong(&payload);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn send_pong(&mut self, payload: &[u8]) -> Result<()> {
        let mut frame = Vec::new();
        frame.push(0x8A);
        let mask = websocket_mask();
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else if payload.len() <= 0xffff {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        self.stream
            .write_all(&frame)
            .context("failed to send websocket pong")?;
        self.stream.flush().ok();
        Ok(())
    }
}

fn websocket_key() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(nanos)
}

fn websocket_mask() -> [u8; 4] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    [nanos[0], nanos[1], nanos[2], nanos[3]]
}

fn read_http_response_headers(stream: &mut TcpStream) -> Result<String> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .context("failed to read websocket handshake")?;
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&data).to_string())
}

fn is_timeout_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use tapestry_core::Observation;

    fn request_event(request_id: &str, url: &str, headers: Value) -> Value {
        json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": request_id,
                "request": { "method": "GET", "url": url, "headers": headers }
            }
        })
    }

    #[test]
    fn secret_query_params_are_redacted_in_cdp_observations() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": {
                    "method": "GET",
                    "url": "http://example.com/api/items?api_key=FAKESECRET-CDP-1&page=2",
                    "headers": {}
                }
            }
        }));

        let observations = builder.finalize();
        let serialized = serde_json::to_string(&observations).unwrap();
        assert!(!serialized.contains("FAKESECRET"));
        assert_eq!(observations[0].query["api_key"], "<redacted>");
        assert_eq!(observations[0].query["page"], 2);
        assert!(observations[0].url.contains("page=2"));
    }

    #[test]
    fn session_events_get_namespaced_request_ids() {
        let message = json!({
            "sessionId": "SW1",
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "42.7",
                "request": { "method": "GET", "url": "http://example.com/api", "headers": {} }
            }
        });
        let (rewritten, raw_id, session) = namespace_session_request(&message);
        assert_eq!(rewritten["params"]["requestId"], "SW1:42.7");
        assert_eq!(raw_id.as_deref(), Some("42.7"));
        assert_eq!(session.as_deref(), Some("SW1"));

        // Root-session messages pass through untouched.
        let root = json!({
            "method": "Network.requestWillBeSent",
            "params": { "requestId": "42.7", "request": {} }
        });
        let (unchanged, raw_id, session) = namespace_session_request(&root);
        assert_eq!(unchanged["params"]["requestId"], "42.7");
        assert_eq!(raw_id.as_deref(), Some("42.7"));
        assert!(session.is_none());
    }

    #[test]
    fn namespaced_service_worker_requests_become_distinct_observations() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        // Same raw requestId arriving from the page and from a service worker
        // session must not collide.
        for (session, item) in [(None, "page"), (Some("SW1"), "worker")] {
            let mut message = json!({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "1",
                    "request": {
                        "method": "GET",
                        "url": format!("http://example.com/api/{item}"),
                        "headers": {}
                    }
                }
            });
            if let Some(session) = session {
                message["sessionId"] = json!(session);
            }
            let (message, _, _) = namespace_session_request(&message);
            builder.ingest_message(&message);
        }

        let observations = builder.finalize();
        assert_eq!(observations.len(), 2);
    }

    #[test]
    fn response_body_present_reflects_marked_bodies() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": { "method": "GET", "url": "http://example.com/api", "headers": {} }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.responseReceived",
            "params": {
                "requestId": "1",
                "response": { "status": 200, "mimeType": "application/json", "headers": {} }
            }
        }));

        assert!(!builder.response_body_present("1"));
        builder.mark_response_body("1", r#"{"ok":true}"#, false);
        assert!(builder.response_body_present("1"));
        assert!(!builder.response_body_present("unknown"));
    }

    #[test]
    fn harvester_collects_credential_headers_from_first_party_requests() {
        let mut harvester = CredentialHarvester::new("https://app.example.com/login");
        harvester.ingest_message(&request_event(
            "1",
            "https://api.example.com/v1/me",
            json!({"Authorization": "Bearer abc123", "Accept": "application/json"}),
        ));

        let credentials = harvester.into_credentials();
        assert_eq!(credentials["Authorization"], "Bearer abc123");
        assert!(!credentials.contains_key("Accept"));
    }

    #[test]
    fn harvester_treats_localhost_requests_as_first_party() {
        // Self-hosted sites live on localhost, which has no registrable domain.
        let mut harvester = CredentialHarvester::new("http://localhost:3000/login");
        harvester.ingest_message(&request_event(
            "1",
            "http://localhost:3000/api/me",
            json!({"Authorization": "Bearer local-tok"}),
        ));
        // A genuinely different host must still be rejected.
        harvester.ingest_message(&request_event(
            "2",
            "http://127.0.0.1:9000/api/me",
            json!({"Authorization": "Bearer other"}),
        ));

        let credentials = harvester.into_credentials();
        assert_eq!(credentials["Authorization"], "Bearer local-tok");
    }

    #[test]
    fn same_site_host_compares_ips_and_localhost_exactly() {
        assert!(same_site_host("localhost", "localhost"));
        assert!(!same_site_host("localhost", "127.0.0.1"));
        assert!(same_site_host("127.0.0.1", "127.0.0.1"));
        // IP literals must not be collapsed by the registrable-domain heuristic.
        assert!(!same_site_host("127.0.0.1", "192.168.0.1"));
        // Real domains still match across subdomains.
        assert!(same_site_host("www.example.com", "api.example.com"));
        assert!(!same_site_host("example.com", "evil.com"));
    }

    #[test]
    fn harvester_merges_extra_info_cookies_and_normalizes_names() {
        let mut harvester = CredentialHarvester::new("https://app.example.com");
        harvester.ingest_message(&request_event(
            "1",
            "https://app.example.com/api",
            json!({}),
        ));
        harvester.ingest_message(&json!({
            "method": "Network.requestWillBeSentExtraInfo",
            "params": {
                "requestId": "1",
                "headers": {
                    "cookie": "session=fresh",
                    ":authority": "app.example.com",
                    "x-csrf-token": "csrf42"
                }
            }
        }));

        let credentials = harvester.into_credentials();
        assert_eq!(credentials["Cookie"], "session=fresh");
        assert_eq!(credentials["X-Csrf-Token"], "csrf42");
        assert!(!credentials.keys().any(|name| name.starts_with(':')));
    }

    #[test]
    fn harvester_ignores_third_party_and_uncorrelated_requests() {
        let mut harvester = CredentialHarvester::new("https://app.example.com");
        harvester.ingest_message(&request_event(
            "1",
            "https://tracker.ads.net/pixel",
            json!({"Cookie": "tracking=me"}),
        ));
        // ExtraInfo for an id never seen via requestWillBeSent.
        harvester.ingest_message(&json!({
            "method": "Network.requestWillBeSentExtraInfo",
            "params": { "requestId": "99", "headers": { "cookie": "mystery=1" } }
        }));

        assert!(harvester.into_credentials().is_empty());
    }

    #[test]
    fn harvester_keeps_the_latest_value_per_header() {
        let mut harvester = CredentialHarvester::new("https://app.example.com");
        harvester.ingest_message(&request_event(
            "1",
            "https://app.example.com/api",
            json!({"Authorization": "Bearer old"}),
        ));
        harvester.ingest_message(&request_event(
            "2",
            "https://app.example.com/api",
            json!({"authorization": "Bearer new"}),
        ));

        let credentials = harvester.into_credentials();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials["Authorization"], "Bearer new");
    }

    #[test]
    fn harvester_never_stores_set_cookie() {
        let mut harvester = CredentialHarvester::new("https://app.example.com");
        harvester.ingest_message(&request_event(
            "1",
            "https://app.example.com/api",
            json!({"Set-Cookie": "sid=abc"}),
        ));
        assert!(harvester.into_credentials().is_empty());
    }

    #[test]
    fn mocked_cdp_events_become_observations() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": {
                    "method": "GET",
                    "url": "http://example.com/api/items?page=1&limit=5",
                    "headers": {"Authorization": "secret"}
                }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.responseReceived",
            "params": {
                "requestId": "1",
                "response": {
                    "status": 200,
                    "mimeType": "application/json",
                    "headers": {"content-type": "application/json"}
                }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));
        builder.mark_response_body("1", r#"{"items":[{"title":"One"}]}"#, false);

        let observations = builder.finalize();

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].query["limit"], 5);
        assert_eq!(
            observations[0].response_body.as_ref().unwrap()["items"][0]["title"],
            "One"
        );
        assert_eq!(
            observations[0].request_headers["Authorization"],
            "<redacted>"
        );
    }

    #[test]
    fn xhr_html_fragments_carry_resource_type_and_capture_warning() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "type": "XHR",
                "request": {
                    "method": "GET",
                    "url": "http://example.com/products-fragment?search=shoes",
                    "headers": {}
                }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.responseReceived",
            "params": {
                "requestId": "1",
                "type": "Fetch",
                "response": {
                    "status": 200,
                    "mimeType": "text/html",
                    "headers": {"content-type": "text/html; charset=utf-8"}
                }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();

        // responseReceived's type wins over the request-time guess.
        assert_eq!(observations[0].resource_type.as_deref(), Some("fetch"));
        assert!(observations[0].is_html_fragment());

        let summary = CaptureSummary::from_observations(&observations);
        assert_eq!(summary.html_fragment_endpoints, 1);
        assert!(summary
            .capture_warnings()
            .iter()
            .any(|warning| warning.contains("HTML fragment")));
    }

    #[test]
    fn base64_response_bodies_are_decoded() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": { "method": "GET", "url": "http://example.com/api/items" }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));
        builder.mark_response_body(
            "1",
            &base64::engine::general_purpose::STANDARD.encode(r#"{"ok":true}"#),
            true,
        );

        let observations = builder.finalize();

        assert_eq!(observations[0].response_body.as_ref().unwrap()["ok"], true);
    }

    #[test]
    fn unavailable_response_bodies_add_warning() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": { "method": "GET", "url": "http://example.com/api/items" }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();

        assert!(observations[0]
            .warnings
            .iter()
            .any(|warning| warning == "cdp_response_body_unavailable"));
    }

    #[test]
    fn redaction_happens_before_persisting_observations() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": {
                    "method": "POST",
                    "url": "http://example.com/api/items",
                    "postData": { "text": "{\"token\":\"secret\",\"name\":\"A\"}" }
                }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));
        builder.mark_response_body("1", r#"{"access_token":"abc","ok":true}"#, false);

        let observations = builder.finalize();

        assert_eq!(
            observations[0].request_body.as_ref().unwrap()["token"],
            "<redacted>"
        );
        assert_eq!(
            observations[0].response_body.as_ref().unwrap()["access_token"],
            "<redacted>"
        );
    }

    #[test]
    fn response_body_size_cap_skips_large_bodies() {
        let mut builder = CdpObservationBuilder::new(
            CaptureOptions {
                include_third_party: false,
                max_body_bytes: 8,
            },
            "http://example.com",
        );
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": { "method": "GET", "url": "http://example.com/api/items" }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));
        builder.mark_response_body("1", r#"{"too":"large"}"#, false);

        let observations = builder.finalize();

        assert!(observations[0].response_body.is_none());
        assert!(observations[0]
            .warnings
            .iter()
            .any(|warning| warning == "cdp_response_body_too_large"));
    }

    #[test]
    fn static_bodies_are_skipped() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": { "method": "GET", "url": "http://example.com/logo.png" }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.responseReceived",
            "params": {
                "requestId": "1",
                "response": { "status": 200, "mimeType": "image/png" }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));
        builder.mark_response_body("1", "not-json", false);

        let observations = builder.finalize();

        assert!(observations[0].response_body.is_none());
        assert!(observations[0]
            .warnings
            .iter()
            .any(|warning| warning == "cdp_response_body_skipped_static_resource"));
    }

    #[test]
    fn json_bodies_are_preserved() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": { "method": "GET", "url": "http://example.com/api/items" }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));
        builder.mark_response_body("1", r#"{"items":[{"title":"One"}]}"#, false);

        let observations = builder.finalize();

        assert_eq!(
            observations[0].response_body.as_ref().unwrap()["items"][0]["title"],
            "One"
        );
    }

    #[test]
    fn third_party_filter_drops_foreign_hosts() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": { "method": "GET", "url": "http://cdn.example.org/api/items" }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();

        assert!(observations.is_empty());
    }

    #[test]
    fn subdomain_is_included_for_same_registrable_domain() {
        // xcdn.example.com should be captured when recording https://www.example.com
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "https://www.example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": { "method": "GET", "url": "https://xcdn.example.com/api/products" }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();

        assert_eq!(observations.len(), 1);
        assert!(observations[0].url.contains("xcdn.example.com"));
    }

    #[test]
    fn subdomain_included_for_country_code_tld() {
        // api.next.co.uk should be captured when recording https://www.next.co.uk
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "https://www.next.co.uk");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": { "method": "GET", "url": "https://xcdn.next.co.uk/api/search" }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();

        assert_eq!(observations.len(), 1);
    }

    #[test]
    fn registrable_domain_handles_common_patterns() {
        assert_eq!(
            registrable_domain("www.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            registrable_domain("xcdn.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            registrable_domain("www.next.co.uk"),
            Some("next.co.uk".to_string())
        );
        assert_eq!(
            registrable_domain("xcdn.next.co.uk"),
            Some("next.co.uk".to_string())
        );
        assert_eq!(
            registrable_domain("api.tesco.com"),
            Some("tesco.com".to_string())
        );
        assert_eq!(
            registrable_domain("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(registrable_domain("localhost"), None);
    }

    #[test]
    fn capture_summary_scores_quality_and_guidance() {
        let observations = vec![
            Observation {
                method: "GET".to_string(),
                url: "https://example.com/api/items".to_string(),
                path: "/api/items".to_string(),
                query: BTreeMap::new(),
                request_headers: BTreeMap::new(),
                request_body: None,
                response_status: Some(200),
                response_headers: BTreeMap::new(),
                response_body: Some(json!({"items":[{"id":1}]})),
                resource_type: None,
                warnings: Vec::new(),
            },
            Observation {
                method: "POST".to_string(),
                url: "https://example.com/api/items".to_string(),
                path: "/api/items".to_string(),
                query: BTreeMap::new(),
                request_headers: BTreeMap::new(),
                request_body: Some(json!({"name":"Item"})),
                response_status: Some(200),
                response_headers: BTreeMap::new(),
                response_body: None,
                resource_type: None,
                warnings: Vec::new(),
            },
        ];
        let summary = CaptureSummary::from_observations(&observations);

        assert_eq!(summary.total_observations, 2);
        assert_eq!(summary.candidate_api_observations, 2);
        assert_eq!(summary.observations_with_response_bodies, 1);
        assert_eq!(summary.json_responses, 1);
        assert_eq!(summary.graphql_requests, 0);
        assert!(matches!(summary.quality_grade(), "C" | "D"));
        assert_eq!(summary.recommended_next_action(), "good enough to generate");
    }

    #[test]
    fn capture_summary_empty_emits_strong_warning() {
        let summary = CaptureSummary::from_observations(&[]);
        let warnings = summary.capture_warnings();

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("No useful API traffic was captured"));
        assert!(summary.minimum_api_failure_message(1).is_some());
    }

    #[test]
    fn capture_summary_low_signal_warns_about_coverage_json_and_replayability() {
        let observations = vec![Observation {
            method: "GET".to_string(),
            url: "https://example.com/api/items".to_string(),
            path: "/api/items".to_string(),
            query: BTreeMap::new(),
            request_headers: BTreeMap::new(),
            request_body: None,
            response_status: Some(200),
            response_headers: BTreeMap::new(),
            response_body: None,
            resource_type: None,
            warnings: Vec::new(),
        }];
        let summary = CaptureSummary::from_observations(&observations);

        let warnings = summary.capture_warnings();

        assert!(warnings
            .iter()
            .any(|warning| warning.contains("Low response-body coverage")));
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("No JSON responses were captured")));
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("No replayable tools were captured")));
        assert!(summary.minimum_api_failure_message(2).is_some());
    }

    // ── ordering ────────────────────────────────────────────────────────────

    #[test]
    fn concurrent_requests_finalize_in_arrival_order() {
        // Three requests sent in order A → B → C, all finish before any body is
        // marked.  The observations must come out in that same sequence order,
        // not sorted by requestId string.
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        for (id, path) in [("10", "/api/a"), ("2", "/api/b"), ("1", "/api/c")] {
            builder.ingest_message(&json!({
                "method": "Network.requestWillBeSent",
                "params": { "requestId": id, "request": { "method": "GET",
                    "url": format!("http://example.com{path}") } }
            }));
        }
        for id in ["10", "2", "1"] {
            builder.ingest_message(&json!({
                "method": "Network.loadingFinished",
                "params": { "requestId": id }
            }));
            builder.mark_response_body(id, r#"{"ok":true}"#, false);
        }

        let observations = builder.finalize();

        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].path, "/api/a");
        assert_eq!(observations[1].path, "/api/b");
        assert_eq!(observations[2].path, "/api/c");
    }

    // ── failed / cancelled requests ─────────────────────────────────────────

    #[test]
    fn loading_failed_produces_observation_with_warning() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": { "requestId": "1", "request": { "method": "GET",
                "url": "http://example.com/api/items" } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFailed",
            "params": { "requestId": "1", "errorText": "net::ERR_ABORTED" }
        }));

        let observations = builder.finalize();

        assert_eq!(observations.len(), 1);
        assert!(observations[0]
            .warnings
            .iter()
            .any(|w| w == "cdp_loading_failed"));
    }

    // ── POST request body ────────────────────────────────────────────────────

    #[test]
    fn post_json_body_is_captured_and_redacted() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": {
                    "method": "POST",
                    "url": "http://example.com/api/login",
                    "postData": { "text": r#"{"username":"alice","password":"s3cr3t"}"# }
                }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));
        builder.mark_response_body("1", r#"{"token":"abc123"}"#, false);

        let observations = builder.finalize();

        assert_eq!(observations[0].method, "POST");
        let body = observations[0].request_body.as_ref().unwrap();
        assert_eq!(body["username"], "alice");
        assert_eq!(body["password"], "<redacted>");
        assert_eq!(
            observations[0].response_body.as_ref().unwrap()["token"],
            "<redacted>"
        );
    }

    #[test]
    fn non_json_post_body_is_not_captured() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "1",
                "request": {
                    "method": "POST",
                    "url": "http://example.com/form",
                    "postData": { "text": "name=alice&age=30" }
                }
            }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();

        assert!(observations[0].request_body.is_none());
    }

    // ── non-200 status codes ─────────────────────────────────────────────────

    #[test]
    fn non_200_status_codes_are_captured() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        for (id, status, path) in [
            ("1", 404u64, "/api/missing"),
            ("2", 401, "/api/secret"),
            ("3", 500, "/api/broken"),
        ] {
            builder.ingest_message(&json!({
                "method": "Network.requestWillBeSent",
                "params": { "requestId": id, "request": { "method": "GET",
                    "url": format!("http://example.com{path}") } }
            }));
            builder.ingest_message(&json!({
                "method": "Network.responseReceived",
                "params": { "requestId": id, "response": { "status": status, "mimeType": "application/json" } }
            }));
            builder.ingest_message(&json!({
                "method": "Network.loadingFinished",
                "params": { "requestId": id }
            }));
        }

        let observations = builder.finalize();

        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].response_status, Some(404));
        assert_eq!(observations[1].response_status, Some(401));
        assert_eq!(observations[2].response_status, Some(500));
    }

    // ── extra-info header merging ────────────────────────────────────────────

    #[test]
    fn request_extra_info_merges_late_arriving_headers() {
        // Chrome sends requestWillBeSentExtraInfo after requestWillBeSent for
        // headers that weren't finalised at dispatch time (e.g. cookies).
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": { "requestId": "1", "request": { "method": "GET",
                "url": "http://example.com/api/items",
                "headers": { "Accept": "application/json" } } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSentExtraInfo",
            "params": { "requestId": "1", "headers": { "Cookie": "session=xyz" } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();

        // Cookie header should be present (and redacted as a secret header)
        assert!(observations[0].request_headers.contains_key("Cookie"));
        assert_eq!(
            observations[0].request_headers["Accept"],
            "application/json"
        );
    }

    #[test]
    fn response_extra_info_merges_late_arriving_response_headers() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": { "requestId": "1", "request": { "method": "GET",
                "url": "http://example.com/api/items" } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.responseReceived",
            "params": { "requestId": "1", "response": { "status": 200,
                "headers": { "content-type": "application/json" } } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.responseReceivedExtraInfo",
            "params": { "requestId": "1", "headers": { "x-cache": "HIT" } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();

        assert_eq!(
            observations[0].response_headers["content-type"],
            "application/json"
        );
        assert_eq!(observations[0].response_headers["x-cache"], "HIT");
    }

    // ── include_third_party flag ─────────────────────────────────────────────

    #[test]
    fn include_third_party_captures_foreign_hosts() {
        let mut builder = CdpObservationBuilder::new(
            CaptureOptions {
                include_third_party: true,
                max_body_bytes: usize::MAX,
            },
            "http://example.com",
        );
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": { "requestId": "1", "request": { "method": "GET",
                "url": "http://analytics.other.com/track" } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();

        assert_eq!(observations.len(), 1);
        assert!(observations[0].url.contains("analytics.other.com"));
    }

    // ── non-JSON response bodies ─────────────────────────────────────────────

    #[test]
    fn non_json_response_body_is_not_stored() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": { "requestId": "1", "request": { "method": "GET",
                "url": "http://example.com/api/data" } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));
        builder.mark_response_body("1", "not valid json !!!", false);

        let observations = builder.finalize();

        // Non-JSON body is not stored (no response_body)
        assert!(observations[0].response_body.is_none());
        // The body fetch was attempted but produced no usable JSON, so unavailable warning is added
        assert!(observations[0]
            .warnings
            .iter()
            .any(|w| w == "cdp_response_body_unavailable"));
    }

    // ── orphan / unknown requestId ───────────────────────────────────────────

    #[test]
    fn events_for_unknown_request_id_are_silently_ignored() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        // These all reference "999" which was never registered
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "999" }
        }));
        builder.mark_response_body("999", r#"{"ok":true}"#, false);
        builder.mark_response_body_unavailable("999");

        let observations = builder.finalize();
        assert!(observations.is_empty());
    }

    // ── redirect handling ────────────────────────────────────────────────────

    #[test]
    fn redirect_reuses_request_id_and_captures_final_url() {
        // Chrome reuses the same requestId when a redirect occurs: a second
        // requestWillBeSent fires with the redirect URL before the first
        // response is fully received.  We expect the final (redirected) URL
        // to be what ends up in the observation.
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": { "requestId": "1", "request": { "method": "GET",
                "url": "http://example.com/old-path" } }
        }));
        // Redirect fires before loadingFinished — reuses same requestId
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": { "requestId": "1", "request": { "method": "GET",
                "url": "http://example.com/api/items" } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.responseReceived",
            "params": { "requestId": "1", "response": { "status": 200,
                "mimeType": "application/json" } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));
        builder.mark_response_body("1", r#"{"items":[]}"#, false);

        let observations = builder.finalize();

        // Only one observation (the redirect chain collapses to one requestId)
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].path, "/api/items");
        assert_eq!(observations[0].response_status, Some(200));
    }

    // ── query type inference ─────────────────────────────────────────────────

    #[test]
    fn query_parameters_are_typed_correctly() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        builder.ingest_message(&json!({
            "method": "Network.requestWillBeSent",
            "params": { "requestId": "1", "request": { "method": "GET",
                "url": "http://example.com/api/search?limit=10&active=true&score=3.14&q=shoes" } }
        }));
        builder.ingest_message(&json!({
            "method": "Network.loadingFinished",
            "params": { "requestId": "1" }
        }));

        let observations = builder.finalize();
        let q = &observations[0].query;

        // integers stay as numbers, booleans as bools, floats as floats, strings as strings
        assert_eq!(q["limit"], serde_json::json!(10));
        assert_eq!(q["active"], serde_json::json!(true));
        assert_eq!(q["score"], serde_json::json!(3.14));
        assert_eq!(q["q"], serde_json::json!("shoes"));
    }

    // ── non-http URL filtering ───────────────────────────────────────────────

    #[test]
    fn non_http_urls_are_not_captured() {
        let mut builder =
            CdpObservationBuilder::new(CaptureOptions::default(), "http://example.com");
        for url in [
            "data:text/plain,hello",
            "chrome-extension://abc/bg.js",
            "blob:http://example.com/some-uuid",
        ] {
            builder.ingest_message(&json!({
                "method": "Network.requestWillBeSent",
                "params": { "requestId": url, "request": { "method": "GET", "url": url } }
            }));
        }

        let observations = builder.finalize();

        assert!(observations.is_empty());
    }
}
