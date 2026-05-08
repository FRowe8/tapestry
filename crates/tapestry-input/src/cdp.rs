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
            origin_host: host_from_url(origin_url),
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
        let query = parsed_url
            .query_pairs()
            .map(|(key, value)| (key.to_string(), infer_scalar(value.as_ref())))
            .collect::<BTreeMap<_, _>>();
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

pub fn record(url: &str, options: &RecordOptions) -> Result<RecordResult> {
    let browser = resolve_browser(options.browser.as_deref())?;
    let port = reserve_port()?;
    let profile_dir = make_profile_dir()?;
    let mut child = launch_browser(&browser, port, &profile_dir, options.headless, url)?;
    let version = wait_for_devtools_version(port, Duration::from_secs(options.timeout_secs))?;
    let websocket_url = version
        .web_socket_debugger_url
        .context("browser did not expose a DevTools websocket URL")?;
    let mut client = WsClient::connect(&websocket_url)?;
    let capture_options = CaptureOptions {
        include_third_party: options.include_third_party,
        max_body_bytes: options.max_body_bytes,
    };
    let mut builder = CdpObservationBuilder::new(capture_options, url);
    client.send_command("Network.enable", json!({}))?;
    client.send_command("Page.enable", json!({}))?;
    client.send_command("Network.setCacheDisabled", json!({ "cacheDisabled": true }))?;
    client.send_command("Page.navigate", json!({ "url": url }))?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    thread::spawn(move || {
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        stop_clone.store(true, Ordering::SeqCst);
    });

    let deadline = Instant::now() + Duration::from_secs(options.timeout_secs.max(1));
    let mut pending_body_commands = HashMap::<u64, String>::new();

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
    if !options.keep_profile {
        let _ = fs::remove_dir_all(&profile_dir);
    }

    Ok(RecordResult { observations })
}

fn handle_cdp_message(
    client: &mut WsClient,
    builder: &mut CdpObservationBuilder,
    pending_body_commands: &mut HashMap<u64, String>,
    message: Value,
) -> Result<()> {
    if let Some(id) = message.get("id").and_then(Value::as_u64) {
        if let Some(request_id) = pending_body_commands.remove(&id) {
            if let Some(error) = message.get("error") {
                let _ = error;
                builder.mark_response_body_unavailable(&request_id);
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
            builder.mark_response_body(&request_id, body, base64_encoded);
        }
        return Ok(());
    }

    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return Ok(());
    };
    match method {
        "Network.loadingFinished" => {
            let request_id = message
                .get("params")
                .and_then(|params| params.get("requestId"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            builder.ingest_message(&message);
            if !request_id.is_empty() {
                let command_id = client.send_command(
                    "Network.getResponseBody",
                    json!({ "requestId": request_id.clone() }),
                )?;
                pending_body_commands.insert(command_id, request_id);
            }
        }
        _ => builder.ingest_message(&message),
    }
    Ok(())
}

fn wait_for_devtools_version(port: u16, timeout: Duration) -> Result<DevToolsVersion> {
    let deadline = Instant::now() + timeout;
    let version_url = format!("http://127.0.0.1:{port}/json/version");
    loop {
        if let Ok(response) = ureq::get(&version_url).call() {
            if let Ok(version) = response.into_json::<DevToolsVersion>() {
                return Ok(version);
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "Timed out waiting for browser DevTools on port {port}. Try again with --browser <path>."
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct DevToolsVersion {
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

fn resolve_browser(explicit: Option<&Path>) -> Result<PathBuf> {
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
    warnings: Vec<String>,
    body_attempted: bool,
    request_finished: bool,
}

impl PendingObservation {
    fn same_site(&self, origin_host: &Option<String>) -> bool {
        match (origin_host, host_from_url(&self.url)) {
            (Some(origin), Some(current)) => origin.eq_ignore_ascii_case(&current),
            _ => true,
        }
    }

    fn into_observation(mut self) -> Observation {
        if self.request_finished && self.body_attempted && self.response_body.is_none() {
            if !self
                .warnings
                .iter()
                .any(|warning| warning == "cdp_response_body_unavailable")
            {
                self.warnings
                    .push("cdp_response_body_unavailable".to_string());
            }
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

fn infer_scalar(s: &str) -> Value {
    if let Ok(i) = s.parse::<i64>() {
        Value::from(i)
    } else if let Ok(f) = s.parse::<f64>() {
        Value::from(f)
    } else if let Ok(b) = s.parse::<bool>() {
        Value::from(b)
    } else {
        Value::from(s)
    }
}

fn host_from_url(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
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
        let id = self.next_id;
        self.next_id += 1;
        let payload = json!({
            "id": id,
            "method": method,
            "params": params,
        });
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
        let fin = header[0] & 0x80 != 0;
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
            _ => {
                if fin {
                    Ok(None)
                } else {
                    Ok(None)
                }
            }
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
}
