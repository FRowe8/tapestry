//! Shared traffic-signal predicates.
//!
//! These heuristics decide what a captured request *is* — API call, static
//! asset, consent/config fetch, bot/security telemetry — and every
//! user-facing number derives from them: the analyzer's signal filter, the
//! post-capture summary in tapestry-input, and the CLI's `diagnose` counts.
//! They were previously maintained as three separate copies that had already
//! drifted apart; they live here so those surfaces cannot disagree again.
//! The canonical semantics are the analyzer's, since the analyzer's filter
//! is the behavior the other surfaces exist to explain.

use crate::Observation;
use serde_json::Value;
use std::collections::BTreeMap;

/// Case-insensitive header lookup: does `name` exist with `needle` anywhere
/// in its value?
pub fn header_contains(headers: &BTreeMap<String, String>, name: &str, needle: &str) -> bool {
    headers.iter().any(|(header_name, value)| {
        header_name.eq_ignore_ascii_case(name)
            && value
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
    })
}

/// Any evidence this request/response pair speaks JSON: a parsed body on
/// either side, or JSON content-type/accept headers.
pub fn has_json_signal(obs: &Observation) -> bool {
    obs.request_body.is_some()
        || obs.response_body.is_some()
        || header_contains(&obs.request_headers, "content-type", "json")
        || header_contains(&obs.request_headers, "accept", "json")
        || header_contains(&obs.response_headers, "content-type", "json")
}

/// The response itself is JSON: a captured body, or a JSON content-type when
/// the body is missing (common when a capture drops bodies).
pub fn is_json_response(obs: &Observation) -> bool {
    obs.response_body.is_some() || header_contains(&obs.response_headers, "content-type", "json")
}

/// Path starts with a conventional API prefix (`/api/`, `/graphql`, `/rest/`,
/// `/rpc/`, or a version segment like `/v2/`).
pub fn is_api_path(path: &str) -> bool {
    let trimmed = path.trim_matches('/').to_ascii_lowercase();
    trimmed == "graphql"
        || trimmed.starts_with("api/")
        || trimmed.starts_with("graphql/")
        || trimmed.starts_with("rest/")
        || trimmed.starts_with("rpc/")
        || trimmed
            .split('/')
            .next()
            .map(is_version_segment)
            .unwrap_or(false)
}

/// A version path segment: `v1`, `v2`, `v10`, ...
pub fn is_version_segment(seg: &str) -> bool {
    seg.len() >= 2 && seg.starts_with('v') && seg[1..].chars().all(|c| c.is_ascii_digit())
}

/// Path ends in a static-asset extension (scripts, styles, images, fonts,
/// media, PDFs).
pub fn is_static_asset_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        ".css", ".js", ".mjs", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".wav", ".pdf",
    ]
    .iter()
    .any(|extension| path.ends_with(extension))
}

/// Consent-management or static-config fetch: known CMP/privacy path
/// markers, or a body-less GET of an `/assets/**.json` file whose response
/// looks like consent/locale/config data rather than app data.
pub fn is_consent_or_config_asset(obs: &Observation) -> bool {
    let path = obs.path.to_ascii_lowercase();
    let consent_markers = [
        "/assets/cmp/",
        "/cmp/",
        "/consent/",
        "/privacy/",
        "/cookie/",
        "/cookies/",
        "/onetrust/",
        "/trustarc/",
    ];
    if consent_markers.iter().any(|marker| path.contains(marker)) {
        return true;
    }

    obs.method == "GET"
        && obs.request_body.is_none()
        && path.contains("/assets/")
        && path.ends_with(".json")
        && response_looks_static_config(obs.response_body.as_ref())
}

fn response_looks_static_config(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let text = value.to_string().to_ascii_lowercase();
    [
        "consent", "cookie", "privacy", "onetrust", "trustarc", "cmp", "locale", "config",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

/// Bot-defense or security telemetry: known vendor path markers, telemetry
/// keys in the request body, or an opaque-path POST with no semantic
/// operation and an empty/opaque response.
pub fn is_bot_or_security_telemetry(obs: &Observation) -> bool {
    let path = obs.path.to_ascii_lowercase();
    let path_markers = [
        "/akam/",
        "/akamai/",
        "/bot/",
        "/challenge/",
        "/captcha/",
        "/risk/",
        "/fingerprint/",
        "/telemetry/",
    ];
    if path_markers.iter().any(|marker| path.contains(marker)) {
        return true;
    }

    if body_contains_telemetry_key(obs.request_body.as_ref()) {
        return true;
    }

    obs.method == "POST"
        && has_opaque_path_segment(&path)
        && !is_graphql_request(obs)
        && semantic_operation_name(&obs.request_body).is_none()
        && response_is_empty_or_opaque(obs.response_body.as_ref())
}

/// Request body carries a bot-defense/fingerprinting key anywhere in its
/// structure.
pub fn body_contains_telemetry_key(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "sensor_data"
                    | "_fingerprint"
                    | "fingerprint"
                    | "challenge"
                    | "captcha"
                    | "bot"
                    | "risk"
                    | "akamai"
            ) || body_contains_telemetry_key(Some(value))
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| body_contains_telemetry_key(Some(value))),
        Value::String(value) => {
            let value = value.to_ascii_lowercase();
            value.contains("sensor_data")
                || value.contains("fingerprint")
                || value.contains("akamai")
        }
        _ => false,
    }
}

fn has_opaque_path_segment(path: &str) -> bool {
    path.trim_matches('/').split('/').any(|segment| {
        segment.len() >= 16
            && segment
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .count()
                >= segment.len() * 3 / 4
            && !contains_semantic_word(segment)
    })
}

fn contains_semantic_word(segment: &str) -> bool {
    let segment = segment.to_ascii_lowercase();
    [
        "api", "search", "basket", "cart", "product", "item", "order", "user", "account", "list",
        "status", "graphql", "category", "grocer",
    ]
    .iter()
    .any(|word| segment.contains(word))
}

fn response_is_empty_or_opaque(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::Object(map)) => {
            map.is_empty() || map.keys().all(|key| !contains_semantic_word(key))
        }
        Some(Value::String(value)) => value.len() > 64 && !contains_semantic_word(value),
        _ => false,
    }
}

/// POST whose body (or any element of a batched array body) carries GraphQL
/// keys (`operationName`/`query`/`variables`).
pub fn is_graphql_request(obs: &Observation) -> bool {
    if obs.method != "POST" {
        return false;
    }
    fn has_graphql_operation(value: &Value) -> bool {
        match value {
            Value::Array(items) => items.iter().any(has_graphql_operation),
            Value::Object(map) => {
                map.contains_key("operationName")
                    || map.contains_key("query")
                    || map.contains_key("variables")
            }
            _ => false,
        }
    }
    obs.request_body
        .as_ref()
        .map(has_graphql_operation)
        .unwrap_or(false)
}

/// Best-effort semantic name for an RPC-style body (`operationName`,
/// `action`, `type`, ...), recursing into batched arrays and `requests`
/// wrappers.
pub fn semantic_operation_name(body: &Option<Value>) -> Option<String> {
    let value = body.as_ref()?;
    match value {
        Value::Object(map) => [
            "operationName",
            "operation",
            "action",
            "type",
            "method",
            "query",
        ]
        .iter()
        .find_map(|key| map.get(*key).and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            map.get("requests")
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .and_then(|value| semantic_operation_name(&Some(value.clone())))
        }),
        Value::Array(values) => values
            .first()
            .and_then(|value| semantic_operation_name(&Some(value.clone()))),
        _ => None,
    }
}

/// The host most observations were captured against; ties broken by
/// first-seen order so the result is deterministic across runs.
pub fn infer_primary_host(observations: &[Observation]) -> Option<String> {
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for (idx, obs) in observations.iter().enumerate() {
        let Some(host) = host_for(&obs.url) else {
            continue;
        };
        let entry = counts.entry(host).or_insert((0, idx));
        entry.0 += 1;
    }

    counts
        .into_iter()
        .max_by(|(_, (count_a, seen_a)), (_, (count_b, seen_b))| {
            count_a.cmp(count_b).then(seen_b.cmp(seen_a))
        })
        .map(|(host, _)| host)
}

/// Host component of a URL, if it parses.
pub fn host_for(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
}

/// Could this observation plausibly become a tool? Not noise (static asset,
/// consent/config, bot telemetry) and carrying at least one API signal (API
/// path, JSON, a request body, or a stateful method).
pub fn is_candidate_api_observation(obs: &Observation) -> bool {
    !is_static_asset_path(&obs.path)
        && !is_consent_or_config_asset(obs)
        && !is_bot_or_security_telemetry(obs)
        && (is_api_path(&obs.path)
            || has_json_signal(obs)
            || obs.request_body.is_some()
            || matches!(obs.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE"))
}
